"""Authenticated Falco webhook that quarantines explicitly allowed lab workloads."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hmac
import logging
import os
import threading
import time
from typing import Callable, Mapping, Optional, Set

from flask import Flask, jsonify, request
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from urllib3.exceptions import HTTPError as TransportError


DEFAULT_ALLOWED_RULES = (
    "Redirect STDOUT/STDIN to Network Connection in Container,"
    "PTRACE anti-debug attempt,"
    "Detect Network Tools in vulnapp"
)
MANAGER_LABEL = "security-lab/managed-by"
MANAGER = "falco-handler"
QUARANTINED_AT = "security-lab/quarantined-at"
EVIDENCE_EXPORTED = "security-lab/evidence-exported"

# Falcosidekick sends each alert once and never retries, so transient API failures
# must be absorbed here. 409 means the pod changed between read and patch.
API_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = 0.2
RETRYABLE_STATUSES = {409, 429, 500, 502, 503, 504}


def _csv_set(value: str) -> Set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


@dataclass(frozen=True)
class Settings:
    webhook_token: str
    allowed_rules: Set[str]
    allowed_namespaces: Set[str]
    target_label_key: str
    target_label_value: str
    detach_label_keys: Set[str]
    max_quarantined_pods: int
    request_timeout_seconds: float
    lock_wait_seconds: float
    pod_name: str
    pod_namespace: str

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> "Settings":
        token = environ.get("WEBHOOK_TOKEN", "").strip()
        if not token or token == "CHANGE_ME":
            raise RuntimeError("WEBHOOK_TOKEN must be configured; refusing to start unauthenticated")

        max_quarantined = int(environ.get("MAX_QUARANTINED_PODS", "3"))
        if max_quarantined < 1:
            raise ValueError("MAX_QUARANTINED_PODS must be at least 1")
        timeout = float(environ.get("K8S_REQUEST_TIMEOUT_SECONDS", "3"))
        if not 0 < timeout <= 10:
            raise ValueError("K8S_REQUEST_TIMEOUT_SECONDS must be in (0, 10]")
        lock_wait = float(environ.get("LOCK_WAIT_SECONDS", "10"))
        if not 0 < lock_wait <= 30:
            raise ValueError("LOCK_WAIT_SECONDS must be in (0, 30]")

        return cls(
            webhook_token=token,
            allowed_rules=_csv_set(environ.get("ALLOWED_RULES", DEFAULT_ALLOWED_RULES)),
            allowed_namespaces=_csv_set(environ.get("ALLOWED_NAMESPACES", "default")),
            target_label_key=environ.get("TARGET_LABEL_KEY", "app").strip(),
            target_label_value=environ.get("TARGET_LABEL_VALUE", "vulnapp").strip(),
            detach_label_keys=_csv_set(
                environ.get("DETACH_LABEL_KEYS", "app,pod-template-hash")
            ),
            max_quarantined_pods=max_quarantined,
            request_timeout_seconds=timeout,
            lock_wait_seconds=lock_wait,
            pod_name=environ.get("POD_NAME", "").strip(),
            pod_namespace=environ.get("POD_NAMESPACE", "default").strip(),
        )


def _resolve_workload(data: dict) -> tuple[Optional[str], Optional[str]]:
    output_fields = data.get("output_fields")
    if not isinstance(output_fields, dict):
        return None, None

    pod = output_fields.get("k8s.pod.name")
    namespace = output_fields.get("k8s.ns.name")
    if pod and namespace:
        return str(pod), str(namespace)
    return None, None


def _is_transient(exc: Exception) -> bool:
    if isinstance(exc, ApiException):
        return exc.status in RETRYABLE_STATUSES
    return isinstance(exc, TransportError)


class _Rejected(Exception):
    """The event is valid but the target pod must not be touched by this handler."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _quarantine_time(pod: object):
    value = (getattr(pod.metadata, "annotations", None) or {}).get(QUARANTINED_AT)
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return timestamp if timestamp.tzinfo else None
    except (AttributeError, ValueError, TypeError):
        return None


def create_app(
    k8s_api: Optional[client.CoreV1Api] = None,
    environ: Optional[Mapping[str, str]] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> Flask:
    """Application factory; dependency injection keeps the response logic testable."""
    settings = Settings.from_environ(os.environ if environ is None else environ)
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    response_lock = threading.Lock()

    gunicorn_logger = logging.getLogger("gunicorn.error")
    if gunicorn_logger.handlers:
        app.logger.handlers = gunicorn_logger.handlers
        app.logger.setLevel(gunicorn_logger.level)

    if k8s_api is None:
        config.load_incluster_config()
        k8s_api = client.CoreV1Api()
        app.logger.info("Authenticated with the Kubernetes API")

    @app.get("/health")
    def health() -> tuple[str, int]:
        return "ok", 200

    @app.get("/ready")
    def ready():
        if not settings.pod_name:
            return jsonify(status="not-ready", reason="POD_NAME is not configured"), 503
        try:
            k8s_api.read_namespaced_pod(
                name=settings.pod_name,
                namespace=settings.pod_namespace,
                _request_timeout=settings.request_timeout_seconds,
            )
            return jsonify(status="ready"), 200
        except Exception as exc:
            app.logger.warning("Kubernetes readiness check failed: %s", exc)
            return jsonify(status="not-ready"), 503

    @app.post("/")
    def webhook():
        supplied_token = request.headers.get("X-Falco-Token", "")
        if not hmac.compare_digest(supplied_token.encode(), settings.webhook_token.encode()):
            app.logger.warning("Rejected webhook with invalid authentication")
            return jsonify(error="unauthorized"), 401

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error="invalid JSON payload"), 400

        rule = str(data.get("rule") or "")
        source = str(data.get("source") or "")
        if source != "syscall" or rule not in settings.allowed_rules:
            app.logger.info("Ignored Falco event source=%s rule=%s", source, rule)
            return jsonify(status="ignored"), 202

        pod, namespace = _resolve_workload(data)
        if not pod or not namespace:
            app.logger.warning(
                "Falco event rule=%s lacks k8s.pod.name/k8s.ns.name output fields; "
                "check the container plugin or append_output extra_fields", rule)
            return jsonify(error="pod identity is missing"), 400
        if namespace not in settings.allowed_namespaces:
            app.logger.warning("Rejected event for namespace=%s", namespace)
            return jsonify(error="namespace is not allowed"), 403

        app.logger.info(
            "Accepted Falco rule=%s priority=%s pod=%s namespace=%s",
            rule,
            data.get("priority"),
            pod,
            namespace,
        )

        # Concurrent alerts wait for their turn: a 503 here is a lost alert because
        # Falcosidekick does not retry.
        if not response_lock.acquire(timeout=settings.lock_wait_seconds):
            app.logger.error("Dropped event for pod=%s: response lock wait exceeded", pod)
            return jsonify(error="response in progress; event dropped"), 503
        try:
            try:
                patched_pod, already_quarantined = with_retries(lambda: contain(pod, namespace))
            except _Rejected as rejection:
                app.logger.warning("Rejected event for pod=%s: %s", pod, rejection.message)
                return jsonify(error=rejection.message), rejection.status
            except (ApiException, TransportError) as exc:
                if isinstance(exc, ApiException) and exc.status == 404:
                    app.logger.warning("Target pod=%s namespace=%s no longer exists", pod, namespace)
                    return jsonify(status="gone", pod=pod, namespace=namespace), 200
                app.logger.error("Kubernetes API error while quarantining pod=%s: %s", pod, exc)
                return jsonify(error="Kubernetes API request failed"), 502

            if (patched_pod.metadata.labels or {}).get("tainted-by-falco") != "true":
                raise RuntimeError("Kubernetes API response did not confirm quarantine label")
            app.logger.info("Quarantine label confirmed pod=%s namespace=%s", pod, namespace)

            # Cleanup happens only after successful containment, and its failure does
            # not undo it: the next accepted event retries the cleanup.
            cleanup_pending = not cleanup(pod, namespace)
            body = {
                "status": "already-quarantined" if already_quarantined else "quarantined",
                "pod": pod,
                "namespace": namespace,
            }
            if cleanup_pending:
                body["cleanup"] = "pending"
            return jsonify(body), 200
        except Exception as exc:
            app.logger.exception("Unexpected quarantine error for pod=%s: %s", pod, exc)
            return jsonify(error="quarantine failed"), 500
        finally:
            response_lock.release()

    def with_retries(operation):
        for attempt in range(1, API_ATTEMPTS + 1):
            try:
                return operation()
            except (ApiException, TransportError) as exc:
                if attempt == API_ATTEMPTS or not _is_transient(exc):
                    raise
                app.logger.warning(
                    "Transient Kubernetes API error (attempt %d/%d): %s", attempt, API_ATTEMPTS, exc)
                sleep(RETRY_BACKOFF_SECONDS * 2 ** (attempt - 1))

    def contain(pod: str, namespace: str):
        """Read, validate and label the target; each retry starts from a fresh read."""
        target_pod = k8s_api.read_namespaced_pod(
            name=pod,
            namespace=namespace,
            _request_timeout=settings.request_timeout_seconds,
        )
        existing_labels = target_pod.metadata.labels or {}
        if existing_labels.get("tainted-by-falco") == "true":
            if existing_labels.get(MANAGER_LABEL) != MANAGER:
                raise _Rejected(403, "quarantine is not managed by this handler")
            return target_pod, True
        if existing_labels.get(settings.target_label_key) != settings.target_label_value:
            raise _Rejected(403, "pod is outside the managed workload")

        # Preserve unrelated metadata. Only selector labels required to detach the
        # lab workload are removed, and resourceVersion provides conflict detection.
        patch_labels = {
            key: None for key in settings.detach_label_keys if key in existing_labels
        }
        patch_labels["tainted-by-falco"] = "true"
        patch_labels[MANAGER_LABEL] = MANAGER
        patch = {
            "metadata": {
                "resourceVersion": target_pod.metadata.resource_version,
                "labels": patch_labels,
                "annotations": {QUARANTINED_AT: datetime.now(timezone.utc).isoformat()},
            }
        }
        patched_pod = k8s_api.patch_namespaced_pod(
            name=pod,
            namespace=namespace,
            body=patch,
            _request_timeout=settings.request_timeout_seconds,
        )
        return patched_pod, False

    def cleanup(pod: str, namespace: str) -> bool:
        """Retain a bounded set of recent forensic pods; returns False if work remains."""
        try:
            quarantined = with_retries(lambda: k8s_api.list_namespaced_pod(
                namespace=namespace,
                label_selector=f"tainted-by-falco=true,{MANAGER_LABEL}={MANAGER}",
                _request_timeout=settings.request_timeout_seconds,
            ))
        except (ApiException, TransportError) as exc:
            app.logger.error("Quarantine succeeded but listing for cleanup failed: %s", exc)
            return False

        previous = [item for item in quarantined.items
                    if item.metadata.name != pod
                    and (item.metadata.labels or {}).get(MANAGER_LABEL) == MANAGER
                    and (item.metadata.labels or {}).get("tainted-by-falco") == "true"
                    and _quarantine_time(item) is not None]
        previous.sort(key=_quarantine_time, reverse=True)
        keep_previous = settings.max_quarantined_pods - 1
        complete = True
        for stale_pod in previous[keep_previous:]:
            # Never destroy unexported evidence automatically. This is a soft
            # retention target, not a hard resource cap or a forensic exporter.
            if (getattr(stale_pod.metadata, "annotations", None) or {}).get(EVIDENCE_EXPORTED) != "true":
                app.logger.warning("Retaining unexported evidence pod=%s", stale_pod.metadata.name)
                continue
            try:
                # No retry here: a 409 means the preconditions no longer hold, and the
                # next accepted event re-lists and re-evaluates the pod anyway.
                k8s_api.delete_namespaced_pod(
                    name=stale_pod.metadata.name,
                    namespace=namespace,
                    body=client.V1DeleteOptions(
                        grace_period_seconds=30,
                        preconditions=client.V1Preconditions(
                            uid=stale_pod.metadata.uid,
                            resource_version=stale_pod.metadata.resource_version),
                    ),
                    _request_timeout=settings.request_timeout_seconds,
                )
                app.logger.info("Deleted expired forensic pod=%s", stale_pod.metadata.name)
            except (ApiException, TransportError) as exc:
                if isinstance(exc, ApiException) and exc.status == 404:
                    continue
                complete = False
                app.logger.error(
                    "Quarantine succeeded but retention cleanup failed for pod=%s: %s",
                    stale_pod.metadata.name,
                    exc,
                )
        return complete

    return app
