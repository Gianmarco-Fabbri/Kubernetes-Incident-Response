# Kubernetes Runtime Security & Incident Response Lab

[![CI](https://github.com/Gianmarco-Fabbri/Kubernetes-Incident-Response/actions/workflows/ci.yml/badge.svg)](https://github.com/Gianmarco-Fabbri/Kubernetes-Incident-Response/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An academic lab for Kubernetes runtime detection and automated incident response,
combining Falco, Falcosidekick, a Python handler and Cilium network policies.
The Flask target is intentionally vulnerable. Never expose it to an untrusted network.
This is not a production controller or a forensic acquisition tool.

- [Technical report (PDF)](Kubernetes_Runtime_Security_Guide.pdf)
- [Validation and integration checklist](#validation-status)

## Architecture

```text
Falco syscall event -> HTTP -> Falcosidekick -> authenticated HTTP -> Python handler
  -> validate event and target -> patch pod labels
  -> Cilium network deny + Service detachment + ReplicaSet replacement
```

### Repository map

| Path | Purpose |
|---|---|
| `material/falco/` | Falco values, custom rule and Falcosidekick ingress restriction |
| `material/falco_handler/` | Response service, scoped RBAC, hardening and unit tests |
| `material/manifests/` | Vulnerable workload, Service, PDB and Cilium quarantine policy |
| `material/vulnapp/` | Deliberately vulnerable Flask target and container build |
| `material/payloads/ptrace.c` | Inspectable Linux anti-debugging demonstration |
| `report/` | LaTeX sources of the technical report (compiled copy at repository root) |
| `.github/workflows/ci.yml` | Unit tests, YAML parsing and container build checks |

## Behaviour and limits

The handler accepts only three named syscall rules and pods in `default` with
`app=vulnapp`. It removes only selector labels, adds a manager label and UTC quarantine
timestamp, and uses `resourceVersion` to detect stale patches. The exact reverse-shell
rule is `Redirect STDOUT/STDIN to Network Connection in Container`.

An explicit Cilium ingress/egress deny selects `tainted-by-falco=true`. Label acceptance
does not prove network enforcement: Cilium, EndpointSlices and ReplicaSets reconcile
asynchronously. Two replicas reduce disruption during a single incident; neither they
nor the eviction PDB guarantee zero downtime. No liveness probe deliberately restarts
the quarantined target, but OOM/node failure can still destroy volatile evidence.

`MAX_QUARANTINED_PODS=3` is a soft retention target. Automatic cleanup only considers
older pods marked `security-lab/managed-by=falco-handler` with a valid quarantine time
and an operator assertion `security-lab/evidence-exported=true`. After actually
collecting and verifying evidence, mark a specific pod using `kubectl annotate pod`.
Unexported and legacy evidence is retained, so monitor resource use. Deletion has UID
and resourceVersion preconditions and a 30-second grace period. Cleanup runs on new
or repeated accepted events, not periodically. Failures return non-2xx for retry;
there is no durable queue or guaranteed delivery.

One Gunicorn process serializes responses with a lock; spare threads serve probes.
Concurrent responses get 503 and require retry. Recreate avoids intended rollout
overlap but interrupts service during upgrades. Do not scale without coordination.

## Environment

Use a disposable Linux Kubernetes cluster with a compatible Cilium installation.
Do not replace the CNI of an existing cluster blindly. The historical lab used Cilium
1.15.14; select a supported version pair for new installations and record it.
Current values target Falco chart **9.1.0 / Falco 0.44.1**, with modern eBPF and kernel
BTF support. The old CrownLabs kmod setup is historical, not the current quickstart.
Chart and direct Python dependencies are pinned; image layers and transitive packages
are not fully locked, so bit-for-bit reproducibility is not claimed.

Run from repository root on the Linux lab host. Image import below targets single-node
containerd; adapt to kind/other runtimes. Build the ptrace binary on Linux, not macOS.

```bash
kubectl config current-context
docker build -t vulnapp:lab-v2 material/vulnapp
docker build -t falco-handler:lab-v2 material/falco_handler/src
docker save vulnapp:lab-v2 falco-handler:lab-v2 | sudo ctr -n k8s.io images import -
kubectl apply -f material/manifests/isolate-tainted-policy.yaml
kubectl apply -f material/manifests/vulnapp-deployment.yaml
kubectl apply -f material/manifests/vulnapp-service.yaml
kubectl apply -f material/manifests/vulnapp-pdb.yaml
kubectl -n default rollout status deployment/vulnapp
```

Install isolation BEFORE enabling response. Then run in one shell:

```bash
export FALCO_WEBHOOK_TOKEN="$(openssl rand -hex 32)"
kubectl -n default create secret generic falco-handler-auth \
  --from-literal=webhook-token="$FALCO_WEBHOOK_TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f material/falco_handler/falco-handler-rbac.yaml
kubectl apply -f material/falco_handler/falco-handler-service.yaml
kubectl apply -f material/falco_handler/falco-handler-networkpolicy.yaml
kubectl apply -f material/falco_handler/falco-handler-deployment.yaml
kubectl -n default rollout restart deployment/falco-handler
kubectl -n default rollout status deployment/falco-handler
kubectl create namespace falco --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f material/falco/falcosidekick-networkpolicy.yaml
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
(
  umask 077
  FALCO_VALUES_DIR=$(mktemp -d)
  trap 'rm -f "$FALCO_VALUES_DIR/values.yaml"; rmdir "$FALCO_VALUES_DIR"' EXIT
  cp material/falco/falco-values.example.yaml "$FALCO_VALUES_DIR/values.yaml"
  perl -pi -e 's/CHANGE_ME/$ENV{FALCO_WEBHOOK_TOKEN}/g' "$FALCO_VALUES_DIR/values.yaml"
  helm upgrade --install falco falcosecurity/falco --version 9.1.0 \
    --reset-values -n falco -f "$FALCO_VALUES_DIR/values.yaml" --wait
)
unset FALCO_WEBHOOK_TOKEN
```

Review local overrides before `--reset-values`; this avoids duplicate custom rules
from the old guide. Changing the token requires restarting the handler: Secret-backed
environment variables do not refresh automatically. Helm stores values in release
metadata; restrict access to those Secrets. HTTP/shared tokens are lab controls, not
TLS/mTLS. The upstream ingress policy admits only Falco pods in the same namespace
to Falcosidekick; keep `hostNetwork: false`. Administrators, node access, pod-label
permissions and other additive allow policies remain part of the trust boundary.

## Migration

Applying a Role does not remove the old ClusterRoleBinding. Inspect
`falco-handler-pod-binding` / `falco-pod-manager` and, for the university version,
`falco-handler-deployment-binding` / `falco-deployment-manager`. Remove the old
cluster-scoped bindings/roles only after confirming ownership and other consumers.
Verify the handler cannot patch pods outside `default`. Legacy quarantines without
manager metadata are deliberately not adopted automatically.

## Tests

```bash
python3 -m venv .venv
.venv/bin/pip install -r material/falco_handler/src/requirements.txt
PYTHONPATH=material/falco_handler/src .venv/bin/python -m unittest discover \
  -s material/falco_handler/tests -v
```

## Validation status

[GitHub Actions](.github/workflows/ci.yml) runs on every push and pull request:
handler unit tests (Python 3.11, on the runner and inside the non-root, read-only,
network-less handler image), Python compilation, YAML parsing of all manifests and
both container builds.

The following checks were executed manually on 19 September 2026:

| Check | Result |
|---|---|
| Target smoke test | Form GET and loopback ping POST passed without external network access |
| Helm rendering | Chart 9.1.0 rendered; webhook header and policy selector labels checked |
| Kubernetes standard manifests | Server-side dry-run passed on Kubernetes v1.35.6+orb1; no resources created |
| Cilium isolation / complete Falco response chain | **Not validated end-to-end in this environment** |

Before claiming an end-to-end result, test on a disposable Cilium cluster:

1. Record Kubernetes, kernel, runtime, chart, ruleset and image versions. Check that
   Falco starts without duplicate rules and emits pod/namespace fields.
2. Verify allowed Falco-to-Falcosidekick and Falcosidekick-to-handler traffic; reject
   requests from unrelated pods and unauthenticated webhook calls.
3. Trigger each accepted rule and observe the target labels, EndpointSlice removal
   and recovery to two ready application replicas.
4. Test controlled ingress/egress TCP, UDP/DNS, ICMP and established connections;
   correlate failures with Cilium drop verdicts and check deny precedence over allow policies.
5. Measure service errors/latency and container restart counts during response.
6. Verify RBAC scope, failed-request retries, duplicate events and retention of
   unrelated or unexported evidence. Check behaviour during bursts and handler upgrades.

A failed internet ping alone does not demonstrate bidirectional containment.
Reading the ServiceAccount token is an exposure exercise, not a detection guaranteed
by this ruleset. The deliberate `shell=True` injection must remain in the lab target.

## Provenance and licenses

Gianmarco Fabbri, M.Sc. student in Cybersecurity Engineering, Politecnico di Torino.
The presentation on 9 September 2026 preceded the afternoon changes; its Git reference
is `9ec6471`, subject to any uncommitted submission differences. Later work extends
the original lab and must not be attributed retrospectively to the submitted version.

The root LICENSE contains MIT terms. The report carries CC BY-NC-SA 3.0 and credits
Francesco Pizzato, Alex Palesandro, Marco Iorio and Stefano Galantino. Preserve those
notices; the root license does not relicense third-party teaching material.
