#!/usr/bin/env bash
# Test, package, and roll out the developer-track exercises.
#
# Every exercise is a directory such as d4-token-checks/orders-api holding exercise.env,
# starter/ (the code you edit), solution/ (the files the exercise changes, as the
# reference apps have them), and tests/ (added to a scratch copy when the tests run).
#
# Rollouts go only to your developer namespace, <user>-rhbk-dev: the script refuses any
# other namespace, builds from local sources with an OpenShift binary build into that
# namespace's internal registry, and never pushes to an external registry.
set -Eeuo pipefail

exercises="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
internal_registry=image-registry.openshift-image-registry.svc:5000

usage() {
  cat >&2 <<'EOF'
Usage: bin/exercise.sh <command> [<exercise>] [options]

  list                          List the exercises
  test <exercise> [--solution]  Run the exercise tests against your starter, or the solution
  materialize <exercise> <dir> [--solution]
                                Copy the starter, or the starter with the solution applied, to <dir>
  package <exercise>            Run the exercise's local build step, if it has one
  rollout <exercise>            Build the starter in your developer namespace and roll it out
  request <exercise> [--print]  File the D8 client request with the ops desk and wait for its
                                answer; --print only prints the request with your reports address
  status <exercise>             Wait for the ops desk to issue the D8 client secret into reports-client

<exercise> is a directory under workshop/developer/exercises, for example
d4-token-checks/orders-api. The developer namespace comes from DEV_NAMESPACE, else from
the Dev Spaces workspace namespace, else from `oc project`.
EOF
  exit 2
}

die() { printf 'exercise.sh: %s\n' "$*" >&2; exit 1; }
note() { printf '==> %s\n' "$*" >&2; }

load() {
  [[ -n "${1:-}" ]] || usage
  exercise="${1%/}"
  dir="$exercises/$exercise"
  [[ "$exercise" != *..* && -f "$dir/exercise.env" ]] || die "no exercise at $exercise (try: bin/exercise.sh list)"
  TITLE="" REFERENCE="" COMPONENT="" HELPER=none HELPER_DEST=. NODE_MODULES=no SETUP_CMD="" TEST_CMD=""
  PACKAGE_CMD="" BUILD="" DEPLOYMENT="" REQUIRES=""
  # shellcheck source=/dev/null
  source "$dir/exercise.env"
}

# Copy a tree, leaving out build output and installed dependencies.
copy_tree() {
  local from="$1" to="$2"
  mkdir -p "$to"
  tar -C "$from" --exclude=./node_modules --exclude=./target --exclude=./dist --exclude='__pycache__' \
    --exclude=./.venv -cf - . | tar -C "$to" -xf -
}

materialize() {
  local to="$1" solution="$2"
  copy_tree "$dir/starter" "$to"
  if [[ "$solution" == yes ]]; then copy_tree "$dir/solution" "$to"; fi
}

cmd_list() {
  local env name
  for env in "$exercises"/d*/*/exercise.env; do
    name="${env#"$exercises"/}"
    load "${name%/exercise.env}"
    printf '%-38s %s (%s container)\n' "$exercise" "$TITLE" "$COMPONENT"
  done
}

cmd_test() {
  load "${1:-}"
  local solution=no
  [[ "${2:-}" == --solution ]] && solution=yes
  [[ -z "${2:-}" || "$solution" == yes ]] || usage
  local scratch
  scratch="$(mktemp -d "${TMPDIR:-/tmp}/exercise-test.XXXXXX")"
  # shellcheck disable=SC2064 # expand now: the trap must remove this scratch directory
  trap "rm -rf '$scratch'" EXIT
  materialize "$scratch" "$solution"
  copy_tree "$dir/tests" "$scratch"
  local helpers="$exercises/test-helpers"
  mkdir -p "$scratch/$HELPER_DEST"
  case "$HELPER" in
    java) cp "$helpers/java/src/main/java/com/example/testing/jwks/MockIssuer.java" "$scratch/$HELPER_DEST/" ;;
    python) cp "$helpers/python/mock_jwks.py" "$scratch/$HELPER_DEST/" ;;
    node) cp "$helpers/node/mock-jwks.mjs" "$scratch/$HELPER_DEST/" ;;
    none) ;;
    *) die "unknown HELPER $HELPER in $exercise/exercise.env" ;;
  esac
  if [[ "$NODE_MODULES" == yes ]]; then
    if [[ -n "${EXERCISE_NODE_MODULES:-}" ]]; then
      ln -s "$EXERCISE_NODE_MODULES" "$scratch/node_modules"
    elif [[ -d "$dir/starter/node_modules" ]]; then
      ln -s "$dir/starter/node_modules" "$scratch/node_modules"
    else
      note "Installing dependencies once into the starter (npm ci)"
      (cd "$dir/starter" && npm ci --no-audit --no-fund)
      ln -s "$dir/starter/node_modules" "$scratch/node_modules"
    fi
  fi
  note "Testing the $([[ "$solution" == yes ]] && echo solution || echo starter) of $exercise"
  (cd "$scratch" && { [[ -z "$SETUP_CMD" ]] || eval "$SETUP_CMD"; } && eval "$TEST_CMD")
}

cmd_materialize() {
  load "${1:-}"
  [[ -n "${2:-}" ]] || usage
  local solution=no
  [[ "${3:-}" == --solution ]] && solution=yes
  [[ ! -e "$2" || -z "$(ls -A "$2")" ]] || die "$2 is not empty"
  materialize "$2" "$solution"
  note "Wrote $exercise ($([[ "$solution" == yes ]] && echo solution || echo starter)) to $2"
}

# PACKAGE_CMD helper for D5: the BFF jar serves the SPA that D3's package step builds.
bff_static() {
  local dist="$exercises/d3-spa-pkce/frontend/starter/dist"
  [[ -f "$dist/index.html" ]] || die "build the SPA first, in the node container: bin/exercise.sh package d3-spa-pkce/frontend"
  rm -rf src/main/resources/static
  mkdir -p src/main/resources/static
  cp -a "$dist/." src/main/resources/static/
}

cmd_package() {
  load "${1:-}"
  if [[ -z "$PACKAGE_CMD" ]]; then
    note "$exercise needs no package step: its Containerfile builds from source"
    return
  fi
  note "Packaging $exercise in its starter directory"
  (cd "$dir/starter" && eval "$PACKAGE_CMD")
}

# The seat's developer namespace, and only that: <user>-rhbk-dev.
dev_namespace() {
  local namespace="${DEV_NAMESPACE:-}"
  if [[ -z "$namespace" && -n "${DEVWORKSPACE_NAMESPACE:-}" ]]; then
    namespace="${DEVWORKSPACE_NAMESPACE%-devspaces}-rhbk-dev"
  fi
  if [[ -z "$namespace" ]]; then namespace="$(oc project -q 2>/dev/null || true)"; fi
  [[ -n "$namespace" ]] || die "no developer namespace: set DEV_NAMESPACE or log in with oc"
  if [[ "$namespace" != *-rhbk-dev || ! "$namespace" =~ ^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$ ]]; then
    die "refusing namespace '$namespace': exercises roll out only to your developer namespace, <user>-rhbk-dev"
  fi
  # In Dev Spaces, oc must run as you. The workspace service account has no
  # rights in <user>-rhbk-dev, so stop with the fix instead of a forbidden error.
  local identity
  identity="$(oc whoami 2>/dev/null || true)"
  if [[ "$identity" == system:serviceaccount:*-devspaces:workspace* ]]; then
    die "oc runs as the workspace service account ($identity), not as you: stop this workspace and start it again from the Dev Spaces dashboard, which logs oc in as you"
  fi
  printf '%s\n' "$namespace"
}

rollout_binary() {
  local namespace="$1" name="$DEPLOYMENT" required kind target
  for required in $REQUIRES; do
    [[ -e "$dir/starter/$required" ]] || die "$exercise/starter/$required is missing; run: bin/exercise.sh package $exercise"
  done
  if oc get "buildconfig/$name" -n "$namespace" >/dev/null 2>&1; then
    kind="$(oc get "buildconfig/$name" -n "$namespace" -o jsonpath='{.spec.output.to.kind}')"
    target="$(oc get "buildconfig/$name" -n "$namespace" -o jsonpath='{.spec.output.to.namespace}')"
    [[ "$kind" == ImageStreamTag && ( -z "$target" || "$target" == "$namespace" ) ]] ||
      die "buildconfig/$name in $namespace does not push to this namespace's image stream; not using it"
  else
    note "Creating binary build $name in $namespace"
    oc new-build --binary --strategy=docker --name="$name" -n "$namespace"
  fi
  # A docker-strategy build reads ./Dockerfile unless told otherwise; the starters ship a Containerfile.
  oc patch "buildconfig/$name" -n "$namespace" --type merge \
    -p '{"spec":{"strategy":{"dockerStrategy":{"dockerfilePath":"Containerfile"}}}}' >/dev/null
  local stage
  stage="$(mktemp -d "${TMPDIR:-/tmp}/exercise-build.XXXXXX")"
  # shellcheck disable=SC2064 # expand now: the trap must remove this staging directory
  trap "rm -rf '$stage'" EXIT
  # Upload the sources and the packaged output the Containerfile copies, not dependencies.
  tar -C "$dir/starter" --exclude=./node_modules --exclude='__pycache__' --exclude=./.venv -cf - . | tar -C "$stage" -xf -
  note "Building $name from $exercise/starter in $namespace"
  oc start-build "$name" --from-dir="$stage" --follow --wait -n "$namespace"
  local image
  image="$(oc get "imagestreamtag/$name:latest" -n "$namespace" -o jsonpath='{.image.dockerImageReference}')"
  [[ "$image" == "$internal_registry/$namespace/$name@sha256:"* ]] ||
    die "built image '$image' is not in $namespace's internal registry; not rolling out"
  note "Rolling out deployment/$name in $namespace"
  oc set image "deployment/$name" "$name=$image" -n "$namespace"
  oc rollout status "deployment/$name" --timeout=300s -n "$namespace"
}

rollout_config() {
  local namespace="$1" rendered key value
  rendered="$(mktemp "${TMPDIR:-/tmp}/exercise-config.XXXXXX")"
  # shellcheck disable=SC2064 # expand now: the trap must remove this rendered file
  trap "rm -f '$rendered'" EXIT
  cp "$dir/starter/reports-config.env" "$rendered"
  # The issuer, Keycloak host, and legacy address are the ones bff-config already holds.
  for key in OIDC_ISSUER KEYCLOAK_HOST LEGACY_BASE_URL; do
    value="$(oc get configmap/bff-config -n "$namespace" -o "jsonpath={.data.$key}")"
    [[ -n "$value" && "$value" != *'|'* ]] || die "bff-config in $namespace has no usable $key"
    sed -i.bak "s|@$key@|$value|g" "$rendered" && rm -f "$rendered.bak"
  done
  if grep -q '@[A-Z_]*@' "$rendered"; then die "reports-config.env has an unknown @...@ placeholder"; fi
  if oc get "configmap/$DEPLOYMENT-config" -n "$namespace" >/dev/null 2>&1; then
    # oc set data has no --from-env-file (oc 4.21 in the workspace), so pass each KEY=VALUE line.
    local -a pairs=()
    mapfile -t pairs < <(grep -Ev '^[[:space:]]*(#|$)' "$rendered")
    oc set data "configmap/$DEPLOYMENT-config" "${pairs[@]}" -n "$namespace"
  else
    oc create configmap "$DEPLOYMENT-config" --from-env-file="$rendered" -n "$namespace"
  fi
  note "Restarting deployment/$DEPLOYMENT in $namespace"
  oc rollout restart "deployment/$DEPLOYMENT" -n "$namespace"
  oc rollout status "deployment/$DEPLOYMENT" --timeout=300s -n "$namespace"
}

cmd_rollout() {
  load "${1:-}"
  local namespace
  namespace="$(dev_namespace)"
  case "$BUILD" in
    binary) rollout_binary "$namespace" ;;
    config)
      [[ -n "$(annotation "secret/$client_secret" "$namespace" "$ops_desk/ops-desk-issued")" ]] ||
        die "the ops desk has not issued the client secret into $client_secret yet; run: bin/exercise.sh request $exercise"
      rollout_config "$namespace" ;;
    *) die "$exercise has no rollout (BUILD=$BUILD)" ;;
  esac
}

# The D8 request and its answer. The ops desk (one per reservation) reviews the request
# against Module 8's requirements, writes its decision as annotations on the request, and on
# a pass writes the client secret into reports-client. Nobody handles or pastes the secret: this script
# reads only annotations, never a Secret's data.
ops_desk=rhbk-workshop
request_configmap=reports-client-request
client_secret=reports-client

# One annotation of an object, or nothing; never its data.
annotation() {
  oc get "$1" -n "$2" -o "go-template={{with .metadata.annotations}}{{with index . \"$3\"}}{{.}}{{end}}{{end}}" \
    2>/dev/null || true
}

wait_seconds() {
  local seconds="${EXERCISE_WAIT_SECONDS:-90}"
  [[ "$seconds" =~ ^[0-9]+$ ]] || die "EXERCISE_WAIT_SECONDS must be a number of seconds"
  printf '%s\n' "$seconds"
}

reports_url() {
  local host
  host="$(oc get route/reports -n "$1" -o jsonpath='{.spec.host}')"
  [[ "$host" =~ ^[a-z0-9.-]+$ ]] || die "no reports route in $1"
  printf 'https://%s\n' "$host"
}

render_request() {
  # Operations needs the settings, not the exercise's ANTI-PATTERN markers.
  grep -Ev '^[[:space:]]*# (ANTI-PATTERN|Exercise D8)' "$dir/starter/client-request.yaml" \
    | sed "s|@REPORTS_URL@|$1|g"
}

# The same rules the ops desk runs, when this container has python3.
local_review() {
  local rendered="$1" url="$2"
  command -v python3 >/dev/null 2>&1 || return 0
  python3 -I -B - "$dir/tests" "$rendered" "$url" <<'PY' || true
import sys
sys.path.insert(0, sys.argv[1])
import reports_request
with open(sys.argv[2], encoding="utf-8") as stream:
    reasons = reports_request.review(stream.read(), sys.argv[3])
print("Checked here with the ops desk's rules: " + ("it passes." if not reasons else "it fails:"), file=sys.stderr)
for requirement, reason in reasons:
    print(f"  {requirement}: {reason}", file=sys.stderr)
PY
}

cmd_request() {
  load "${1:-}"
  [[ -f "$dir/starter/client-request.yaml" ]] || die "$exercise has no client request"
  [[ -z "${2:-}" || "${2:-}" == --print ]] || usage
  local namespace rendered digest seconds state="" reasons url
  namespace="$(dev_namespace)"
  url="$(reports_url "$namespace")"
  if [[ "${2:-}" == --print ]]; then
    render_request "$url"
    return
  fi
  seconds="$(wait_seconds)"
  rendered="$(mktemp "${TMPDIR:-/tmp}/exercise-request.XXXXXX")"
  # shellcheck disable=SC2064 # expand now: the trap must remove this rendered file
  trap "rm -f '$rendered'" EXIT
  render_request "$url" > "$rendered"
  digest="$(sha256sum "$rendered" | cut -d' ' -f1)"
  # The request goes in a file, never a command argument. Server-side apply under this
  # script's own field manager replaces the data and keeps the desk's annotations.
  note "Filing $request_configmap in $namespace for the ops desk"
  oc create configmap "$request_configmap" --from-file=client-request.yaml="$rendered" \
      --dry-run=client -o yaml -n "$namespace" \
    | oc label --local -f - -o yaml "$ops_desk/ops-desk-request=reports" \
        "$ops_desk/attendee=${namespace%-rhbk-dev}" \
    | oc apply --server-side --field-manager=exercise-sh -f - -n "$namespace" >/dev/null
  note "Waiting up to ${seconds}s for the ops desk"
  local deadline=$((SECONDS + seconds))
  while :; do
    if [[ "$(annotation "configmap/$request_configmap" "$namespace" "$ops_desk/ops-desk-request-sha256")" == "$digest" ]]; then
      state="$(annotation "configmap/$request_configmap" "$namespace" "$ops_desk/ops-desk-state")"
      [[ "$state" == approved || "$state" == rejected ]] && break
    fi
    (( SECONDS < deadline )) || break
    sleep 3
  done
  case "$state" in
    approved)
      note "The ops desk approved the request and created the reports client"
      note "Next: bin/exercise.sh status $exercise" ;;
    rejected)
      reasons="$(annotation "configmap/$request_configmap" "$namespace" "$ops_desk/ops-desk-reasons")"
      printf 'The ops desk rejected the request. Requirement and reason:\n' >&2
      printf '%s\n' "$reasons" | sed 's/^/  /' >&2
      die "fix $exercise/starter/client-request.yaml and run: bin/exercise.sh request $exercise" ;;
    *)
      local_review "$rendered" "$url"
      die "the ops desk has not answered yet; run bin/exercise.sh request $exercise again in a minute" ;;
  esac
}

cmd_status() {
  load "${1:-}"
  [[ "$BUILD" == config ]] || die "$exercise has no client secret"
  local namespace seconds issued=""
  namespace="$(dev_namespace)"
  seconds="$(wait_seconds)"
  local deadline=$((SECONDS + seconds))
  while :; do
    issued="$(annotation "secret/$client_secret" "$namespace" "$ops_desk/ops-desk-issued")"
    [[ -n "$issued" ]] && break
    (( SECONDS < deadline )) || break
    sleep 3
  done
  if [[ -z "$issued" ]]; then
    local state
    state="$(annotation "configmap/$request_configmap" "$namespace" "$ops_desk/ops-desk-state")"
    die "the ops desk has not issued the secret into $client_secret (request: ${state:-not filed or not reviewed}); run: bin/exercise.sh request $exercise"
  fi
  note "The ops desk wrote the client secret into $client_secret at $issued"
  note "Next: bin/exercise.sh rollout $exercise"
}

command="${1:-}"
[[ -n "$command" ]] || usage
shift
case "$command" in
  list) cmd_list ;;
  test) cmd_test "$@" ;;
  materialize) cmd_materialize "$@" ;;
  package) cmd_package "$@" ;;
  rollout) cmd_rollout "$@" ;;
  request) cmd_request "$@" ;;
  status) cmd_status "$@" ;;
  -h|--help|help) usage ;;
  *) usage ;;
esac
