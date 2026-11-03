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
  request <exercise>            Print the D8 client request with your reports address
  secret <exercise>             Store the D8 client secret (read from the terminal) in reports-client

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
    config) rollout_config "$namespace" ;;
    *) die "$exercise has no rollout (BUILD=$BUILD)" ;;
  esac
}

cmd_request() {
  load "${1:-}"
  [[ -f "$dir/starter/client-request.yaml" ]] || die "$exercise has no client request"
  local namespace host
  namespace="$(dev_namespace)"
  host="$(oc get route/reports -n "$namespace" -o jsonpath='{.spec.host}')"
  [[ "$host" =~ ^[a-z0-9.-]+$ ]] || die "no reports route in $namespace"
  sed "s|@REPORTS_URL@|https://$host|g" "$dir/starter/client-request.yaml"
}

cmd_secret() {
  load "${1:-}"
  [[ "$BUILD" == config ]] || die "$exercise has no client secret"
  local namespace secret
  namespace="$(dev_namespace)"
  [[ -t 0 ]] || die "run this in a terminal: it reads the secret without echoing it"
  read -r -s -p "Client secret operations returned for reports: " secret
  printf '\n' >&2
  [[ -n "$secret" ]] || die "no secret entered"
  # The value goes through a pipe, never a command argument.
  printf '%s' "$secret" | oc set data secret/reports-client --from-file=BFF_CLIENT_SECRET=/dev/stdin -n "$namespace"
  note "Stored the secret in reports-client; now run: bin/exercise.sh rollout $exercise"
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
  secret) cmd_secret "$@" ;;
  -h|--help|help) usage ;;
  *) usage ;;
esac
