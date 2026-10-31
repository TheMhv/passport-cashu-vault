kernel="lib/keyos/simulator/xous/kernel/keyos-kernel"
sim_pid=""

refuse_running_simulator() {
  if pgrep -f "$kernel" >/dev/null; then
    echo "A KeyOS simulator is already running; close it first." >&2
    exit 1
  fi
}

start_simulator() {
  local log="$out/simulator-$1.log"
  set -m
  "$root/scripts/sdk-shell.sh" bash -c "cd '$root/passport-app' && exec foundation sim" >"$log" 2>&1 &
  sim_pid=$!
  set +m
  for _ in $(seq 1 1200); do
    if grep -q "vault open" "$log"; then
      return 0
    fi
    if ! kill -0 "$sim_pid" 2>/dev/null; then
      echo "The simulator exited before the app started:" >&2
      tail -30 "$log" >&2
      return 1
    fi
    sleep 0.5
  done
  echo "The app did not start within 10 minutes:" >&2
  tail -30 "$log" >&2
  return 1
}

stop_simulator() {
  if [ -n "$sim_pid" ]; then
    kill -TERM -- "-$sim_pid" 2>/dev/null || true
    for _ in $(seq 1 40); do
      pgrep -f "$kernel" >/dev/null || break
      sleep 0.25
    done
    kill -KILL -- "-$sim_pid" 2>/dev/null || true
    sim_pid=""
  fi
}
