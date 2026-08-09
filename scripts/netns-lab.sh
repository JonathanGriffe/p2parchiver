#!/usr/bin/env bash
#
# A NAT lab in Linux network namespaces.
#
# Two nodes on one host connect over loopback and prove nothing: there is no NAT to
# traverse, so a "successful" hole punch is just a direct dial wearing a costume. This
# builds the missing topology — two nodes each behind their own NAT, and a routable server
# neither of them can be reached from — using the kernel's real conntrack and MASQUERADE.
# It is a simulation of the internet, not of NAT.
#
#   homeA 10.1.0.2 ── natA ─┤10.1.0.1 | 100.64.0.2├─┐
#                                                   ├── aclab0 ── 100.64.0.4  srv
#   homeB 10.2.0.2 ── natB ─┤10.2.0.1 | 100.64.0.3├─┘
#
# Each home sits behind its own router namespace, and the translation happens there, on a
# genuine forwarding path. A node's packets can only come back through a mapping it opened
# first — the property being tested, and the one loopback cannot provide.
#
# An earlier version put the MASQUERADE inside the node's own namespace, translating
# locally-generated traffic. Outbound worked, so the server saw the right addresses and
# everything relayed fine — but no punched packet ever arrived, and DCUtR failed 30/30
# against a lab that could not have passed. `natcheck` exists because that failure was
# indistinguishable from a real bug for far too long.
#
# STATUS: relay and reservation paths are exercised correctly and this lab found two real
# bugs with them. Hole punching is NOT validated here — `natcheck` fails even with plain
# MASQUERADE on a proper forwarding path, so packets that should traverse are not, for a
# reason not yet identified. Until `natcheck` passes, a `relayed` verdict from `test` says
# nothing about DCUtR: it is the expected result of a lab that cannot punch. Hole punching
# was moved to real-network testing instead; see deploy/README.md.
#
# Anyone picking this up: start with `natcheck`, not `test`. Suspects not yet ruled out are
# the host's bridge netfilter (`net.bridge.bridge-nf-call-iptables`, which Docker enables,
# combined with a DROP policy on FORWARD) and conntrack's handling of the two routers
# sharing one L2 segment. `conntrack -L` inside natA/natB during a punch would settle it.
#
# Requires root: `ip netns` needs CAP_NET_ADMIN. This is the only part of the project
# that does.
#
#   sudo scripts/netns-lab.sh up [--symmetric]
#   sudo scripts/netns-lab.sh natcheck      # is the NAT model itself punchable?
#   sudo scripts/netns-lab.sh test [runs]
#   sudo scripts/netns-lab.sh down
#
# `--symmetric` picks a fresh external port per destination, which is what defeats hole
# punching. Both modes matter: see `test`.

set -euo pipefail

BRIDGE=aclab0
NET=100.64.0            # RFC 6598 shared address space — the "internet" segment
SRV_IP=$NET.4
LAB=/tmp/ac-lab

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AC="$REPO/target/release/ac"
ACS="$REPO/target/release/ac-server"

# name, LAN subnet, node address, router's LAN address, router's WAN address.
NODES=(
    "homeA 10.1.0 10.1.0.2 10.1.0.1 $NET.2"
    "homeB 10.2.0 10.2.0.2 10.2.0.1 $NET.3"
)

# The default filter is `libp2p=warn`, which hides the hole-punch machinery entirely — a
# failed upgrade and an upgrade that was never attempted look identical from outside. The
# lab exists to tell those apart, so it asks for the two behaviours by name.
NODE_LOG="${RUST_LOG:-ac=info,ac_net=info,libp2p_dcutr=debug,libp2p_relay=debug,libp2p_autonat=debug}"

need_root() {
    [[ $EUID -eq 0 ]] || { echo "needs root: sudo $0 $*" >&2; exit 1; }
}

need_binaries() {
    for b in "$AC" "$ACS"; do
        [[ -x $b ]] || { echo "missing $b — run: cargo build --release" >&2; exit 1; }
    done
}

# ---------------------------------------------------------------- topology

up() {
    local masq_flags=""
    # Endpoint-*dependent* mapping: a new external port per destination, so the address a
    # peer learns from the relay is not the address it must punch toward. This is the case
    # DCUtR cannot solve, and a stable relayed connection is the correct outcome.
    [[ ${1:-} == --symmetric ]] && masq_flags="--random-fully"

    down 2>/dev/null || true
    mkdir -p "$LAB"

    ip link add $BRIDGE type bridge
    ip addr add $NET.1/24 dev $BRIDGE
    ip link set $BRIDGE up

    # The server: routable, nothing between it and the bridge.
    ip netns add srv
    ip link add veth-srv type veth peer name in-srv netns srv
    ip link set veth-srv master $BRIDGE up
    ip netns exec srv ip addr add $SRV_IP/24 dev in-srv
    ip netns exec srv ip link set in-srv up
    ip netns exec srv ip link set lo up

    for spec in "${NODES[@]}"; do
        read -r ns lan inside gw wan <<<"$spec"
        local rt="nat${ns#home}"

        ip netns add "$ns"
        ip netns add "$rt"
        ip netns exec "$ns" ip link set lo up
        ip netns exec "$rt" ip link set lo up

        # Router's WAN leg onto the shared segment.
        ip link add "w-$ns" type veth peer name "br-$ns"
        ip link set "w-$ns" netns "$rt"
        ip link set "br-$ns" master $BRIDGE up
        ip netns exec "$rt" ip addr add "$wan/24" dev "w-$ns"
        ip netns exec "$rt" ip link set "w-$ns" up

        # Router's LAN leg down to the node.
        ip link add "l-$ns" type veth peer name eth0 netns "$ns"
        ip link set "l-$ns" netns "$rt"
        ip netns exec "$rt" ip addr add "$gw/24" dev "l-$ns"
        ip netns exec "$rt" ip link set "l-$ns" up

        ip netns exec "$ns" ip addr add "$inside/24" dev eth0
        ip netns exec "$ns" ip link set eth0 up
        ip netns exec "$ns" ip route add default via "$gw"

        # The node's only route out is through the router, so translation happens while
        # forwarding — which is what makes conntrack treat a punched packet as the reply
        # to a mapping the node opened, and deliver it.
        ip netns exec "$rt" sysctl -qw net.ipv4.ip_forward=1
        # shellcheck disable=SC2086
        ip netns exec "$rt" iptables -t nat -A POSTROUTING \
            -s "$lan.0/24" -o "w-$ns" -j MASQUERADE $masq_flags
    done

    echo "lab up${masq_flags:+ (symmetric NAT)}"
    echo "  server  $SRV_IP        in netns srv"
    for spec in "${NODES[@]}"; do
        read -r ns _ inside _ wan <<<"$spec"
        echo "  $ns   $inside  →  (nat${ns#home})  →  $wan"
    done
}

down() {
    for ns in srv homeA homeB natA natB; do
        # Kill what is running inside before deleting: a namespace with live processes is
        # unlinked but not destroyed, and its veth would then collide with the next `up`.
        ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    ip link del $BRIDGE 2>/dev/null || true
    rm -rf "$LAB"
    echo "lab down"
}

# ---------------------------------------------------------------- scenario

# Bring up the server and enrol both nodes. Prints the server's peer id.
bootstrap() {
    rm -rf "$LAB"; mkdir -p "$LAB/srv" "$LAB/homeA" "$LAB/homeB"

    # Bind only the lab address: announcing loopback as well would hand every client a
    # circuit address that cannot work, wasting a dial on each attempt.
    cat >"$LAB/srv/config.toml" <<EOF
listen = ["/ip4/$SRV_IP/udp/4001/quic-v1", "/ip4/$SRV_IP/tcp/4001"]
listen_enroll = ["/ip4/$SRV_IP/udp/4002/quic-v1"]
EOF

    ip netns exec srv env AC_SERVER_HOME="$LAB/srv" "$ACS" init >/dev/null
    ip netns exec srv env AC_SERVER_HOME="$LAB/srv" "$ACS" run >"$LAB/srv.out" 2>"$LAB/srv.err" &
    sleep 3

    local speer
    speer=$(grep -m1 '^peer ' "$LAB/srv.out" | awk '{print $2}')
    [[ -n $speer ]] || { echo "server did not start; see $LAB/srv.err" >&2; exit 1; }

    for spec in "${NODES[@]}"; do
        read -r ns _ inside _ _ <<<"$spec"
        # mDNS off: both namespaces share the bridge's broadcast domain, so it would find
        # peers the NATs are supposed to hide and quietly invalidate the whole experiment.
        cat >"$LAB/$ns/config.toml" <<EOF
listen = ["/ip4/$inside/udp/0/quic-v1", "/ip4/$inside/tcp/0"]
mdns = false
EOF
        local code
        code=$(ip netns exec srv env AC_SERVER_HOME="$LAB/srv" \
            "$ACS" invite new --label "$ns" | awk '/^invite/{print $2}')
        # The username doubles as the namespace name, so `verified <name>` lines in a
        # node's output say which lab node vouched for which.
        ip netns exec "$ns" env AC_HOME="$LAB/$ns" \
            "$AC" join "/ip4/$SRV_IP/udp/4002/quic-v1/p2p/$speer" "$code" --username "$ns" \
            >"$LAB/$ns.join" 2>&1 || { echo "$ns failed to enrol" >&2; cat "$LAB/$ns.join" >&2; exit 1; }
    done

    echo "$speer"
}

# Start A and leave it running. Prints its peer id.
#
# A stays up for the whole measurement, which is both realistic and necessary. Restarting
# it per run made every second run fail: the relay still held the *previous* process's
# reservation and delivered the circuit into that dead connection, which the server does
# not notice for ~15s. That is a genuine property of a node that restarts — worth knowing,
# and worth testing on purpose — but it is not hole punching, and mixing the two makes the
# hole-punch number meaningless.
start_listener() {
    ip netns exec homeA env AC_HOME="$LAB/homeA" RUST_LOG="$NODE_LOG" "$AC" run \
        >"$LAB/homeA.out" 2>"$LAB/homeA.err" &
    A_PID=$!

    local waited=0
    until grep -q '^reserved' "$LAB/homeA.out" 2>/dev/null; do
        sleep 1; waited=$((waited + 1))
        if [[ $waited -ge 25 ]]; then
            echo "homeA never reserved (see $LAB/homeA.err)" >&2
            exit 1
        fi
    done

    ip netns exec homeA env AC_HOME="$LAB/homeA" "$AC" id
}

# One run: B probes the already-listening A. Echoes the verdict.
attempt() {
    local peer_a=$1

    ip netns exec homeB env AC_HOME="$LAB/homeB" RUST_LOG="$NODE_LOG" "$AC" probe --peer "$peer_a" \
        >"$LAB/homeB.probe" 2>"$LAB/homeB.err" || true

    # Keep the per-run logs: the interesting run is rarely the last one, and overwriting
    # them means the only evidence of a failure is gone by the time the tally prints.
    local n=${RUN_N:-0}
    cp "$LAB/homeB.err" "$LAB/run$n.homeB.err" 2>/dev/null || true
    cp "$LAB/homeB.probe" "$LAB/run$n.probe" 2>/dev/null || true

    local path
    path=$(awk '/^path/{ $1=""; $2=""; print }' "$LAB/homeB.probe" | xargs || true)
    echo "${path:-no verdict}"
}

test_runs() {
    local runs=${1:-10}
    need_binaries

    echo "bootstrapping…"
    bootstrap >/dev/null
    local peer_a
    peer_a=$(start_listener)
    echo "listener homeA $peer_a"
    echo

    local direct=0 relayed=0 other=0
    for i in $(seq 1 "$runs"); do
        local verdict
        verdict=$(RUN_N=$i attempt "$peer_a")
        printf "  run %2d/%d  %s\n" "$i" "$runs" "$verdict"
        case "$verdict" in
            *DIRECT*)  direct=$((direct + 1)) ;;
            *relayed*) relayed=$((relayed + 1)) ;;
            *)         other=$((other + 1)) ;;
        esac
    done

    echo
    echo "  direct   $direct/$runs"
    echo "  relayed  $relayed/$runs"
    [[ $other -gt 0 ]] && echo "  no verdict $other/$runs"

    # The two modes have opposite pass conditions, and asserting only the first would
    # report a false failure on exactly the case the relay exists for.
    echo
    echo "Expected: endpoint-independent NAT → direct ≥ 9/10"
    echo "          symmetric NAT           → relayed = $runs/$runs, and stable"
}

# Does a bare UDP hole punch work between the two homes?
#
# When a punch fails there are two suspects — the NAT model built here, and the code being
# tested — and the logs of a failed DCUtR attempt cannot tell them apart. This removes
# libp2p from the picture: two sockets, one packet each, no protocol. If this fails the lab
# is wrong; if it passes the lab is sound and the fault is upstream of it.
natcheck() {
    local port=50000
    mkdir -p "$LAB"
    local py='
import socket, sys, time
me, peer = sys.argv[1], sys.argv[2]
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((me, 50000))
except OSError as e:
    print(f"bind {me}:50000 failed: {e}"); sys.exit(2)
s.settimeout(0.5)
# Send first, then listen, repeatedly. The opening packet is expected to be dropped by the
# far NAT — its job is to open *our* side. What matters is whether anything arrives.
deadline = time.time() + 8
while time.time() < deadline:
    try:
        s.sendto(b"punch", (peer, 50000))
    except OSError as e:
        print(f"send to {peer}:50000 failed: {e}"); sys.exit(2)
    try:
        _, src = s.recvfrom(64)
        print(f"RECEIVED from {src[0]}:{src[1]}")
        sys.exit(0)
    except socket.timeout:
        pass
print("NOTHING RECEIVED")
sys.exit(1)
'
    echo "punching both ways on udp/$port (8s) …"
    ip netns exec homeA python3 -c "$py" 10.1.0.2 "$NET.3" >"$LAB/natcheck.A" 2>&1 &
    local pa=$!
    ip netns exec homeB python3 -c "$py" 10.2.0.2 "$NET.2" >"$LAB/natcheck.B" 2>&1 &
    local pb=$!
    # `|| ra=$?` rather than a bare `wait`: `set -e` aborts on a non-zero exit, and a failed
    # punch is exactly the non-zero exit this function exists to report. Left bare, the
    # script dies before printing the result it just measured.
    local ra=0 rb=0
    wait $pa || ra=$?
    wait $pb || rb=$?

    echo "  homeA: $(cat "$LAB/natcheck.A" 2>/dev/null || echo '(no output)')"
    echo "  homeB: $(cat "$LAB/natcheck.B" 2>/dev/null || echo '(no output)')"
    echo
    if [[ $ra -eq 0 && $rb -eq 0 ]]; then
        echo "NAT permits hole punching — a failed DCUtR run is the code's problem, not the lab's."
    else
        echo "NAT blocks hole punching. Expected under --symmetric; under plain MASQUERADE it"
        echo "means the lab is not modelling an endpoint-independent NAT and the direct-connection"
        echo "target cannot be met here regardless of the code."
    fi
}

case "${1:-}" in
    up)   need_root "$@"; shift; up "$@" ;;
    natcheck) need_root "$@"; natcheck ;;
    down) need_root "$@"; down ;;
    test) need_root "$@"; shift; test_runs "$@" ;;
    *)    sed -n '2,30p' "$0" | sed 's/^# \?//'; exit 1 ;;
esac
