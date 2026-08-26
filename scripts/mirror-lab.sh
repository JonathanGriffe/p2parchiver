#!/usr/bin/env bash
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AC="$REPO/target/release/ac"
ACS="$REPO/target/release/ac-server"
LAB="${LAB_DIR:-/tmp/ac-mirror-lab}"

NODE_LOG="${RUST_LOG:-ac=debug,ac_net=info,libp2p=warn}"

# Generous, because CI machines are slow and the point of a failure here is to be legible
# rather than fast. Discovery runs on a 300s interval, but a node also asks at startup.
SETTLE=90

EDIT_PAUSE=120

pass=0
fail=0

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mok\033[0m    %s\n' "$*"; pass=$((pass + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m  %s\n' "$*"; fail=$((fail + 1)); }

# Wait until a command succeeds, or give up. `$1` seconds, then the command.
wait_for() {
    local limit=$1 label=$2; shift 2
    local deadline=$((SECONDS + limit))
    while (( SECONDS < deadline )); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    printf '  (gave up waiting for %s after %ss)\n' "$label" "$limit"
    return 1
}

ac() { local who=$1; shift; AC_HOME="$LAB/$who" "$AC" "$@"; }

cleanup() {
    [[ "${KEEP:-}" == "yes" ]] && { echo "leaving nodes running; kill with: pkill -f target/release/ac"; return; }
    pkill -f "$REPO/target/release/ac " 2>/dev/null || true
    pkill -f "$REPO/target/release/ac-server" 2>/dev/null || true
    sleep 0.5
}
trap cleanup EXIT

[[ "${1:-}" == "keep" ]] && KEEP=yes

# ---------------------------------------------------------------- the network

need_binaries() {
    [[ -x "$AC" && -x "$ACS" ]] || {
        echo "build first: cargo build --release" >&2
        exit 1
    }
}

start_server() {
    say "server"
    mkdir -p "$LAB/srv"
    AC_SERVER_HOME="$LAB/srv" "$ACS" init >/dev/null

    # Fixed ports. An ephemeral service port would orphan every client the moment this
    # process restarted, since a client stores the service address at enrolment.
    cat > "$LAB/srv/config.toml" <<'TOML'
listen = ["/ip4/127.0.0.1/udp/45001/quic-v1"]
listen_enroll = ["/ip4/127.0.0.1/udp/45002/quic-v1"]
external = ["/ip4/127.0.0.1/udp/45001/quic-v1"]
mdns = false
TOML

    RUST_LOG="$NODE_LOG" AC_SERVER_HOME="$LAB/srv" "$ACS" run > "$LAB/srv.log" 2>&1 &
    wait_for 20 "the server to listen" grep -q "^enrol " "$LAB/srv.log"

    SRV_PEER=$(grep -m1 "^peer " "$LAB/srv.log" | awk '{print $2}')
    ENROL=$(grep -m1 "^enrol " "$LAB/srv.log" | awk '{print $2}')/p2p/$SRV_PEER
    echo "  peer  $SRV_PEER"
    echo "  enrol $ENROL"
}

enrol() {
    local who=$1
    mkdir -p "$LAB/$who"
    local code
    # By field, not by shape: the server peer id on the last line also looks like a token,
    # and picking it produced "this does not look like an invite code" from three lines away.
    code=$(AC_SERVER_HOME="$LAB/srv" "$ACS" invite new --label "$who" | awk '/^invite/ {print $2}')
    ac "$who" join "$ENROL" "$code" --username "$who" >/dev/null

    sed -i 's/^mdns = .*/mdns = false/' "$LAB/$who/config.toml"
    echo "  $who $(ac "$who" id)"
}

run_node() {
    local who=$1
    # No --dial. The whole point.
    RUST_LOG="$NODE_LOG" AC_HOME="$LAB/$who" "$AC" run > "$LAB/$who.log" 2>&1 &
    echo $! > "$LAB/$who.pid"
}

stop_node() {
    local who=$1
    [[ -f "$LAB/$who.pid" ]] || return 0
    kill "$(cat "$LAB/$who.pid")" 2>/dev/null || true
    wait_for 10 "$who to stop" bash -c "! kill -0 $(cat "$LAB/$who.pid") 2>/dev/null"
}
group_id() {
    ac "$1" group list 2>/dev/null | awk 'NR==1 && /^[a-z]/ && NF>=4 {print $2}'
}

holds() { ac "$1" file list "$(group_id "$1")" 2>/dev/null | grep -q "$2.*local"; }

knows() { ac "$1" file list "$(group_id "$1")" 2>/dev/null | grep -q "$2"; }

in_group() { [[ "$(group_id "$1")" =~ ^[0-9a-f]{8}$ ]]; }

main() {
    need_binaries

    pkill -x ac-server 2>/dev/null || true
    pkill -x ac 2>/dev/null || true
    wait_for 15 "port 45001 to be free" \
        bash -c '! ss -lun 2>/dev/null | grep -q "127.0.0.1:45001"'

    rm -rf "$LAB"; mkdir -p "$LAB"

    start_server

    say "enrolling"
    enrol alice; enrol bob; enrol carol; enrol dave

    BOB=$(ac bob id)
    CAROL=$(ac carol id)
    DAVE=$(ac dave id)

    say "1. they find each other, unprompted"
    run_node alice; run_node bob; run_node carol

    wait_for 30 "alice to see the others in the registry" \
        bash -c "[ \$(grep -ac 'discovered a peer' '$LAB/alice.log' 2>/dev/null || echo 0) -ge 2 ]" \
        || true

    say "one group, two members"
    ac alice group create --name holiday >/dev/null
    GROUP=$(group_id alice)
    ac alice group add "$GROUP" "$BOB" --username bob >/dev/null
    ac alice group add "$GROUP" "$CAROL" --username carol >/dev/null

    mkdir -p "$LAB/content"
    head -c 300000 /dev/urandom > "$LAB/content/photo.jpg"
    head -c 120000 /dev/urandom > "$LAB/content/notes.txt"
    ac alice file add "$GROUP" "$LAB/content/photo.jpg" >/dev/null
    ac alice file add "$GROUP" "$LAB/content/notes.txt" >/dev/null
    echo "  $GROUP with 2 files"

    if wait_for "$SETTLE" "bob to hear about the group" in_group bob \
       && wait_for "$SETTLE" "carol to hear about the group" in_group carol; then
        ok "bob and carol learned the group with no --dial"
    else
        bad "the group did not reach both members"
    fi

    ac bob group accept "$GROUP" >/dev/null 2>&1 || true
    ac carol group accept "$GROUP" >/dev/null 2>&1 || true

    say "2. auto-mirror: files arrive without being asked for"
    if wait_for "$SETTLE" "bob to hold both files" bash -c \
        "$(declare -f ac group_id holds); LAB=$LAB AC=$AC; holds bob photo.jpg && holds bob notes.txt"
    then
        ok "bob mirrored both files, with nobody running 'ac file get'"
    else
        bad "bob did not mirror the group"
    fi

    if wait_for "$SETTLE" "carol to hold both files" bash -c \
        "$(declare -f ac group_id holds); LAB=$LAB AC=$AC; holds carol photo.jpg && holds carol notes.txt"
    then
        ok "carol mirrored both files too"
    else
        bad "carol did not mirror the group"
    fi

    say "3. the bytes are the bytes"
    for who in bob carol; do
        local_root="$LAB/$who/files"
        got=$(find "$local_root" -name photo.jpg -print -quit 2>/dev/null)
        if [[ -n "$got" ]] && cmp -s "$got" "$LAB/content/photo.jpg"; then
            ok "$who's copy is byte-identical"
        else
            bad "$who's copy differs or is missing"
        fi
    done

    say "4. a new member is reached in seconds, not hours"
    run_node dave
    sleep 2
    ac alice group add "$GROUP" "$DAVE" --username dave >/dev/null
    if wait_for 120 "dave to hear about the group" in_group dave; then
        ok "dave learned the group promptly after being added"
    else
        bad "dave did not learn the group (property 1 of the plan)"
    fi

    say "5. it goes quiet"
    before=$(grep -c "dialling a member" "$LAB/alice.log" || true)
    sleep 25
    after=$(grep -c "dialling a member" "$LAB/alice.log" || true)
    if (( after - before <= 2 )); then
        ok "alice dialled $((after - before)) time(s) in 25 idle seconds"
    else
        bad "alice dialled $((after - before)) times while nothing was changing"
    fi

    say "6. connections close when both sides are done"
    if grep -q "both sides are done; closing" "$LAB/alice.log" \
       || grep -q "both sides are done; closing" "$LAB/bob.log"; then
        ok "the close handshake completed at least once"
    else
        bad "no connection was ever closed by agreement"
    fi

    say "7. a change after the quiet re-dials"
    head -c 50000 /dev/urandom > "$LAB/content/late.bin"
    ac alice file add "$GROUP" "$LAB/content/late.bin" >/dev/null
    if wait_for "$((EDIT_PAUSE + SETTLE))" "the late file to reach bob" bash -c \
        "$(declare -f ac group_id holds); LAB=$LAB AC=$AC; holds bob late.bin"
    then
        ok "a file added after everyone went quiet still propagates"
    else
        bad "the late file never reached bob"
    fi

    say "8. bytes come from whoever holds them, not from the author"
    if wait_for "$SETTLE" "carol to be told about the late file" bash -c \
        "$(declare -f ac group_id knows); LAB=$LAB AC=$AC; knows carol late.bin"
    then
        ok "alice told carol as well as bob, the author tells everyone"
    else
        bad "carol was never told about the late file"
    fi

    stop_node alice
    if wait_for "$SETTLE" "carol to fetch the late file from bob" bash -c \
        "$(declare -f ac group_id holds); LAB=$LAB AC=$AC; holds carol late.bin"
    then
        ok "carol pulled the bytes with the author gone, so the source rotated to bob"
    else
        bad "carol knew about the file and never got its bytes from bob"
    fi

    say "9. ac peer status answers 'why is nothing happening'"
    if ac bob peer status | grep -qE "missing|heartbeat"; then
        ok "status reports the group's state"
        ac bob peer status | sed 's/^/       /'
    else
        bad "status printed nothing useful"
        ac bob peer status | sed 's/^/       /'
    fi

    say "result"
    printf '  %d passed, %d failed\n\n' "$pass" "$fail"
    (( fail == 0 ))
}

main "$@"
