#!/usr/bin/env python3
"""adv_harness.py — adversarial-load tests against a LOCAL TLS 1.3 endpoint.

SAFETY BOUNDARY: every test connects only to 127.0.0.1 (localhost). No
external host is ever contacted. The target is the local `openssl s_server`
test deployment started by scripts/run_adversarial.sh on the same machine.
Tests:
  capture    — record one real ClientHello from openssl s_client (via a
               dummy local listener) for use as truncation input.
  malformed  — send malformed ClientHello variants to the local server and
               record the server response / failure mode.
  truncated  — send a prefix of a real ClientHello, then RST-close; record
               server behaviour and confirm it stays alive.
  flood      — N rapid full handshakes at limited concurrency; record
               success rate, throughput, server CPU and memory.
  slowloris  — hold M stalled partial-handshake connections open; measure
               whether a legitimate handshake can complete while they are
               held, and the server resource cost of the stalls.
  probe      — one legitimate handshake via openssl s_client; exit 0 iff the
               server answers with a verified TLS 1.3 handshake.

All results are written as CSV (one row per trial) plus a human-readable
log. Every test ends with a probe so a dead server is detected immediately.
"""
import argparse
import csv
import os
import random
import socket
import struct
import subprocess
import sys
import time

HOST = "127.0.0.1"
ALERT_NAMES = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    21: "decryption_failed", 22: "record_overflow", 40: "handshake_failure",
    41: "no_certificate", 42: "bad_certificate", 43: "unsupported_certificate",
    44: "certificate_revoked", 45: "certificate_expired", 46: "certificate_unknown",
    47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied",
    50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
    71: "insufficient_security", 80: "internal_error", 86: "inappropriate_fallback",
    87: "user_canceled", 90: "no_renegotiation", 109: "missing_extension",
    110: "unsupported_extension", 111: "certificate_unobtainable",
    112: "unrecognized_name", 113: "bad_certificate_status_response",
    114: "bad_certificate_hash_value", 115: "unknown_psk_identity",
    116: "certificate_required", 120: "no_application_protocol",
}


def log(msg):
    print(msg, flush=True)


def parse_alert(data):
    """Return a human description of the first TLS record in data, if any."""
    if len(data) < 7:
        return "no-tls-record"
    rtype, _ver, rlen = data[0], int.from_bytes(data[1:3], "big"), int.from_bytes(data[3:5], "big")
    if rtype == 0x15 and rlen >= 2 and len(data) >= 7:
        level, desc = data[5], data[6]
        return "alert level=%d desc=%d (%s)" % (level, desc, ALERT_NAMES.get(desc, "unknown"))
    if rtype == 0x16:
        return "handshake-record len=%d (server replied with a handshake message)" % rlen
    return "record type=0x%02x len=%d" % (rtype, rlen)


def procstat(pid):
    """Return (cpu_total_s, rss_kb) for a pid from /proc, or (None, None)."""
    try:
        clk = os.sysconf("SC_CLK_TCK")
        parts = open(f"/proc/{pid}/stat").read().split()
        cpu = (int(parts[13]) + int(parts[14])) / clk
        rss = None
        for line in open(f"/proc/{pid}/status"):
            if line.startswith("VmRSS:"):
                rss = int(line.split()[1])
                break
        return cpu, rss
    except Exception:
        return None, None


def probe_handshake(port, group, timeout=15):
    """One legitimate handshake via openssl s_client. Returns (ok, ms, detail)."""
    t0 = time.monotonic()
    env = dict(os.environ)
    try:
        p = subprocess.run(
            ["openssl", "s_client", "-connect", f"{HOST}:{port}",
             "-groups", group, "-tls1_3",
             "-provider", "default", "-provider", "oqsprovider",
             "-CAfile", os.environ["TLS_CAFILE"], "-verify_return_error"],
            input=b"", capture_output=True, timeout=timeout, env=env)
        out = (p.stdout + p.stderr).decode(errors="ignore")
        ms = (time.monotonic() - t0) * 1000
        ok = "Verify return code: 0 (ok)" in out and "New, TLSv1.3" in out
        detail = "verified" if ok else (out.splitlines()[-1][:120] if out.splitlines() else "no output")
        return ok, ms, detail
    except subprocess.TimeoutExpired:
        return False, (time.monotonic() - t0) * 1000, "TIMEOUT"
    except Exception as e:
        return False, (time.monotonic() - t0) * 1000, f"ERROR {e}"


def send_and_observe(port, payload, close_rst=False, read_timeout=5.0):
    """Connect, send payload, read whatever the server sends, return a dict."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(read_timeout)
    t0 = time.monotonic()
    try:
        s.connect((HOST, port))
        if payload:
            s.sendall(payload)
        if close_rst:
            # SO_LINGER takes struct linger {int l_onoff; int l_linger}:
            # 8 bytes, onoff=1, linger=0 -> RST on close. (A 4-byte value
            # raises OSError EINVAL on Linux.)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            except OSError:
                pass
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 8192:
                    break
        except socket.timeout:
            pass
        ms = (time.monotonic() - t0) * 1000
        return {"server_bytes": len(data), "server_reply": parse_alert(data),
                "closed_by_server": len(data) > 0 or True, "ms": round(ms, 1)}
    except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError) as e:
        return {"server_bytes": 0, "server_reply": f"connection {type(e).__name__}",
                "closed_by_server": True, "ms": round((time.monotonic() - t0) * 1000, 1)}
    except socket.timeout:
        return {"server_bytes": 0, "server_reply": "connect-timeout",
                "closed_by_server": False, "ms": round((time.monotonic() - t0) * 1000, 1)}
    finally:
        try:
            s.close()
        except Exception:
            pass


def build_client_hello(group_hex=0x11EC, key_share_bytes=None, legacy_version=0x0303,
                       offered_versions=(0x0304,), random_bytes=None):
    """Build a minimal TLS 1.3 ClientHello (handshake + record framing)."""
    rnd = random_bytes if random_bytes is not None else bytes(random.Random(42).randbytes(32))
    body = b""
    body += legacy_version.to_bytes(2, "big")
    body += rnd
    body += b"\x00"  # session id length 0
    body += (2).to_bytes(2, "big") + b"\x13\x01"  # one cipher suite
    body += b"\x01\x00"  # compression methods
    exts = b""
    # supported_versions
    sv = b"".join(v.to_bytes(2, "big") for v in offered_versions)
    exts += (0x002B).to_bytes(2, "big") + (len(sv) + 1).to_bytes(2, "big") + bytes([len(sv)]) + sv
    # supported_groups
    sg = group_hex.to_bytes(2, "big")
    exts += (0x000A).to_bytes(2, "big") + (len(sg) + 2).to_bytes(2, "big") + (2).to_bytes(2, "big") + sg
    # key_share
    ks = key_share_bytes if key_share_bytes is not None else b"\x00" * 1216
    kse = group_hex.to_bytes(2, "big") + len(ks).to_bytes(2, "big") + ks
    exts += (0x0033).to_bytes(2, "big") + (len(kse) + 2).to_bytes(2, "big") + (len(kse)).to_bytes(2, "big") + kse
    # signature_algorithms
    sa = b"\x04\x03\x08\x04"
    exts += (0x000D).to_bytes(2, "big") + (len(sa) + 2).to_bytes(2, "big") + (len(sa)).to_bytes(2, "big") + sa
    body += len(exts).to_bytes(2, "big") + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    rec = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
    return rec


# ---------------- subcommands ----------------

def cmd_capture(args):
    """Listen once on localhost, record the ClientHello openssl s_client sends."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, args.port))
    srv.listen(1)
    srv.settimeout(20)
    log(f"capture: listening on {HOST}:{args.port}, run s_client against it")
    proc = subprocess.Popen(
        ["openssl", "s_client", "-connect", f"{HOST}:{args.port}",
         "-groups", args.group, "-tls1_3",
         "-provider", "default", "-provider", "oqsprovider",
         "-CAfile", os.environ["TLS_CAFILE"]],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        conn, _ = srv.accept()
        conn.settimeout(5)
        data = b""
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        conn.close()
    finally:
        proc.terminate()
        proc.wait(timeout=5)
        srv.close()
    with open(args.out, "wb") as f:
        f.write(data)
    log(f"capture: wrote {len(data)} bytes to {args.out}")
    log(f"capture: first record type=0x{data[0]:02x} len={int.from_bytes(data[3:5], 'big') if len(data) >= 5 else 'n/a'}")
    return 0


def cmd_malformed(args):
    real = open(args.clienthello, "rb").read()
    log(f"malformed: real ClientHello {len(real)} bytes from {args.clienthello}")
    variants = {
        "V1-truncated-record": real[:15],
        "V2-garbage-100B": bytes(random.Random(7).randbytes(100)),
        "V3-oversized-length": b"\x16\x03\x01\x40\x00" + real[5:55],
        "V4-bad-version-tls10": build_client_hello(legacy_version=0x0301, offered_versions=(0x0301,)),
        "V5-bad-keyshare-zero-ek": build_client_hello(key_share_bytes=b"\x00" * 1216),
        "V6-empty-close": b"",
    }
    rows = []
    for name, payload in variants.items():
        for trial in range(1, args.trials + 1):
            obs = send_and_observe(args.port, payload, close_rst=(name in ("V1-truncated-record", "V6-empty-close")))
            ok, ms, detail = probe_handshake(args.port, args.group)
            rows.append({"variant": name, "trial": trial, "sent_bytes": len(payload),
                         "server_bytes": obs["server_bytes"], "server_reply": obs["server_reply"],
                         "observe_ms": obs["ms"], "probe_ok": ok, "probe_ms": round(ms, 1),
                         "probe_detail": detail})
            log(f"malformed {name} trial {trial}: sent={len(payload)}B server={obs['server_reply']} "
                f"({obs['server_bytes']}B, {obs['ms']}ms) probe_ok={ok} probe_ms={round(ms, 1)}")
    with open(args.csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    log(f"malformed: wrote {len(rows)} rows to {args.csv}")
    return 0


def cmd_truncated(args):
    real = open(args.clienthello, "rb").read()
    rows = []
    for k in (20, 100):
        for trial in range(1, args.trials + 1):
            obs = send_and_observe(args.port, real[:k], close_rst=True)
            ok, ms, detail = probe_handshake(args.port, args.group)
            rows.append({"prefix_bytes": k, "trial": trial, "server_bytes": obs["server_bytes"],
                         "server_reply": obs["server_reply"], "observe_ms": obs["ms"],
                         "probe_ok": ok, "probe_ms": round(ms, 1), "probe_detail": detail})
            log(f"truncated prefix={k}B trial {trial}: server={obs['server_reply']} "
                f"({obs['server_bytes']}B) probe_ok={ok} probe_ms={round(ms, 1)}")
    with open(args.csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    log(f"truncated: wrote {len(rows)} rows to {args.csv}")
    return 0


def cmd_flood(args):
    import concurrent.futures
    cpu0, rss0 = procstat(args.server_pid)
    log(f"flood: server pid={args.server_pid} cpu_before={cpu0}s rss_before={rss0}KiB "
        f"n={args.n} concurrency={args.concurrency} group={args.group}")
    rows = []

    def one(i):
        ok, ms, detail = probe_handshake(args.port, args.group, timeout=30)
        return {"attempt": i, "ok": ok, "ms": round(ms, 1), "detail": detail}

    t0 = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        for row in ex.map(one, range(1, args.n + 1)):
            rows.append(row)
    wall = time.monotonic() - t0
    cpu1, rss1 = procstat(args.server_pid)
    ok_n = sum(1 for r in rows if r["ok"])
    lat = sorted(r["ms"] for r in rows)
    log(f"flood: success {ok_n}/{args.n} ({100.0 * ok_n / args.n:.1f}%) wall={wall:.2f}s "
        f"rate={args.n / wall:.2f} handshakes/s")
    log(f"flood: latency ms min={lat[0]:.1f} median={lat[len(lat)//2]:.1f} "
        f"p95={lat[int(len(lat)*0.95)-1]:.1f} max={lat[-1]:.1f}")
    if cpu0 is not None and cpu1 is not None:
        log(f"flood: server cpu {cpu0:.3f}s -> {cpu1:.3f}s delta={cpu1-cpu0:.3f}s "
            f"({1000*(cpu1-cpu0)/args.n:.2f} ms CPU per handshake attempt)")
    if rss0 is not None and rss1 is not None:
        log(f"flood: server rss {rss0}KiB -> {rss1}KiB delta={rss1-rss0}KiB "
            f"({(rss1-rss0)/args.n:.2f} KiB per handshake attempt)")
    with open(args.csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    with open(args.summary, "w") as f:
        f.write(f"flood summary n={args.n} success={ok_n} wall_s={wall:.2f} "
                f"rate_per_s={args.n/wall:.2f}\n")
        f.write(f"latency_ms min={lat[0]:.1f} median={lat[len(lat)//2]:.1f} "
                f"p95={lat[int(len(lat)*0.95)-1]:.1f} max={lat[-1]:.1f}\n")
        if cpu0 is not None and cpu1 is not None:
            f.write(f"server_cpu_delta_s={cpu1-cpu0:.3f} cpu_ms_per_attempt={1000*(cpu1-cpu0)/args.n:.2f}\n")
        if rss0 is not None and rss1 is not None:
            f.write(f"server_rss_before_kib={rss0} server_rss_after_kib={rss1} rss_delta_kib={rss1-rss0}\n")
    log(f"flood: wrote {len(rows)} rows to {args.csv}, summary to {args.summary}")
    return 0


def cmd_slowloris(args):
    cpu0, rss0 = procstat(args.server_pid)
    log(f"slowloris: server pid={args.server_pid} cpu_before={cpu0}s rss_before={rss0}KiB "
        f"stalls={args.stalls} hold={args.hold}s")
    stalls = []
    header = b"\x16\x03\x01\x02\x00"  # TLS record header claiming a 512-byte ClientHello
    for i in range(args.stalls):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((HOST, args.port))
            s.sendall(header)
            stalls.append(s)
        except Exception as e:
            log(f"slowloris: stall {i} failed to open: {e}")
            break
    log(f"slowloris: {len(stalls)} stalled connections open; holding {args.hold}s")
    time.sleep(5)
    cpu_mid, rss_mid = procstat(args.server_pid)
    log(f"slowloris: at t=5s server cpu={cpu_mid}s rss={rss_mid}KiB")
    ok, ms, detail = probe_handshake(args.port, args.group, timeout=10)
    log(f"slowloris: legitimate handshake DURING stall: ok={ok} ms={round(ms, 1)} detail={detail}")
    during = {"probe_ok_during_stall": ok, "probe_ms_during_stall": round(ms, 1), "probe_detail": detail}
    remaining = args.hold - 5 - (ms / 1000.0)
    if remaining > 0:
        time.sleep(remaining)
    # How many stalls are still open from the server side? A recv with a
    # short timeout that times out (rather than returning b'') means the
    # server has not closed the connection.
    still_open = 0
    for s in stalls:
        s.settimeout(0.5)
        try:
            data = s.recv(1)
            if data == b"":
                pass  # server closed it
            else:
                still_open += 1
        except socket.timeout:
            still_open += 1
        except Exception:
            pass
    log(f"slowloris: stalls still open after {args.hold}s hold: {still_open}/{len(stalls)}")
    for s in stalls:
        try:
            s.close()
        except Exception:
            pass
    time.sleep(2)
    cpu1, rss1 = procstat(args.server_pid)
    ok2, ms2, detail2 = probe_handshake(args.port, args.group, timeout=15)
    log(f"slowloris: legitimate handshake AFTER releasing stalls: ok={ok2} ms={round(ms2, 1)} detail={detail2}")
    log(f"slowloris: server cpu {cpu0}s -> {cpu1}s rss {rss0}KiB -> {rss1}KiB")
    with open(args.summary, "w") as f:
        f.write(f"slowloris stalls_opened={len(stalls)} hold_s={args.hold}\n")
        f.write(f"probe_during_stall ok={during['probe_ok_during_stall']} ms={during['probe_ms_during_stall']} detail={during['probe_detail']}\n")
        f.write(f"stalls_still_open_after_hold={still_open}\n")
        f.write(f"probe_after_release ok={ok2} ms={round(ms2, 1)} detail={detail2}\n")
        if cpu0 is not None and cpu1 is not None:
            f.write(f"server_cpu_before_s={cpu0} server_cpu_after_s={cpu1} cpu_delta_s={cpu1-cpu0:.3f}\n")
        if rss0 is not None and rss1 is not None:
            f.write(f"server_rss_before_kib={rss0} server_rss_mid_kib={rss_mid} server_rss_after_kib={rss1}\n")
    return 0


def cmd_probe(args):
    ok, ms, detail = probe_handshake(args.port, args.group)
    log(f"probe: ok={ok} ms={round(ms, 1)} detail={detail}")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("capture")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--group", default="X25519MLKEM768")
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_capture)
    p = sub.add_parser("malformed")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--group", default="X25519MLKEM768")
    p.add_argument("--clienthello", required=True)
    p.add_argument("--trials", type=int, default=10)
    p.add_argument("--csv", required=True)
    p.set_defaults(fn=cmd_malformed)
    p = sub.add_parser("truncated")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--group", default="X25519MLKEM768")
    p.add_argument("--clienthello", required=True)
    p.add_argument("--trials", type=int, default=10)
    p.add_argument("--csv", required=True)
    p.set_defaults(fn=cmd_truncated)
    p = sub.add_parser("flood")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--group", default="X25519MLKEM768")
    p.add_argument("--server-pid", type=int, required=True)
    p.add_argument("--n", type=int, default=200)
    p.add_argument("--concurrency", type=int, default=10)
    p.add_argument("--csv", required=True)
    p.add_argument("--summary", required=True)
    p.set_defaults(fn=cmd_flood)
    p = sub.add_parser("slowloris")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--group", default="X25519MLKEM768")
    p.add_argument("--server-pid", type=int, required=True)
    p.add_argument("--stalls", type=int, default=30)
    p.add_argument("--hold", type=int, default=30)
    p.add_argument("--summary", required=True)
    p.set_defaults(fn=cmd_slowloris)
    p = sub.add_parser("probe")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--group", default="X25519MLKEM768")
    p.set_defaults(fn=cmd_probe)
    args = ap.parse_args()
    sys.exit(args.fn(args))


if __name__ == "__main__":
    main()
