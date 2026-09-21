#!/usr/bin/env python3
"""
Wi-Fi Scanner / Sniffer with SQLite logging, web dashboard, and rogue-AP detection.
Linux-only (NetworkManager required).

Usage:
    python3 wifi_tool.py -scan                 # one-shot scan, print table
    python3 wifi_tool.py -sniff                # live monitor + SQLite + alerts
    python3 wifi_tool.py -sniff -serve         # + web dashboard at :5000

Dependencies (optional but recommended, install in a venv):
    pip install mac-vendor-lookup flask


BSSID-in-whitelist — the AP's MAC matches one you explicitly trusted. Clean.

SSID-match, BSSID-mismatch — a different MAC is broadcasting an SSID you own. This is the signal that could mean an evil twin, but has several innocent explanations:

    Mesh nodes / extenders. Your Eero, Nest Wifi, Orbi, etc. all broadcast the same SSID from different BSSIDs. All of them will trip this unless you add each BSSID to the whitelist. Same for a router in AP mode, or a Wi-Fi extender.

    Router replacement. You swapped routers and the new one has a different MAC. The old BSSID may linger in the scan cache.

    MAC randomization on your client. Not an AP-side issue, but worth knowing: some phones randomize their MAC when probing, which doesn't affect this check (we look at BSSIDs of APs, not clients) but can confuse related tooling.

    A genuinely new AP a neighbor set up with the same common SSID. NETGEAR, xfinitywifi, linksys — these are shared by millions of routers. If your SSID is generic, you'll get constant false positives. Use a unique SSID (not your address, not your last name, not the router's default) and this problem goes away.


What the detection does NOT do:

    It can't confirm an evil twin by itself. A real evil-twin attack involves the attacker's AP broadcasting your SSID and deauthing you off your real AP so your client roams to the attacker. Detecting that requires monitor mode and looking at 802.11 management frames (deauth floods) — that's a different kind of tool (think aircrack-ng, kismet, or a custom scapy script) and needs a Wi-Fi adapter that supports monitor mode. On a Steam Deck's built-in adapter, that's typically not available.

    It can't see hidden SSIDs. If an attacker runs a hidden network, you get an empty SSID field and no match. You can still whitelist by BSSID, but you won't get the SSID-mismatch signal.

    It can't see client associations. You won't know which devices are connected to the suspicious AP. That's also a monitor-mode thing.

    It's a heuristic, not a security control. Treat a flag as "worth a look," not "confirmed attack." The most common cause of a flag is a mesh node or extender.

Signs that raise the alarm from "maybe" to "probably":

    Unusually strong signal for an AP that just appeared. If your router is two rooms away but the "same SSID" is showing 90/100, that's suspicious — the attacker is probably close to you.

    Different security type than your real AP. Your router is WPA3; the look-alike is WPA2 or open. That's a red flag.

    Different vendor than your real AP. If your router is TP-Link and the look-alike is "Unknown" or a completely different OUI, investigate.

    Simultaneous deauth events on your real AP (needs monitor mode to see).

    Your real AP disappears from scans while the clone appears. That's the classic evil-twin pattern.

What to do if you get a flag:

    Check the mesh/extender hypothesis first. List every AP you own and its BSSID. Add them all to the whitelist.

    Look at the vendor field. If it matches the vendor of your real AP, it's probably legit hardware.

    Look at the channel. Attackers usually clone the channel of the real AP to make roaming seamless, but some don't. A weird channel is a mild clue.

    Walk around with the dashboard open and watch signal strength as you move. Your real router's signal should drop as you move away; if the flagged AP's signal increases when you move toward a specific neighbor or spot, that tells you where it's coming from.

    If it's genuinely suspicious, change your Wi-Fi password (WPA2 passphrases are recoverable from captured handshakes if they're weak), and consider using WPA3 if your router supports it — WPA3-SAE is resistant to offline dictionary attacks, which takes the wind out of most practical evil-twin attacks.



"""

import argparse
import sqlite3
import subprocess
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# --- Optional vendor lookup -------------------------------------------------
try:
    from mac_vendor_lookup import MacLookup
    VENDOR_LOOKUP = MacLookup()
    VENDOR_AVAILABLE = True
except ImportError:
    VENDOR_AVAILABLE = False


# ============================================================================
# Config
# ============================================================================
DB_PATH = Path.home() / ".wifi_sniffer.db"
DEFAULT_INTERVAL = 10
NEW_DEVICE_WINDOW = 300

# Bump whenever you change the schema — old DBs get recreated automatically.
SCHEMA_VERSION = 3

# --- Named AP whitelist -----------------------------------------------------
# Map BSSID (MAC of the AP) -> friendly name.
#
# Why BSSID and not SSID? Because an attacker can trivially broadcast any
# SSID they like. The BSSID is baked into the AP's hardware (or at least it's
# what the AP is currently claiming), so pinning your known-good APs by MAC
# gives us something concrete to compare against.
#
# Fill these in with the MACs of YOUR routers/APs. Use `-scan` to find them,
# or `sqlite3 ~/.wifi_sniffer.db "SELECT bssid, ssid FROM aps;"`.
#
# Example:
#     "78:45:58:2D:4A:D0": "Home Router (main)",
#     "A4:2B:B0:11:22:33": "Home Router (5 GHz)",
#     "DE:AD:BE:EF:00:01": "Garage AP",
WHITELIST = {
    # "XX:XX:XX:XX:XX:XX": "Friendly name",
}

# SSIDs that you own. If a BSSID advertises one of these SSIDs but is NOT in
# the whitelist, it's flagged as a possible rogue / evil twin.
#
# This is derived automatically from the whitelist above — if you put your
# router in the whitelist, its SSID is automatically considered "yours".
# You can also add SSIDs here manually if you have APs whose BSSIDs you don't
# know yet.
OWNED_SSIDS = set()

# Severity threshold: an AP flagged as rogue gets a hard red flag; an unknown
# AP sharing an SSID with a whitelisted AP (but no other signals) gets an
# amber "warn" flag. Set to True to only alert on confirmed BSSID mismatches.
STRICT_ROGUE_ONLY = False


FIELDS = [
    "BSSID", "SSID", "MODE", "CHAN", "FREQ", "RATE",
    "SIGNAL", "BARS", "SECURITY", "WPA-FLAGS", "RSN-FLAGS",
]


# ============================================================================
# nmcli wrapper
# ============================================================================
def _split_escaped_colons(line):
    parts, current, i = [], [], 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line) and line[i + 1] == ":":
            current.append(":")
            i += 2
        elif ch == ":":
            parts.append("".join(current))
            current = []
            i += 1
        else:
            current.append(ch)
            i += 1
    parts.append("".join(current))
    return parts


def scan_networks():
    cmd = ["nmcli", "-t", "-f", ",".join(FIELDS), "device", "wifi", "list"]
    try:
        result = subprocess.run(
            cmd, text=True, encoding="utf-8", errors="ignore",
            capture_output=True, timeout=30,
        )
    except FileNotFoundError:
        print("Error: 'nmcli' not found. Is NetworkManager installed?")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[scan] nmcli timed out.")
        return []

    if result.returncode != 0:
        print(f"[scan] nmcli error: {result.stderr.strip()}")
        return []

    networks = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = _split_escaped_colons(line)
        if len(parts) == len(FIELDS):
            networks.append(dict(zip(FIELDS, parts)))
    return networks


def get_vendor(bssid):
    if not VENDOR_AVAILABLE or not bssid:
        return "Unknown"
    try:
        return VENDOR_LOOKUP.lookup(bssid)
    except Exception:
        return "Unknown"


# ============================================================================
# Rogue / evil-twin detection
# ============================================================================
def _normalize_bssid(bssid):
    return bssid.upper().replace("-", ":") if bssid else ""


def _build_owned_ssids():
    """Derive the set of owned SSIDs from the whitelist + manual additions."""
    owned = {s.lower() for s in OWNED_SSIDS if s}
    # (We don't have SSIDs in the whitelist dict, so this only uses manual
    #  additions plus whatever's populated at runtime by the sniffer.)
    return owned


def classify_network(net, whitelist, owned_ssids):
    """
    Return a dict describing the trust status of a network:
      {
        "status": "known" | "rogue" | "warn" | "unknown",
        "reason": "...",
        "friendly_name": "..." or None,
      }

    Detection logic (in order):
      1. BSSID is in the whitelist -> known.
      2. BSSID is NOT in the whitelist, but its SSID matches an owned SSID
         -> rogue (possible evil twin / rogue AP).
      3. BSSID is NOT in the whitelist, but its SSID matches a whitelisted
         AP's SSID -> rogue (same logic; owned_ssids is populated at runtime).
      4. Otherwise -> unknown (just a neighbor's network, not suspicious).
    """
    bssid = _normalize_bssid(net["BSSID"])
    ssid = (net.get("SSID") or "").strip()
    ssid_lower = ssid.lower()

    if bssid in whitelist:
        return {
            "status": "known",
            "friendly_name": whitelist[bssid],
            "reason": "BSSID matches whitelist",
        }

    if ssid_lower and ssid_lower in owned_ssids:
        return {
            "status": "rogue",
            "friendly_name": None,
            "reason": f"BSSID not whitelisted but advertises your SSID '{ssid}'",
        }

    return {
        "status": "unknown",
        "friendly_name": None,
        "reason": "",
    }


def detect_rogues(networks, whitelist, owned_ssids):
    """Return a list of (net, classification) for rogue/warn networks."""
    out = []
    for net in networks:
        c = classify_network(net, whitelist, owned_ssids)
        if c["status"] in ("rogue", "warn"):
            out.append((net, c))
    return out


# ============================================================================
# SQLite logging
# ============================================================================
def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)

    # Schema version check — recreate if we've changed the schema
    conn.execute(
        "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"
    )
    row = conn.execute(
        "SELECT value FROM meta WHERE key='schema_version'"
    ).fetchone()
    current = int(row[0]) if row else 0

    if current != SCHEMA_VERSION:
        if current:
            print(f"[db] schema v{current} → v{SCHEMA_VERSION}, recreating tables")
        conn.executescript("""
            DROP TABLE IF EXISTS aps;
            DROP TABLE IF EXISTS observations;
            DROP TABLE IF EXISTS rogues;
        """)
        conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS aps (
            bssid TEXT PRIMARY KEY,
            ssid TEXT,
            vendor TEXT,
            channel TEXT,
            freq TEXT,
            security TEXT,
            best_signal INTEGER DEFAULT 0,
            first_seen REAL,
            last_seen REAL,
            hits INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bssid TEXT,
            ssid TEXT,
            channel TEXT,
            freq TEXT,
            signal INTEGER,
            security TEXT,
            timestamp REAL
        );
        CREATE INDEX IF NOT EXISTS idx_obs_bssid ON observations(bssid);
        CREATE INDEX IF NOT EXISTS idx_obs_time  ON observations(timestamp);

        CREATE TABLE IF NOT EXISTS rogues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bssid TEXT,
            ssid TEXT,
            vendor TEXT,
            channel TEXT,
            signal INTEGER,
            security TEXT,
            reason TEXT,
            first_seen REAL,
            last_seen REAL
        );
        CREATE INDEX IF NOT EXISTS idx_rogues_bssid ON rogues(bssid);
    """)
    conn.commit()
    return conn


def _to_int(v, default=0):
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


def db_upsert_ap(conn, net, vendor):
    now = time.time()
    signal = _to_int(net["SIGNAL"])
    ssid = net["SSID"] or "<hidden>"

    row = conn.execute(
        "SELECT hits, best_signal FROM aps WHERE bssid = ?", (net["BSSID"],)
    ).fetchone()

    if row is None:
        conn.execute(
            "INSERT INTO aps (bssid, ssid, vendor, channel, freq, security, "
            "best_signal, first_seen, last_seen, hits) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
            (net["BSSID"], ssid, vendor, net["CHAN"], net["FREQ"],
             net["SECURITY"], signal, now, now),
        )
        conn.commit()
        return True, 1, signal

    hits, best = row
    hits += 1
    best = max(best or 0, signal)
    conn.execute(
        "UPDATE aps SET ssid = ?, channel = ?, freq = ?, security = ?, "
        "best_signal = ?, last_seen = ?, hits = ? WHERE bssid = ?",
        (ssid, net["CHAN"], net["FREQ"], net["SECURITY"],
         best, now, hits, net["BSSID"]),
    )
    conn.commit()
    return False, hits, best


def db_log_observation(conn, net):
    conn.execute(
        "INSERT INTO observations (bssid, ssid, channel, freq, signal, "
        "security, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (net["BSSID"], net["SSID"] or "<hidden>", net["CHAN"], net["FREQ"],
         _to_int(net["SIGNAL"]), net["SECURITY"], time.time()),
    )
    conn.commit()


def db_log_rogue(conn, net, reason):
    """Record or update a rogue detection event."""
    now = time.time()
    row = conn.execute(
        "SELECT id FROM rogues WHERE bssid = ?", (net["BSSID"],)
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE rogues SET last_seen = ?, signal = ?, reason = ? WHERE id = ?",
            (now, _to_int(net["SIGNAL"]), reason, row[0]),
        )
    else:
        conn.execute(
            "INSERT INTO rogues (bssid, ssid, vendor, channel, signal, "
            "security, reason, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (net["BSSID"], net["SSID"] or "<hidden>", get_vendor(net["BSSID"]),
             net["CHAN"], _to_int(net["SIGNAL"]), net["SECURITY"],
             reason, now, now),
        )
    conn.commit()


def db_all_aps(conn):
    cur = conn.execute(
        "SELECT bssid, ssid, vendor, channel, freq, security, "
        "best_signal, first_seen, last_seen, hits "
        "FROM aps ORDER BY last_seen DESC"
    )
    rows = cur.fetchall()
    cols = ["bssid", "ssid", "vendor", "channel", "freq", "security",
            "best_signal", "first_seen", "last_seen", "hits"]
    return [dict(zip(cols, r)) for r in rows]


def db_all_rogues(conn):
    cur = conn.execute(
        "SELECT bssid, ssid, vendor, channel, signal, security, reason, "
        "first_seen, last_seen FROM rogues ORDER BY last_seen DESC"
    )
    rows = cur.fetchall()
    cols = ["bssid", "ssid", "vendor", "channel", "signal", "security",
            "reason", "first_seen", "last_seen"]
    return [dict(zip(cols, r)) for r in rows]


# ============================================================================
# Channel congestion
# ============================================================================
def _channel_sort_key(ch):
    try:
        return int(ch)
    except (ValueError, TypeError):
        return 9999


def channel_congestion(networks):
    by_channel = defaultdict(lambda: {"count": 0, "networks": []})
    for net in networks:
        ch = net.get("CHAN") or net.get("channel") or "?"
        by_channel[ch]["count"] += 1
        by_channel[ch]["networks"].append(
            net.get("SSID") or net.get("ssid") or "<hidden>"
        )
    return dict(sorted(by_channel.items(), key=lambda kv: _channel_sort_key(kv[0])))


def print_channel_map(networks):
    congestion = channel_congestion(networks)
    if not congestion:
        print("No networks to map.")
        return

    max_count = max(c["count"] for c in congestion.values())
    print("\n=== Channel Congestion Map ===")

    band_24 = {ch: d for ch, d in congestion.items() if _channel_sort_key(ch) <= 14}
    band_5 = {ch: d for ch, d in congestion.items() if _channel_sort_key(ch) > 14}

    for label, band in (("2.4 GHz", band_24), ("5 GHz", band_5)):
        if not band:
            continue
        print(f"\n  [{label}]")
        for ch, data in band.items():
            bar = "█" * data["count"]
            print(f"    Ch {ch:>3}  |{bar:<{max_count}}|  {data['count']} AP(s)")

    if band_24:
        candidates = {"1": 0, "6": 0, "11": 0}
        for ch in candidates:
            candidates[ch] = band_24.get(ch, {}).get("count", 0)
        best = min(candidates, key=candidates.get)
        print(f"\n  Recommended 2.4 GHz channel: {best} "
              f"({candidates[best]} AP(s) on it)")
    print()


# ============================================================================
# Live sniffer
# ============================================================================
class LiveSniffer:
    def __init__(self, interval=DEFAULT_INTERVAL):
        self.interval = interval
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.conn = init_db()
        self.latest = {}
        self.scan_count = 0
        self.last_error = None
        self.last_scan_time = 0.0
        self._thread = None

        # Whitelist setup — build once at startup
        self.whitelist = {_normalize_bssid(k): v for k, v in WHITELIST.items()}

        # Owned SSIDs are populated dynamically as we see whitelisted APs.
        # Start with any manual entries.
        self.owned_ssids = {s.lower() for s in OWNED_SSIDS if s}
        # Also seed from any whitelisted AP we can derive an SSID for later —
        # done during scans (see _run).

        if not self.whitelist:
            print("[rogue-detect] Whitelist is empty — no rogue detection active.")
            print("              Populate WHITELIST at the top of the script.")
        else:
            print(f"[rogue-detect] Whitelist loaded with {len(self.whitelist)} AP(s).")

    def _run(self):
        while not self._stop.is_set():
            try:
                networks = scan_networks()
                now = time.time()

                # First pass: extend owned_ssids from whitelisted APs we see
                for net in networks:
                    bssid = _normalize_bssid(net["BSSID"])
                    if bssid in self.whitelist and net["SSID"]:
                        self.owned_ssids.add(net["SSID"].lower())

                with self._lock:
                    self.scan_count += 1
                    self.last_scan_time = now
                    self.last_error = None

                    for net in networks:
                        vendor = get_vendor(net["BSSID"])
                        is_new, hits, _ = db_upsert_ap(self.conn, net, vendor)
                        db_log_observation(self.conn, net)

                        classification = classify_network(
                            net, self.whitelist, self.owned_ssids
                        )
                        self.latest[net["BSSID"]] = {
                            **net,
                            "vendor": vendor,
                            "hits": hits,
                            "last_seen": now,
                            "status": classification["status"],
                            "friendly_name": classification["friendly_name"],
                            "reason": classification["reason"],
                        }

                        if classification["status"] == "rogue":
                            db_log_rogue(self.conn, net, classification["reason"])

                        if is_new:
                            self._alert(net, vendor, classification)

            except Exception as e:
                with self._lock:
                    self.last_error = str(e)
                print(f"[sniffer] error: {e}")

            self._stop.wait(self.interval)

    def _alert(self, net, vendor, classification):
        ssid = net["SSID"] or "<hidden>"
        ts = datetime.now().strftime("%H:%M:%S")

        if classification["status"] == "rogue":
            print(f"\a\a[{ts}] ⚠  POSSIBLE EVIL-TWIN / ROGUE AP DETECTED")
            print(f"        SSID:    {ssid}")
            print(f"        BSSID:   {net['BSSID']}  (vendor: {vendor})")
            print(f"        Channel: {net['CHAN']}  Signal: {net['SIGNAL']}")
            print(f"        Reason:  {classification['reason']}")
        elif classification["status"] == "known":
            print(f"\a[{ts}] NEW AP: {ssid}  [{classification['friendly_name']}]  "
                  f"{net['BSSID']}  (vendor: {vendor})")
        else:
            print(f"\a[{ts}] NEW AP: {ssid}  {net['BSSID']}  "
                  f"(vendor: {vendor}, ch {net['CHAN']}, "
                  f"signal {net['SIGNAL']}, {net['SECURITY']})")

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        try:
            self.conn.close()
        except Exception:
            pass

    def live_snapshot(self):
        with self._lock:
            now = time.time()
            return [
                {
                    "bssid": bssid,
                    "ssid": net["SSID"] or "<hidden>",
                    "channel": net["CHAN"],
                    "freq": net["FREQ"],
                    "signal": _to_int(net["SIGNAL"]),
                    "security": net["SECURITY"],
                    "vendor": net["vendor"],
                    "hits": net["hits"],
                    "status": net.get("status", "unknown"),
                    "friendly_name": net.get("friendly_name"),
                    "reason": net.get("reason", ""),
                    "is_new": (now - net["last_seen"]) < NEW_DEVICE_WINDOW
                              and net["hits"] == 1,
                }
                for bssid, net in self.latest.items()
            ]

    def all_aps(self):
        with self._lock:
            return db_all_aps(self.conn)

    def all_rogues(self):
        with self._lock:
            return db_all_rogues(self.conn)

    def channel_map(self):
        with self._lock:
            return channel_congestion(list(self.latest.values()))

    def stats(self):
        with self._lock:
            return {
                "scan_count": self.scan_count,
                "last_error": self.last_error,
                "last_scan_time": self.last_scan_time,
                "live_ap_count": len(self.latest),
                "db_path": str(DB_PATH),
                "whitelist_size": len(self.whitelist),
                "rogue_count": sum(
                    1 for n in self.latest.values()
                    if n.get("status") == "rogue"
                ),
            }


def print_scan_table(networks):
    if not networks:
        print("No networks found.")
        return

    whitelist = {_normalize_bssid(k): v for k, v in WHITELIST.items()}
    owned = {s.lower() for s in OWNED_SSIDS if s}
    for net in networks:
        bssid = _normalize_bssid(net["BSSID"])
        if bssid in whitelist and net["SSID"]:
            owned.add(net["SSID"].lower())

    networks = sorted(networks, key=lambda n: _to_int(n["SIGNAL"]), reverse=True)

    print(f"\nFound {len(networks)} network(s):\n")
    for i, net in enumerate(networks, 1):
        ssid = net["SSID"] or "<hidden>"
        c = classify_network(net, whitelist, owned)

        marker = ""
        if c["status"] == "rogue":
            marker = "  ⚠ POSSIBLE EVIL-TWIN / ROGUE AP"
        elif c["status"] == "known":
            marker = f"  ✓ [{c['friendly_name']}]"

        print(f"[{i:>2}] {ssid}{marker}")
        print(f"     BSSID (MAC):  {net['BSSID']}")
        print(f"     Vendor:       {get_vendor(net['BSSID'])}")
        print(f"     Mode:         {net['MODE']}")
        print(f"     Channel:      {net['CHAN']}  ({net['FREQ']} MHz)")
        print(f"     Rate:         {net['RATE']}")
        print(f"     Signal:       {net['SIGNAL']}/100  {net['BARS']}")
        print(f"     Security:     {net['SECURITY']}")
        if c["status"] == "rogue":
            print(f"     REASON:       {c['reason']}")
        if net["WPA-FLAGS"] and net["WPA-FLAGS"] != "--":
            print(f"     WPA Flags:    {net['WPA-FLAGS']}")
        if net["RSN-FLAGS"] and net["RSN-FLAGS"] != "--":
            print(f"     RSN Flags:    {net['RSN-FLAGS']}")
        print("-" * 60)


# ============================================================================
# Web dashboard
# ============================================================================
try:
    from flask import Flask, render_template_string, jsonify, Response
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


DASHBOARD_HTML = """<!doctype html>
<html>
<head>
<title>Wi-Fi Dashboard</title>
<style>
  body { font-family: -apple-system, Segoe UI, sans-serif; margin: 1.5rem;
         background: #f6f7f9; color: #222; }
  h1 { margin-bottom: .25rem; }
  .sub { color: #666; font-size: .9rem; margin-bottom: 1rem; }
  .status { font-size: .85rem; color: #444; margin-bottom: 1rem;
            background: #fff; padding: .55rem .85rem; border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0,0,0,.06); }
  .alert-banner { background: #fee2e2; color: #7f1d1d; border-left: 4px solid #b91c1c;
                  padding: .75rem 1rem; border-radius: 6px; margin-bottom: 1rem;
                  display: none; }
  .alert-banner.show { display: block; }
  .alert-banner strong { font-size: 1.05rem; }
  .tabs { margin-bottom: 1rem; }
  .tabs button { background: #e2e8f0; border: none; padding: .5rem 1rem;
                 border-radius: 6px; cursor: pointer; font-size: .9rem;
                 margin-right: .5rem; }
  .tabs button.active { background: #2d3748; color: #fff; }
  .tabs button.warn { background: #fde68a; color: #92400e; }
  .tabs button.warn.active { background: #b45309; color: #fff; }
  table { border-collapse: collapse; width: 100%; background: #fff;
          box-shadow: 0 1px 3px rgba(0,0,0,.08); border-radius: 6px;
          overflow: hidden; }
  th, td { padding: .55rem .75rem; text-align: left;
           border-bottom: 1px solid #eee; font-size: .9rem; }
  th { background: #2d3748; color: #fff; font-weight: 600; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f0f4ff; }
  tr.new td { background: #fffbe6; }
  tr.rogue td { background: #fee2e2; }
  tr.rogue:hover td { background: #fecaca; }
  .sig-strong { color: #14803c; font-weight: 600; }
  .sig-mid    { color: #b7791f; font-weight: 600; }
  .sig-weak   { color: #b91c1c; font-weight: 600; }
  .hidden     { color: #999; font-style: italic; }
  .badge      { background: #e2e8f0; color: #333; border-radius: 10px;
                padding: 1px 8px; font-size: .8rem; margin-left: .35rem; }
  .badge-new  { background: #fde68a; color: #92400e; font-weight: 600; }
  .badge-known{ background: #d1fae5; color: #065f46; font-weight: 600; }
  .badge-rogue{ background: #b91c1c; color: #fff; font-weight: 700;
                animation: pulse 1.5s infinite; }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: .55; }
  }
  .friendly { color: #065f46; font-weight: 600; }
  .meta       { margin-top: 1rem; color: #555; font-size: .85rem; }
  .chanmap    { margin-top: 1.5rem; background: #fff; padding: 1rem;
                border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .bar        { display: inline-block; height: 14px; background: #4c51bf;
                border-radius: 2px; vertical-align: middle; }
  .err        { color: #b91c1c; }
  .view       { display: none; }
  .view.active { display: block; }
  .disclaimer { font-size: .78rem; color: #666; background: #fef9c3;
                border-left: 3px solid #ca8a04; padding: .5rem .75rem;
                border-radius: 4px; margin-top: 1rem; }
</style>
</head>
<body>
  <h1>📡 Wi-Fi Dashboard</h1>
  <div class="sub">Updated every 5 seconds.</div>

  <div id="rogue-banner" class="alert-banner">
    <strong>⚠ POSSIBLE EVIL-TWIN / ROGUE AP DETECTED</strong>
    <div id="rogue-detail" style="margin-top:.35rem; font-size:.9rem;"></div>
  </div>

  <div class="status" id="status">Loading…</div>

  <div class="tabs">
    <button id="tab-live" class="active" onclick="showTab('live')">Live APs</button>
    <button id="tab-all" onclick="showTab('all')">All Seen</button>
    <button id="tab-rogues" class="warn" onclick="showTab('rogues')">
      Rogue Detections <span id="rogue-count-badge"></span>
    </button>
  </div>

  <div id="view-live" class="view active">
    <table>
      <thead><tr>
        <th>SSID</th><th>BSSID</th><th>Vendor</th><th>Ch</th>
        <th>Freq</th><th>Signal</th><th>Security</th><th>Hits</th>
      </tr></thead>
      <tbody id="rows-live"><tr><td colspan="8">Loading…</td></tr></tbody>
    </table>
  </div>

  <div id="view-all" class="view">
    <table>
      <thead><tr>
        <th>SSID</th><th>BSSID</th><th>Vendor</th><th>Ch</th>
        <th>Best</th><th>Security</th><th>Hits</th>
        <th>First seen</th><th>Last seen</th>
      </tr></thead>
      <tbody id="rows-all"><tr><td colspan="9">Loading…</td></tr></tbody>
    </table>
  </div>

  <div id="view-rogues" class="view">
    <table>
      <thead><tr>
        <th>SSID</th><th>BSSID</th><th>Vendor</th><th>Ch</th>
        <th>Signal</th><th>Security</th><th>Reason</th>
        <th>First seen</th><th>Last seen</th>
      </tr></thead>
      <tbody id="rows-rogues"><tr><td colspan="9">No rogue detections.</td></tr></tbody>
    </table>
    <div class="disclaimer">
      <strong>What this means:</strong> the flagged AP is broadcasting an SSID
      that matches one of your whitelisted networks, but its BSSID (MAC) is
      not in your whitelist. This <em>can</em> indicate an evil-twin or rogue
      AP — but it can also be a legitimate mesh node, a repeater, or a router
      you forgot to add. Verify before reacting.
    </div>
  </div>

  <div class="chanmap">
    <strong>Channel Congestion (live)</strong>
    <div id="chanmap">…</div>
  </div>

  <div class="meta">
    <a href="/api/live">JSON live</a> ·
    <a href="/api/all">JSON all</a> ·
    <a href="/api/rogues">JSON rogues</a> ·
    <a href="/api/channels">JSON channels</a> ·
    <a href="/api/stats">JSON stats</a> ·
    <a href="/api/export.csv">Export CSV</a>
  </div>

<script>
function esc(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function fmtSignal(s) {
  const n = parseInt(s, 10);
  if (isNaN(n)) return s;
  const cls = n >= 70 ? 'sig-strong' : n >= 40 ? 'sig-mid' : 'sig-weak';
  return `<span class="${cls}">${n}</span>`;
}
function fmtTime(epoch) {
  if (!epoch) return '—';
  return new Date(epoch * 1000).toLocaleString();
}
function showTab(name) {
  for (const t of ['live','all','rogues']) {
    document.getElementById('view-' + t).classList.toggle('active', t === name);
    document.getElementById('tab-' + t).classList.toggle('active', t === name);
  }
}

async function refresh() {
  const stats = await (await fetch('/api/stats')).json();
  document.getElementById('status').innerHTML =
    `scans: <b>${stats.scan_count}</b> · ` +
    `live APs: <b>${stats.live_ap_count}</b> · ` +
    `whitelist: <b>${stats.whitelist_size}</b> · ` +
    `rogues: <b style="color:#b91c1c">${stats.rogue_count}</b> · ` +
    `last scan: ${stats.last_scan_time
        ? new Date(stats.last_scan_time * 1000).toLocaleTimeString()
        : '—'} · ` +
    (stats.last_error
        ? `<span class="err">error: ${esc(stats.last_error)}</span>`
        : `<span style="color:#14803c">ok</span>`);

  const live = await (await fetch('/api/live')).json();

  // Rogue banner
  const roguesLive = live.filter(n => n.status === 'rogue');
  const banner = document.getElementById('rogue-banner');
  const detail = document.getElementById('rogue-detail');
  if (roguesLive.length) {
    banner.classList.add('show');
    detail.innerHTML = roguesLive.map(r =>
      `<div>• <b>${esc(r.ssid)}</b> from <code>${esc(r.bssid)}</code> ` +
      `(${esc(r.vendor)}) — ${esc(r.reason)}</div>`
    ).join('');
  } else {
    banner.classList.remove('show');
  }

  const rowsLive = document.getElementById('rows-live');
  if (!live.length) {
    rowsLive.innerHTML =
      '<tr><td colspan="8">No networks yet — waiting for first scan.</td></tr>';
  } else {
    // Sort: rogues first, then by signal
    live.sort((a,b) => {
      const rank = s => s === 'rogue' ? 0 : s === 'known' ? 2 : 1;
      const d = rank(a.status) - rank(b.status);
      return d !== 0 ? d : (b.signal - a.signal);
    });
    rowsLive.innerHTML = live.map(n => {
      let cls = '';
      if (n.status === 'rogue') cls = 'rogue';
      else if (n.is_new) cls = 'new';

      let ssidCell = n.ssid && n.ssid !== '<hidden>'
        ? esc(n.ssid)
        : '<span class="hidden">&lt;hidden&gt;</span>';

      let badges = '';
      if (n.status === 'rogue') {
        badges += ' <span class="badge badge-rogue">⚠ ROGUE</span>';
      } else if (n.status === 'known' && n.friendly_name) {
        badges += ` <span class="badge badge-known">✓ ${esc(n.friendly_name)}</span>`;
      } else if (n.is_new) {
        badges += ' <span class="badge badge-new">NEW</span>';
      }

      return `<tr class="${cls}" title="${esc(n.reason || '')}">
        <td>${ssidCell}${badges}</td>
        <td><code>${esc(n.bssid)}</code></td>
        <td>${esc(n.vendor)}</td>
        <td>${esc(n.channel)}</td>
        <td>${esc(n.freq)} MHz</td>
        <td>${fmtSignal(n.signal)}</td>
        <td>${esc(n.security)}</td>
        <td>${n.hits}</td>
      </tr>`;
    }).join('');
  }

  const all = await (await fetch('/api/all')).json();
  const rowsAll = document.getElementById('rows-all');
  if (!all.length) {
    rowsAll.innerHTML = '<tr><td colspan="9">No APs recorded yet.</td></tr>';
  } else {
    rowsAll.innerHTML = all.map(n => `
      <tr>
        <td>${n.ssid && n.ssid !== '<hidden>'
              ? esc(n.ssid)
              : '<span class="hidden">&lt;hidden&gt;</span>'}</td>
        <td><code>${esc(n.bssid)}</code></td>
        <td>${esc(n.vendor)}</td>
        <td>${esc(n.channel)}</td>
        <td>${fmtSignal(n.best_signal)}</td>
        <td>${esc(n.security)}</td>
        <td>${n.hits}</td>
        <td>${fmtTime(n.first_seen)}</td>
        <td>${fmtTime(n.last_seen)}</td>
      </tr>`).join('');
  }

  const rogues = await (await fetch('/api/rogues')).json();
  const countBadge = document.getElementById('rogue-count-badge');
  countBadge.textContent = rogues.length ? `(${rogues.length})` : '';
  const rowsRogues = document.getElementById('rows-rogues');
  if (!rogues.length) {
    rowsRogues.innerHTML = '<tr><td colspan="9">No rogue detections.</td></tr>';
  } else {
    rowsRogues.innerHTML = rogues.map(n => `
      <tr class="rogue">
        <td>${esc(n.ssid)}</td>
        <td><code>${esc(n.bssid)}</code></td>
        <td>${esc(n.vendor)}</td>
        <td>${esc(n.channel)}</td>
        <td>${fmtSignal(n.signal)}</td>
        <td>${esc(n.security)}</td>
        <td>${esc(n.reason)}</td>
        <td>${fmtTime(n.first_seen)}</td>
        <td>${fmtTime(n.last_seen)}</td>
      </tr>`).join('');
  }

  const cm = await (await fetch('/api/channels')).json();
  const max = Math.max(1, ...Object.values(cm).map(c => c.count));
  document.getElementById('chanmap').innerHTML = Object.keys(cm).length
    ? Object.entries(cm).map(([ch, d]) => {
        const w = Math.round((d.count / max) * 220);
        return `<div>Ch ${esc(ch).padStart(3)} &nbsp;
          <span class="bar" style="width:${w}px"></span>
          &nbsp; ${d.count}</div>`;
      }).join('')
    : '<div style="color:#999">No APs yet.</div>';
}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""


def start_web_dashboard(sniffer, host="127.0.0.1", port=5000):
    if not FLASK_AVAILABLE:
        print("[!] Flask not installed — skipping web dashboard.")
        return

    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/api/live")
    def api_live():
        return jsonify(sniffer.live_snapshot())

    @app.route("/api/all")
    def api_all():
        return jsonify(sniffer.all_aps())

    @app.route("/api/rogues")
    def api_rogues():
        return jsonify(sniffer.all_rogues())

    @app.route("/api/channels")
    def api_channels():
        return jsonify(sniffer.channel_map())

    @app.route("/api/stats")
    def api_stats():
        return jsonify(sniffer.stats())

    @app.route("/api/export.csv")
    def api_export():
        rows = sniffer.all_aps()
        cols = ["ssid", "bssid", "vendor", "channel", "freq", "security",
                "best_signal", "hits", "first_seen", "last_seen"]
        header = ",".join(cols) + "\n"

        def esc(v):
            s = str(v).replace('"', '""')
            return f'"{s}"'

        body = "\n".join(
            ",".join(esc(r.get(c, "")) for c in cols) for r in rows
        )
        return Response(header + body, mimetype="text/csv",
                        headers={"Content-Disposition":
                                 "attachment; filename=wifi_export.csv"})

    print(f"[dashboard] http://{host}:{port}  (Ctrl+C to quit)")
    app.run(host=host, port=port, debug=False, use_reloader=False)


# ============================================================================
# Main
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Wi-Fi scanner/sniffer with SQLite, dashboard, and rogue-AP detection.",
    )
    parser.add_argument("-scan", action="store_true",
                        help="One-shot scan and print table.")
    parser.add_argument("-sniff", action="store_true",
                        help="Live monitor: SQLite logging, new-AP alerts, rogue detection.")
    parser.add_argument("-serve", action="store_true",
                        help="Run the web dashboard (use with -sniff).")
    parser.add_argument("-i", "--interval", type=int, default=DEFAULT_INTERVAL,
                        help=f"Scan interval in seconds (default {DEFAULT_INTERVAL}).")
    parser.add_argument("--host", type=str, default="127.0.0.1",
                        help="Dashboard bind host (default 127.0.0.1).")
    parser.add_argument("--port", type=int, default=5000,
                        help="Dashboard port (default 5000).")

    args = parser.parse_args()

    if not (args.scan or args.sniff):
        parser.print_help()
        return

    if args.scan:
        print("Scanning for nearby Wi-Fi networks…\n")
        print_scan_table(scan_networks())
        return

    if args.sniff:
        print(f"Starting live sniffer (interval {args.interval}s)…")
        print(f"Database: {DB_PATH}")
        sniffer = LiveSniffer(interval=args.interval)
        sniffer.start()

        if args.serve:
            print("Press Ctrl+C to stop.")
            try:
                start_web_dashboard(sniffer, host=args.host, port=args.port)
            except KeyboardInterrupt:
                print("\nShutting down…")
            finally:
                sniffer.stop()
        else:
            for _ in range(20):
                if sniffer.scan_count > 0:
                    break
                time.sleep(1)
            print_channel_map(list(sniffer.latest.values()))
            print(f"Sniffing… ({sniffer.scan_count} scans so far, "
                  f"Ctrl+C to stop)")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nShutting down…")
            finally:
                sniffer.stop()


if __name__ == "__main__":
    main()
