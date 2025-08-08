import threading
import time
from collections import defaultdict, deque
import curses
import subprocess
import atexit
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt, RadioTap, sendp

# Configuration
BASE_INTERFACE = 'wlan0'   # Replace with your interface name (no 'mon')
MON_INTERFACE = f'{BASE_INTERFACE}mon'
INTERFACE = MON_INTERFACE    # Monitor-mode interface
SUSPICIOUS_SSIDS = {"Free Wifi", "Starbucks WiFi", "Linksys", "HackerSSID"}

# Flood thresholds and windows (seconds)
THRESHOLDS = {
    'beacon': {'count': 100, 'window': 10},
    'probe':  {'count': 200, 'window': 10},
    'deauth': {'count': 50,  'window': 10},
    'disassoc': {'count': 50, 'window': 10},
    'wps':    {'count': 50,  'window': 10},
    'rtscts': {'count': 100, 'window': 10},
}

# Global state
ap_ssid_map    = defaultdict(set)    # SSID -> set of BSSIDs
client_probes  = defaultdict(set)    # client MAC -> set of SSIDs probed
counters       = {k: deque() for k in THRESHOLDS}
alerts         = deque(maxlen=10)
lock           = threading.Lock()

def audit_flood(counter_name, alert_msg):
    now = time.time()
    dq = counters[counter_name]
    dq.append(now)
    # prune old
    window = THRESHOLDS[counter_name]['window']
    while dq and dq[0] < now - window:
        dq.popleft()
    if len(dq) >= THRESHOLDS[counter_name]['count']:
        alerts.appendleft(f"⚠️ Flood: {alert_msg} ({len(dq)}/{THRESHOLDS[counter_name]['count']} in {window}s)")

# Monitor mode management

def enable_monitor_mode():
    subprocess.run(['sudo', 'airmon-ng', 'start', BASE_INTERFACE], check=True)

def disable_monitor_mode():
    subprocess.run(['sudo', 'airmon-ng', 'stop', MON_INTERFACE], check=True)

atexit.register(disable_monitor_mode)

# Karma responder: replies to probe requests by advertising SSIDs

def karma_responder():
    while True:
        with lock:
            # use SSIDs we've seen
            ssids = list(ap_ssid_map.keys())
            clients = list(client_probes.keys())
        for client in clients:
            for ssid in ssids:
                bssids = ap_ssid_map.get(ssid)
                if not bssids:
                    continue
                bssid = next(iter(bssids))
                # build a probe response
                pkt = (
                    RadioTap()/Dot11(type=0, subtype=5,
                                     addr1=client, addr2=bssid, addr3=bssid)/
                    Dot11ProbeResp()/Dot11Elt(ID='SSID', info=ssid.encode())
                )
                sendp(pkt, iface=INTERFACE, verbose=False)
        time.sleep(1)

# Packet processing
def handle_packet(pkt):
    if not pkt.haslayer(Dot11):
        return
    dot11 = pkt[Dot11]
    subtype = (dot11.type, dot11.subtype)
    now = time.time()

    # Management: Deauth (0,12)
    if subtype == (0,12):
        src, dst = dot11.addr2, dot11.addr1
        with lock:
            counters['deauth'].append(now)
            alerts.appendleft(f"🛑 Deauth from {src} to {dst}")
        audit_flood('deauth', 'deauthentication')

    # Management: Disassociation (0,10)
    elif subtype == (0,10):
        src, dst = dot11.addr2, dot11.addr1
        with lock:
            counters['disassoc'].append(now)
            alerts.appendleft(f"🛑 Disassoc from {src} to {dst}")
        audit_flood('disassoc', 'disassociation')

    # Beacon frame (0,8)
    elif subtype == (0,8):
        ssid = pkt.info.decode(errors='ignore')
        bssid = dot11.addr2
        with lock:
            seen = ap_ssid_map[ssid]
            if bssid not in seen and seen:
                twins = ", ".join(seen | {bssid})
                alerts.appendleft(f"🧿 Evil Twin: SSID '{ssid}' on BSSIDs {twins}")
            seen.add(bssid)
            counters['beacon'].append(now)
        audit_flood('beacon', 'beacon frames')

    # Probe Request (0,4)
    elif subtype == (0,4):
        client = dot11.addr2
        ssid = pkt.info.decode(errors='ignore')
        with lock:
            client_probes[client].add(ssid)
            counters['probe'].append(now)
            # Hidden SSID reveal
            if ssid == '':
                alerts.appendleft(f"❗ Hidden SSID probe from {client}")
            # Suspicious SSID
            if ssid in SUSPICIOUS_SSIDS:
                alerts.appendleft(f"❗ {client} probed for suspicious SSID '{ssid}'")
        audit_flood('probe', 'probe requests')

    # Control: RTS/CTS
    elif dot11.type == 1 and dot11.subtype in (11,12):
        with lock:
            counters['rtscts'].append(now)
        audit_flood('rtscts', 'RTS/CTS frames')

    # WPS IE detection in Beacon/ProbeResp
    if pkt.haslayer(Dot11Elt):
        el = pkt.getlayer(Dot11Elt)
        while el:
            if el.ID == 221 and el.info.startswith(b"\x00\x50\xf2\x04"):
                with lock:
                    counters['wps'].append(now)
                audit_flood('wps', 'WPS IE frames')
                break
            el = el.payload.getlayer(Dot11Elt)

# Sniffer thread

def start_sniff():
    sniff(iface=INTERFACE, prn=handle_packet, store=False)

# Curses dashboard
def curses_dashboard(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(1000)

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        with lock:
            stats = {
                'APs': sum(len(bssids) for bssids in ap_ssid_map.values()),
                'Clients': len(client_probes),
                'Probes': len(counters['probe']),
                'Beacons': len(counters['beacon']),
                'Deauths': len(counters['deauth']),
                'Disassocs': len(counters['disassoc']),
                'WPS': len(counters['wps']),
                'RTS/CTS': len(counters['rtscts']),
            }
            recent_alerts = list(alerts)

        # Title
        stdscr.addstr(0, 2, "WiFi PineAP-style Dashboard", curses.A_BOLD)
        # Stats
        for i, (k, v) in enumerate(stats.items(), start=2):
            stdscr.addstr(i, 4, f"{k}: {v}")

        # Recent Alerts
        line = len(stats) + 3
        stdscr.addstr(line, 2, "Last 10 Alerts:")
        for i, alert in enumerate(recent_alerts, start=line+1):
            if i >= h - 1:
                break
            stdscr.addstr(i, 4, alert[:w-8])

        # Footer
        stdscr.addstr(h-1, 2, "Press Ctrl+C or 'q' to exit.")
        stdscr.refresh()

        try:
            key = stdscr.getch()
            if key in (ord('q'), 3):  # 'q' or Ctrl+C
                break
        except curses.error:
            pass

if __name__ == '__main__':
    try:
        print(f"Enabling monitor mode on {BASE_INTERFACE}...")
        enable_monitor_mode()
        # Start sniff thread
        threading.Thread(target=start_sniff, daemon=True).start()
        # Start Karma responder
        threading.Thread(target=karma_responder, daemon=True).start()
        # Launch curses UI
        curses.wrapper(curses_dashboard)
    except KeyboardInterrupt:
        pass
    finally:
        print(f"Disabling monitor mode on {MON_INTERFACE}...")
        disable_monitor_mode()
