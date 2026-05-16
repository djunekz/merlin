import argparse
import signal
import socket
import json
import os
import sys
import time
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from merlincolor import *
from merlinset import *
from merlinlogo import *
from merlinconf import MAX_THREADS, OUTPUT_DIR, SAVE_REPORTS, PORT_RANGE

SERVICE_MAP = {
    20:'FTP-data', 21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP',
    53:'DNS', 67:'DHCP', 68:'DHCP', 69:'TFTP', 79:'Finger',
    80:'HTTP', 88:'Kerberos', 110:'POP3', 111:'RPCbind', 119:'NNTP',
    123:'NTP', 135:'MSRPC', 137:'NetBIOS-NS', 138:'NetBIOS-DGM',
    139:'NetBIOS-SSN', 143:'IMAP', 161:'SNMP', 162:'SNMP-trap',
    179:'BGP', 194:'IRC', 389:'LDAP', 443:'HTTPS', 445:'SMB',
    465:'SMTPS', 500:'IKE', 512:'rexec', 513:'rlogin', 514:'syslog',
    515:'LPD', 520:'RIP', 554:'RTSP', 587:'SMTP-submission',
    631:'IPP', 636:'LDAPS', 873:'rsync', 902:'VMware',
    993:'IMAPS', 995:'POP3S', 1080:'SOCKS', 1194:'OpenVPN',
    1433:'MSSQL', 1434:'MSSQL-UDP', 1521:'Oracle-DB',
    1723:'PPTP', 2049:'NFS', 2181:'ZooKeeper', 2375:'Docker',
    2376:'Docker-TLS', 3000:'Node/Grafana', 3306:'MySQL',
    3389:'RDP', 3690:'SVN', 4443:'HTTPS-alt', 4848:'GlassFish',
    5000:'Flask/UPnP', 5432:'PostgreSQL', 5900:'VNC',
    5984:'CouchDB', 6379:'Redis', 6443:'Kubernetes-API',
    7077:'Spark', 7474:'Neo4j', 8000:'HTTP-alt',
    8080:'HTTP-proxy', 8443:'HTTPS-alt', 8888:'Jupyter',
    9000:'PHP-FPM/SonarQube', 9090:'Prometheus', 9200:'Elasticsearch',
    9300:'Elasticsearch-cluster', 10250:'Kubelet', 11211:'Memcached',
    27017:'MongoDB', 27018:'MongoDB-shard', 28017:'MongoDB-web',
    50000:'DB2', 50070:'Hadoop-HDFS', 61616:'ActiveMQ',
}

RISK_PORTS = {
    21:'FTP sends credentials in plaintext',
    23:'Telnet sends everything in plaintext',
    69:'TFTP — no authentication',
    79:'Finger — user enumeration',
    111:'RPCbind — RPC service exposure',
    135:'MSRPC — Windows attack surface',
    137:'NetBIOS NS — information disclosure',
    138:'NetBIOS DGM — information disclosure',
    139:'NetBIOS SSN — SMB over NetBIOS',
    161:'SNMP — may expose device info',
    445:'SMB — EternalBlue / ransomware target',
    512:'rexec — plaintext remote execution',
    513:'rlogin — plaintext remote login',
    873:'rsync — may allow unauth file access',
    1080:'SOCKS proxy — potential open proxy',
    2375:'Docker — unauth API if open',
    3389:'RDP — brute-force target',
    4848:'GlassFish admin',
    5900:'VNC — graphical remote access',
    5984:'CouchDB — may allow unauth access',
    6379:'Redis — unauth access if misconfigured',
    7474:'Neo4j — may expose browser UI',
    8888:'Jupyter — RCE if unprotected',
    9200:'Elasticsearch — unauth data access',
    9300:'Elasticsearch cluster comms',
    10250:'Kubelet — K8s node exec endpoint',
    11211:'Memcached — amplification DDoS risk',
    27017:'MongoDB — unauth access if misconfigured',
    28017:'MongoDB web interface',
    50070:'Hadoop HDFS NameNode web UI',
    61616:'ActiveMQ — deserialization target',
}

HTTP_PROBE = b'HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n'
BANNER_PROBES = {
    21:  b'',
    22:  b'',
    25:  b'',
    80:  b'HEAD / HTTP/1.0\r\n\r\n',
    110: b'',
    143: b'',
    443: b'',
    3306: b'',
    5432: b'',
    6379: b'PING\r\n',
    11211: b'stats\r\n',
    27017: b'',
}

def _parse_port_range(s):
    presets = {
        'full':    range(1, 65536),
        'all':     range(1, 65536),
        'remote':  [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 5900],
        'web':     [80, 443, 8080, 8443, 8000, 8888],
        'common':  [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5432, 5900, 8080],
    }
    s_lower = s.strip().lower()
    if s_lower in presets:
        return sorted(presets[s_lower])
    ports = set()
    for part in s.split(','):
        part = part.strip()
        if '-' in part:
            a, b = part.split('-', 1)
            try:
                ports.update(range(int(a), int(b) + 1))
            except ValueError:
                pass
        else:
            try:
                ports.add(int(part))
            except ValueError:
                pass
    return sorted(ports) if ports else sorted(range(1, 1025))

def _scan_port(host, port, timeout=1.2):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False

def banner_grab(host, port, timeout=2.5):
    probe = BANNER_PROBES.get(port, b'')
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if probe:
                s.sendall(probe)
            banner = s.recv(1024).decode(errors='replace').strip()
            return banner[:200]
    except Exception:
        return ''

def service_detect(host, port, banner):
    svc = SERVICE_MAP.get(port, 'unknown')
    if not banner:
        return svc
    b = banner.lower()
    if 'ssh-' in b:                return 'SSH'
    if 'ftp' in b:                 return 'FTP'
    if 'smtp' in b or 'postfix' in b or 'sendmail' in b: return 'SMTP'
    if 'pop3' in b or '+ok' in b:  return 'POP3'
    if 'imap' in b:                return 'IMAP'
    if 'mysql' in b:               return 'MySQL'
    if 'postgresql' in b:          return 'PostgreSQL'
    if 'redis' in b:               return 'Redis'
    if 'mongodb' in b:             return 'MongoDB'
    if 'http/' in b:               return 'HTTP'
    if 'pong' in b and port == 6379: return 'Redis'
    return svc

def os_ttl_guess(ip):
    try:
        import subprocess
        result = subprocess.run(['ping', '-c', '1', '-W', '2', ip],
                                capture_output=True, text=True, timeout=5)
        match = __import__('re').search(r'ttl=(\d+)', result.stdout, __import__('re').IGNORECASE)
        if match:
            ttl = int(match.group(1))
            if ttl <= 64:   return f"Linux/Unix (TTL≈{ttl})"
            if ttl <= 128:  return f"Windows (TTL≈{ttl})"
            if ttl <= 255:  return f"Cisco/Network device (TTL≈{ttl})"
    except Exception:
        pass
    return 'Unknown'

def scan_ports(host, ports, threads=MAX_THREADS, grab=False):
    open_ports = {}
    print(f"\n{plus} {LY}Scanning {LC}{len(ports)}{LY} ports on {W}{host}{N}")
    bar_total = len(ports)
    done      = [0]

    def _do(port):
        _, is_open = _scan_port(host, port)
        done[0] += 1
        if done[0] % 100 == 0 or done[0] == bar_total:
            pct = int(done[0] / bar_total * 30)
            bar = LG + '█' * pct + DG + '░' * (30 - pct) + N
            print(f"\r  [{bar}] {LC}{done[0]}/{bar_total}{N}", end='', flush=True)
        return port, is_open

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(_do, p): p for p in ports}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports[port] = {}

    print()

    for port in sorted(open_ports.keys()):
        banner  = banner_grab(host, port) if grab else ''
        service = service_detect(host, port, banner)
        risk    = RISK_PORTS.get(port, '')
        risk_str = f"  {LR}⚠ {risk}{N}" if risk else ''
        open_ports[port] = {'service': service, 'banner': banner, 'risk': risk}
        print(f"  {sukses} {LG}OPEN{N}  {LY}{port:5d}/tcp{N}  {LC}{service:<22}{N}{risk_str}")
        if banner:
            print(f"       {DG}↳ {banner[:90]}{N}")

    return open_ports

def main():
    print(logo)
    parser = argparse.ArgumentParser(description=LY + "Merlin — Port Scanner + Service Detection")
    parser.add_argument('-u', '--url',        required=True)
    parser.add_argument('-p', '--ports',      default=PORT_RANGE)
    parser.add_argument('-t', '--threads',    type=int, default=MAX_THREADS)
    parser.add_argument('--grab-banners',     action='store_true')
    parser.add_argument('--os-detect',        action='store_true')
    parser.add_argument('--top100',           action='store_true', help='Scan top 100 common ports')
    parser.add_argument('-o', '--output',     dest='output_dir', default=OUTPUT_DIR)
    args = parser.parse_args()

    TOP100 = [21,22,23,25,53,80,88,110,111,119,123,135,137,138,139,143,161,
              179,389,443,445,465,500,587,631,636,873,993,995,1080,1433,1521,
              1723,2049,2375,3000,3306,3389,3690,4443,4848,5000,5432,5900,
              5984,6379,6443,7474,8000,8080,8443,8888,9000,9090,9200,9300,
              10250,11211,27017,27018,28017,50070,61616]

    parsed = urlparse(args.url if '://' in args.url else 'https://' + args.url)
    host   = parsed.hostname

    print(f"\n{LY}{'═'*65}{N}")
    print(f"{plus} {LY}Port Scanner{N} → {LC}{host}{N}")
    print(f"{LY}{'═'*65}{N}")

    try:
        ip = socket.gethostbyname(host)
        print(f"  {sukses} Resolved → {LG}{ip}{N}")
    except socket.gaierror as e:
        print(f"  {err} Could not resolve: {e}")
        sys.exit(1)

    if args.os_detect:
        os_guess = os_ttl_guess(ip)
        print(f"  {star} OS Guess (TTL heuristic): {LY}{os_guess}{N}")

    ports    = TOP100 if args.top100 else _parse_port_range(args.ports)
    t0       = time.time()
    results  = scan_ports(host, ports, args.threads, grab=args.grab_banners)
    elapsed  = time.time() - t0

    risky = {p: v for p, v in results.items() if v.get('risk')}
    print(f"\n{note} {LY}Scan complete{N}: {LG}{len(results)}{N} open / {len(ports)} scanned — {LY}{elapsed:.2f}s{N}")
    if risky:
        print(f"{note} {LR}High-risk ports open: {', '.join(str(p) for p in sorted(risky.keys()))}{N}")

    if SAVE_REPORTS:
        os.makedirs(args.output_dir, exist_ok=True)
        fname = os.path.join(args.output_dir, f"portscan_{host.replace('.','_')}.json")
        with open(fname, 'w', encoding='utf-8') as f:
            json.dump({"target": host, "ip": ip, "open_ports": {str(k): v for k, v in results.items()}},
                      f, indent=4)
        print(f"{sukses} Report saved → {LY}{fname}{N}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\033[1;92m[*]\033[0m Scan interrupted. Returning to menu...\033[0m')
