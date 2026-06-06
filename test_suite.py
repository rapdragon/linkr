#!/usr/bin/env python3
"""
Linkr integration test suite.
Tests add, delete, and verification across Linkr, NPM, Pi-hole, and both Swarm replicas.
Edit is UI-only — no API endpoint exists; that test is manual.

Usage: python3 test_suite.py
"""

import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

LINKR_URL   = "http://10.69.0.100:5000"
API_KEY     = "WtSRfeFdM0QBhwWklaEiwLjPPlUU84kuonTLqsWnhdA"
TEST_DOMAIN = "linkr-test.dragonfang.net"
TEST_HOST   = "10.69.0.100"
TEST_PORT   = 5000  # Linkr itself — known good target
NPM_URL     = "http://10.69.0.100:81"
NPM_USER    = "rapdragon@dragonfang.net"
NPM_PASS    = "Fireball01"
PIHOLE_API  = "http://10.69.0.99:20720"
PIHOLE_PASS = "AafuTBVrUKu2fqB32AAWHR5GSAxMC9q3Ou79scU8RtY="

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
SKIP = "\033[93mSKIP\033[0m"

results = []

def check(name, ok, detail=""):
    status = PASS if ok else FAIL
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
    results.append((name, ok))
    return ok

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def linkr(method, path, body=None):
    url = LINKR_URL + path
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("X-API-Key", API_KEY)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())
    except Exception as e:
        return 0, {"error": str(e)}

def npm_token():
    body = json.dumps({"identity": NPM_USER, "secret": NPM_PASS}).encode()
    req = urllib.request.Request(NPM_URL + "/api/tokens", data=body)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read()).get("token")

def npm_proxy_hosts(token):
    req = urllib.request.Request(NPM_URL + "/api/nginx/proxy-hosts")
    req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())

def pihole_dns_hosts():
    req = urllib.request.Request(f"{PIHOLE_API}/api/config/dns/hosts", method="GET")
    req.add_header("X-FTL-SID", get_pihole_sid())
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            d = json.loads(r.read())
            return d.get("config", {}).get("dns", {}).get("hosts", [])
    except Exception:
        return []

def get_pihole_sid():
    body = json.dumps({"password": PIHOLE_PASS}).encode()
    req = urllib.request.Request(f"{PIHOLE_API}/api/auth", data=body)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read()).get("session", {}).get("sid", "")

def npm_containers():
    out = subprocess.check_output(
        ["docker", "ps", "--format", "{{.Names}}"], text=True
    )
    return [l for l in out.strip().splitlines() if "npm_npm." in l]

def nginx_config_exists(container, domain):
    out = subprocess.run(
        ["docker", "exec", container, "ls", "/data/nginx/proxy_host/"],
        capture_output=True, text=True
    )
    # Find the config file for this domain
    hosts_out = subprocess.run(
        ["docker", "exec", container, "grep", "-rl", domain, "/data/nginx/proxy_host/"],
        capture_output=True, text=True
    )
    return bool(hosts_out.stdout.strip())

# ─────────────────────────────────────────────
section("0. Pre-flight checks")
# ─────────────────────────────────────────────

status, data = linkr("GET", "/api/health")
check("Linkr health endpoint responds", status == 200)

status, data = linkr("GET", "/api/fqdns")
check("Linkr API key auth works", status == 200, f"{len(data)} FQDNs currently")

npm_tok = None
try:
    npm_tok = npm_token()
    check("NPM auth works", bool(npm_tok))
except Exception as e:
    check("NPM auth works", False, str(e))

containers = npm_containers()
check("Both NPM replicas running", len(containers) == 2, f"found: {containers}")

# Make sure test domain doesn't already exist
if status == 200:
    existing = [f["domain"] for f in data]
    if TEST_DOMAIN in existing:
        print(f"\n  ⚠ Cleaning up leftover test domain from previous run...")
        linkr("DELETE", f"/api/fqdns/{TEST_DOMAIN}")
        time.sleep(3)

# ─────────────────────────────────────────────
section("1. Add FQDN (internal, no cert)")
# ─────────────────────────────────────────────

status, data = linkr("POST", "/api/fqdns", {
    "domain": TEST_DOMAIN,
    "forward_host": TEST_HOST,
    "forward_port": TEST_PORT,
    "type": "internal",
    "dns_ip": "10.69.0.100"
})
check("Linkr POST /api/fqdns returns 201", status == 201, str(data))
created_proxy_id = data.get("proxy_id")
check("Response includes proxy_id", bool(created_proxy_id))

time.sleep(5)  # allow swarm reload to propagate

# Verify NPM
if npm_tok:
    hosts = npm_proxy_hosts(npm_tok)
    npm_match = next((h for h in hosts if TEST_DOMAIN in h.get("domain_names", [])), None)
    check("NPM proxy host created", bool(npm_match))
    if npm_match:
        check("NPM forward host correct", npm_match.get("forward_host") == TEST_HOST)
        check("NPM forward port correct", str(npm_match.get("forward_port")) == str(TEST_PORT))
        check("No SSL cert on HTTP-only host", npm_match.get("certificate_id") == 0)

# Verify Pi-hole DNS
hosts_list = pihole_dns_hosts()
dns_entry = f"10.69.0.100 {TEST_DOMAIN}"
check("Pi-hole DNS entry created", dns_entry in hosts_list, f"looking for: {dns_entry}")

# Verify nginx configs on BOTH replicas
for container in containers:
    check(f"nginx config present on {container.split('.')[1][:6]}",
          nginx_config_exists(container, TEST_DOMAIN))

# ─────────────────────────────────────────────
section("2. Swarm reload — both replicas consistent")
# ─────────────────────────────────────────────

if len(containers) == 2:
    cfg_counts = []
    for container in containers:
        out = subprocess.run(
            ["docker", "exec", container, "ls", "/data/nginx/proxy_host/"],
            capture_output=True, text=True
        )
        count = len(out.stdout.strip().splitlines())
        cfg_counts.append(count)
    check("Both replicas have same nginx config count",
          cfg_counts[0] == cfg_counts[1],
          f"replica counts: {cfg_counts}")

# ─────────────────────────────────────────────
section("3. List FQDNs — test domain visible")
# ─────────────────────────────────────────────

status, data = linkr("GET", "/api/fqdns")
check("GET /api/fqdns succeeds", status == 200)
test_entry = next((f for f in data if f["domain"] == TEST_DOMAIN), None)
check("Test domain appears in list", bool(test_entry))
if test_entry:
    check("List shows correct forward_host", test_entry.get("proxy", {}).get("forward_host") == TEST_HOST)
    check("List shows DNS IP", test_entry.get("dns_ip") == "10.69.0.100")

# ─────────────────────────────────────────────
section("4. HTTP-only config survives NPM restart")
# ─────────────────────────────────────────────

print("  Forcing NPM service restart (scale 0 → 2)...")
subprocess.run(["docker", "service", "scale", "npm_npm=0"], capture_output=True)
time.sleep(15)
subprocess.run(["docker", "service", "scale", "npm_npm=2"], capture_output=True)
time.sleep(20)

containers = npm_containers()
check("NPM replicas back after restart", len(containers) == 2)
for container in containers:
    check(f"HTTP-only config survived restart on {container.split('.')[1][:6]}",
          nginx_config_exists(container, TEST_DOMAIN))

# ─────────────────────────────────────────────
section("5. Duplicate add rejected")
# ─────────────────────────────────────────────

status, data = linkr("POST", "/api/fqdns", {
    "domain": TEST_DOMAIN,
    "forward_host": TEST_HOST,
    "forward_port": TEST_PORT,
    "type": "internal",
    "dns_ip": "10.69.0.100"
})
check("Duplicate domain returns 409", status == 409, str(data))

# ─────────────────────────────────────────────
section("6. Validation — bad inputs rejected")
# ─────────────────────────────────────────────

status, data = linkr("POST", "/api/fqdns", {
    "domain": "bad-port-test.dragonfang.net",
    "forward_host": TEST_HOST,
    "forward_port": 99999
})
check("Port 99999 rejected", status == 400, str(data))

status, data = linkr("POST", "/api/fqdns", {
    "forward_host": TEST_HOST,
    "forward_port": 80
})
check("Missing domain rejected", status == 400, str(data))

status, data = linkr("POST", "/api/fqdns", {
    "domain": "no-host-test.dragonfang.net",
    "forward_port": 80
})
check("Missing forward_host rejected", status == 400, str(data))

# ─────────────────────────────────────────────
section("7. Read-only API key rejected on writes")
# ─────────────────────────────────────────────

ro_keys = []
try:
    import sqlite3
    conn = sqlite3.connect("/root/linkr/data/dns_proxy_manager.db")
    ro_keys = conn.execute("SELECT key FROM api_keys WHERE permission='read'").fetchall()
    conn.close()
except Exception:
    pass

if ro_keys:
    ro_key = ro_keys[0][0]
    req = urllib.request.Request(LINKR_URL + "/api/fqdns",
                                  data=b'{}', method="POST")
    req.add_header("X-API-Key", ro_key)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            check("Read-only key blocked on POST", False, "should have been rejected")
    except urllib.error.HTTPError as e:
        check("Read-only key blocked on POST", e.code == 403)
else:
    print(f"  [{SKIP}] Read-only API key — none exist, skipping")

# ─────────────────────────────────────────────
section("8. Add internal CA cert via PATCH")
# ─────────────────────────────────────────────

NPM_CERTS_PATH = "/var/lib/docker/volumes/npm_npm_data/_data/custom_ssl"

status, data = linkr("PATCH", f"/api/fqdns/{TEST_DOMAIN}", {"cert_action": "internal", "force_ssl": True})
check("PATCH cert_action=internal returns 200", status == 200, str(data))
cert_id = data.get("cert_id", 0)
check("Response includes cert_id", cert_id > 0)

time.sleep(5)

# Verify cert files written to NPM volume
cert_dir = os.path.join(NPM_CERTS_PATH, f"npm-{cert_id}")
check("cert dir exists in NPM volume", os.path.isdir(cert_dir), cert_dir)
check("fullchain.pem exists", os.path.isfile(os.path.join(cert_dir, "fullchain.pem")))
check("privkey.pem exists", os.path.isfile(os.path.join(cert_dir, "privkey.pem")))
check("chain.pem exists", os.path.isfile(os.path.join(cert_dir, "chain.pem")))

# Verify fullchain contains both cert and CA
if os.path.isfile(os.path.join(cert_dir, "fullchain.pem")):
    fullchain = open(os.path.join(cert_dir, "fullchain.pem")).read()
    check("fullchain.pem contains 2 certs (cert + CA)", fullchain.count("BEGIN CERTIFICATE") == 2)

# Verify NPM has cert applied
if npm_tok:
    hosts = npm_proxy_hosts(npm_tok)
    npm_match = next((h for h in hosts if TEST_DOMAIN in h.get("domain_names", [])), None)
    check("NPM proxy host has cert applied", npm_match and npm_match.get("certificate_id") == cert_id)
    check("NPM ssl_forced enabled", npm_match and npm_match.get("ssl_forced") == True)

# ─────────────────────────────────────────────
section("9. Create FQDN with internal cert (POST type=internal_cert)")
# ─────────────────────────────────────────────

TEST_DOMAIN2 = "linkr-test2.dragonfang.net"
linkr("DELETE", f"/api/fqdns/{TEST_DOMAIN2}")  # cleanup if exists
time.sleep(2)

status, data = linkr("POST", "/api/fqdns", {
    "domain": TEST_DOMAIN2,
    "forward_host": TEST_HOST,
    "forward_port": TEST_PORT,
    "type": "internal_cert",
    "force_ssl": True,
    "dns_ip": "10.69.0.100"
})
check("POST type=internal_cert returns 201", status == 201, str(data))
cert_id2 = data.get("cert_id", 0)
check("Response includes cert_id", cert_id2 > 0)

time.sleep(5)

cert_dir2 = os.path.join(NPM_CERTS_PATH, f"npm-{cert_id2}")
check("cert dir created in NPM volume", os.path.isdir(cert_dir2))
check("Pi-hole DNS entry created for domain2", f"10.69.0.100 {TEST_DOMAIN2}" in pihole_dns_hosts())

if npm_tok:
    hosts = npm_proxy_hosts(npm_tok)
    npm_match2 = next((h for h in hosts if TEST_DOMAIN2 in h.get("domain_names", [])), None)
    check("NPM proxy host created with cert", npm_match2 and npm_match2.get("certificate_id") == cert_id2)

# cleanup domain2
linkr("DELETE", f"/api/fqdns/{TEST_DOMAIN2}")

# ─────────────────────────────────────────────
section("10. Edit FQDN (PATCH)")
# ─────────────────────────────────────────────

NEW_PORT = 5001
status, data = linkr("PATCH", f"/api/fqdns/{TEST_DOMAIN}", {"forward_port": NEW_PORT})
check("Linkr PATCH /api/fqdns/<domain> returns 200", status == 200, str(data))
check("Response shows updated port", data.get("forward_port") == NEW_PORT)

time.sleep(5)

# Verify NPM updated
if npm_tok:
    hosts = npm_proxy_hosts(npm_tok)
    npm_match = next((h for h in hosts if TEST_DOMAIN in h.get("domain_names", [])), None)
    check("NPM forward port updated", npm_match and npm_match.get("forward_port") == NEW_PORT)
    check("NPM forward host unchanged", npm_match and npm_match.get("forward_host") == TEST_HOST)

# Verify both replicas have updated config
containers = npm_containers()
for container in containers:
    check(f"nginx config present after edit on {container.split('.')[1][:6]}",
          nginx_config_exists(container, TEST_DOMAIN))

# Verify PATCH on non-existent domain returns 404
status, data = linkr("PATCH", "/api/fqdns/doesnotexist.dragonfang.net", {"forward_port": 80})
check("PATCH non-existent domain returns 404", status == 404, str(data))

# Verify bad port rejected
status, data = linkr("PATCH", f"/api/fqdns/{TEST_DOMAIN}", {"forward_port": 0})
check("PATCH bad port rejected", status == 400, str(data))

# ─────────────────────────────────────────────
section("11. Delete FQDN")
# ─────────────────────────────────────────────

status, data = linkr("DELETE", f"/api/fqdns/{TEST_DOMAIN}")
check("Linkr DELETE returns 200", status == 200, str(data))

time.sleep(5)

# Verify NPM
if npm_tok:
    hosts = npm_proxy_hosts(npm_tok)
    npm_match = next((h for h in hosts if TEST_DOMAIN in h.get("domain_names", [])), None)
    check("NPM proxy host removed", npm_match is None)

# Verify Pi-hole
hosts_list = pihole_dns_hosts()
check("Pi-hole DNS entry removed", dns_entry not in hosts_list)

# Verify nginx configs gone from both replicas
containers = npm_containers()
for container in containers:
    check(f"nginx config removed from {container.split('.')[1][:6]}",
          not nginx_config_exists(container, TEST_DOMAIN))

# ─────────────────────────────────────────────
section("12. Delete non-existent domain (graceful)")
# ─────────────────────────────────────────────

status, data = linkr("DELETE", f"/api/fqdns/{TEST_DOMAIN}")
check("Deleting non-existent domain returns 200 (idempotent)", status == 200, str(data))

# ─────────────────────────────────────────────
section("Results")
# ─────────────────────────────────────────────

passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
total  = len(results)

print(f"\n  {passed}/{total} passed", end="")
if failed:
    print(f"  ({failed} FAILED):")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")
else:
    print("  — all good")


sys.exit(0 if failed == 0 else 1)
