# External (WAN) exposure

Answers "what does the internet see of me?" — which a NAT'd internal scan cannot (self-scanning your public IP loops back to the LAN). Run via `scripts/Get-ExternalExposure.ps1`.

## How it works
Resolves your public IP (ipify/ifconfig.me), then queries **Shodan InternetDB** (`https://internetdb.shodan.io/{ip}` — free, no key) for the ports, CPEs, CVEs, hostnames, and tags Shodan last observed on that IP. Read-only, no active probing of the edge.

## Reading the result
- **404 / no ports** = good — nothing Shodan has indexed as externally open.
- **Open ports** = confirm each is intentional. Common findings:
  - **7547 (TR-069/CWMP)** — ISP remote-management of the gateway. Historically Mirai-targeted. You usually can't close it while using the ISP's gateway; **bridging the gateway** (see the EOL-gateway remediation) removes it from your trust path.
  - Any **forwarded service** you (or UPnP) opened — the highest-priority thing to review and close if unneeded.
- **Hostname** often reveals ISP + region (e.g. a PTR like `...<region>.<isp>.net` → ISP + metro) — normal, but note it's public.

## Accuracy caveats
- InternetDB reflects Shodan's **last scan**, not a live probe — it can be stale or miss a just-opened port.
- Residential IPs **rotate** (DHCP), so re-check; a finding may belong to a prior lease.
- For a definitive live external port test, use an **authorized outside vantage** (a VPS you control, or an online port-scanner you're permitted to use) against your current public IP.

## Feed it in
Record externally-visible ports as findings (CIS 12 Network Infrastructure / 04 Secure Config). A newly-appearing WAN port between runs is a **page-worthy** change (often a UPnP mapping or a forward you forgot).
