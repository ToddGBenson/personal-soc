# Remediation library

Reusable, correct remediation blocks keyed by finding type. Use these in Phase 5–6 so wording stays consistent and defensible across engagements. Adjust device-specific UI names to the actual gear.

---

### NFS export to `*` (unauthenticated read/write)
**Severity:** Critical (CIS 03). **Impact:** any host on the segment can read/modify/delete the data — including backups.
**Fix:** Disable NFS in the NAS UI if unused (SMB usually covers home needs). If required, bind each export to specific host IPs and drop shared/public exports to read-only. Verify `no_root_squash` is off. Re-scan `nfs-showmount` to confirm `*` is gone.

### SMBv1 enabled / signing not required
**Severity:** Critical–High (CIS 04). **Impact:** EternalBlue-class protocol; relay/downgrade if signing optional.
**Fix:** Disable SMBv1 on the NAS and all clients. Require SMB signing. Enforce per-user authentication on shares; remove guest/anonymous access. Confirm with `nmap --script smb-protocols,smb2-security-mode`.

### Backups on a network-writable share
**Severity:** Critical (CIS 11). **Impact:** ransomware or a rogue device encrypts data and the only backup together.
**Fix:** Implement 3-2-1 — 3 copies, 2 media, 1 off-site/offline. At least one copy must be **offline or immutable** (rotated external drive kept disconnected, or cloud storage with object-lock/versioning). Recovery data must not be writable from the network it protects. Test a restore.

### Flat network / no segmentation
**Severity:** High (CIS 06). **Impact:** any foothold is instantly lateral-movement-ready.
**Fix:** Introduce VLANs behind a real firewall with default-deny between zones: Trusted (PC/phones), IoT (egress-limited, no path to Trusted/Servers), Servers/NAS (reachable only from Trusted, authenticated), Guest (internet-only), and an isolated Lab if doing security work. Move IoT to its own SSID→VLAN.

### End-of-life ISP gateway as sole infrastructure
**Severity:** High (CIS 12). **Impact:** unpatchable device is router+firewall+DNS+AP single point; old kernel.
**Fix:** Put the ISP gateway in bridge/passthrough (modem only) and add a supported firewall/router — OPNsense on a mini-PC (most control), or UniFi Gateway / Firewalla (least effort). This also enables VLANs (CIS 06) and IDS (CIS 13) in one move.

### UPnP IGD enabled
**Severity:** Medium (CIS 04). **Impact:** any LAN device can open WAN firewall ports with no authentication.
**Fix:** Disable UPnP on the gateway; forward ports manually only where needed. Audit the current port-map table. Note: some gateways don't expose the map cleanly — record as inconclusive if unreadable, and disable UPnP regardless.

### WPA3 transition mode
**Severity:** High–Medium (CIS 04). **Impact:** attacker forces the WPA2/PSK path, losing SAE protection against offline cracking and deauth.
**Fix:** Set trusted SSIDs to WPA3-only once no WPA2-only client needs them. Keep a separate WPA2 IoT SSID (mapped to the IoT VLAN) for legacy gadgets so the trusted network can go WPA3-only.

### Open Wi-Fi SSID broadcasting in-home
**Severity:** Critical–High (CIS 04). **Impact:** unauthenticated wireless entry point; sign of a device stuck in setup mode.
**Fix:** Identify the broadcasting device (correlate signal/OUI), complete or secure its onboarding, and remove any saved open profile from clients.

### No monitoring / visibility
**Severity:** High (CIS 13). **Impact:** intrusions leave no detectable or reconstructable trace.
**Fix (right-sized):** Enable Suricata/Zeek IDS **inside** the new firewall (OPNsense/UniFi) and centralize its logs — ~80% of the value for ~10% of the effort. **Security Onion** (full NSM: Suricata+Zeek+ELK) only when the user will *actively tune and watch it* and has a dedicated host + SPAN/tap; an unwatched sensor is theater. Graduate to it when doing real NSM/threat-hunting, not before.

### Excess services on the NAS (SSH, GoodSync, cloud, rpcbind)
**Severity:** Medium (CIS 04). **Impact:** each open service is attack surface you aren't using.
**Fix:** Disable SSH, GoodSync/sync servers, and cloud/remote access unless actively used. Keep only SMB (authenticated) for a home file server. Re-scan to confirm the ports closed.

### ISP remote-management agent
**Severity:** Medium (CIS 15). **Impact:** provider access to the gateway you don't control or monitor.
**Fix:** Not directly removable while using the ISP gateway; bridging it (see EOL-gateway fix) removes the agent from your trust path. Otherwise document it as accepted third-party risk.

### Kali / offensive tooling
It's a toolbox, not infrastructure — it secures nothing. Run as a disposable, snapshotted VM on the **isolated Lab VLAN only**, never on the home LAN, never aimed at production devices except as a scoped, authorized exercise.

### CI/CD for a solo/small builder
For **network config**: infrastructure-as-code — config in git, reviewed, reversible. Not four environments.
For **software**: right-size to dev → CI (build+test) → one staging that mirrors prod → prod. Because it's *security* tooling, add SAST + dependency/CVE scanning + secret scanning as CI gates. Move source and build artifacts off any unsecured NAS into a proper git remote + artifact store.
