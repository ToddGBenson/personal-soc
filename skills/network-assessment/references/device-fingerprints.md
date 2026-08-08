# Device fingerprints — ports, banners, and OUI hints

Knowledgebase for Phases 1–3. Correlate **open ports + service banner + MAC OUI** to identify a device. No single signal is reliable alone (nmap's `-sV` guesses can be wrong — we saw a Resideo host mislabeled as IKEA Tradfri), so cross-check at least two.

## Port / service signatures

| Port(s) | Signature | Likely device |
|---------|-----------|---------------|
| `9999/tcp` "abyss" | TP-Link local protocol (unauth, static-XOR "encryption") | **Kasa** smart plug/switch |
| `8008/8009/8443/9000` | Chromecast / Cast | Google Cast, some smart TVs |
| `8009` tcpwrapped alone | Cast target | Chromecast / Cast-enabled TV |
| `7000` + `5000` rtsp, `49152-3` | AirTunes / AirPlay | Apple TV / AirPlay speaker |
| `7000` rtsp `AirTunes` | AirPlay receiver | HomePod / AppleTV / AV receiver |
| `1080` socks5 "no auth" + `_spotify-connect`/`_matter` | local cast/voice port (rejects external CONNECT) | **Amazon Echo** — benign, not an open proxy |
| `443` only, `ssl/https?` | minimal cloud-IoT endpoint | Echo / Ring / generic IoT |
| `80` IKEA Tradfri httpd | Zigbee gateway | IKEA Tradfri hub (verify OUI!) |
| `80/443` lighttpd 1.4.x | embedded web UI | **Resideo/Honeywell** thermostat |
| `22,80,111,139,445,2049,11000,49154` + `GstpServer` banner, `os-name-ver: NAS-WD` | WD My Cloud stack | **WD My Cloud NAS** (GoodSync on 11000) |
| `80/443` micro_httpd, UPnP `5431` (BRCM), `Linux 2.4`, board_id `C####A` | Actiontec/CenturyLink gateway | **ISP DSL gateway** (often EOL) |
| `5357` BaseHTTPServer / `7680` | WSD / Windows Delivery Optimization | Windows host |
| `49152-49157` unknown | UPnP/DLNA endpoints | Roku (`_rdlink`), media renderers |
| `8888` + tcpwrapped | local API | Echo / casting device |

## mDNS service types → device class

`_googlecast`,`_googlezone` → Chromecast · `_viziocast` → Vizio TV · `_spotify-connect` → Echo/speaker/PS · `_airplay`,`_raop` → Apple/AirPlay · `_matter`,`_matterd` → Matter/Thread device (often Echo hub) · `_rdlink` → Roku · `_companion-link`,`_sleep-proxy` → Apple · `_smb`,`_http` on the NAS · `_ssh`,`_sftp-ssh`,`_workstation` → a Linux host (Avahi default; Echoes advertise this too).

## Vendor OUI hints (first 3 octets)

| OUI prefix | Vendor | Usually |
|-----------|--------|---------|
| `70:F2:20` | Actiontec | ISP gateway |
| `00:14:EE` | Western Digital | NAS |
| `6C:0C:9A`,`90:A8:22`,`DC:A0:D0`,`2873F6`,`40A2DB`,`68DBF5`,`34D270`,`2824C9` | Amazon | Echo / Fire |
| `B0:A7:B9`,`10:27:F5`,`50:C7:BF`,`A4:2B:B0`,`98:25:4A`,`50:D4:F7`,`D8:07:B6`,`B4:B0:24`,`B0:BE:76` | TP-Link | Kasa plugs |
| `00:D0:2D`,`48:A2:E6` | Resideo | Honeywell thermostat |
| `A0:6A:44` | Vizio | smart TV |
| `A8:4A:63` | TPV | Philips/AOC display / TV |
| `2C:9E:00` | Sony Interactive | PlayStation |
| `AC:67:84` | Google | Chromecast/Nest |
| `C4:82:E1` | (Tuya/SmartLife range) | smart-home gadget |

**Randomized MACs:** if the second-least-significant bit of the first octet is set (`x2/x6/xA/xE` as the second hex digit), the MAC is locally administered — likely a phone or a privacy-randomizing device. Not in the OUI DB by design; identify by mDNS/behavior instead.

## Identification tips

- A device that ignores ICMP but appears in ARP/mDNS is still live — don't drop it.
- Count Kasa devices by `9999`-open hosts; Echoes by Amazon OUI + `_spotify-connect`/`_matter`.
- The NAS is the highest-value host on most home nets — fingerprint it fully and enumerate its shares first.
- Note the Wi-Fi AP: if SSID BSSIDs ≈ the router LAN MAC, the gateway is the AP.
