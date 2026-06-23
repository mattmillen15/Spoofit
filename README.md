# Spoofit

Spoofit is an email spoofability assessment tool for authorized penetration testing. It evaluates DMARC posture, probes Exchange Online's EOP direct-send endpoint for gateway bypass, tests all MX servers for open relay, enumerates full Microsoft tenant scope via [azmap.dev](https://azmap.dev), and lets you compose and deliver test emails directly from the terminal.

---

## Usage

```
python3 Spoofit.py
```

No arguments launches the interactive menu. CLI flags are available for scripted or automated use.

```
usage: Spoofit.py [-h] [-t TARGET] [-o OUTPUT] [-s SENDER] [-r RECIPIENTS] [-f RESPONDER_IP] [--no-expand]

options:
  -h, --help              show this help message and exit
  -t, --target TARGET     Domain or file of domains to check.
  -o, --output OUTPUT     Output CSV filename.
  -s, --sender SENDER     Spoofed sender email.
  -r, --recipients RECIP  Recipient email or file.
  -f, --forced RESP_IP    Forced auth — responder IP.
  --no-expand             Skip tenant domain expansion via azmap.dev.

Examples:
  Spoofit.py                                          # interactive menu
  Spoofit.py -t domain.com                            # check domain + all tenant domains
  Spoofit.py -t domain.com --no-expand                # check that domain only
  Spoofit.py -t domains.txt                           # check from file
  Spoofit.py -s from@domain.com -r to@domain.com      # send spoofed email
  Spoofit.py -s from@domain.com -r to@domain.com -f 10.0.0.1   # forced auth
```

---

## What It Checks

### DMARC
Evaluates `p=reject`, `p=quarantine`, `p=none`, missing record, and subdomain `sp=` tag inheritance. Domains with no MX record are skipped.

### EOP Direct Send
Probes `domain-com.mail.protection.outlook.com` with a full SMTP handshake (EHLO + MAIL FROM + RCPT TO, no DATA) to test whether Exchange Online accepts direct inbound connections, bypassing any third-party gateway (Proofpoint, Mimecast, etc.) that may be the primary MX.

Three result states:
- **OPEN** — MAIL FROM and RCPT TO both accepted. Immediately exploitable.
- **LIKELY OPEN** — MAIL FROM accepted (no connector restriction); RCPT TO rejected only due to sending IP reputation (Spamhaus/Barracuda/etc.). Any clean sending IP bypasses this. The vulnerability is present — the block is not a configuration control.
- **Closed** — MAIL FROM rejected at the connector or relay level. Properly restricted.

### Open Relay
Probes every MX record for the domain (all priority levels) with an external-to-external SMTP envelope (`MAIL FROM:<probe@spoofit.invalid>` → `RCPT TO:<probe@relay-test.invalid>`). If accepted, the server will relay mail to arbitrary recipients for anyone on the internet. Backup MX servers (higher preference number) are checked — they are often less hardened than the primary.

### Tenant Domain Expansion
Passing a single domain to `-t` or the interactive menu queries azmap.dev for the full list of domains in the Microsoft tenant. All discovered domains are offered for scanning automatically. Use `--no-expand` or a domains file to skip this.

---

## Infrastructure Note

The EOP probe and open relay checks require outbound port 25. Run from a VPS or dedicated pentest infrastructure — most ISPs and many cloud providers block outbound port 25 by default. The EOP probe uses `.invalid` TLD addresses so no actual mail is generated even if the server accepts the envelope.

---

## Interactive Menu

Launching with no arguments:

```
  [1]  Check domain / tenant
  [2]  Send spoofed email
  [3]  Forced authentication
  [q]  Quit
```

After a scan, the post-scan menu offers:

```
  [1]  Send test email     (lists discovered EOP endpoints as routing options)
  [2]  Export results to CSV
  [3]  New scan
  [m]  Main menu
```

---

## Configuration

Edit `conf/spoofit.conf` for default email subject and body. The forced authentication template is at `conf/forced_auth_template.html` — set the responder IP at runtime with `-f`.

---

## Output

Results are printed to the terminal with risk-based color coding (RED = exploitable, GREEN = protected) and written to CSV.

| Column | Description |
|---|---|
| Domain | Target domain |
| DMARC Policy | Raw policy finding |
| Spoofable | Yes / No |
| Risk | CRITICAL / HIGH / MEDIUM / PROTECTED / N/A |
| O365 | Whether Exchange Online was identified |
| EOP Host | EOP direct-send hostname checked |
| EOP Direct Send | Open / Likely Open / Closed / N/A |
| EOP Notes | SMTP response detail |
| OnMicrosoft Domain | Tenant `.onmicrosoft.com` domain |
| MX Open Relay | Open count / total MX checked (e.g. `1/3`) |
| Relay Detail | Hostname and IP of any open relay servers |
