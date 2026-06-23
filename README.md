# Spoofit

Spoofit is an email spoofability assessment tool for authorized penetration testing. It identifies DMARC misconfigurations, probes Microsoft Exchange Online's EOP direct-send endpoint for gateway bypass, enumerates full tenant domain scope via [azmap.dev](https://azmap.dev), and lets you compose and deliver test emails directly from the terminal.

---

## Usage

```
python3 Spoofit.py
```

No arguments launches the interactive menu. CLI flags are available for scripted use.

```
usage: Spoofit.py [-h] [-t TARGET] [-o OUTPUT] [-s SENDER] [-r RECIPIENTS] [-f RESPONDER_IP] [--no-expand]

options:
  -h, --help              show this help message and exit
  -t, --target TARGET     Domain or file of domains to check.
  -o, --output OUTPUT     Output CSV filename.
  -s, --sender SENDER     Spoofed sender email.
  -r, --recipients RECIP  Recipient email or file.
  -f, --forced RESP_IP    Forced auth — responder IP.
  --no-expand             Do not auto-expand to all tenant domains via azmap.dev.

Examples:
  Spoofit.py                                          # interactive menu
  Spoofit.py -t domain.com                            # check domain + all tenant domains
  Spoofit.py -t domain.com --no-expand                # check that domain only
  Spoofit.py -t domains.txt                           # check domains from file
  Spoofit.py -s from@domain.com -r to@domain.com      # send spoofed email
  Spoofit.py -s from@domain.com -r to@domain.com -f 10.0.0.1   # forced auth
```

---

## What It Checks

When running a domain check, Spoofit:

- **DMARC** — evaluates `p=reject`, `p=quarantine`, `p=none`, missing, subdomain `sp=` inheritance
- **MX existence** — skips domains with no MX record
- **O365 detection** — detected via MX record or SPF `include:spf.protection.outlook.com`
- **EOP direct-send probe** — checks `domain-com.mail.protection.outlook.com` with SMTP handshake (EHLO + MAIL FROM + RCPT TO, no DATA) to detect gateway bypass
- **Tenant domain expansion** — queries azmap.dev for the full list of domains in the tenant, auto-scans all of them

### Tenant Expansion

Passing a single domain to `-t` or via the interactive menu will look up the Microsoft tenant via azmap.dev and offer to scan all associated domains. This gives complete coverage without manually enumerating tenant domains.

To skip expansion: `--no-expand`, or use a domains file with `-t domains.txt`.

### EOP Direct Send

Even when an organization routes inbound mail through Proofpoint or Mimecast, the Exchange Online endpoint (`domain-com.mail.protection.outlook.com`) may accept direct connections. If it does, the gateway is bypassed entirely. Spoofit probes this with a non-DATA SMTP handshake.

> Requires outbound port 25. Run from a VPS or pentest infrastructure, not a standard ISP connection. EOP may accept the transaction and silently quarantine — confirm with a live send during the engagement.

---

## Interactive Menu

Launching with no arguments enters the interactive menu:

```
  [1]  Check domain / tenant
  [2]  Send spoofed email
  [3]  Forced authentication
  [q]  Quit
```

After a scan, a post-scan menu offers:

```
  [1]  Send test email     (lists discovered EOP endpoints as routing options)
  [2]  Export results to CSV
  [3]  New scan
  [m]  Main menu
```

---

## Configuration

Edit `conf/spoofit.conf` for default email subjects and body text. The forced authentication template is at `conf/forced_auth_template.html`.

---

## Output

Results are printed to the terminal with risk-based color coding and written to CSV.

| Column | Description |
|---|---|
| Domain | Target domain |
| DMARC Policy | Raw policy finding |
| Spoofable | Yes / No |
| Risk | CRITICAL / HIGH / MEDIUM / PROTECTED / N/A |
| O365 | Whether Exchange Online was identified |
| EOP Host | The EOP direct-send hostname checked |
| EOP Direct Send | Open / Closed / N/A |
| EOP Notes | SMTP response detail |
| OnMicrosoft Domain | Tenant `.onmicrosoft.com` domain |
