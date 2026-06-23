# Spoofit
Spoofit is designed to send spoofed emails for security testing. The tool takes advantage of situations where a domain's DMARC policy is not set to "reject," allowing spoofed emails to be sent using Microsoft's "direct send" with a higher likelihood of bypassing spam filters and reaching the target's inbox.

## Update 10/3/2025
Unauthenticated enumeration of Microsoft tenants is essentially broken -- breaking the portion of this tool that would enumerate domains in a target tenant. The tool has been modified to take a list of domains with the `-t` flag. To obtain a list of domains in the target tenant, use one of the following:
- https://micahvandeusen.com/tools/tenant-domains/
- https://osint.aadinternals.com/
___

## Usage

```
python3 Spoofit.py

   _____                   _____ __
  / ___/____  ____  ____  / __(_) /_
  \__ \/ __ \/ __ \/ __ \/ /_/ / __/
 ___/ / /_/ / /_/ / /_/ / __/ / /_
/____/ .___/\____/\____/_/ /_/\__/
    /_/

usage: Spoofit.py [-h] [-t TARGET] [-o OUTPUT] [-s SENDER] [-r RECIPIENTS] [-f RESPONDER_IP]

options:
  -h, --help            show this help message and exit
  -t, --target TARGET   Target domain or file containing list of domains to check.
  -o, --output OUTPUT   Output CSV filename (optional, auto-generated if not specified).
  -s, --sender SENDER   Spoofed sender email.
  -r, --recipients RECIPIENTS
                        Recipient email or file containing list of recipient emails.
  -f, --forced RESPONDER_IP
                        Forced authentication with responder-ip.

Examples:

  1) Check single domain:
     Spoofit.py -t domain.com

  2) Check multiple domains from file:
     Spoofit.py -t domains.txt -o results.csv

  3) Send a spoofed email (single recipient):
     Spoofit.py -s sender@domain.com -r recipient@domain.com

  4) Send a spoofed email (multiple recipients from file):
     Spoofit.py -s sender@domain.com -r recipients.txt

  5) Forced authentication:
     Spoofit.py -s sender@domain.com -r recipient@domain.com -f responder-ip
```
___

## What It Checks

When running `-t`, Spoofit evaluates each domain for:

- **DMARC policy** — `p=reject` (protected), `p=quarantine` (partial), `p=none` / missing (spoofable)
- **Subdomain policy** — checks `sp=` tag on the org domain when a subdomain has no direct DMARC record
- **MX record existence** — domains with no MX cannot receive mail and are skipped
- **O365/Exchange Online detection** — identified via MX record or SPF `include:spf.protection.outlook.com`
- **EOP direct-send probe** — when O365 is detected, Spoofit checks `domain-com.mail.protection.outlook.com` directly to see if mail can be delivered to that endpoint, bypassing a third-party gateway (Proofpoint, Mimecast, etc.) that may be the primary MX
- **OnMicrosoft.com DMARC** — attempts to discover and check the tenant's `.onmicrosoft.com` domain for spoofability

### EOP Direct Send

Even if an organization routes inbound mail through Proofpoint or Mimecast, the underlying Exchange Online endpoint (`domain-com.mail.protection.outlook.com`) may still accept direct connections from the internet. If it does, the gateway is effectively bypassed. Spoofit probes this with a standard SMTP handshake (EHLO + MAIL FROM + RCPT TO) without sending DATA.

> Note: The probe requires outbound port 25. Run from a VPS or pentest infrastructure, not a standard ISP connection. EOP may also accept the transaction but silently quarantine — confirm with a live send during the engagement.

___

## Configuration
Edit `conf/spoofit.conf` to customize the subject and body of emails. The forced authentication email template is in `conf/forced_auth_template.html`.

___

## Output

Results are printed to the terminal with color coding and written to a CSV. The CSV includes:

| Column | Description |
|---|---|
| Domain | Target domain |
| DMARC Policy | Raw policy finding |
| Spoofing Possible | Yes / No / Maybe / Doubtful |
| O365 Detected | Whether Exchange Online was identified |
| EOP Host | The EOP direct-send hostname checked |
| EOP Direct Send | Open / Closed / N/A |
| EOP Notes | SMTP response detail |
| OnMicrosoft Domain | Discovered `.onmicrosoft.com` domain, if any |
