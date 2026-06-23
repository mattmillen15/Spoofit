# Spoofit Roadmap

## Current State (v1.3)

### Checks
- DMARC policy evaluation (`p=reject`, `p=quarantine`, `p=none`, missing)
- Subdomain policy inheritance (`sp=` tag logic)
- MX record existence check (no MX = not a mail-receiving domain)
- O365/Exchange Online detection (MX + SPF indicators)
- **EOP direct-send probe** — always runs regardless of O365 detection; three result states: Open / Likely Open (IP reputation block only) / Closed
- **IP reputation awareness** — distinguishes Spamhaus/Barracuda/SORBS RCPT TO rejections from actual connector-level blocks; MAIL FROM acceptance is the true indicator of vulnerability
- **Open relay check across all MX records** — probes every MX priority level with external-to-external envelope; backup MX servers often less hardened than primary
- **OnMicrosoft.com discovery via azmap.dev** — `tenant_name` from API response
- **Full tenant domain expansion via azmap.dev** — `related_domains` gives all tenant domains; auto-scanned when passing a single domain

### Send Capabilities
- Direct-to-MX spoofed email delivery
- Forced authentication email (SMB/responder capture via `file://` UNC path)
- Bulk send from recipient file
- RFC 5322 headers (`Date`, `Message-ID`, `MIME-Version`) to reduce spam scoring
- Interactive compose from terminal — post-scan menu offers discovered EOP endpoints as routing options

### UI
- Interactive menu (no-args launch): domain check, send, forced auth
- Post-scan menu: send test email, export CSV, new scan
- Per-domain results with risk label (CRITICAL / HIGH / MEDIUM / PROTECTED / N/A)
- Notes shown for all EOP outcomes (open, likely, closed) for operator context
- Summary table with ANSI-aware column alignment — DMARC, RISK, EOP, RELAY columns
- Critical findings callout block with severity distinction
- CSV export with full findings including relay detail

---

## Planned

### v1.4 — Extended Protocol Analysis
- [ ] **SPF deep analysis**: detect `+all` (open relay), missing SPF, `~all` vs `-all` distinction, `?all`
- [ ] **DKIM record check**: confirm DKIM selectors exist (`selector1/selector2._domainkey`), flag missing DKIM
- [ ] **MTA-STS policy check**: detect domains enforcing MTA-STS (RFC 8461) which prevents STARTTLS stripping
- [ ] **BIMI record check**: presence/absence of `default._bimi` (informational)
- [ ] **Email gateway fingerprinting**: detect Proofpoint, Mimecast, Barracuda, Cisco IronPort by MX hostname pattern, banner, or headers

### v1.5 — Enhanced Send Capabilities
- [ ] **MIME multipart support**: send both `text/plain` and `text/html` parts — missing plaintext part is a spam signal
- [ ] **Reply-To header manipulation**: route replies to attacker-controlled address
- [ ] **Display name spoofing**: `"CEO Name" <attacker@external.com>` format testing
- [ ] **Custom header injection**: allow arbitrary headers (e.g., `X-Originating-IP`, `X-Mailer`) via config
- [ ] **Attachment support**: send with file attachment for credential harvest or macro delivery
- [ ] **STARTTLS support**: some servers reject unencrypted SMTP connections

### v1.6 — Output & Integration
- [ ] **JSON output format**: machine-readable output for integration with reporting pipelines
- [ ] **Verbose mode** (`-v`): show raw DNS records, SMTP banners, full DMARC record strings
- [ ] **Rate limiting** (`--delay N`): configurable delay between domain checks
- [ ] **Markdown/HTML report**: single-file report suitable for pasting into pentest reports

### Long-term / Research
- [ ] **DMARC alignment bypass techniques**: `From:` header edge cases, IDN homographs, whitespace tricks
- [ ] **SPF `+all` exploit path**: demonstrate relay from a permitted IP range
- [ ] **Internal relay via onmicrosoft.com**: test whether misconfigured tenant relay allows spoofed From headers that appear internal
- [ ] **ARC (Authenticated Received Chain) analysis**: determine whether forwarders break DMARC and whether ARC sealing is present
- [ ] **Catch-all address detection**: identify if target domain accepts mail for any recipient

---

## Known Issues / Limitations

- **EOP probe requires outbound port 25**: many ISPs and cloud providers block outbound port 25. Run from a VPS or pentest infrastructure.
- **EOP likely-open vs confirmed-open**: when a sending IP is on a reputation blocklist, RCPT TO is rejected before delivery is attempted. The MAIL FROM 250 response confirms no connector-level restriction exists — verify with a live send from a clean IP.
- **EOP may silently accept then blackhole**: some EOP configurations accept the SMTP transaction (250 OK) but silently discard or quarantine without delivery. A successful probe does not guarantee inbox delivery — confirm with a live send during the engagement.
- **azmap.dev coverage**: not all Microsoft tenants are indexed. Domains not found fall back to single-domain scan.
