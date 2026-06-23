# Spoofit Roadmap

## Current State (v1.2)

### Checks
- DMARC policy evaluation (`p=reject`, `p=quarantine`, `p=none`, missing)
- Subdomain policy inheritance (`sp=` tag logic)
- MX record existence check (no MX = not a mail-receiving domain)
- **O365/Exchange Online detection** (MX + SPF indicators)
- **EOP direct-send probe** (`domain-com.mail.protection.outlook.com`) — always runs, detects gateway bypass even when Proofpoint/Mimecast is primary MX
- **OnMicrosoft.com discovery via azmap.dev** — `tenant_name` from azmap.dev API
- **Full tenant domain expansion via azmap.dev** — `related_domains` gives all tenant domains; auto-scanned when passing a single domain to `-t`

### Send Capabilities
- Direct-to-MX spoofed email delivery
- Forced authentication email (SMB/responder capture via `file://` UNC path)
- Bulk send from recipient file
- RFC 5322 headers (`Date`, `Message-ID`, `MIME-Version`) to reduce spam scoring
- **Interactive compose from terminal** — post-scan menu presents discovered EOP endpoints as routing options

### UI
- **Interactive menu** (no-args launch): domain check, send, forced auth
- **Post-scan menu**: send test email, export CSV, new scan
- Per-domain results with risk label (CRITICAL / HIGH / MEDIUM / PROTECTED / N/A)
- Summary table with correct ANSI-aware column alignment
- Critical findings callout block
- CSV export with full findings

---

## Planned

### v1.2 — Extended Protocol Analysis
- [ ] **SPF deep analysis**: detect `+all` (open relay), missing SPF, `~all` vs `-all` distinction, `?all`
- [ ] **DKIM record check**: confirm DKIM selectors exist (`selector1/selector2._domainkey`), flag missing DKIM as a finding
- [ ] **MTA-STS policy check**: detect domains enforcing MTA-STS (RFC 8461) which prevents STARTTLS stripping
- [ ] **BIMI record check**: presence/absence of `default._bimi` (informational, indicates brand protection investment)
- [ ] **Multi-MX probe**: test all MX priority levels, not just lowest — backup MX servers are often less hardened

### v1.3 — Enhanced Send Capabilities
- [ ] **MIME multipart support**: send both `text/plain` and `text/html` parts — missing plaintext part is a spam signal
- [ ] **Reply-To header manipulation**: route replies to attacker-controlled address
- [ ] **Display name spoofing**: `"CEO Name" <attacker@external.com>` format testing
- [ ] **Custom header injection**: allow arbitrary headers (e.g., `X-Originating-IP`, `X-Mailer`) via config
- [ ] **Attachment support**: send with file attachment for credential harvest or macro delivery
- [ ] **STARTTLS support**: some servers reject unencrypted SMTP connections

### v1.4 — Tenant & Infrastructure Enumeration
- [x] **onmicrosoft.com discovery via azmap.dev**: `GET /api/tenant?domain=X` returns `tenant_name` directly; replaces broken Microsoft API methods
- [x] **Full tenant domain sweep via azmap.dev**: `related_domains` lists every domain in the tenant — passing one domain to `-t` or the interactive menu auto-discovers and checks all
- [ ] **Generic SMTP relay test**: beyond EOP — test any discovered SMTP server for open relay (`RCPT TO:<external>` from external sender)
- [ ] **Email gateway fingerprinting**: detect Proofpoint, Mimecast, Barracuda, Cisco IronPort by MX hostname pattern, banner, or headers

### v1.5 — Output & Integration
- [ ] **JSON output format**: machine-readable output for integration with reporting pipelines
- [ ] **Verbose mode** (`-v`): show raw DNS records, SMTP banners, full DMARC record strings
- [ ] **Rate limiting** (`--delay N`): configurable delay between sends to reduce detection likelihood
- [ ] **Markdown/HTML report**: single-file report suitable for pasting into pentest reports

### Long-term / Research
- [ ] **DMARC alignment bypass techniques**: test edge cases — `From:` header with multiple addresses, internationalized domain names (IDN homographs), whitespace tricks
- [ ] **SPF `+all` exploit path**: if target has `+all` or is reachable from a permitted IP range, demonstrate relay from that range
- [ ] **Internal relay via onmicrosoft.com**: if tenant relay is misconfigured, test whether mail sent to `tenant.onmicrosoft.com` SMTP accepts spoofed From headers that appear internal, bypassing DMARC alignment for the tenant's primary domain
- [ ] **ARC (Authenticated Received Chain) analysis**: determine whether intermediate forwarders break DMARC and whether ARC sealing is present
- [ ] **Catch-all address detection**: identify if target domain accepts mail for any recipient (useful for payload delivery and enumeration)

---

## Known Issues / Limitations

- **OnMicrosoft.com auto-discovery is unreliable**: the tenant name doesn't always match the primary domain label. Use [aadinternals.com](https://aadinternals.com) or [osint.aadinternals.com](https://osint.aadinternals.com) for manual enumeration.
- **Unauthenticated tenant domain enumeration is largely broken**: Microsoft disabled the public APIs. See README for current workarounds.
- **EOP probe requires outbound port 25**: many ISPs and cloud providers block outbound port 25. Run from a VPS or pentest infrastructure that has port 25 open.
- **EOP may silently accept then blackhole**: some EOP configurations accept the SMTP transaction (250 OK) but silently discard or quarantine without delivery. A successful probe does not guarantee inbox delivery — confirm with a live send during the engagement.
