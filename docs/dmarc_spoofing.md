# DMARC & Email Spoofing

## Summary

Email spoofing is the forging of the `From:` header in an email to make it appear sent from a domain the attacker does not control. DMARC (Domain-based Message Authentication, Reporting, and Conformance) is the primary control that prevents spoofed mail from being delivered. When DMARC is missing or configured with a permissive policy, spoofed mail reaches the inbox.

## How Spoofing Works

SMTP has no built-in authentication for the `From:` header. Any mail client or tool can set `From: ceo@target.com` regardless of where the mail actually originates. Without DMARC enforcement, receiving mail servers have no instruction to reject or quarantine this mail.

DMARC works by:
1. Publishing a DNS TXT record at `_dmarc.domain.com` specifying a policy
2. Tying that policy to SPF (authorized sending IPs) and DKIM (cryptographic signature)
3. Instructing receiving servers what to do when neither SPF nor DKIM pass for the `From:` domain

## Policy Values

| Policy | Effect | Spoofable? |
|---|---|---|
| `p=reject` | Receiving server must discard spoofed mail | No |
| `p=quarantine` | Spoofed mail delivered to spam/junk folder | Partially — reaches the server |
| `p=none` | No action taken — monitoring only | Yes — delivered to inbox |
| Missing record | No instruction — receiving server decides | Yes — typically delivered |

## Subdomain Inheritance

If a subdomain (`mail.domain.com`) has no DMARC record, the receiving server looks at the organizational domain (`domain.com`) DMARC record and applies the `sp=` (subdomain policy) tag if present:

- `sp=reject` — subdomains are protected even without their own record
- `sp=none` or absent — subdomains fall back to the org `p=` value
- No org DMARC at all — subdomain is fully spoofable

Large organizations often lock down their primary domain but leave acquired or legacy subdomains unprotected.

## What Spoofit Tests

For each domain:
1. Checks for a `_dmarc` TXT record
2. Parses the `p=` tag
3. For subdomains with no direct record, checks the org domain `sp=` tag
4. Reports policy, spoofability, and risk level

Risk levels:
- **CRITICAL** — EOP direct-send open (see [eop_direct_send.md](eop_direct_send.md))
- **HIGH** — `p=none` or missing DMARC, spoofed mail lands in inbox
- **MEDIUM** — `p=quarantine`, spoofed mail lands in spam
- **PROTECTED** — `p=reject` enforced

## Remediation

1. Publish a DMARC record at `_dmarc.domain.com` with at minimum `p=quarantine`.
2. Move to `p=reject` once SPF and DKIM are confirmed working for all legitimate mail flows.
3. Set `sp=reject` to protect subdomains: `v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@domain.com`
4. Publish DMARC records for every subdomain that sends mail, rather than relying on inheritance.
5. Use the `rua=` tag to receive aggregate reports — these show what mail is failing authentication and from where.

## Notes

- DMARC only governs the `From:` header visible to the recipient. The SMTP envelope sender (`MAIL FROM`) is separate and governed by SPF alone.
- `p=reject` does not prevent all spoofing techniques — display name spoofing (`"CEO Name" <attacker@external.com>`) bypasses DMARC entirely since the From domain is legitimate.
- A domain with `p=reject` but an open EOP direct-send endpoint is still a significant finding — mail delivered through EOP bypasses third-party gateway filtering regardless of DMARC outcome.
