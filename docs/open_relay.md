# Open Relay

## Summary

An open relay is a mail server that accepts and forwards email on behalf of any sender to any recipient, without requiring authentication. Anyone on the internet can connect to the server, provide an arbitrary sender address, and have the mail forwarded to any destination.

## Why It Matters

**As an attacker**, an open relay lets you:
- Send mail from any forged address through the victim's own infrastructure
- Route phishing or spam through a trusted, reputable mail server — bypassing recipient-side spam filters that would block your own IP
- Obfuscate the true origin of an attack (mail headers show the relay, not you)

**For the organization running the relay**, the consequences include:
- Their mail server IP and domain get listed on Spamhaus, Barracuda, and other blocklists — breaking legitimate outbound mail
- Potential abuse at scale by spammers once the relay is discovered
- Reputational damage that can take weeks to remediate

Backup MX servers (higher preference number, lower priority) are the most common location for this finding. They are often legacy infrastructure, receive less operational attention, and may have been misconfigured or never properly hardened.

## Detection

Spoofit connects to each MX server and sends a two-step SMTP probe with fully external addresses:

```
EHLO probe
MAIL FROM:<probe@spoofit.invalid>   → 250 OK?
RCPT TO:<probe@relay-test.invalid>  → 250 OK?   ← vulnerable if accepted
```

`.invalid` is a reserved TLD that no mail server is legitimately responsible for. If a server accepts `RCPT TO` for a `.invalid` address, it will relay for any destination. No `DATA` command is sent — no actual mail is generated.

The key test is whether the server accepts a `RCPT TO` for a domain it has no responsibility for. Accepting `RCPT TO` for its own domain is normal inbound delivery — that is not an open relay.

## Remediation

1. Configure the MTA (Postfix, Sendmail, Exchange, etc.) to only accept `RCPT TO` for domains the server is authoritative for.
2. Require SMTP AUTH for any relay of outbound mail.
3. Apply the same restriction to all MX records at every priority level — not just the primary.
4. Review and harden backup/secondary MX servers — they are the most common location for this finding.
5. After remediation, check blocklist status: [Spamhaus](https://check.spamhaus.org), [MXToolbox Blacklist Check](https://mxtoolbox.com/blacklists.aspx).
