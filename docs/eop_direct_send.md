# EOP Direct Send

## Summary

Microsoft Exchange Online (O365/M365) tenants have a persistent SMTP endpoint at:

```
<domain>-<tld>.mail.protection.outlook.com
```

**Example:** `contoso.com` → `contoso-com.mail.protection.outlook.com`

This endpoint accepts direct SMTP connections from the internet. If an organization routes their primary MX through a third-party email security gateway (Proofpoint, Mimecast, Barracuda, Cisco ESA, etc.) but does **not** configure that gateway as a required inbound path on the EOP side, an attacker can bypass the gateway entirely by delivering mail directly to the EOP endpoint.

This is distinct from [open relay](open_relay.md) — the attacker is not using the target's server to forward mail outbound. They are connecting to the target's *inbound* receiver directly, as the sender, and the receiver accepts the connection when it should not.

## Attack Path

```
Normal flow:
  Attacker → [Proofpoint/Mimecast MX] → Exchange Online → Recipient
                      ↑
          Gateway scans, sandboxes, filters here

Bypass flow:
  Attacker → [domain-com.mail.protection.outlook.com:25] → Exchange Online → Recipient
                                ↑
                  Proofpoint/Mimecast never sees this mail
```

## Why It Works

Exchange Online's EOP endpoint is always reachable from the internet by default. Microsoft requires customers to explicitly configure "Enhanced Filtering for Connectors" and/or IP allowlisting to enforce inbound mail flow through the security gateway. Many organizations configure their DNS MX to point to the gateway but never complete the EOP-side enforcement, leaving the direct path open.

## Probe Results

Spoofit probes the endpoint with a full SMTP handshake (no DATA — no mail is sent):

```
EHLO probe
MAIL FROM:<probe@domain.com>  → 250 OK?
RCPT TO:<probe@domain.com>    → 250 OK?
```

Three possible outcomes:

**OPEN** — Both MAIL FROM and RCPT TO return 250. The endpoint is immediately exploitable from any IP.

**LIKELY OPEN** — MAIL FROM returns 250 (no connector restriction), but RCPT TO is rejected due to the probing IP being on a reputation blocklist (Spamhaus, Barracuda, etc.). The EOP endpoint has no configuration preventing direct delivery — the block is purely IP reputation and does not apply to a clean sending IP. Any attacker with a non-listed IP (a fresh VPS, for example) can deliver directly. The vulnerability is present; this probe environment is what prevented the full 250.

**Closed** — MAIL FROM is rejected at the connector or relay level. EOP is configured to require mail to arrive from authorized sources.

The indicator of misconfiguration is **MAIL FROM returning 250**. A properly restricted EOP connector rejects the envelope before RCPT TO is reached.

## Impact

- All mail delivered via direct send bypasses the third-party gateway entirely — no sandboxing, no URL rewriting, no anti-phishing analysis
- The organization's investment in Proofpoint/Mimecast provides no protection for this delivery path
- Combined with weak or missing DMARC, the sender address can be fully spoofed (see [dmarc_spoofing.md](dmarc_spoofing.md))
- Even with `p=reject` DMARC, mail from attacker-controlled domains can be delivered unscanned directly to inboxes

## Multi-Domain Note

Each accepted domain in the tenant has its own EOP endpoint. The connector restriction must be applied per domain — a restriction on `contoso.com` does not automatically apply to `contoso-professionals.com` or `contoso-onmicrosoft-com.mail.protection.outlook.com`.

Spoofit checks every domain discovered via azmap.dev tenant expansion, so all endpoints in the tenant are covered in a single scan.

## Remediation

1. In Exchange Admin Center → Mail Flow → Connectors, create an inbound connector requiring mail to arrive from the gateway's IP range.
2. Enable "Enhanced Filtering for Connectors" so EOP respects the gateway's spam/malware verdicts.
3. Apply the connector restriction to every accepted domain in the tenant — not just the primary.
4. Verify the `.onmicrosoft.com` domain endpoint is also restricted — it has its own EOP hostname.
5. After configuring, re-test: `telnet domain-com.mail.protection.outlook.com 25` and attempt MAIL FROM. A properly configured connector will reject at that step.

## References

- Microsoft Docs: [Configure a connector to route mail](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/set-up-connectors-to-route-mail)
- Microsoft Docs: [Enhanced Filtering for Connectors](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/enhanced-filtering-for-connectors)
