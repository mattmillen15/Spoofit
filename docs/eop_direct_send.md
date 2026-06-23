# EOP Direct Send Vulnerability

## Summary

Microsoft Exchange Online (O365/M365) tenants have a persistent SMTP endpoint at:

```
<domain>-<tld>.mail.protection.outlook.com
```

**Example:** `contoso.com` → `contoso-com.mail.protection.outlook.com`

This endpoint accepts direct SMTP connections from the internet. If an organization routes their primary MX through a third-party email security gateway (Proofpoint, Mimecast, Barracuda, Cisco ESA, etc.) but does **not** configure that gateway as a required inbound path on the EOP side, an attacker can bypass the gateway entirely by sending directly to the EOP endpoint.

## Attack Path

```
Normal flow:
  Attacker → [Proofpoint/Mimecast MX] → Exchange Online → Recipient

Bypass flow:
  Attacker → [domain-com.mail.protection.outlook.com:25] → Exchange Online → Recipient
                        ↑
              Proofpoint/Mimecast never sees this mail
```

## Why It Works

Exchange Online's EOP endpoint is always reachable from the internet by default. Microsoft requires customers to explicitly configure "Enhanced Filtering for Connectors" and/or IP allowlisting to enforce inbound mail flow through the security gateway. Many organizations configure their DNS MX to point to the gateway but never complete the EOP-side enforcement, leaving the direct path open.

## Detection

Check whether `domain-com.mail.protection.outlook.com` resolves and accepts:

```
EHLO probe
MAIL FROM:<spoof@domain.com>  → 250 OK
RCPT TO:<target@domain.com>   → 250 OK   ← vulnerable
```

Spoofit performs this probe automatically when Exchange Online is detected for a target domain.

## Remediation (for defenders)

1. In Exchange Admin Center → Mail Flow → Connectors, create an inbound connector that requires mail to arrive from the gateway's IP range.
2. Enable "Enhanced Filtering for Connectors" so EOP respects the gateway's spam/malware verdicts.
3. Consider enabling "Reject messages that don't pass inbound MX check" if your gateway supports it.
4. Audit all accepted domains in EOP and ensure each has the appropriate connector restriction.
5. Check **all** domains in the tenant (including sub-domains and secondary domains) — the vulnerability is per-domain, not per-tenant.

## Multi-Domain Note

If a tenant has multiple accepted domains (e.g., `contoso.com`, `contoso-professionals.com`), **each** has its own EOP endpoint:

- `contoso-com.mail.protection.outlook.com`
- `contoso-professionals-com.mail.protection.outlook.com`

Each must be checked independently — the connector restriction must be applied for every domain.

## OnMicrosoft Domain Relay

The tenant's `.onmicrosoft.com` domain (`tenant.onmicrosoft.com`) also has an EOP endpoint:

```
tenant-onmicrosoft-com.mail.protection.outlook.com
```

If this domain's DMARC is missing or `p=none`, and the tenant allows relay from it, an attacker may be able to send mail that passes through Exchange Online infrastructure and appears to originate internally, potentially passing DMARC alignment checks for the `.onmicrosoft.com` domain while spoofing display-name attributes of internal users.

## References

- Microsoft Docs: [Configure a connector to route mail to an on-premises environment](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/set-up-connectors-to-route-mail)
- Microsoft Docs: [Enhanced Filtering for Connectors in Exchange Online](https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/enhanced-filtering-for-connectors)
