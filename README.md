# Spoofit
SpoofIt is designed to send spoofed emails for security testing. The tool intends to take advantage of situations where a domain's DMARC policy is not set to "reject," allowing spoofed emails to be sent using Microsoft's "direct send" with a higher likelihood of bypassing spam filters and reaching the target's inbox.
___
## Usage

```
python3 Spoofit.py

   _____                   _____ __ 
  / ___/____  ____  ____  / __(_) /_
  \__ \/ __ \/ __ \/ __ \/ /_/ / __/
 ___/ / /_/ / /_/ / /_/ / __/ / /_  
/____/ .___/\____/\____/_/ /_/\__/  
    /_/                             
   
usage: Spoofit.py [-h] [-t TARGET] [-o OUTPUT] [-s SENDER] [-r RECIPIENTS] [-f RESPONDER_IP]

DMARC-Focused Email Spoofing Tool.

options:
  -h, --help            show this help message and exit
  -t, --target TARGET   Target domain or file containing list of domains to check.
  -o, --output OUTPUT   Output CSV filename (optional, auto-generated if not specified).
  -s, --sender SENDER   Spoofed sender email.
  -r, --recipients RECIPIENTS
                        Recipient email or file containing list of recipient emails.
  -f, --forced RESPONDER_IP
                        Forced authentication with responder-ip.

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
```
___

## Configuration
Edit the spoofit.conf file in the conf directory to customize the subject and body of the emails. The forced authentication email template is stored separately in forced_auth_template.html within the same directory.

___
