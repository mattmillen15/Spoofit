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
   
Usage: Spoofit.py [-h] [-c CHECK] [-t] [-s SENDER] [-r RECIPIENTS] [-f FORCED] 

DMARC Focused Email Spoofing Tool

options:
  -h, --help            show this help message and exit
  -c CHECK, --check CHECK
                        Check spoofability for a domain.
  -t, --tenant          Checks spoofability for all domains in Microsoft tenant.
  -s SENDER, --sender SENDER
                        Spoofed sender email.
  -r RECIPIENTS, --recipients RECIPIENTS
                        Recipient email or file.
  -f FORCED, --forced FORCED
                        Forced auth email with Responder IP.

Examples:
  1) Check Spoofability of domain via missing DMARC records:
     Spoofit.py -c example.com

  2) Check Spoofability for all domains in Microsoft tenant (automatically saves CSV):
     Spoofit.py -c example.com -t

  3) Send spoofed email:
     Spoofit.py -s <sender@domain.com> -r <recipient@domain.com or file.txt>

  4) Forced-auth:
     Spoofit.py -s <sender@domain.com> -r <recipient@domain.com> -f <responder-ip>

```
___

## Configuration
Edit the spoofit.conf file in the conf directory to customize the subject and body of the emails. The forced authentication email template is stored separately in forced_auth_template.html within the same directory.

___
