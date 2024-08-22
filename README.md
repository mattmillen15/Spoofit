# Spoofit
SpoofIt is a Python tool designed to send spoofed emails for security testing. The tool intends to take advantage of situations where a domain's DMARC policy is not set to "reject," allowing spoofed emails to be sent using Microsoft's "direct send" with a higher likelihood of bypassing spam filters and reaching the target's inbox. SpoofIt is ideal for testing the resilience of email security by simulating phishing attacks or sending forced authentication emails, helping organizations identify and address vulnerabilities in their email defenses.
___
## Usage
1. Confirm that the DMARC records are not properly deployed. Ideally policy doesn't exist, or DMARC policy is set to "none". (Still may be possible with "Quarantine", but will surely land in spam.) My go to check is a python3 fork of Spoofcheck: https://github.com/a6avind/spoofcheck

2. Send email using spoofed sender address. (-s can be a single email address or a list of emails. -f is for forced authentication emails, where you'll need to supply your Responder IP as an argument. 
```zsh
python3 Spoofit.py --help                                                         

   _____                   _____ __ 
  / ___/____  ____  ____  / __(_) /_
  \__ \/ __ \/ __ \/ __ \/ /_/ / __/
 ___/ / /_/ / /_/ / /_/ / __/ / /_  
/____/ .___/\____/\____/_/ /_/\__/  
    /_/                             
   
usage: Spoofit.py [-h] -s SENDER -r RECIPIENTS [-f FORCED]

Email Spoofing Tool

options:
  -h, --help            show this help message and exit
  -s SENDER, --sender SENDER
                        Email address to use as the spoofed sender
  -r RECIPIENTS, --recipients RECIPIENTS
                        Recipient email address or file containing multiple addresses
  -f FORCED, --forced FORCED
                        Optional: Forced authentication email with responder IP
```
___

## Configuration
Edit the spoofit.conf file in the conf directory to customize the subject and body of the emails. The forced authentication email template is stored separately in forced_auth_template.html within the same directory.

___
