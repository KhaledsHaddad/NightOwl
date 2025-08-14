import tkinter as tk
from tkinter import scrolledtext, filedialog, ttk
import requests
import dns.resolver
import socket
import ssl
import threading
from queue import Queue, Empty
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import builtwith
import whois
import warnings

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

BG_COLOR = "#000000"
FG_COLOR = "#00FF00"
FONT = ("Consolas", 11)

scanning = False

def get_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        subdomains = set()
        for entry in data:
            name = entry.get('name_value')
            for sub in name.split('\n'):
                if sub.endswith(domain):
                    subdomains.add(sub.strip())
        return sorted(subdomains)
    except Exception as e:
        return [f"Error: {str(e)}"]

def start_scan():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Starting subdomain enumeration for {domain}...\n")
    root.update()
    results = get_subdomains(domain)
    if results and "Error:" not in results[0]:
        output_text.insert(tk.END, f"Found {len(results)} subdomains:\n")
        for sub in results:
            output_text.insert(tk.END, f" - {sub}\n")
    else:
        output_text.insert(tk.END, results[0] + "\n")

def dns_lookup(domain):
    records = {}
    types = ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT']
    try:
        for rtype in types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                records[rtype] = []
        return records
    except Exception as e:
        return f"Error: {str(e)}"

def start_dns_lookup():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Starting DNS lookup for {domain}...\n")
    root.update()
    records = dns_lookup(domain)
    if isinstance(records, dict):
        for rtype, entries in records.items():
            output_text.insert(tk.END, f"\n{rtype} Records:\n")
            if entries:
                for entry in entries:
                    output_text.insert(tk.END, f" - {entry}\n")
            else:
                output_text.insert(tk.END, "  None\n")
    else:
        output_text.insert(tk.END, records + "\n")

def port_worker(progress_callback=None):
    while True:
        port = q.get()
        if port is None:
            break
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((domain_global, port))
            if result == 0:
                results_queue.put(f"Port {port}: Open\n")
            sock.close()
        except:
            pass
        if progress_callback:
            progress_callback()
        q.task_done()

def start_port_scan():
    global domain_global, q, results_queue, scanning, scanned_ports_count
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain or IP.\n")
        return
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Starting port scan on {domain} (ports 1-1024)...\n")
    root.update()
    domain_global = domain
    q = Queue()
    results_queue = Queue()
    scanning = True
    scanned_ports_count = 0
    num_ports = 1024
    progress_bar["maximum"] = num_ports
    progress_bar["value"] = 0

    def progress_update():
        global scanned_ports_count
        scanned_ports_count += 1
        progress_bar["value"] = scanned_ports_count

    num_threads = 100
    for _ in range(num_threads):
        t = threading.Thread(target=port_worker, args=(progress_update,))
        t.daemon = True
        t.start()

    for port in range(1, num_ports + 1):
        q.put(port)

    def finish_scan():
        q.join()
        for _ in range(num_threads):
            q.put(None)
        global scanning
        scanning = False

    threading.Thread(target=finish_scan).start()
    process_queue()

def process_queue():
    try:
        while True:
            line = results_queue.get_nowait()
            output_text.insert(tk.END, line)
            output_text.see(tk.END)
            results_queue.task_done()
    except Empty:
        pass
    if scanning:
        root.after(100, process_queue)
    else:
        progress_bar["value"] = 0

def start_ssl_info():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Fetching SSL/TLS info for {domain}...\n")
    root.update()
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                output_text.insert(tk.END, "\nCertificate Details:\n")
                subject = dict(x[0] for x in cert.get('subject', ()))
                output_text.insert(tk.END, f"  Common Name: {subject.get('commonName', 'N/A')}\n")
                output_text.insert(tk.END, f"  Organization: {subject.get('organizationName', 'N/A')}\n")
                output_text.insert(tk.END, f"  Issuer: {dict(x[0] for x in cert.get('issuer', ())).get('commonName', 'N/A')}\n")
                output_text.insert(tk.END, f"  Valid From: {cert.get('notBefore', 'N/A')}\n")
                output_text.insert(tk.END, f"  Valid To: {cert.get('notAfter', 'N/A')}\n")
                output_text.insert(tk.END, f"  Serial Number: {cert.get('serialNumber', 'N/A')}\n")
                output_text.insert(tk.END, f"  Version: {cert.get('version', 'N/A')}\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error fetching SSL info: {str(e)}\n")

def start_take_screenshot():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Taking screenshot of https://{domain} ...\n")
    root.update()
    try:
        options = Options()
        options.headless = True
        options.add_argument("--window-size=1920,1080")
        driver = webdriver.Chrome(options=options)
        driver.get(f"https://{domain}")
        filepath = filedialog.asksaveasfilename(defaultextension=".png",
                                                filetypes=[("PNG files", "*.png")],
                                                title="Save screenshot as")
        if filepath:
            driver.save_screenshot(filepath)
            output_text.insert(tk.END, f"Screenshot saved to {filepath}\n")
        else:
            output_text.insert(tk.END, "Screenshot canceled.\n")
        driver.quit()
    except Exception as e:
        output_text.insert(tk.END, f"Error taking screenshot: {str(e)}\n")

def start_backup_check():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return
    common_backups = [
        "backup.zip", "backup.rar", "backup.tar.gz", "backup.tar", "backup.sql",
        "site.bak", "site_backup.zip", "old.zip", "old.tar.gz", "www.zip", "www.tar.gz",
        "backup1.zip", "backup2019.zip", "backup2020.zip"
    ]
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Checking common backup files on https://{domain}/ ...\n")
    root.update()
    found = []
    for fname in common_backups:
        url = f"https://{domain}/{fname}"
        try:
            resp = requests.head(url, timeout=5, allow_redirects=True)
            if resp.status_code == 200:
                found.append(fname)
                output_text.insert(tk.END, f"Found backup file: {url}\n")
                output_text.see(tk.END)
        except Exception:
            pass
    if not found:
        output_text.insert(tk.END, "No common backup files found.\n")

def start_http_headers():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Fetching HTTP headers for https://{domain} ...\n")
    root.update()
    try:
        resp = requests.head(f"https://{domain}", timeout=7)
        headers = resp.headers
        output_text.insert(tk.END, "\nHTTP Headers:\n")
        for k, v in headers.items():
            output_text.insert(tk.END, f"{k}: {v}\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error fetching headers: {str(e)}\n")

def subdomain_takeover_check(subdomain):
    fingerprints = [
        "There isn't a Github Pages site here.",
        "NoSuchBucket",
        "The specified bucket does not exist",
        "Heroku | No such app",
        "Sorry, We Couldn't Find That Page",
        "There is no app configured at that hostname",
        "No such app",
        "The page you requested is not available",
        "The requested URL was not found on this server",
        "Sorry, this shop is currently unavailable",
        "Sorry, this shop is currently unavailable.",
        "Welcome to your new site!",
        "Project not found",
        "Do you want to register",
        "Repository not found",
        "No such domain",
        "Custom domain verification failed",
    ]
    try:
        url = f"http://{subdomain}"
        resp = requests.get(url, timeout=7)
        content = resp.text
        for fp in fingerprints:
            if fp.lower() in content.lower():
                return True, fp
    except Exception:
        try:
            url = f"https://{subdomain}"
            resp = requests.get(url, timeout=7, verify=False)
            content = resp.text
            for fp in fingerprints:
                if fp.lower() in content.lower():
                    return True, fp
        except Exception:
            pass
    return False, ""

def start_subdomain_takeover():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Starting subdomain takeover check for {domain}...\n")
    root.update()
    subs = get_subdomains(domain)
    if not subs or ("Error:" in subs[0]):
        output_text.insert(tk.END, "Failed to get subdomains or none found.\n")
        return
    vulnerable = []
    for sub in subs:
        output_text.insert(tk.END, f"Checking {sub} ...\n")
        root.update()
        vulnerable_flag, reason = subdomain_takeover_check(sub)
        if vulnerable_flag:
            output_text.insert(tk.END, f"!!! Vulnerable to takeover: {sub} (Reason: {reason})\n")
            vulnerable.append(f"{sub} - {reason}")
        else:
            output_text.insert(tk.END, f"Safe: {sub}\n")
    if vulnerable:
        try:
            filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                                    filetypes=[("Text files", "*.txt")],
                                                    title="Save takeover results as")
            if filename:
                with open(filename, "w") as f:
                    for line in vulnerable:
                        f.write(line + "\n")
                output_text.insert(tk.END, f"\nResults saved to {filename}\n")
            else:
                output_text.insert(tk.END, "\nSave canceled.\n")
        except Exception as e:
            output_text.insert(tk.END, f"\nError saving file: {str(e)}\n")
    else:
        output_text.insert(tk.END, "\nNo vulnerable subdomains found.\n")

def start_technology_stack():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Detecting technology stack for {domain} ...\n")
    root.update()
    try:
        techs = builtwith.parse(f"http://{domain}")
        if techs:
            for category, tech_list in techs.items():
                output_text.insert(tk.END, f"\n{category}:\n")
                for tech in tech_list:
                    output_text.insert(tk.END, f" - {tech}\n")
        else:
            output_text.insert(tk.END, "No technology data found.\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error detecting tech stack: {str(e)}\n")

def start_whois_lookup():
    domain = domain_entry.get().strip()
    if not domain:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, "Please enter a domain.\n")
        return
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Performing WHOIS lookup for {domain} ...\n")
    root.update()
    try:
        w = whois.whois(domain)
        for key, value in w.items():
            output_text.insert(tk.END, f"{key}: {value}\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error performing WHOIS lookup: {str(e)}\n")

def save_report():
    content = output_text.get(1.0, tk.END).strip()
    if not content:
        return
    filename = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Text files", "*.txt")],
                                            title="Save report as")
    if filename:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(content)
        output_text.insert(tk.END, f"\nReport saved to {filename}\n")

root = tk.Tk()
root.title("owl - Recon Tool")
root.configure(bg=BG_COLOR)
root.geometry("700x750")

domain_label = tk.Label(root, text="Domain / IP:", bg=BG_COLOR, fg=FG_COLOR, font=FONT)
domain_label.pack(pady=(10,0))

domain_entry = tk.Entry(root, font=FONT, bg="#003300", fg=FG_COLOR, insertbackground=FG_COLOR)
domain_entry.pack(fill=tk.X, padx=10, pady=(0,10))

buttons_frame = tk.Frame(root, bg=BG_COLOR)
buttons_frame.pack(pady=(0,10))

scan_btn = tk.Button(buttons_frame, text="Subdomain Scan", command=start_scan, bg="#004400", fg=FG_COLOR, font=FONT, width=15)
scan_btn.pack(side=tk.LEFT, padx=5)

dns_btn = tk.Button(buttons_frame, text="DNS Lookup", command=start_dns_lookup, bg="#004400", fg=FG_COLOR, font=FONT, width=15)
dns_btn.pack(side=tk.LEFT, padx=5)

port_btn = tk.Button(buttons_frame, text="Port Scan", command=start_port_scan, bg="#004400", fg=FG_COLOR, font=FONT, width=15)
port_btn.pack(side=tk.LEFT, padx=5)

ssl_btn = tk.Button(buttons_frame, text="SSL Info", command=start_ssl_info, bg="#004400", fg=FG_COLOR, font=FONT, width=15)
ssl_btn.pack(side=tk.LEFT, padx=5)

screenshot_btn = tk.Button(buttons_frame, text="Take Screenshot", command=start_take_screenshot, bg="#004400", fg=FG_COLOR, font=FONT, width=15)
screenshot_btn.pack(side=tk.LEFT, padx=5)

backup_btn = tk.Button(buttons_frame, text="Backup File Check", command=start_backup_check, bg="#004400", fg=FG_COLOR, font=FONT, width=15)
backup_btn.pack(side=tk.LEFT, padx=5)

headers_btn = tk.Button(buttons_frame, text="HTTP Headers", command=start_http_headers, bg="#004400", fg=FG_COLOR, font=FONT, width=15)
headers_btn.pack(side=tk.LEFT, padx=5)

takeover_btn = tk.Button(buttons_frame, text="Subdomain Takeover", command=start_subdomain_takeover, bg="#004400", fg=FG_COLOR, font=FONT, width=15)
takeover_btn.pack(side=tk.LEFT, padx=5)

tech_btn = tk.Button(buttons_frame, text="Tech Stack", command=start_technology_stack, bg="#004400", fg=FG_COLOR, font=FONT, width=15)
tech_btn.pack(side=tk.LEFT, padx=5)

whois_btn = tk.Button(buttons_frame, text="WHOIS Lookup", command=start_whois_lookup, bg="#004400", fg=FG_COLOR, font=FONT, width=15)
whois_btn.pack(side=tk.LEFT, padx=5)

save_btn = tk.Button(root, text="Save Report", command=save_report, bg="#004400", fg=FG_COLOR, font=FONT, width=20)
save_btn.pack(pady=(0,10))

progress_bar = ttk.Progressbar(root, orient="horizontal", length=680, mode="determinate")
progress_bar.pack(pady=(0,10))

output_text = scrolledtext.ScrolledText(root, font=FONT, bg="#001100", fg=FG_COLOR, wrap=tk.WORD)
output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

footer = tk.Label(root, text="khaled.s.haddad | khaledhaddad.tech | owl", bg=BG_COLOR, fg=FG_COLOR, font=("Consolas", 10))
footer.pack(pady=(0,10))

root.mainloop()
