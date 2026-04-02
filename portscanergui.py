import socket
import threading
import time
import queue
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ---------------------------
# Service Map (extend freely)
# ---------------------------
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    445: 'SMB',
    3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt'
}

DANGEROUS_PORTS = {21, 23, 445}

RECOMMENDATIONS = {
    21: "Use secure FTP alternatives like SFTP or FTPS.",
    22: "Ensure SSH is configured with strong keys and disable password auth if possible.",
    23: "Disable Telnet; use SSH instead. Telnet sends data in plaintext.",
    80: "Enforce HTTPS to secure web traffic.",
    445: "Block SMB at edge firewalls; extreme risk for ransomware like WannaCry.",
    3389: "Restrict RDP access with VPN and MFA."
}

THREATS = {
    21: "Brute force, plaintext credentials sniffing.",
    22: "Brute force, credential stuffing.",
    23: "Plaintext credential sniffing, unauthorized access.",
    80: "Web attacks, injection, XSS.",
    445: "Ransomware propagation, unauthorized file access.",
    3389: "Brute force, unauthorized remote execution."
}

def grab_banner(ip, port, timeout=1.0):
    """Attempt basic banner grabbing."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        
        # Handle SSL/TLS ports safely without crashing
        if port in [443, 8443]:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            s = context.wrap_socket(s, server_hostname=ip)
            s.connect((ip, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        else:
            s.connect((ip, port))
            # Send payload for HTTP variants
            if port in [80, 8080]:
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        
        # Clean up multi-line HTTP responses for cleaner view
        if banner.startswith("HTTP/"):
            banner = banner.split("\r\n")[0]
            
        return banner if banner else "No banner"
    except socket.timeout:
        return "Timeout"
    except Exception:
        return "Could not grab banner"

class PortScanner:
    def __init__(self, target, start_port, end_port, timeout=0.5, max_workers=500):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.max_workers = max_workers
        self._stop_event = threading.Event()

        self.total_ports = max(0, end_port - start_port + 1)
        self.scanned_count = 0
        self.open_ports = []
        self._lock = threading.Lock()
        self.result_queue = queue.Queue()

    def stop(self):
        self._stop_event.set()

    def _scan_port(self, port):
        if self._stop_event.is_set():
            return
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((self.target, port))
            if result == 0:
                service = COMMON_PORTS.get(port, 'Unknown')
                banner = grab_banner(self.target, port, timeout=1.0)
                with self._lock:
                    self.open_ports.append({
                        'port': port,
                        'service': service,
                        'banner': banner
                    })
                self.result_queue.put(('open', port, service, banner))
            s.close()
        except Exception as e:
            self.result_queue.put(('error', port, str(e)))
        finally:
            with self._lock:
                self.scanned_count += 1
            self.result_queue.put(('progress', self.scanned_count, self.total_ports))

    def resolve_target(self):
        return socket.gethostbyname(self.target)

    def run(self):
        sem = threading.Semaphore(self.max_workers)
        threads = []

        for port in range(self.start_port, self.end_port + 1):
            if self._stop_event.is_set():
                break
            sem.acquire()
            t = threading.Thread(target=self._worker_wrapper, args=(sem, port), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.result_queue.put(('done', None, None, None))

    def _worker_wrapper(self, sem, port):
        try:
            self._scan_port(port)
        finally:
            sem.release()

def calculate_risk_score(open_ports):
    # base risk based on number of ports open
    score = min(len(open_ports) * 5, 40)
    
    # additional risk for dangerous ports
    for p in open_ports:
        port = p['port']
        if port in DANGEROUS_PORTS:
            score += 20
        elif port in COMMON_PORTS:
            score += 5
            
    score = min(score, 100)
    level = "Low"
    if score >= 70:
        level = "High"
    elif score >= 40:
        level = "Medium"
        
    return score, level

def check_password_strength(password):
    length = len(password)
    has_digits = any(c.isdigit() for c in password)
    has_symbols = any(not c.isalnum() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    
    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1
    if has_digits: score += 1
    if has_symbols: score += 1
    if has_upper and has_lower: score += 1
    
    if score >= 4:
        return "Strong"
    elif score >= 2:
        return "Medium"
    else:
        return "Weak"

class IntelligentToolkitGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Intelligent Cyber Security Toolkit")
        self.geometry("900x600")
        self.minsize(800, 500)
        self.configure(bg="#2b2b2b")
        
        # Scanner state
        self.scanner_thread = None
        self.scanner = None
        self.start_time = None
        self.end_time = None
        self.poll_after_ms = 40
        self.last_target = None
        self.last_open_ports = []
        self.total_scanned = 0
        
        # Styling
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure("TFrame", background="#333333")
        style.configure("Sidebar.TFrame", background="#1e1e1e")
        style.configure("Sidebar.TButton", background="#1e1e1e", foreground="white", font=("Arial", 11, "bold"), borderwidth=0, focuscolor="#1e1e1e", padding=10)
        style.map("Sidebar.TButton", background=[('active', '#3a3a3a')])
        style.configure("Content.TFrame", background="#2b2b2b")
        style.configure("TLabel", background="#2b2b2b", foreground="white", font=("Arial", 10))
        style.configure("Header.TLabel", font=("Arial", 14, "bold"), background="#2b2b2b", foreground="#4da6ff")
        style.configure("TButton", font=("Arial", 10), background="#4da6ff", foreground="white")
        style.map("TButton", background=[('active', '#3388dd')])
        
        self.build_ui()
        
    def build_ui(self):
        # LEFT: Sidebar
        self.sidebar = ttk.Frame(self, style="Sidebar.TFrame", width=200)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        
        lbl_brand = tk.Label(self.sidebar, text="SecToolkit", font=("Arial", 16, "bold"), bg="#1e1e1e", fg="#4da6ff", pady=20)
        lbl_brand.pack(fill="x")
        
        btns = ["Scan", "Results", "Analysis", "Password Tool", "Reports"]
        for btn_text in btns:
            btn = ttk.Button(self.sidebar, text=btn_text, style="Sidebar.TButton", command=lambda t=btn_text: self.show_section(t))
            btn.pack(fill="x", pady=2)
            
        # RIGHT: Main content
        self.content_area = ttk.Frame(self, style="Content.TFrame")
        self.content_area.pack(side="right", fill="both", expand=True)
        
        # Sections mapping
        self.sections = {}
        
        self.create_scan_section()
        self.create_results_section()
        self.create_analysis_section()
        self.create_password_section()
        self.create_reports_section()
        
        self.show_section("Scan")

    def show_section(self, name):
        for sec in self.sections.values():
            sec.pack_forget()
        self.sections[name].pack(fill="both", expand=True)

    # --- SCAN SECTION ---
    def create_scan_section(self):
        sec = ttk.Frame(self.content_area, style="Content.TFrame")
        self.sections["Scan"] = sec
        
        lbl_title = ttk.Label(sec, text="Port Scanner", style="Header.TLabel")
        lbl_title.pack(pady=20)
        
        frm_inputs = ttk.Frame(sec, style="Content.TFrame")
        frm_inputs.pack(pady=10)
        
        ttk.Label(frm_inputs, text="Target IP/Host:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.ent_target = ttk.Entry(frm_inputs, width=30)
        self.ent_target.grid(row=0, column=1, padx=5, pady=5)
        self.ent_target.bind("<Return>", lambda e: self.start_scan())
        
        ttk.Label(frm_inputs, text="Start Port:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.ent_start = ttk.Entry(frm_inputs, width=15)
        self.ent_start.insert(0, "1")
        self.ent_start.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        self.ent_start.bind("<Return>", lambda e: self.start_scan())
        
        ttk.Label(frm_inputs, text="End Port:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.ent_end = ttk.Entry(frm_inputs, width=15)
        self.ent_end.insert(0, "1024")
        self.ent_end.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        self.ent_end.bind("<Return>", lambda e: self.start_scan())
        
        frm_btns = ttk.Frame(sec, style="Content.TFrame")
        frm_btns.pack(pady=15)
        
        self.btn_start = ttk.Button(frm_btns, text="Start Scan", command=self.start_scan)
        self.btn_start.pack(side="left", padx=10)
        
        self.btn_stop = ttk.Button(frm_btns, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=10)
        
        # Progress and Status
        self.var_status_scan = tk.StringVar(value="Ready")
        ttk.Label(sec, textvariable=self.var_status_scan).pack(pady=5)
        
        self.progress = ttk.Progressbar(sec, orient="horizontal", mode="determinate", length=400)
        self.progress.pack(pady=10)
        
        self.var_elapsed = tk.StringVar(value="Elapsed: 0.00s")
        ttk.Label(sec, textvariable=self.var_elapsed).pack(pady=5)
        
    # --- RESULTS SECTION ---
    def create_results_section(self):
        sec = ttk.Frame(self.content_area, style="Content.TFrame")
        self.sections["Results"] = sec
        
        lbl_title = ttk.Label(sec, text="Live Scan Results", style="Header.TLabel")
        lbl_title.pack(pady=10)
        
        frm_text = ttk.Frame(sec)
        frm_text.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.txt_results = tk.Text(frm_text, bg="#1e1e1e", fg="#00ff00", font=("Consolas", 10), state="disabled")
        self.txt_results.pack(side="left", fill="both", expand=True)
        
        scroll = ttk.Scrollbar(frm_text, command=self.txt_results.yview)
        scroll.pack(side="right", fill="y")
        self.txt_results.config(yscrollcommand=scroll.set)
        
        ttk.Button(sec, text="Clear Results", command=self.clear_results).pack(pady=10)

    # --- ANALYSIS SECTION ---
    def create_analysis_section(self):
        sec = ttk.Frame(self.content_area, style="Content.TFrame")
        self.sections["Analysis"] = sec
        
        lbl_title = ttk.Label(sec, text="Security Analysis", style="Header.TLabel")
        lbl_title.pack(pady=10)
        
        frm_text = ttk.Frame(sec)
        frm_text.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.txt_analysis = tk.Text(frm_text, bg="#1e1e1e", fg="white", font=("Consolas", 10), state="disabled")
        self.txt_analysis.pack(side="left", fill="both", expand=True)
        
        scroll = ttk.Scrollbar(frm_text, command=self.txt_analysis.yview)
        scroll.pack(side="right", fill="y")
        self.txt_analysis.config(yscrollcommand=scroll.set)
        
        ttk.Button(sec, text="Refresh Analysis", command=self.refresh_analysis).pack(pady=10)

    # --- PASSWORD SECTION ---
    def create_password_section(self):
        sec = ttk.Frame(self.content_area, style="Content.TFrame")
        self.sections["Password Tool"] = sec
        
        lbl_title = ttk.Label(sec, text="Password Strength Checker", style="Header.TLabel")
        lbl_title.pack(pady=20)
        
        frm_in = ttk.Frame(sec, style="Content.TFrame")
        frm_in.pack(pady=10)
        
        ttk.Label(frm_in, text="Enter Password:").grid(row=0, column=0, padx=5, pady=5)
        self.ent_pass = ttk.Entry(frm_in, width=30, show="*")
        self.ent_pass.grid(row=0, column=1, padx=5, pady=5)
        self.ent_pass.bind("<Return>", lambda e: self.check_password())
        
        ttk.Button(frm_in, text="Check", command=self.check_password).grid(row=0, column=2, padx=5, pady=5)
        
        self.var_pass_res = tk.StringVar(value="")
        self.lbl_pass_res = tk.Label(sec, textvariable=self.var_pass_res, font=("Arial", 12, "bold"), bg="#2b2b2b")
        self.lbl_pass_res.pack(pady=20)
        
    def check_password(self):
        pwd = self.ent_pass.get()
        if not pwd:
            return
        strength = check_password_strength(pwd)
        colors = {"Weak": "#ff4d4d", "Medium": "#ffcc00", "Strong": "#4dff4d"}
        self.var_pass_res.set(f"Strength: {strength}")
        self.lbl_pass_res.config(fg=colors.get(strength, "white"))

    # --- REPORTS SECTION ---
    def create_reports_section(self):
        sec = ttk.Frame(self.content_area, style="Content.TFrame")
        self.sections["Reports"] = sec
        
        lbl_title = ttk.Label(sec, text="Complete Security Report", style="Header.TLabel")
        lbl_title.pack(pady=10)
        
        frm_text = ttk.Frame(sec)
        frm_text.pack(fill="both", expand=True, padx=20, pady=10)
        
        self.txt_report = tk.Text(frm_text, bg="#1e1e1e", fg="white", font=("Consolas", 10), state="disabled")
        self.txt_report.pack(side="left", fill="both", expand=True)
        
        scroll = ttk.Scrollbar(frm_text, command=self.txt_report.yview)
        scroll.pack(side="right", fill="y")
        self.txt_report.config(yscrollcommand=scroll.set)
        
        frm_btns = ttk.Frame(sec, style="Content.TFrame")
        frm_btns.pack(pady=10)
        
        self.btn_gen_report = ttk.Button(frm_btns, text="Generate Complete Report", command=self.preview_report, state="disabled")
        self.btn_gen_report.pack(side="left", padx=10)
        
        self.btn_save = ttk.Button(frm_btns, text="Save Detailed Report (.txt)", command=self.save_report, state="disabled")
        self.btn_save.pack(side="left", padx=10)

    # -----------------------
    # Scanner Logic & Handlers
    # -----------------------
    def log_result(self, msg):
        self.txt_results.config(state="normal")
        self.txt_results.insert(tk.END, msg + "\n")
        self.txt_results.see(tk.END)
        self.txt_results.config(state="disabled")

    def start_scan(self):
        if self.scanner_thread and self.scanner_thread.is_alive():
            return
            
        target = self.ent_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Enter a target.")
            return
            
        # Clean up URL-like targets if user pasted a link
        if "://" in target:
            target = target.split("://")[1]
        target = target.split("/")[0]
        self.ent_target.delete(0, tk.END)
        self.ent_target.insert(0, target)
            
        try:
            sp = int(self.ent_start.get().strip())
            ep = int(self.ent_end.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Ports must be numbers.")
            return
            
        self.scanner = PortScanner(target, sp, ep, timeout=0.5, max_workers=500)
        
        try:
            ip = self.scanner.resolve_target()
            self.last_target = f"{target} ({ip})"
        except Exception:
            messagebox.showerror("Error", "Failed to resolve target.")
            return

        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        if hasattr(self, 'btn_save'):
            self.btn_save.config(state="disabled")
        if hasattr(self, 'btn_gen_report'):
            self.btn_gen_report.config(state="disabled")
        
        self.clear_results()
        self.last_open_ports = []
        self.total_scanned = 0
        
        self.start_time = time.time()
        self.end_time = None
        
        self.log_result(f"[*] Starting scan on {self.last_target}")
        self.log_result(f"[*] Port range: {sp} - {ep}\n")
        
        self.scanner_thread = threading.Thread(target=self.scanner.run, daemon=True)
        self.scanner_thread.start()
        
        self.after(self.poll_after_ms, self.poll_results)
        self.update_elapsed()
        self.show_section("Results")
        
    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
            self.var_status_scan.set("Stopping...")
            self.log_result("\n[!] Scan stopped by user.")

    def update_elapsed(self):
        if self.start_time and not self.end_time:
            elapsed = time.time() - self.start_time
            self.var_elapsed.set(f"Elapsed: {elapsed:.2f}s")
            self.after(200, self.update_elapsed)

    def poll_results(self):
        if not self.scanner:
            return
            
        try:
            while True:
                msg = self.scanner.result_queue.get_nowait()
                m_type = msg[0]
                if m_type == 'open':
                    port, svc, banner = msg[1], msg[2], msg[3]
                    bn_snippet = (banner[:30] + '...') if len(banner) > 30 else banner
                    bn_str = f" [Banner: {bn_snippet}]" if banner != "No banner" and banner != "Could not grab banner" else ""
                    self.log_result(f"[+] Port {port:<5} OPEN  | {svc:<10} {bn_str}")
                elif m_type == 'progress':
                    scanned, total = msg[1], msg[2]
                    self.progress.config(maximum=total, value=scanned)
                    self.var_status_scan.set(f"Scanning: {scanned}/{total}")
                elif m_type == 'done':
                    self.end_time = time.time()
                    elapsed = self.end_time - self.start_time
                    self.last_open_ports = self.scanner.open_ports
                    self.total_scanned = self.scanner.total_ports
                    self.log_result(f"\n[*] Scan complete. Found {len(self.last_open_ports)} open ports.")
                    self.log_result(f"[*] Scan duration: {elapsed:.2f}s")
                    self.var_status_scan.set("Completed")
                    self.btn_start.config(state="normal")
                    self.btn_stop.config(state="disabled")
                    
                    self.btn_save.config(state="normal")
                    if hasattr(self, 'btn_gen_report'):
                        self.btn_gen_report.config(state="normal")
                    self.refresh_analysis()
                    
        except queue.Empty:
            pass
            
        if self.scanner_thread and self.scanner_thread.is_alive():
            self.after(self.poll_after_ms, self.poll_results)
        else:
            self.btn_start.config(state="normal")
            self.btn_stop.config(state="disabled")

    def clear_results(self):
        self.txt_results.config(state="normal")
        self.txt_results.delete("1.0", tk.END)
        self.txt_results.config(state="disabled")
        self.progress.config(value=0)
        self.var_elapsed.set("Elapsed: 0.00s")
        self.var_status_scan.set("Ready")

    # -----------------------
    # Analysis & Reports
    # -----------------------
    def refresh_analysis(self):
        self.txt_analysis.config(state="normal")
        self.txt_analysis.delete("1.0", tk.END)
        
        if not self.last_target:
            self.txt_analysis.insert(tk.END, "No scan data available. Please run a scan first.")
            self.txt_analysis.config(state="disabled")
            return
            
        r_score, r_level = calculate_risk_score(self.last_open_ports)
        
        # OS Guess based on TTL logic is hard without ping, we mock basic OS based on common ports
        os_guess = "Unknown"
        ports = [p['port'] for p in self.last_open_ports]
        if 3389 in ports or 445 in ports or 139 in ports:
            os_guess = "Likely Windows"
        elif 22 in ports and 445 not in ports:
            os_guess = "Likely Linux/Unix"
            
        text = f"TARGET: {self.last_target}\n"
        text += "="*40 + "\n\n"
        
        text += "[ METRICS ]\n"
        scan_time = (self.end_time - self.start_time) if self.end_time else 0
        text += f"Total Ports Scanned : {self.total_scanned}\n"
        text += f"Total Open Ports    : {len(self.last_open_ports)}\n"
        text += f"Scan Duration       : {scan_time:.2f} seconds\n"
        text += f"OS Guess            : {os_guess}\n\n"
        
        text += "[ RISK SCORING ]\n"
        text += f"Score: {r_score}/100\n"
        text += f"Level: {r_level}\n\n"
        
        text += "[ ATTACK SIMULATION & THREATS ]\n"
        threat_count = 0
        for p in self.last_open_ports:
            port = p['port']
            if port in THREATS:
                text += f"- Port {port}: {THREATS[port]}\n"
                threat_count +=1
        if threat_count == 0:
            text += "- No standard high-threat vectors detected on known ports.\n"
        text += "\n"
        
        text += "[ SECURITY RECOMMENDATIONS ]\n"
        rec_count = 0
        for p in self.last_open_ports:
            port = p['port']
            if port in RECOMMENDATIONS:
                text += f"- Port {port}: {RECOMMENDATIONS[port]}\n"
                rec_count +=1
        if rec_count == 0:
            text += "- No specific recommendations for the discovered ports.\n"
            
        self.txt_analysis.insert(tk.END, text)
        self.txt_analysis.config(state="disabled")

    def generate_report_text(self):
        r_score, r_level = calculate_risk_score(self.last_open_ports)
        
        text = "=== INTELLIGENT CYBER SECURITY TOOLKIT COMPLETE REPORT ===\n\n"
        text += f"Target: {self.last_target}\n"
        scan_time = (self.end_time - self.start_time) if self.end_time else 0
        text += f"Scan Duration: {scan_time:.2f} seconds\n"
        text += f"Risk Score: {r_score}/100 ({r_level})\n"
        text += f"Ports Scanned: {self.total_scanned}\n"
        text += f"Open Ports Detected: {len(self.last_open_ports)}\n\n"
        
        text += "--- DETAILED OPEN PORTS ---\n"
        if not self.last_open_ports:
            text += "No open ports found.\n"
        for p in self.last_open_ports:
            text += f"Port: {p['port']:<5} | Service: {p['service']:<10} | Banner: {p['banner']}\n"
            
        text += "\n--- THREAT MODELING ---\n"
        threat_found = False
        for p in self.last_open_ports:
            if p['port'] in THREATS:
                text += f"[*] Port {p['port']} ({p['service']}): {THREATS[p['port']]}\n"
                threat_found = True
        if not threat_found:
            text += "[+] No standard high-threat vectors detected on known ports.\n"
                
        text += "\n--- SECURITY RECOMMENDATIONS ---\n"
        rec_found = False
        for p in self.last_open_ports:
            if p['port'] in RECOMMENDATIONS:
                text += f"[*] Port {p['port']} ({p['service']}): {RECOMMENDATIONS[p['port']]}\n"
                rec_found = True
        if not rec_found:
            text += "[+] No specific recommendations for the discovered ports.\n"
            
        return text

    def preview_report(self):
        if not self.last_target:
            return
            
        report_text = self.generate_report_text()
        self.txt_report.config(state="normal")
        self.txt_report.delete("1.0", tk.END)
        self.txt_report.insert(tk.END, report_text)
        self.txt_report.config(state="disabled")

    def save_report(self):
        if not self.last_open_ports and not self.last_target:
            return
            
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="security_report.txt")
        if not filepath:
            return
            
        try:
            report_text = self.generate_report_text()
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report_text)
                        
            messagebox.showinfo("Success", f"Report saved to {filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save report: {e}")

def main():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-10), 7)
        except Exception:
            pass
    app = IntelligentToolkitGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
