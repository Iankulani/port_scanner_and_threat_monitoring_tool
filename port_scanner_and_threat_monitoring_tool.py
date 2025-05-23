import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import socket
import threading
import time
from datetime import datetime
import ipaddress
import subprocess
import platform
import os
import queue
import json
import csv
from collections import defaultdict

# ==============================================
#               PORT SCANNER CLASS
# ==============================================
class PortScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("Acuurate Cyber Defense Port Scanner & Threat Monitor")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # Variables
        self.target_ip = tk.StringVar()
        self.start_port = tk.IntVar(value=1)
        self.end_port = tk.IntVar(value=1024)
        self.scanning = False
        self.scan_thread = None
        self.threat_monitoring = False
        self.monitor_thread = None
        self.open_ports = []
        self.port_services = self.load_port_services()
        self.threat_log = queue.Queue()
        self.ip_stats = defaultdict(lambda: {"count": 0, "ports": set()})
        self.mac_ip_map = {}
        
        # GUI Setup
        self.setup_gui()
        
        # Load known vulnerabilities
        self.vulnerabilities = self.load_vulnerabilities()
        
    # ==============================================
    #               GUI SETUP
    # ==============================================
    def setup_gui(self):
        # Main Frames
        self.top_frame = ttk.Frame(self.root, padding="10")
        self.top_frame.pack(fill=tk.X)
        
        self.middle_frame = ttk.Frame(self.root, padding="10")
        self.middle_frame.pack(fill=tk.BOTH, expand=True)
        
        self.bottom_frame = ttk.Frame(self.root, padding="10")
        self.bottom_frame.pack(fill=tk.BOTH, expand=True)
        
        # IP Entry
        ttk.Label(self.top_frame, text="Target IP:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.ip_entry = ttk.Entry(self.top_frame, textvariable=self.target_ip, width=20)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Port Range
        ttk.Label(self.top_frame, text="Start Port:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.start_port_entry = ttk.Entry(self.top_frame, textvariable=self.start_port, width=8)
        self.start_port_entry.grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Label(self.top_frame, text="End Port:").grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        self.end_port_entry = ttk.Entry(self.top_frame, textvariable=self.end_port, width=8)
        self.end_port_entry.grid(row=0, column=5, padx=5, pady=5)
        
        # Scan Buttons
        self.scan_button = ttk.Button(self.top_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=6, padx=5, pady=5)
        
        self.stop_button = ttk.Button(self.top_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=7, padx=5, pady=5)
        
        # Monitor Button
        self.monitor_button = ttk.Button(self.top_frame, text="Start Monitoring", command=self.toggle_monitoring)
        self.monitor_button.grid(row=0, column=8, padx=5, pady=5)
        
        # Results Treeview
        self.results_tree = ttk.Treeview(
            self.middle_frame,
            columns=("Port", "Status", "Service", "Vulnerability"),
            show="headings",
            selectmode="extended"
        )
        
        self.results_tree.heading("Port", text="Port")
        self.results_tree.heading("Status", text="Status")
        self.results_tree.heading("Service", text="Service")
        self.results_tree.heading("Vulnerability", text="Vulnerability")
        
        self.results_tree.column("Port", width=80, anchor=tk.CENTER)
        self.results_tree.column("Status", width=100, anchor=tk.CENTER)
        self.results_tree.column("Service", width=200, anchor=tk.W)
        self.results_tree.column("Vulnerability", width=300, anchor=tk.W)
        
        scrollbar = ttk.Scrollbar(self.middle_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Threat Log
        ttk.Label(self.bottom_frame, text="Threat Log").pack(anchor=tk.W)
        self.threat_log_text = scrolledtext.ScrolledText(
            self.bottom_frame,
            wrap=tk.WORD,
            width=100,
            height=10,
            state=tk.DISABLED
        )
        self.threat_log_text.pack(fill=tk.BOTH, expand=True)
        
        # Export Button
        self.export_button = ttk.Button(self.bottom_frame, text="Export Results", command=self.export_results)
        self.export_button.pack(pady=5)
        
        # Context Menu
        self.setup_context_menu()
        
        # Tooltips
        self.setup_tooltips()
    
    # ==============================================
    #               SCAN FUNCTIONS
    # ==============================================
    def start_scan(self):
        target_ip = self.target_ip.get()
        start_port = self.start_port.get()
        end_port = self.end_port.get()
        
        if not target_ip:
            messagebox.showerror("Error", "Please enter a target IP!")
            return
        
        try:
            ipaddress.ip_address(target_ip)
        except ValueError:
            messagebox.showerror("Error", "Invalid IP address!")
            return
        
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            messagebox.showerror("Error", "Invalid port range (1-65535)!")
            return
        
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.results_tree.delete(*self.results_tree.get_children())
        self.open_ports = []
        
        self.scan_thread = threading.Thread(
            target=self.run_scan,
            args=(target_ip, start_port, end_port),
            daemon=True
        )
        self.scan_thread.start()
        
        self.log_threat(f"Started scanning {target_ip} (Ports: {start_port}-{end_port})")
    
    def stop_scan(self):
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.log_threat("Scan stopped by user")
    
    def run_scan(self, target_ip, start_port, end_port):
        for port in range(start_port, end_port + 1):
            if not self.scanning:
                break
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    service = self.port_services.get(port, "Unknown")
                    vuln = self.check_vulnerability(port, service)
                    
                    self.open_ports.append(port)
                    self.results_tree.insert("", tk.END, values=(port, "OPEN", service, vuln))
                else:
                    self.results_tree.insert("", tk.END, values=(port, "CLOSED", "-", "-"))
                
                sock.close()
            except Exception as e:
                self.log_threat(f"Error scanning port {port}: {str(e)}", is_error=True)
        
        self.scanning = False
        self.root.after(0, lambda: self.scan_button.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED))
        self.log_threat(f"Scan completed. Found {len(self.open_ports)} open ports.")
    
    # ==============================================
    #               THREAT MONITORING
    # ==============================================
    def toggle_monitoring(self):
        if not self.threat_monitoring:
            self.start_monitoring()
        else:
            self.stop_monitoring()
    
    def start_monitoring(self):
        target_ip = self.target_ip.get()
        
        if not target_ip:
            messagebox.showerror("Error", "Please enter a target IP!")
            return
        
        self.threat_monitoring = True
        self.monitor_button.config(text="Stop Monitoring")
        self.monitor_thread = threading.Thread(
            target=self.run_monitoring,
            args=(target_ip,),
            daemon=True
        )
        self.monitor_thread.start()
        self.log_threat(f"Started monitoring threats on {target_ip}")
    
    def stop_monitoring(self):
        self.threat_monitoring = False
        self.monitor_button.config(text="Start Monitoring")
        self.log_threat("Threat monitoring stopped")
    
    def run_monitoring(self, target_ip):
        while self.threat_monitoring:
            try:
                # Simulate threat detection (in a real app, use pcap/pydivert)
                time.sleep(2)
                self.detect_threats(target_ip)
            except Exception as e:
                self.log_threat(f"Monitoring error: {str(e)}", is_error=True)
    
    def detect_threats(self, target_ip):
        # Simulate random threats (replace with real packet analysis)
        import random
        threats = [
            f"Port scan detected from {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            f"Possible DoS attack on port {random.choice([80, 443, 22])}",
            f"Unusual traffic pattern from {target_ip}",
            f"Suspicious login attempt on port 22 (SSH)"
        ]
        
        threat = random.choice(threats)
        self.log_threat(threat)
    
    # ==============================================
    #               UTILITY FUNCTIONS
    # ==============================================
    def load_port_services(self):
        # Common port-service mappings
        return {
            20: "FTP (Data)",
            21: "FTP (Control)",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP-Alt"
        }
    
    def load_vulnerabilities(self):
        # Common vulnerabilities per port/service
        return {
            21: "FTP Anonymous Login Possible",
            22: "Weak SSH Credentials",
            23: "Telnet (Unencrypted Communication)",
            80: "Possible Web Vulnerabilities (XSS, SQLi)",
            443: "SSL/TLS Vulnerabilities",
            3389: "RDP Brute Force Risk"
        }
    
    def check_vulnerability(self, port, service):
        return self.vulnerabilities.get(port, "No known vulnerabilities")
    
    def log_threat(self, message, is_error=False):
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        log_msg = f"{timestamp} {message}\n"
        
        self.threat_log_text.config(state=tk.NORMAL)
        self.threat_log_text.insert(tk.END, log_msg)
        
        if is_error:
            self.threat_log_text.tag_add("error", "end-2l linestart", "end-1l lineend")
            self.threat_log_text.tag_config("error", foreground="red")
        
        self.threat_log_text.see(tk.END)
        self.threat_log_text.config(state=tk.DISABLED)
    
    def export_results(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, "w") as f:
                f.write(f"Port Scan Results for {self.target_ip.get()}\n")
                f.write("=" * 50 + "\n")
                
                for item in self.results_tree.get_children():
                    port, status, service, vuln = self.results_tree.item(item)["values"]
                    f.write(f"Port: {port}\tStatus: {status}\tService: {service}\tVulnerability: {vuln}\n")
                
                f.write("\nThreat Log:\n")
                f.write("=" * 50 + "\n")
                f.write(self.threat_log_text.get("1.0", tk.END))
            
            self.log_threat(f"Results exported to {file_path}")
        except Exception as e:
            self.log_threat(f"Export failed: {str(e)}", is_error=True)
    
    # ==============================================
    #               GUI ENHANCEMENTS
    # ==============================================
    def setup_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Copy", command=self.copy_selected)
        self.context_menu.add_command(label="Details", command=self.show_details)
        
        self.results_tree.bind("<Button-3>", self.show_context_menu)
    
    def show_context_menu(self, event):
        item = self.results_tree.identify_row(event.y)
        if item:
            self.results_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def copy_selected(self):
        selected = self.results_tree.selection()
        if selected:
            item = self.results_tree.item(selected[0])
            self.root.clipboard_clear()
            self.root.clipboard_append(str(item["values"]))
    
    def show_details(self):
        selected = self.results_tree.selection()
        if selected:
            item = self.results_tree.item(selected[0])
            port, status, service, vuln = item["values"]
            
            details = (
                f"Port: {port}\n"
                f"Status: {status}\n"
                f"Service: {service}\n"
                f"Vulnerability: {vuln}"
            )
            
            messagebox.showinfo("Port Details", details)
    
    def setup_tooltips(self):
        from tkinter import Toplevel
        
        class ToolTip:
            def __init__(self, widget, text):
                self.widget = widget
                self.text = text
                self.tipwindow = None
                self.widget.bind("<Enter>", self.showtip)
                self.widget.bind("<Leave>", self.hidetip)
            
            def showtip(self, event):
                x, y, _, _ = self.widget.bbox("insert")
                x += self.widget.winfo_rootx() + 25
                y += self.widget.winfo_rooty() + 25
                
                self.tipwindow = tw = Toplevel(self.widget)
                tw.wm_overrideredirect(True)
                tw.wm_geometry(f"+{x}+{y}")
                
                label = tk.Label(tw, text=self.text, bg="lightyellow", relief="solid", borderwidth=1)
                label.pack()
            
            def hidetip(self):
                if self.tipwindow:
                    self.tipwindow.destroy()
                    self.tipwindow = None
        
        # Add tooltips
        ToolTip(self.ip_entry, "Enter target IP (e.g., 192.168.1.1)")
        ToolTip(self.start_port_entry, "Starting port (1-65535)")
        ToolTip(self.end_port_entry, "Ending port (1-65535)")
        ToolTip(self.scan_button, "Start scanning for open ports")
        ToolTip(self.monitor_button, "Monitor for network threats")

# ==============================================
#               MAIN EXECUTION
# ==============================================
if __name__ == "__main__":
    root = tk.Tk()
    app = PortScanner(root)
    root.mainloop()