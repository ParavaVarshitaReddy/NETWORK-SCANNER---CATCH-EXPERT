import ipaddress
import socket
import tkinter as tk
from tkinter import ttk, messagebox
import nmap
import requests
from scapy.all import srp, Ether, ARP
from datetime import datetime
from manuf import manuf

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")

        # Style for Treeview
        style = ttk.Style()
        style.theme_use("clam")  # Choose a theme for Treeview
        style.configure("Treeview.Heading", font=('Helvetica', 10, 'bold'))  # Font for column headings
        style.configure("Treeview", font=('Helvetica', 10))  # Font for data

        # Treeview for displaying scan results
        columns = ("IP", "MAC", "Hostname", "Vendor", "Date", "OS", "Version")
        self.tree = ttk.Treeview(root, columns=columns, show='headings', selectmode="browse")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center", minwidth=100, stretch=True)
        self.tree.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky='nsew')

        # Separator lines
        for col in columns[:-1]:
            self.tree.heading(col, text=col.upper(), anchor='center')

        # Add a horizontal separator line
        separator = ttk.Separator(root, orient='horizontal')
        separator.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 10))

        # Labels and entries for IP range
        tk.Label(root, text="Start IP:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
        self.start_ip_entry = tk.Entry(root)
        self.start_ip_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        tk.Label(root, text="End IP:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
        self.end_ip_entry = tk.Entry(root)
        self.end_ip_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        # Scan button
        self.scan_button = tk.Button(root, text="Scan", command=self.on_scan)
        self.scan_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Adjust row heights
        for i in range(len(columns)):
            self.tree.heading(columns[i], text=columns[i].upper(), anchor=tk.W)

    def test_dns_resolution(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror:
            return None

    def get_vendor(self, mac):
        p = manuf.MacParser()
        vendor = p.get_manuf(mac)
        if vendor:
            return vendor

        url = f"https://api.macvendors.com/{mac}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return response.text
            else:
                return "Unknown"
        except requests.RequestException as e:
            print(f"Error fetching vendor: {e}")
            return "Unknown"

    def resolve_hostname(self, ip_addr):
        try:
            hostname = socket.gethostbyaddr(ip_addr)[0]
        except socket.herror:
            hostname = "Unknown"
        return hostname

    def get_device_info(self, ip):
        nm = nmap.PortScanner()
        try:
            nm.scan(ip, arguments='-O -sV')
            info = {
                "OS": "Unknown",
                "Version": "Unknown"
            }
            if ip in nm.all_hosts():
                # Extract OS information
                if 'osmatch' in nm[ip]:
                    info["OS"] = nm[ip]['osmatch'][0].get('name', "Unknown")
                # Extract version from service detection
                if 'osclass' in nm[ip]:
                    info["Version"] = nm[ip]['osclass'][0].get('osgen', "Unknown")
                    # If version not found in 'osclass', try fetching from service detection
                    if info["Version"] == "Unknown":
                        for proto in nm[ip].all_protocols():
                            lport = nm[ip][proto].keys()
                            for port in lport:
                                info["Version"] = nm[ip][proto][port].get('version', "Unknown")
                                break
                # If version still not found, attempt other methods
                if info["Version"] == "Unknown":
                    # Add additional methods to retrieve version information
                    # Method 1: Perform additional service version scans using different techniques
                    # Method 2: Query devices directly for version information
                    # Method 3: Utilize third-party APIs or databases
                    # Method 4: Extract version information from responses to specific requests (e.g., HTTP headers)
                    pass
            return info
        except Exception as e:
            print(f"Error retrieving device info: {e}")
            return {"OS": "Unknown", "Version": "Unknown"}

    def scan_network(self, start_ip, end_ip):
        active_hosts = []
        try:
            start_ip_obj = ipaddress.ip_address(start_ip)
            end_ip_obj = ipaddress.ip_address(end_ip)
            max_mac_length = 0  # Initialize maximum MAC address length
            for ip in range(int(start_ip_obj), int(end_ip_obj) + 1):
                ip_addr = str(ipaddress.ip_address(ip))
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_addr), timeout=2, verbose=False)
                for sent, received in ans:
                    mac = received.hwsrc
                    hostname = self.resolve_hostname(ip_addr)
                    vendor = self.get_vendor(mac)
                    date = datetime.now().strftime("%Y-%m-%d")
                    info = self.get_device_info(ip_addr)

                    active_hosts.append((ip_addr, mac, hostname, vendor, date, info["OS"], info["Version"]))
                    max_mac_length = max(max_mac_length, len(mac))
            
            # Adjust MAC column width based on the maximum MAC address length
            self.tree.column("MAC", width=max_mac_length * 10)  # Assuming each character takes around 10 pixels width
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
        return active_hosts

    def on_scan(self):
        # Get inputs
        start_ip = self.start_ip_entry.get()
        end_ip = self.end_ip_entry.get()

        # Perform DNS resolution test
        if self.test_dns_resolution('example.com'):
            # Scan network
            active_hosts = self.scan_network(start_ip, end_ip)
            # Populate treeview with results
            for row in self.tree.get_children():
                self.tree.delete(row)
            for host in active_hosts:
                self.tree.insert("", "end", values=host)
        else:
            messagebox.showerror("DNS Error", "Failed to to resolve example.com")

def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

