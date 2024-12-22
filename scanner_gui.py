import tkinter as tk
from tkinter import ttk, messagebox
import socket
import os
import subprocess

# Network scanning functions
def scan_network(start_ip, end_ip):
    """Scans the network in the given IP range."""
    active_hosts = []
    # Example: For simplicity, this will just add a few dummy hosts
    # In a real-world scenario, you would use a library like scapy or subprocess to perform actual network scanning.
    for ip in range(int(start_ip.split('.')[-1]), int(end_ip.split('.')[-1]) + 1):
        ip_address = '.'.join(start_ip.split('.')[:-1]) + f'.{ip}'
        active_hosts.append((ip_address, "00:00:00:00:00:00", "hostname", "Vendor", "2024-12-22", "Linux", "1.0"))
    return active_hosts

def test_dns_resolution(domain):
    """Tests if DNS resolution works for the given domain."""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.error:
        return False

# GUI for Network Scanner
class NetworkScannerGUI:
    def __init__(self, root):
        # Initialize main GUI window
        self.root = root
        self.root.title("Network Scanner")
        
        # Set up Treeview for displaying results
        self.setup_treeview()
        
        # Input fields for IP range
        self.setup_inputs()

        # Scan button
        self.scan_button = tk.Button(root, text="Scan", command=self.on_scan)
        self.scan_button.grid(row=3, column=0, columnspan=2, pady=10)

    def setup_treeview(self):
        """Sets up the Treeview widget to display scan results."""
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview.Heading", font=('Helvetica', 10, 'bold'))
        style.configure("Treeview", font=('Helvetica', 10))
        
        columns = ("IP", "MAC", "Hostname", "Vendor", "Date", "OS", "Version")
        self.tree = ttk.Treeview(self.root, columns=columns, show='headings', selectmode="browse")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center", minwidth=100, stretch=True)
        self.tree.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky='nsew')

    def setup_inputs(self):
        """Sets up input fields for IP range."""
        tk.Label(self.root, text="Start IP:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
        self.start_ip_entry = tk.Entry(self.root)
        self.start_ip_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        tk.Label(self.root, text="End IP:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
        self.end_ip_entry = tk.Entry(self.root)
        self.end_ip_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

    def on_scan(self):
        """Handles the Scan button click."""
        start_ip = self.start_ip_entry.get()
        end_ip = self.end_ip_entry.get()
        
        if test_dns_resolution('example.com'):
            active_hosts = scan_network(start_ip, end_ip)
            for row in self.tree.get_children():
                self.tree.delete(row)
            for host in active_hosts:
                self.tree.insert("", "end", values=host)
        else:
            messagebox.showerror("DNS Error", "Failed to resolve example.com")

# Main function to run the application
def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
