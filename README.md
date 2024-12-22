# Catchexpert

**Catchexpert** is a Python-based network scanning tool designed to identify active devices, open ports, and potential vulnerabilities within a specified IP range.
It combines a user-friendly GUI with advanced scanning techniques to assist network administrators and 
cybersecurity enthusiasts in maintaining secure and efficient networks.

---

## Features

- **Graphical User Interface (GUI):** Intuitive interface built with `Tkinter` for ease of use.
- **Device Discovery:** Detects active devices on a network using ARP requests.
- **Detailed Device Information:** Retrieves IP, MAC address, hostname, vendor, OS, and version information.
- **Advanced Scanning:** Leverages `nmap` for in-depth OS and service detection.
- **Error Handling:** Includes robust error handling for DNS resolution, vendor retrieval, and device
-  information.
- **Vendor Identification:** Uses the `manuf` library with an online fallback for accurate
-  MAC address vendor data.

---

## Prerequisites

Before running the project, ensure the following are installed on your system:

- Python 3.8 or later
- Required Python libraries (see `requirements.txt`)

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/catchexpert.git
   cd catchexpert
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

1. Run the main application:
   ```bash
   python main.py
   ```

2. Enter the IP range in the GUI (Start IP and End IP).
3. Click the **Scan** button to initiate the network scan.
4. View the results in the table, including IP, MAC, hostname, vendor, OS, and version information.

---

## Project Structure

- **`final_code`**: Entry point for the application.
- **`scanner_gui.py`**: Contains the GUI implementation.
- **`requirements.txt`**: Lists all dependencies.

---

## Dependencies

- `nmap`
- `requests`
- `scapy`
- `manuf`
- `tkinter`


---

Special thanks to the developers of:
- `nmap` for their powerful network scanning tool.
- `scapy` for its robust packet manipulation capabilities.
- `manuf` for simplifying MAC address vendor identification.

---

"Catch the vulnerabilities, be the expert!"

