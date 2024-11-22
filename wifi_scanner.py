import subprocess
import netifaces
import time
import os
import csv
import requests
import signal
import sys
import select
from datetime import datetime, timedelta
from scapy.all import Dot11ProbeReq, sniff
from tqdm import tqdm
import http.server
import socketserver
import threading

# --- Configuration ---

# Telegram Bot Configuration (replace with your details)

TELEGRAM_BOT_TOKEN = ""  # Replace with your Telegram bot token
CHAT_ID = ""  # Replace with your Telegram chat ID
SCAN_DURATION = 4 * 60  # Scan for 4 minutes
NOTIFICATION_THRESHOLD = 10 * 60  # 10 minutes cooldown for alerts
WHITELIST_THRESHOLD = 5 * 60 * 60  # 5 hours for whitelisting
CLEANUP_THRESHOLD = 1 * 60 * 60  # 1 hour for cleanup
DAILY_REPORT_TIME = 5  # 5 AM local time for the daily report
DATA_FILE = "ssid_info.csv"  # File to store SSID information

# --- Global variables ---
ssid_info = {}  # Dictionary to store SSID information
whitelist = set()  # Set to store whitelisted SSIDs
interrupted = False  # Flag to track if Ctrl+C has been pressed

# --- Web server functions ---
def generate_ssid_table_html(ssid_info):
    """Generates the HTML code for the SSID table."""
    table_html = """
    <table border="1">
      <thead>
        <tr>
          <th>SSID</th>
          <th>First Seen</th>
          <th>Last Seen</th>
          <th>Alerted</th>
          <th>Whitelisted</th>
          <th>RSSI</th>
        </tr>
      </thead>
      <tbody>
    """
    for ssid, info in ssid_info.items():
        table_html += f"""
        <tr>
          <td>{ssid}</td>
          <td>{info["first_seen"].strftime("%Y-%m-%d %H:%M:%S")}</td>
          <td>{info["last_seen"].strftime("%Y-%m-%d %H:%M:%S")}</td>
          <td>{info["alerted"]}</td>
          <td>{info["whitelisted"]}</td>
          <td>{info["rssi"]}</td>
        </tr>
      """
    table_html += """
      </tbody>
    </table>
    """
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
      <title>SSID Monitoring</title>
    </head>
    <body>
      <h1>Detected SSIDs</h1>
      {table_html}
    </body>
    </html>
    """

class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler to serve the SSID table."""
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(generate_ssid_table_html(ssid_info), "utf-8"))
        else:
            super().do_GET()

    def log_message(self, format, *args):
        """Suppress log messages from the web server."""
        pass  # Do nothing to suppress logging

def start_web_server():
    """Starts the web server on port 4567."""
    with socketserver.TCPServer(("", 4567), MyHttpRequestHandler) as httpd:
        httpd.serve_forever()

# --- Network monitoring functions ---
def set_monitor_mode():
    """
    Finds a wireless interface without an IP, sets it to monitor mode,
    runs airodump-ng, and returns the interface name.
    """
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        if iface == 'lo':  # Skip loopback interface
            continue
        if netifaces.ifaddresses(iface).get(netifaces.AF_INET):  # Skip interfaces with IP addresses
            print(f"Skipping interface {iface} (has an IP address).")
            continue
        try:
            print(f"Putting interface {iface} into monitor mode...")
            subprocess.run(['airmon-ng', 'start', iface], check=True)
            monitor_interface = subprocess.check_output(
                ['iwconfig'], universal_newlines=True
            )
            monitor_interface = monitor_interface.split('\n')
            for line in monitor_interface:
                if "Mode:Monitor" in line:
                    monitor_interface = line.split()[0]
                    break
            else:
                print(f"Could not determine monitor interface name for {iface}")
                sys.exit(1)
            command = f"airodump-ng {monitor_interface}"  # Run airodump-ng in the background
            subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return monitor_interface
        except subprocess.CalledProcessError:
            print(f"Interface {iface} does not support monitor mode or an error occurred.")
    print("No suitable interface found for monitor mode.")
    sys.exit(1)

def send_silent_message(message):
    """Sends a silent Telegram message to the specified chat ID."""
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": CHAT_ID,
        "text": message,
        "disable_notification": True  # Enable silent notification
    }
    try:
        requests.post(url, data=data)
        # Removed print statement here
    except requests.exceptions.RequestException as e:
        print(f"Error sending Telegram message: {e}")

def load_ssid_info():
    """Loads SSID information from the CSV file."""
    ssid_info = {}
    try:
        with open(DATA_FILE, 'r', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                ssid = row['SSID']
                try:
                    ssid_info[ssid] = {
                        'first_seen': datetime.strptime(row['First Seen'], '%Y-%m-%d %H:%M:%S'),
                        'last_seen': datetime.strptime(row['Last Seen'], '%Y-%m-%d %H:%M:%S'),
                        'alerted': row['Alerted'] == 'True',
                        'whitelisted': row['Whitelisted'] == 'True',
                        'rssi': int(row['RSSI']) if 'RSSI' in row else -100
                    }
                except ValueError as e:
                    print(f"Error parsing date in CSV for SSID {ssid}: {e}")
    except (FileNotFoundError, IOError) as e:
        print(f"Error loading SSID information: {e}")
    return ssid_info

def save_ssid_info(ssid_info):
    """Saves SSID information to the CSV file."""
    try:
        with open(DATA_FILE, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['SSID', 'First Seen', 'Last Seen', 'Alerted', 'Whitelisted', 'RSSI']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for ssid, info in ssid_info.items():
                writer.writerow({
                    'SSID': ssid,
                    'First Seen': info['first_seen'].strftime('%Y-%m-%d %H:%M:%S'),
                    'Last Seen': info['last_seen'].strftime('%Y-%m-%d %H:%M:%S'),
                    'Alerted': str(info['alerted']),
                    'Whitelisted': str(info['whitelisted']),
                    'RSSI': info['rssi']
                })
    except (IOError, PermissionError) as e:
        print(f"Error saving SSID information: {e}")

def sniff_packets(pkt):
    """Processes sniffed network packets."""
    if pkt.haslayer(Dot11ProbeReq):
        ssid = pkt[Dot11ProbeReq].info.decode('utf-8')
        now = datetime.now()
        rssi = pkt.dBm_AntSignal  # Get RSSI value
        if not ssid:  # Check if SSID is empty (hidden SSID)
            ssid = "Hidden"
        if any(keyword in ssid.lower() for keyword in ["house", "netgear", "spectrum"]):  # Ignore common SSIDs
            return  # Skip this SSID
        if ssid in ssid_info:
            ssid_info[ssid]['last_seen'] = now
            if rssi > ssid_info[ssid]['rssi']:  # Update strongest RSSI
                ssid_info[ssid]['rssi'] = rssi
        else:
            ssid_info[ssid] = {
                "first_seen": now,
                "last_seen": now,
                "alerted": False,
                "whitelisted": False,
                "rssi": rssi
            }
        elapsed_time = (now - ssid_info[ssid]["first_seen"]).total_seconds()
        if not ssid_info[ssid]["alerted"] and not ssid_info[ssid]["whitelisted"] and \
           NOTIFICATION_THRESHOLD < elapsed_time < WHITELIST_THRESHOLD:  # Check for notifications
            message = f"SSID {ssid} has been seen for {elapsed_time / 60:.2f} minutes. Consider investigating."
            send_silent_message(message)
            ssid_info[ssid]["alerted"] = True
        elif elapsed_time >= WHITELIST_THRESHOLD and not ssid_info[ssid]["whitelisted"]:  # Check for whitelisting
            ssid_info[ssid]["whitelisted"] = True
            whitelist.add(ssid)

def clean_up_ssids():
    """Removes old, non-whitelisted SSIDs from tracking."""
    now = datetime.now()
    for ssid, info in list(ssid_info.items()):
        if (now - info["last_seen"]).total_seconds() > CLEANUP_THRESHOLD and not info["whitelisted"]:
            print(f"SSID {ssid} has not been seen for {CLEANUP_THRESHOLD / 60} minutes. Removing from tracking.")
            del ssid_info[ssid]

def send_daily_report(previous_ssid_info):
    """Sends a daily report of network activity to Telegram."""
    today = datetime.now()
    yesterday = today - timedelta(days=1)
    new_ssids = [ssid for ssid, info in ssid_info.items() if info['first_seen'] >= yesterday]
    whitelisted_ssids = [ssid for ssid, info in ssid_info.items() if info['whitelisted']]
    removed_ssids = [ssid for ssid, info in previous_ssid_info.items() if ssid not in ssid_info]
    message = f"**Daily Network Activity Report ({today.strftime('%Y-%m-%d')})**\n\n"
    if new_ssids:
        message += "**New SSIDs Detected:**\n"
        for ssid in new_ssids:
            message += f"- {ssid}\n"
    if whitelisted_ssids:
        message += "\n**Whitelisted SSIDs:**\n"
        for ssid in whitelisted_ssids:
            message += f"- {ssid}\n"
    if removed_ssids:
        message += "\n**Removed SSIDs:**\n"
        for ssid in removed_ssids:
            message += f"- {ssid}\n"
    send_silent_message(message)
    return ssid_info.copy()

def display_ssid_table(ssid_info):
    """Displays SSID information in a formatted table."""
    os.system('clear')
    table_data = [
        ["Line", "SSID", "First Seen", "Last Seen", "Alerted", "Whitelisted", "RSSI"]
    ]
    line_num = 1
    for ssid, info in ssid_info.items():
        table_data.append([
            line_num,
            ssid,
            info["first_seen"].strftime("%Y-%m-%d %H:%M:%S"),
            info["last_seen"].strftime("%Y-%m-%d %H:%M:%S"),
            info["alerted"],
            info["whitelisted"],
            info["rssi"]
        ])
        line_num += 1
    print(tabulate.tabulate(table_data, headers="firstrow", tablefmt="grid"))

def handle_whitelist_input(ssid_info):
    """Handles user input for whitelisting SSIDs."""
    if not ssid_info:
        return
    display_ssid_table(ssid_info)
    print("Enter the line numbers of SSIDs to whitelist (comma-separated), "
          "or leave blank to continue without whitelisting:")
    ready, _, _ = select.select([sys.stdin], [], [], 30)
    if ready:
        whitelist_input = input()
    else:
        print("Timeout reached. Continuing without whitelisting.")
        return
    if whitelist_input.strip():
        try:
            whitelist_lines = [int(line) for line in whitelist_input.split(',')]
            for line_num in whitelist_lines:
                if 1 <= line_num <= len(ssid_info):
                    ssid_to_whitelist = list(ssid_info.keys())[line_num - 1]
                    ssid_info[ssid_to_whitelist]['whitelisted'] = True
                    print(f"SSID {ssid_to_whitelist} whitelisted.")
                else:
                    print(f"Invalid line number: {line_num}")
        except ValueError:
            print("Invalid input. Please enter line numbers separated by commas.")

def main():
    """Main function to run the script."""
    global ssid_info, previous_ssid_info, daily_report_sent, interrupted
    ssid_info = load_ssid_info()
    previous_ssid_info = ssid_info.copy()
    daily_report_sent = False
    interrupted = False
    monitor_interface = set_monitor_mode()
    def signal_handler(sig, frame):
        print("\nExiting...")
        try:  # Stop monitor mode
            original_iface = monitor_interface[:-3]
            subprocess.run(['airmon-ng', 'stop', monitor_interface], check=True)
            print(f"Monitor mode stopped on {original_iface}")
        except subprocess.CalledProcessError as e:
            print(f"Error stopping monitor mode: {e}")
        save_ssid_info(ssid_info)
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)  # Handle Ctrl+C
    if not ssid_info:
        print("No SSIDs found in the CSV file. Starting a new scan.")
    handle_whitelist_input(ssid_info)
    save_ssid_info(ssid_info)
    web_server_thread = threading.Thread(target=start_web_server)  # Start the web server in a separate thread
    web_server_thread.daemon = True
    web_server_thread.start()
    while True:
        try:
            with tqdm(total=SCAN_DURATION, desc="Scanning", unit="s") as pbar:  # Scan with progress bar
                for _ in range(SCAN_DURATION):
                    sniff(prn=sniff_packets, iface=monitor_interface, timeout=1)
                    pbar.update(1)
        except OSError as e:
            print(f"Error during sniffing: {e}")
        except KeyboardInterrupt:
            print("\nCtrl+C pressed. Exiting...")
            interrupted = True
            break
        handle_whitelist_input(ssid_info)  # Prompt for whitelisting after every scan (optional)
        save_ssid_info(ssid_info)
        clean_up_ssids()
        now = datetime.now()
        if now.hour == DAILY_REPORT_TIME and now.minute >= 0 and not daily_report_sent:  # Send daily report
            previous_ssid_info = send_daily_report(previous_ssid_info)
            daily_report_sent = True
        if now.hour == 0:  # Reset daily report flag at midnight
            daily_report_sent = False
        if interrupted:  # Check if Ctrl+C was pressed
            break

if __name__ == "__main__":
    main()
