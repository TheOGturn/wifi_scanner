import subprocess
import netifaces
import time
import os
import csv
import requests
import signal
import sys
import select
import tabulate
from datetime import datetime, timedelta
from scapy.all import Dot11ProbeReq, sniff
from tqdm import tqdm
import http.server
import socketserver
import threading
from collections import OrderedDict
from urllib.parse import urlparse, parse_qs
import logging

# --- Configuration ---

# Telegram Bot Configuration (replace with your details)

TELEGRAM_BOT_TOKEN = ""  # Replace with your Telegram bot token
CHAT_ID = ""  # Replace with your Telegram chat ID
SCAN_DURATION = 4 * 60  # Scan for 4 minutes
NOTIFICATION_THRESHOLD = 10 * 60  # 10 minutes cooldown for alerts
WHITELIST_THRESHOLD = 5 * 60 * 60  # 5 hours for whitelisting
CLEANUP_THRESHOLD = 30 * 60  # 1 hour for cleanup was 1 * 60 * 60
DAILY_REPORT_TIME = 5  # 5 AM local time for the daily report
DATA_FILE = "ssid_info.csv"  # File to store SSID information

# --- Global variables ---
ssid_info = {}  # Dictionary to store SSID information
whitelist = set()  # Set to store whitelisted SSIDs
interrupted = False  # Flag to track if the server has been stopped
httpd = None  # Add this for the global httpd object
logging.basicConfig(filename='ssid_monitor.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Web server functions ---
def generate_ssid_table_html(ssid_info):
    """Generates the HTML code for the SSID table with checkboxes and whitelist button."""
    table_html = """
    <table border="1">
        <thead>
            <tr>
                <th>Whitelist</th>
                <th>SSID</th>
                <th>First Seen</th>
                <th>Last Seen</th>
                <th>Alerted</th>
                <th>Whitelisted</th>
                <th>RSSI</th>
            </tr>
        </thead>
        <tbody>
        <form method="POST">
    """

    # Sort ssid_info by RSSI in descending order (strongest first)
    sorted_ssid_info = OrderedDict(
        sorted(ssid_info.items(), key=lambda item: item[1]['rssi'],
               reverse=True))

    for ssid, info in sorted_ssid_info.items():
        checked = 'checked' if info['whitelisted'] else ''
        table_html += f"""
        <tr>
            <td><input type="checkbox" name="ssid" value="{ssid}" {checked}></td>
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
    <button type="submit">Whitelist Selected SSIDs</button>
    </form>
    """
    # Get the last 10 log messages
    log_messages = get_log_messages()

    # Add a div to display the log messages
    table_html += f"""
    <h2>Activity Log</h2>
    <div id="log-window">{log_messages}</div>
    <script>
    // Refresh the page after 10 seconds
    setTimeout(function(){{ location.reload(); }}, 10000);
    </script>
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


def get_log_messages(num_messages=10):
    """Reads the last 'num_messages' lines from the log file and formats them as an HTML table."""
    with open('ssid_monitor.log', 'r') as f:
        lines = f.readlines()[-num_messages:]
        lines.reverse()  # Reverse the order of lines

    table_html = """
    <table border="1">
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Level</th>
                <th>Message</th>
            </tr>
        </thead>
        <tbody>
    """
    for line in lines:
        try:
            timestamp, level, message = line.strip().split(" - ", 2)
            
            # Remove milliseconds from the timestamp
            timestamp = timestamp.split(".")[0]  

            table_html += f"""
            <tr>
                <td>{timestamp}</td>
                <td>{level}</td>
                <td>{message}</td>
            </tr>
            """
        except ValueError:
            pass  # Ignore lines that don't match the expected format
    table_html += "</tbody></table>"
    return table_html


class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler to serve the SSID table and handle POST requests."""

    def do_GET(self):
        """Handles GET requests to display the SSID table."""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes(generate_ssid_table_html(ssid_info), "utf-8"))

    def do_POST(self):
        """Handles POST requests to whitelist the selected SSID."""
        global ssid_info
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode("utf-8")
        parsed_data = parse_qs(post_data)  


        if 'ssid' in parsed_data:
            ssids_to_whitelist = parsed_data[
                'ssid']  # Get list of selected SSIDs
            # Make sure to iterate over a *copy* of the keys, as you're modifying the dictionary during iteration
            for ssid in list(ssid_info.keys()):
                if ssid not in ssids_to_whitelist:
                    ssid_info[ssid]['whitelisted'] = False
                else:
                    ssid_info[ssid]['whitelisted'] = True
                    logging.info(f"SSID {ssid} whitelisted from web.")

        self.send_response(303)  # Redirect after POST
        self.send_header('Location', '/')
        self.end_headers()

    def log_message(self, format, *args):
        """Suppress log messages from the web server."""
        pass  # Do nothing to suppress logging


def start_web_server():
    """Starts the web server on port 4567."""
    global interrupted, httpd
    httpd = socketserver.TCPServer(("", 4567), MyHttpRequestHandler)
    while not interrupted:
        httpd.handle_request()


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
        if netifaces.ifaddresses(iface).get(
                netifaces.AF_INET):  # Skip interfaces with IP addresses
            print(f"Skipping interface {iface} (has an IP address).")
            continue
        try:
            print(f"Putting interface {iface} into monitor mode...")
            subprocess.run(['airmon-ng', 'start', iface], check=True)
            monitor_interface = subprocess.check_output(
                ['iwconfig'], universal_newlines=True)
            monitor_interface = monitor_interface.split('\n')
            for line in monitor_interface:
                if "Mode:Monitor" in line:
                    monitor_interface = line.split()[0]
                    break
            else:
                print(
                    f"Could not determine monitor interface name for {iface}")
                sys.exit(1)
            command = f"airodump-ng {monitor_interface}"  # Run airodump-ng in the background
            subprocess.Popen(command,
                             shell=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
            return monitor_interface
        except subprocess.CalledProcessError:
            print(
                f"Interface {iface} does not support monitor mode or an error occurred."
            )
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
                        'first_seen':
                        datetime.strptime(row['First Seen'],
                                          '%Y-%m-%d %H:%M:%S'),
                        'last_seen':
                        datetime.strptime(row['Last Seen'],
                                          '%Y-%m-%d %H:%M:%S'),
                        'alerted':
                        row['Alerted'] == 'True',
                        'whitelisted':
                        row['Whitelisted'] == 'True',
                        'rssi':
                        int(row['RSSI']) if 'RSSI' in row else -100
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
            fieldnames = [
                'SSID', 'First Seen', 'Last Seen', 'Alerted', 'Whitelisted',
                'RSSI'
            ]
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
    global ssid_info
    if pkt.haslayer(Dot11ProbeReq):
        ssid = pkt[Dot11ProbeReq].info.decode('utf-8')
        rssi = pkt.dBm_AntSignal  # Get RSSI value

        # Ignore hidden SSIDs with RSSI >= -30
        if not ssid and rssi >= -55:
            return

        now = datetime.now()
        if not ssid:  # Check if SSID is empty (hidden SSID)
            ssid = "Hidden"
        if any(keyword in ssid.lower()
               for keyword in ["house", "netgear", "spectrum"]
              ):  # Ignore common SSIDs
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
        if not ssid_info[ssid]["alerted"] and not ssid_info[ssid][
                "whitelisted"] and NOTIFICATION_THRESHOLD < elapsed_time < WHITELIST_THRESHOLD:  # Check for notifications
            message = f"SSID {ssid} has been seen for {elapsed_time / 60:.2f} minutes. Consider investigating."
            send_silent_message(message)
            ssid_info[ssid]["alerted"] = True
            logging.info(f"Sent alert for SSID: {ssid}")
        elif elapsed_time >= WHITELIST_THRESHOLD and not ssid_info[ssid][
                "whitelisted"]:  # Check for whitelisting
            ssid_info[ssid]["whitelisted"] = True
            whitelist.add(ssid)
            logging.info(f"Whitelisted SSID: {ssid}")


def clean_up_ssids():
    """Removes old, non-whitelisted SSIDs from tracking."""
    global ssid_info
    now = datetime.now()
    for ssid, info in list(ssid_info.items()):
        if (now - info["last_seen"]).total_seconds() > CLEANUP_THRESHOLD and not info[
                "whitelisted"]:
            logging.info(
                f"SSID {ssid} has not been seen for {CLEANUP_THRESHOLD / 60} minutes. Removing from tracking."
            )
            del ssid_info[ssid]


def send_daily_report(previous_ssid_info):
    """Sends a daily report of network activity to Telegram."""
    today = datetime.now()
    yesterday = today - timedelta(days=1)
    new_ssids = [
        ssid for ssid, info in ssid_info.items() if info['first_seen'] >= yesterday
    ]
    whitelisted_ssids = [
        ssid for ssid, info in ssid_info.items() if info['whitelisted']
    ]
    removed_ssids = [
        ssid for ssid, info in previous_ssid_info.items()
        if ssid not in ssid_info
    ]
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
    """Displays SSID information in a formatted table, sorted by RSSI."""
    os.system('clear')
    table_data = [
        ["Line", "SSID", "First Seen", "Last Seen", "Alerted", "Whitelisted",
         "RSSI"]
    ]
    line_num = 1

    # Sort ssid_info by RSSI in descending order (strongest first)
    sorted_ssid_info = OrderedDict(
        sorted(ssid_info.items(), key=lambda item: item[1]['rssi'],
               reverse=True))

    for ssid, info in sorted_ssid_info.items():  # Use the sorted dictionary
        table_data.append([
            line_num, ssid,
            info["first_seen"].strftime("%Y-%m-%d %H:%M:%S"),
            info["last_seen"].strftime("%Y-%m-%d %H:%M:%S"),
            info["alerted"], info["whitelisted"], info["rssi"]
        ])
        line_num += 1
    print(tabulate.tabulate(table_data, headers="firstrow", tablefmt="grid"))




def main():
    """Main function to run the script."""
    global ssid_info, previous_ssid_info, daily_report_sent, interrupted, httpd
    ssid_info = load_ssid_info()
    previous_ssid_info = ssid_info.copy()
    daily_report_sent = False
    interrupted = False
    monitor_interface = set_monitor_mode()

    def signal_handler(sig, frame):
        """Handles SIGINT signal (Ctrl+C) to stop the server."""
        global interrupted, httpd
        print("\nExiting...")
        interrupted = True  # Set the flag to stop the server
        if httpd:
            httpd.shutdown()  # Stop the server
        try:  # Stop monitor mode
            original_iface = monitor_interface[:-3]
            subprocess.run(['airmon-ng', 'stop', monitor_interface], check=True)
            print(f"Monitor mode stopped on {original_iface}")
        except subprocess.CalledProcessError as e:
            print(f"Error stopping monitor mode: {e}")
        save_ssid_info(ssid_info)
        sys.exit(0)  # Exit the program

    signal.signal(signal.SIGINT, signal_handler)  # Handle Ctrl+C

    web_server_thread = threading.Thread(target=start_web_server)
    web_server_thread.daemon = True
    web_server_thread.start()

    while True:
        try:
            # Removed the non-blocking sniffing loop
            sniff(prn=sniff_packets, iface=monitor_interface, timeout=SCAN_DURATION)  
        except OSError as e:
            print(f"Error during sniffing: {e}")
        except KeyboardInterrupt:
            print("\nCtrl+C pressed. Exiting...")
            interrupted = True
            break  # Exit the loop

        save_ssid_info(ssid_info)
        clean_up_ssids()
        now = datetime.now()
        if now.hour == DAILY_REPORT_TIME and now.minute >= 0 and not daily_report_sent:  # Send daily report
            previous_ssid_info = send_daily_report(previous_ssid_info)
            daily_report_sent = True
        if now.hour == 0:  # Reset daily report flag at midnight
            daily_report_sent = False
        if interrupted:  # Check if Ctrl+C was pressed
            break  # Exit the loop

if __name__ == "__main__":
    main()
