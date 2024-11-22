```markdown
# Wireless Network Monitor

This Python script monitors your wireless network for new or unknown devices and sends alerts via Telegram. It also provides a web interface to view the detected devices.

## Features

- **Real-time monitoring:**  Continuously scans for wireless devices probing for networks.
- **Telegram alerts:** Sends silent notifications to your Telegram account when a new device is detected.
- **Web interface:** Displays a table of detected devices with their details (SSID, first seen, last seen, RSSI, etc.) on a simple web page.
- **Whitelisting:** Allows you to whitelist known devices to prevent further alerts.
- **Cleanup:**  Removes old, non-whitelisted devices from the tracking list.
- **Daily report:** Sends a daily summary of network activity to Telegram.
- **Ignores common SSIDs:**  Filters out common SSIDs like "house", "netgear", and "spectrum" to reduce noise.
- **Suppresses web server logs:**  Runs the web server silently without logging messages to the console.

## Requirements

- **Python 3:** Make sure you have Python 3 installed.
- **Required libraries:** Install the necessary Python libraries using:
  ```bash
  pip install scapy netifaces requests python-telegram-bot tabulate tqdm
  ```
- **Wireless network interface:** A wireless adapter that supports monitor mode.
- **Airodump-ng:**  Install `airodump-ng` (part of the `aircrack-ng` suite).
- **Telegram bot:** Create a Telegram bot and obtain its token.
- **Telegram chat ID:** Get the chat ID where you want to receive alerts.

## Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/TheOGturn/wifi_scanner/
   ```
2. **Install requirements:**
   ```bash
   pip install -r requirements.txt
   ```
3. **Configure the script:**
   - Open the `wireless_network_monitor.py` script and replace the following placeholders with your actual details:
     - `TELEGRAM_BOT_TOKEN` 
     - `CHAT_ID`
4. **Run the script:**
   ```bash
   sudo python3 wireless_network_monitor.py
   ```

## Usage

- **Access the web interface:** Open a web browser and go to `http://your_server_ip:4567/` to view the detected devices.
- **Whitelist devices:** You can whitelist devices through the web interface or by manually editing the `ssid_info.csv` file.

## Disclaimer

This script is intended for educational and personal use only. Use it responsibly and ethically. Unauthorized monitoring of wireless networks may be illegal in your jurisdiction.
```

