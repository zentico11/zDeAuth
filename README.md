# Zentico DeAuth Wi-Fi Attack GUI Tool

## Overview

This Python-based GUI application allows you to scan nearby Wi-Fi networks and perform various Wi-Fi attacks such as Deauthentication, Beacon Flood, and Authentication Flood. It leverages your wireless adapter's **monitor mode** and uses the **Scapy** library to craft and send custom packets.

---

## Features

- List available wireless network adapters
- Enable/Disable monitor mode on selected adapter
- Scan nearby Wi-Fi networks with live updates
- Select one or multiple target networks for attack (multi-selection supported)
- Choose attack type: Deauth, Beacon Flood, Auth Flood
- Adjust attack speed with a delay slider (1 ms to 1000 ms)
- Start and stop attacks smoothly
- Real-time attack statistics (packets sent, elapsed time)
- Event logging within the GUI

---

## Requirements

- Python 3.x
- Scapy Python Library
- **tkinter** (usually included in Python standard library)
- Linux OS with wireless adapter supporting monitor mode and packet injection
- `aircrack-ng` suite installed (for `airodump-ng` scanning)
- Root privileges to run the script and control network interfaces

---

## Installation

1. Download or clone the repository.
2. Install dependencies:
    ```bash
    pip install scapy
    sudo apt-get install aircrack-ng
    ```
3. Run the script as root:
    ```bash
    sudo python3 wifi_attack_gui.py
    ```

---

## How It Works

### 1. Adapter Selection  
Click **Refresh** to list all available wireless adapters. Select your desired adapter from the dropdown menu.

### 2. Enable Monitor Mode  
Click **Enable Monitor** to switch your wireless adapter into monitor mode, enabling packet sniffing and injection.

### 3. Scan Networks  
Press **Scan** to start scanning nearby Wi-Fi networks. Results appear in a list showing SSID and MAC address.

### 4. Select Target Networks  
Select one or multiple networks for attack:
- Hold **Ctrl** (or Command on Mac) and click networks to multi-select.
- Selected entries are highlighted.

### 5. Choose Attack Type  
Select the attack type from the dropdown:
- **Deauth**: Sends deauthentication frames to disconnect clients.
- **Beacon Flood**: Sends fake beacon frames to flood the air.
- **Auth Flood**: Sends authentication request frames repeatedly.

### 6. Adjust Attack Speed  
Use the slider to set the delay between packets from 1 millisecond (fast) up to 1000 milliseconds (slow).

### 7. Start Attack  
Click **Start Attack** to launch the selected attack against the chosen targets.

### 8. Stop Attack  
Click **Stop Attack** or disable monitor mode to stop the attack cleanly.

---

## Important Notes

- **Monitor mode must be enabled before scanning or attacking.**  
- Attacks will stop automatically if monitor mode is disabled.  
- Root privileges are required for all operations.  
- Only attack networks you own or have explicit permission to test. Unauthorized attacks are illegal and unethical.  

---

## Troubleshooting

- Ensure your wireless adapter supports monitor mode and packet injection.  
- Verify `aircrack-ng` is installed and working (`airodump-ng` command).  
- If scanning fails, check adapter status and permissions.  
- Adjust the delay slider if the attack is too slow or too fast.  

---

## Keyboard Shortcuts

- **Ctrl + Click** (or Command + Click on Mac): Select multiple networks for simultaneous attack.

---

## Author

Created by Zentico - Zentico11

---

Feel free to customize and extend this tool responsibly. If you need help or additional features, just ask!
