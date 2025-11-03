import time
import pywifi
import time

from spoofmac.util import random_mac_address 
from spoofmac.interface import set_interface_mac

class Wifi:
    def __init__(self):
        self.wifi = pywifi.PyWiFi()
        self.profile = None
        self.iface = None

    def init_interface(self, ifname: str=None):
        self.iface = self.find_interface(ifname)
        #interface name is not valid
        if self.iface == None:
            if ifname != None:
                print(f"Interface {ifname} not found, trying to use another one")
            interfaces = self.get_interfaces()
            if interfaces == [] or interfaces[0] == None:
                raise Exception("[-] Not a single wifi interface was found ! Could not proceed.")
            self.iface = interfaces[0]
            print(f"Interface found, proceed with {self.iface.name()}")

    def find_interface(self, ifname):
        if ifname == None:
            return None
        
        ifaces = self.get_interfaces()
        for iface in ifaces:
            if ifname == iface.name():
                return iface
            
        return None

    def init_profile(self, ssid, auth, key):
        self.ssid = ssid
        self.key = key
        self.auth = auth

        profile = self.find_saved_profile(self.iface, self.ssid)
        if profile == None:
            profile = pywifi.Profile()
            profile.ssid = self.ssid
            profile.auth = self.get_auth(self.auth)
            profile.akm.append(self.get_akm(self.auth))
            profile.cipher = self.get_cipher(self.auth)
            profile.key = self.key

        self.profile = profile

    def get_auth(self, auth):
        if auth == "WEP":
            return pywifi.const.AUTH_ALG_SHARED
        return pywifi.const.AUTH_ALG_OPEN

    def get_akm(self, auth):
        if auth == "WPA":
            return pywifi.const.AKM_TYPE_WPA
        elif auth == "WPA2":
            return pywifi.const.AKM_TYPE_WPA2
        elif auth == "WPAPSK":
            return pywifi.const.AKM_TYPE_WPAPSK
        elif auth == "WPA2PSK":
            return pywifi.const.AKM_TYPE_WPA2PSK
        else:
            return pywifi.const.AKM_TYPE_NONE

    def get_cipher(self, auth):
        if auth == "WPA":
            return pywifi.const.CIPHER_TYPE_TKIP
        elif auth == "WPA2":
            return pywifi.const.CIPHER_TYPE_CCMP
        elif auth == "WPAPSK":
            return pywifi.const.CIPHER_TYPE_TKIP
        elif auth == "WPA2PSK":
            return pywifi.const.CIPHER_TYPE_CCMP
        elif auth == "WEP":
            return pywifi.const.CIPHER_TYPE_WEP
        else:
            return pywifi.const.CIPHER_TYPE_NONE

    def get_key_type(self, auth):
        if auth == "WEP":
            return pywifi.const.KEY_TYPE_NETWORKKEY
        return pywifi.const.KEY_TYPE_PASSPHRASE

    def find_saved_profile(self, iface, ssid):
        profiles = iface.network_profiles()
        for profile in profiles:
            if profile.ssid == ssid:
                return profile
            
        return None
    

    def get_interfaces(self):
        return self.wifi.interfaces()
    
    def parse_auth_akm(self, auth, akm_list):
        auth_str = ""
        if auth == pywifi.const.AUTH_ALG_OPEN:
            auth_str = "OPEN"
        elif auth == pywifi.const.AUTH_ALG_SHARED:
            auth_str = "WEP"
        else:
            auth_str = f"UNKNOWN({auth})"

        akm_names = []
        for akm in akm_list:
            if akm == pywifi.const.AKM_TYPE_NONE:
                akm_names.append("NONE")
            elif akm == pywifi.const.AKM_TYPE_WPA:
                akm_names.append("WPA")
            elif akm == pywifi.const.AKM_TYPE_WPAPSK:
                akm_names.append("WPAPSK")
            elif akm == pywifi.const.AKM_TYPE_WPA2:
                akm_names.append("WPA2")
            elif akm == pywifi.const.AKM_TYPE_WPA2PSK:
                akm_names.append("WPA2PSK")
            elif akm == pywifi.const.AKM_TYPE_UNKNOWN:
                akm_names.append("UNKNOWN")
            else:
                akm_names.append(f"OTHER({akm})")

        return auth_str, ", ".join(akm_names)


    def list_wifi_networks(self, ifnames, scan_wait=2):
        interfaces = []
        if ifnames != []:
            for ifname in ifnames:
                iface = self.find_interface(ifname)
                if iface != None:
                    interfaces.append(iface)
            if interfaces == []:
                print("[-] Invalid interfaces. Aborting...")
                return
        else:
            interfaces = self.get_interfaces()

        if not interfaces:
            print("[-] Not a single wifi interface was found! Aborting...")
            return

        for iface in interfaces:
            print(f"[+] Enumerating networks with {iface.name()}")
            iface.scan()
            time.sleep(scan_wait) #from documentation, we need to wait between 2 and 8 seconds to get scan results
            results = iface.scan_results()
            for r in results:
                auth_str, akm_str = self.parse_auth_akm(r.auth, r.akm)
                print(f"\tSSID: {r.ssid}\n\tBSSID: {r.bssid}\n\tAuth: {auth_str}\n\tAKM: {akm_str}\n")

    def get_status(self, iface):
        """
        return one of this:
            const.IFACE_DISCONNECTED
            const.IFACE_SCANNING
            const.IFACE_INACTIVE
            const.IFACE_CONNECTING
            const.IFACE_CONNECTED
        """
        return self.iface.status() 

    def connection_handler(self, target_mac, ifname, ssid, key, port, local_admin, auth=None, connect_timeout=10):
        try:
            print(f"[+] Setting MAC address {target_mac} on {ifname}")
            set_interface_mac(ifname, target_mac, port)
        except Exception as e:
            print(f"[-] Failed to set MAC address: {e}")
            return

        self.init_interface(ifname)
        iface = self.iface

        if not auth:
            auth = "WPA2PSK"

        self.init_profile(ssid, auth, key)

        print(f"[+] Attempting to connect to '{ssid}' using interface '{ifname}'")

        iface.remove_all_network_profiles()
        tmp_profile = iface.add_network_profile(self.profile)
        iface.connect(tmp_profile)

        start_time = time.time()
        connected = False

        while time.time() - start_time < connect_timeout:
            status = iface.status()
            if status == pywifi.const.IFACE_CONNECTED:
                print(f"[✓] Connected successfully to {ssid}")
                connected = True
                break
            else:
                print(f"[~] Waiting for connection... (status: {status})")
                time.sleep(1)

        if not connected:
            iface.disconnect()
            print(f"[-] Connection to '{ssid}' timed out after {connect_timeout}s")
            return

        while True:
            status = iface.status()
            if status == pywifi.const.IFACE_DISCONNECTED:
                print("[!] Interface disconnected. Retrying with random MAC...")
                new_mac = random_mac_address(local_admin)
                print(f"[+] New random MAC: {new_mac}")

                try:
                    set_interface_mac(ifname, new_mac, port)
                except Exception as e:
                    print(f"[-] Failed to set random MAC: {e}")
                    time.sleep(3)
                    continue

                iface.disconnect()
                time.sleep(2)
                iface.connect(tmp_profile)

                start_time = time.time()
                reconnected = False
                while time.time() - start_time < connect_timeout:
                    status = iface.status()
                    if status == pywifi.const.IFACE_CONNECTED:
                        print(f"[✓] Reconnected successfully to {ssid}")
                        reconnected = True
                        break
                    else:
                        time.sleep(1)

                if not reconnected:
                    print(f"[-] Reconnection to '{ssid}' timed out after {connect_timeout}s — WiFi may be unavailable.")
                    break

            time.sleep(2)




if __name__ == "__main__":
    # Server_name is a case insensitive string, and/or regex pattern which demonstrates
    # the name of targeted WIFI device or a unique part of it.
    server_name = "example_name"
    password = "your_password"
    interface_name = "wlp0s20f3" # i. e wlp2s0  
    F = Wifi(server_name=server_name,
               password=password,
               interface=interface_name)
    ifaces = F.get_interfaces()
    F.list_wifi_networks(ifaces[0])