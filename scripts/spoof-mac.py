#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""SpoofMAC

Usage:
    spoof-mac list [--wifi]
    spoof-mac randomize [--local] <devices>...
    spoof-mac set <mac> <devices>...
    spoof-mac reset <devices>...
    spoof-mac normalize <mac>
    spoof-mac networks  [--scan-wait=SEC] [<devices>...]
    spoof-mac connect <mac> <device> <ssid> <key> [--local] [--auth=AUTH] [--connect-timeout=SEC]
    spoof-mac -h | --help
    spoof-mac --version

Options:

    -h --help               Shows this message.
    --version               Show package version.
    --wifi                  Try to only show wireless interfaces.
    --local                 Set the locally administered flag on randomized MACs.

    --auth=AUTH             Authentication method [default: WPA2PSK]
    --scan-wait=SEC         Seconds to wait after initiating scan [default: 2.0]
    --connect-timeout=SEC   Timeout seconds for connection attempt [default: 10]

"""
import sys
import os

if sys.platform == 'win32':
    import ctypes

from docopt import docopt

from spoofmac.version import __version__
from spoofmac.util import *
from spoofmac.wifi import Wifi

from spoofmac.interface import (
    wireless_port_names,
    find_interfaces,
    find_interface,
    set_interface_mac,
    get_os_spoofer
)

# Return Codes
SUCCESS = 0
INVALID_ARGS = 1001
UNSUPPORTED_PLATFORM = 1002
INVALID_TARGET = 1003
INVALID_MAC_ADDR = 1004
NON_ROOT_USER = 1005


def list_interfaces(args, spoofer):
    targets = []

    # Should we only return prospective wireless interfaces?
    if args['--wifi'] or args['connect'] or args['networks']:
        targets += wireless_port_names

    for port, device, address, current_address in spoofer.find_interfaces(targets=targets):
        line = []
        line.append('[+] "{port}"'.format(port=port))
        line.append('on device "{device}"'.format(device=device))
        if address:
            line.append('with MAC address {mac}'.format(mac=address))
        if current_address and address != current_address:
            line.append('currently set to {mac}'.format(mac=current_address))
        print(' '.join(line))


def main(args, root_or_admin):
    spoofer = None

    try:
        spoofer = get_os_spoofer()
    except NotImplementedError:
        return UNSUPPORTED_PLATFORM

    if args['list']:
        if args['--wifi']:
            wifi = Wifi()
            for iface in wifi.get_interfaces():
                print(f"[+] {iface.name()}\t({' '.join([p.ssid for p in iface.network_profiles()])})")
            if len(wifi.get_interfaces()) == 0:
                print("[-] No wifi interfaces Found")
        else:
            list_interfaces(args, spoofer)
    elif args['networks']:
        scan_wait = float(args['--scan-wait'])
        wifi = Wifi()
        wifi.list_wifi_networks(args['<devices>'], scan_wait)
    elif args['randomize'] or args['set'] or args['reset']:
        targets = args['<devices>']
        for target in targets:
            # Fill out the details for `target`, which could be a Hardware
            # Port or a literal device.
            #print("Debuf:",target)
            result = find_interface(target)
            if result is None:
                print(f'[-] couldn\'t find the device for {target}')
                return INVALID_TARGET

            port, device, address, current_address = result
            if args['randomize']:
                target_mac = random_mac_address(args['--local'])
            elif args['set']:
                target_mac = args['<mac>']
                if int(target_mac[1], 16) % 2:
                    print('Warning: The address you supplied is a multicast address and thus can not be used as a host address.')
                if not read_saved_mac(target):
                    save_mac(spoofer.get_interface_mac(target).split(" ")[1], target)
            elif args['reset']:
                if address is None:
                    print('- {target} missing hardware MAC'.format(
                        target=target
                    ))
                    continue
                target_mac = read_saved_mac(target)
                if not target_mac:
                    print("[-] Couldn't read saved mac address.")

            if not MAC_ADDRESS_R.match(target_mac):
                print('[-] {mac} is not a valid MAC address'.format(
                    mac=target_mac
                ))
                return INVALID_MAC_ADDR

            if not root_or_admin:
                if sys.platform == 'win32':
                    print('Error: Must run this with administrative privileges to set MAC addresses')
                    return NON_ROOT_USER
                else:
                    print('Error: Must run this as root (or with sudo) to set MAC addresses')
                    return NON_ROOT_USER

            set_interface_mac(device, target_mac, port)
    elif args['normalize']:
        print(normalize_mac_address(args['<mac>']))
        

    elif args['connect']:
        ssid = args['<ssid>']
        key = args['<key>']
        auth = args['--auth']
        timeout = int(args['--connect-timeout'])
        target_mac = args['<mac>']
        if target_mac == 'random':
            target_mac = random_mac_address(args['--local'])
        ifname = args['<device>']

        result = find_interface(ifname)
        if result is None:
            print(f'[-] couldn\'t find the device for {ifname}')
            return INVALID_TARGET
        
        port, _, _, _ = result

        if not read_saved_mac(ifname):
            save_mac(spoofer.get_interface_mac(ifname).split(" ")[1], ifname)

        wifi = Wifi()
        wifi.connection_handler(target_mac, ifname, ssid, key, port, args['--local'], auth, timeout)
        

    else:
        print('Error: Invalid arguments - check help usage')
        return INVALID_ARGS

    del spoofer

    return SUCCESS


if __name__ == '__main__':
    arguments = docopt(__doc__, version=__version__)
    try:
        root_or_admin = os.geteuid() == 0
    except AttributeError:
        root_or_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    sys.exit(main(arguments, root_or_admin))
