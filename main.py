import ipaddress
import os
import subprocess

terminals = ['x-terminal-emulator', 'gnome-terminal', 'konsole', 'xfce4-terminal']
gateway = '192.168.100.1'
dhcp_range_start = '192.168.100.2'
dhcp_range_end = '192.168.100.192'
dhcp_range_mask = '255.255.255.0'
channel = '1'
interface = ''
internet_facing_interface = ''
ssid = 'localnet'
ssid_password = 'password'


def red(string):
    return f'\033[91m{string}\033[0m'

def clear():
    subprocess.run('clear')


def green(string):
    return f'\033[92m{string}\033[0m'

def change_interface():
    global interface
    print("Available Network Interfaces: \n")
    interfaces = run_command("iw dev | grep Interface | awk '{print $2}'").split('\n')
    select_with_number = []
    interface_count = 0
    for intf in interfaces:
        if intf != '':
            interface_count += 1
            select_with_number.append([interface_count, intf])
            print(f'{green(select_with_number[interface_count - 1][0])}) {select_with_number[interface_count - 1][1]}')
    while True:
        selection = input(f"\nEnter the number of the interface {green('(type exit to return)')} : ")
        if selection.lower() == 'exit':
            break
        elif selection.isnumeric():
            if interface_count >= int(selection) > 0:
                interface = select_with_number[int(selection) - 1][1]
                break
            elif int(selection) > interface_count:
                print(f'Selected interface ({selection}) {red("does not exist")}')

def change_internet_facing_interface():
    global internet_facing_interface
    print("Available Network Interfaces: \n")
    interfaces = run_command("ip link show | grep UP | awk -F: '{print $2}'").split('\n')
    select_with_number = []
    interface_count = 0
    for intf in interfaces:
        intf = intf.strip()
        if intf != '' and intf != internet_facing_interface:
            interface_count += 1
            select_with_number.append([interface_count, intf])
            print(f'{green(select_with_number[interface_count - 1][0])}) {select_with_number[interface_count - 1][1]}')
    while True:
        selection = input(f"\nEnter the number of the interface {green('(type exit to return)')} : ")
        if selection.lower() == 'exit':
            break
        if selection.isnumeric():
            if interface_count >= int(selection) > 0:
                internet_facing_interface = select_with_number[int(selection) - 1][1]
                break
            elif int(selection) > interface_count:
                print(f'Selected interface ({selection}) {red("does not exist")}')

def change_gateway():
    global gateway
    global dhcp_range_start
    global dhcp_range_end
    # pattern = r'^\d{3}:\d{3}:\d{3}:1'
    #     # ^ : start of string
    #     # \d{3}: exactly 3 digits
    while 1:
        new_gateway = input(f'\nnew gateway IP / 999 to exit')
        if new_gateway == '999':
            return
        try:
            ip = ipaddress.ip_address(new_gateway)
            if not ip.is_private:
                print('Selected ip is not valid for gateway\n',
                      'use ip in range 10.0.0.0 to 10.255.255.255\n',
                      '172.16.0.0 to 172.31.255.255\n',
                      '192.168.0.0 to 192.168.255.255\n')
            elif ip.is_unspecified or str(ip).endswith(".0") or str(ip).endswith(".255"):
                print('Selected IP is not valid for gateway\n'
                      'gateway IP`s can`t end with 0 or 255'
                      )
            else:
                gateway = str(ip)
                #
                parts = str(ip).split('.')
                parts[-1] = str(int(parts[-1]) +1)
                dhcp_range_start = '.'.join(parts)
                parts[-1] = str(255)
                dhcp_range_end = '.'.join(parts)
                return
        except ValueError:
            print(f'Given input {green(new_gateway)} is not a valid IP Address')

def change_ssid():
    global ssid
    while 1:
        new_ssid = input(
            f'\nnew ssid / type 999 to exit : ')
        if new_ssid == '999':
            return
        if new_ssid:
            print(f'Selected SSID is : {green(new_ssid)}')
            while 1:
                selection = input('Confirm Y/N : ').upper()
                if selection == 'Y':
                    ssid = new_ssid
                    return
                elif selection == 'N':
                    return


def change_password():
    global ssid_password
    while 1:
        new_password = input(
            f'\nnew password / type 999 to exit : ')
        if new_password == '999':
            return
        elif len(new_password) < 8:
            print('Password cannot be smaller than 8 characters/integers')
        elif len(new_password) >= 8:
            print(f'Selected PASSWORD is : {green(new_password)}')
            while 1:
                selection = input('Confirm Y/N : ').upper()
                if selection == 'Y':
                    ssid_password = new_password
                    return
                elif selection == 'N':
                    return


def change_channel():
    global channel
    while 1:
        new_channel = input(
            f'\nnew channel (0 < channel < 15) / type 999 to exit : ')
        if new_channel == '999':
            return
        elif not new_channel.isnumeric():
            print('give an integer between and including 1 and 14')
        elif 1 <= int(new_channel) <= 14:
            print(f'Selected Channel is : {green(new_channel)}')
            while 1:
                selection = input('Confirm Y/N : ').upper()
                if selection == 'Y':
                    channel = new_channel
                    return
                elif selection == 'N':
                    return

def popen_command_new_terminal(command):
    for terminal in terminals:
        try:
            terminal_command = ""
            if terminal == 'gnome-terminal':
                terminal_command = f"{terminal} -e /bin/sh -c '{command}; exec bash'"
            elif terminal == 'konsole':
                terminal_command = f"{terminal} -e /bin/sh -c '{command}; exec bash'"
            elif terminal == 'xfce4-terminal':
                terminal_command = f"{terminal} -e 'bash -c \"{command}; exec bash\"'"
            else:
                terminal_command = f"{terminal} -e 'bash -c \"{command}; exec bash\"'"
            print(f"Executing command: {terminal_command}\n")
            process = subprocess.Popen(terminal_command, shell=True, preexec_fn=os.setsid)
            return process
        except Exception as e:
            print(f"Failed to execute command in {terminal}: {e} \n")

def run_command(command):
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        return result.stdout
    else:
        return result.stderr


def create_file_in_tmp(file, content):
    location = f'/tmp/{file}'
    with open(location, 'w') as new_file:
        for line in content:
            new_file.write(line + "\n")
    print(f'{green(file)} created at {green(location)}')


def dnsmasq():
    conf_content = [
        f'interface={interface}',
        f"log-queries",
        f"log-dhcp",
        f'dhcp-range={dhcp_range_start},{dhcp_range_end},{dhcp_range_mask}24h',
        f'dhcp-option=option:router,{gateway}', # f'dhcp-option=3,{gateway}',
        # f'dhcp-option=option:dns-server,{gateway}', # f'dhcp-option=6,{gateway}',
        # f'listen-address=127.0.0.1',
        # f'server=8.8.8.8',
    ]
    create_file_in_tmp('dnsmasq.conf', conf_content)
    popen_command_new_terminal('dnsmasq -C /tmp/dnsmasq.conf -d')


def hostapd(WPA2=True):
    if WPA2:
        conf_content = [
            f'interface={interface}',
            f'driver=nl80211',
            f'hw_mode=g',
            f'ssid={ssid}',
            f'channel={channel}',
            f'wmm_enabled=0',
            f'macaddr_acl=0',
            f'auth_algs=1',
            f'ignore_broadcast_ssid=0',
            f'wpa=2',
            f'wpa_passphrase={ssid_password}',
            f'wpa_key_mgmt=WPA-PSK',
            f'wpa_pairwise=TKIP',
            f'rsn_pairwise=CCMP',
        ]
    else:
        conf_content = [
            f'interface={interface}',
            f'driver=nl80211',
            f'hw_mode=g',
            f'ssid={ssid}',
            f'channel={channel}',
        ]
    create_file_in_tmp('hostapd.conf', conf_content)
    popen_command_new_terminal(f'hostapd /tmp/hostapd.conf')


if __name__ == "__main__":
    while 1:
        clear()
        inputs = [
            f'{green("1)")} Change Broadcast Interface  {green("|")}   Current Broadcast Interface  : {green(interface)}',
            f'{green("2)")} Change Internet Interface   {green("|")}   Current Internet  Interface  : {green(internet_facing_interface)}',
            f'{green("-------------------------------------------------------------------------------------")}',
            f'{green("3)")} Change Gateway              {green("|")}   Current Gateway              : {green(gateway)}',
            f'                               {green("|")}   DHCP-START                   : {green(dhcp_range_start)}',
            f'                               {green("|")}   DHCP-END                     : {green(dhcp_range_end)}',
            f'{green("4)")} Change SSID                 {green("|")}   Current SSID                 : {green(ssid)}',
            f'{green("5)")} Change Password             {green("|")}   Current Password             : {green(ssid_password)}',
            f'{green("6)")} Change Channel              {green("|")}   Current Channel              : {green(channel)}',
            f'{green("-------------------------------------------------------------------------------------")}',
            f'{green("7)")}  Start WPA2 Encrypted Network      {green(ssid_password)}',
            f'{green("8)")}  Start Open Network',
        ]

        for i in inputs:
            print(i)
        match input(f'\n{red("> ")}').lower():
            case '1':
                change_interface()
            case '2':
                change_internet_facing_interface()
            case '3':
                change_gateway()
            case '4':
                change_ssid()
            case '5':
                change_password()
            case '6':
                change_channel()
            case '7':
                break
            case '8':
                break


