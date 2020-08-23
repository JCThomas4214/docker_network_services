#!/usr/bin/python3

import os
import sys
import argparse
import socket
import fcntl
import struct
import getpass
import configparser
from subprocess import run, Popen, PIPE
from dotenv import load_dotenv
from collections import OrderedDict

host_iface = None

class MultiOrderedDict(OrderedDict):
    def __setitem__(self, key, value):
        if isinstance(value, list) and key in self:
            self[key].extend(value)
        else:
            super().__setitem__(key, value)

def restart_wireguard():
    '''
    Restarts the wireguard container
    '''
    with Popen(['docker-compose', 'ps'], stdout=PIPE, stderr=PIPE, stdin=PIPE) as pub:
        running_containers = pub.communicate()
        if 'wireguard' in str(running_containers):
            run(['docker-compose', 'stop', 'wireguard'])
            run(['docker-compose', 'start', 'wireguard'])


def update_services():
    '''
    Takes down containers, pulls the latest images, and brings them back up
    '''
    run(['docker-compose', 'down'])
    run(['docker-compose', 'pull'])
    run(['docker-compose', 'up', '-d'])

def next_ip_addr(ip_addrs:list=[], first_three_octets:list=['10','200','200'], forth_octet:int=2):
    '''
    This only increments the last octet and does not account for anything else
    '''
    if len(ip_addrs) > 0:
        first_three_octets = ip_addrs[0].split('.')[:-1]
        forth_octet = int(ip_addrs.pop(0).split('.')[-1:][0]) + 1

    for ip_addr in ip_addrs:
        curr_forth_octet = ip_addr.split('.')[-1:][0]
        if curr_forth_octet == str(forth_octet):
            forth_octet += 1

    first_three_octets.append(str(forth_octet))
    return '.'.join(first_three_octets)

def get_ip_address(ifname: str):
    '''
    Gets the ip address from a interface on the host
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(), 
        0x8915, 
        struct.pack('256s', ifname[:15])
        )[20:24])

def get_wireguard_public_key(private_key: bytearray):
    '''
    Generates a public key for wireguard and returns it
    '''
    with Popen(['wg', 'pubkey'], stdout=PIPE, stderr=PIPE, stdin=PIPE) as pub:
        public_key = pub.communicate(input=private_key)[0].strip()
    return public_key

def get_wireguard_keys():
    '''
    Generates a private key for wireguard and returns it
    '''
    with Popen(['wg', 'genkey'], stdout=PIPE, stderr=PIPE) as priv:
        private_key = priv.communicate()[0].strip()
    public_key = get_wireguard_public_key(private_key)
    
    return dict(public_key=public_key, private_key=private_key)


def list_peers(iface: str):
    '''
    Wireguard keeps all peers listed in the interface config file. This function will read 
    this file for the interface passed in and print out all peers to stdout
    '''
    server_conf = configparser.RawConfigParser(dict_type=MultiOrderedDict, strict=False, empty_lines_in_values=False)
    server_conf.read([f'etc-wireguard/{iface}.conf'])

    publickeys = server_conf.get('Peer', 'PublicKey').split(os.linesep)
    allowedips = server_conf.get('Peer', 'AllowedIPs').split(os.linesep)

    print(f'\nThe following peers are allowed on interface {iface}\n')
    for i, key in enumerate(publickeys):
        print('[Peer]')
        print(f'PublicKey = {key}')
        print(f'AllowedIPs = {allowedips[i]}\n')

def delete_peer(iface: str, public_keys: list):
    '''
    Wireguard keeps all peers listed in the interface config file. This function will take read 
    this file for the interface passed in and remove all public keys listed in with the --delete-peer
    flag.
    '''
    load_dotenv()

    new_config = configparser.ConfigParser()
    new_config.optionxform = str

    server_conf = configparser.RawConfigParser(dict_type=MultiOrderedDict, strict=False, empty_lines_in_values=False)
    server_conf.read([f'etc-wireguard/{iface}.conf'])

    try:
        publickeys = server_conf.get('Peer', 'PublicKey').split(os.linesep)
        allowedips = server_conf.get('Peer', 'AllowedIPs').split(os.linesep)
    except configparser.NoSectionError as e:
        sys.exit(e)

    # itterate all public keys and delete
    for public_key in public_keys:
        try:
            i = publickeys.index(public_key)
        except ValueError:
            sys.exit('The public key was not found.')
        
        del publickeys[i]
        del allowedips[i]

    try:
        new_config['Interface'] = {
            'PrivateKey': server_conf.get('Interface', 'PrivateKey'),
            'Address': server_conf.get('Interface', 'Address'),
            'ListenPort': os.getenv('WG_PORT'),
            'PostUp': server_conf.get('Interface', 'PostUp'),
            'PostDown': server_conf.get('Interface', 'PostDown')
        }
    except configparser.NoOptionError as e:
        sys.exit(e)
    with open(f'etc-wireguard/{iface}.conf', 'w') as new_conf_file:
        new_config.write(new_conf_file)
    for i, key in enumerate(publickeys):
        with open(f'etc-wireguard/{iface}.conf', 'a') as new_conf_file:
            new_config = configparser.ConfigParser()
            new_config.optionxform = str
            new_config['Peer'] = {
                'PublicKey': key,
                'AllowedIPs': allowedips[i]
            }
            new_config.write(new_conf_file)
    restart_wireguard()

def create_peer_conf(iface:str, name: str):
    '''
    Create a client wireguard configuration file
    '''
    config = configparser.ConfigParser()
    config.optionxform = str
    keys = get_wireguard_keys()
    private_key = keys['private_key']

    server_conf = configparser.RawConfigParser(dict_type=MultiOrderedDict, strict=False, empty_lines_in_values=False)
    server_conf.read([f'etc-wireguard/{iface}.conf'])

    try:
        allowedips = server_conf.get('Peer', 'AllowedIPs').split(os.linesep)
        next_addr = next_ip_addr(allowedips)
    except configparser.NoSectionError:
        next_addr = next_ip_addr()

    config['Interface'] = {
        'PrivateKey': private_key.decode(),
        'Address': input(f' - Input tunnel interface IP for {name} (default {next_addr}): ') or next_addr,
        'DNS': server_conf['Interface']['Address'].replace('/24', '')
    }
    config['Peer'] = {
        'PublicKey': get_wireguard_public_key(server_conf['Interface']['PrivateKey'].encode()).decode(),
        'Endpoint': f'{os.getenv("PublicIP")}:{os.getenv("WG_PORT")}',
        'AllowedIPs': '0.0.0.0/0, ::/0'
    }

    with open(f'{iface}-cli-{name}.conf', 'w') as conf_file:
        config.write(conf_file)
    return config

def add_wireguard_peer(iface: str, names: list):
    '''
    Creates a Peer section in the wireguard interface config file and creates a client
    wireguard config file.
    '''
    load_dotenv()

    config = configparser.ConfigParser()
    config.optionxform = str

    for name in names:
        peer_conf = create_peer_conf(iface, name)
        config['Peer'] = {
            'PublicKey': get_wireguard_public_key(peer_conf['Interface']['PrivateKey'].encode()).decode(),
            'AllowedIPs': peer_conf['Interface']['Address']
        }
        try:
            with open(f'etc-wireguard/{iface}.conf', 'a') as conf_file:
                config.write(conf_file)
        except:
            sys.exit('This interface config file does not exist.')
    restart_wireguard()

def create_wireguard_conf():
    '''
    Create interface wireguard configuration file
    '''
    global host_iface
    config = configparser.ConfigParser()
    config.optionxform = str    
    wg_iface = input(' - WireGuard interface name? (default wg0) ') or 'wg0'

    keys = get_wireguard_keys()
    private_key = keys['private_key']

    config['Interface'] = {
        'PrivateKey': private_key.decode(),
        'Address': input(' - WireGuard interface tunnel IPv4 address? (default 10.200.200.1/24) ') or '10.200.200.1/24',
        'ListenPort': input(' - WireGuard interface port? (default 51280) ') or '51820',
        'PostUp': f'iptables -A FORWARD -i {wg_iface} -j ACCEPT; iptables -t nat -A POSTROUTING -o {host_iface} -j MASQUERADE; ip6tables -A FORWARD -i {wg_iface} -j ACCEPT; ip6tables -t nat -A POSTROUTING -o {host_iface} -j MASQUERADE',
        'PostDown': f'iptables -D FORWARD -i {wg_iface} -j ACCEPT; iptables -t nat -D POSTROUTING -o {host_iface} -j MASQUERADE; ip6tables -D FORWARD -i {wg_iface} -j ACCEPT; ip6tables -t nat -D POSTROUTING -o {host_iface} -j MASQUERADE'
    }
    
    os.makedirs(os.path.dirname(f'etc-wireguard/{wg_iface}.conf'), exist_ok=True)
    with open(f'etc-wireguard/{wg_iface}.conf', 'w') as conf_file:
        config.write(conf_file)
    # run(['sudo', 'chown', '-v', 'root:root', f'etc-wireguard/{wg_iface}.conf'])
    run(['sudo', 'chmod', '660', f'etc-wireguard/{wg_iface}.conf'])

    with open('.env', 'a+') as env_file:
        env_str = (
            f'INTERFACE={host_iface}\n'
            F'WG_PORT={config["Interface"]["ListenPort"]}\n\n'
        )
        env_file.write(env_str)



def create_env_file():
    '''
    Creates the .env file used with docker-compose to stage container environment vars
    '''
    global host_iface
    tmp = getpass.getpass(prompt=' - Pihole Web Password: ', stream=None)
    webpass = tmp if tmp == getpass.getpass(prompt=' - Verify Pihole Web Password: ', stream=None) else sys.exit('Passwords do not match!')
    pub_address = input(' - Input your public IP address: ') or sys.exit('Public IP is needed for WireGuard.')
    try:
        host_iface = input(' - Host interface name: ')
    except:
        sys.exit('The interface does not exist!')
    host_ipv4 = get_ip_address(host_iface.encode())

    with open('.env', 'w') as env_file:
        env_str = (
            f'WEBPASSWORD={webpass}\n\n'
            f'PublicIP={pub_address}\n'
            f'ServerIP={host_ipv4}\n'
            # f'ServerIPv6={host_ipv6}\n'
            'IPv6=False\n'
            f'TZ=America/Chicago\n'
            f'DNS1=127.0.0.1#5053\n'
            f'DNS2=127.0.0.1#5054\n'
            f'DNSMASQ_USER=pihole\n'
            f'DNSMASQ_LISTENING=local\n'
        )
        env_file.write(env_str)

def setup():
    create_env_file()
    # Create the WireGuard config file and pass wg port to env file
    create_wireguard_conf()


def main():
    parser = argparse.ArgumentParser(
        description='Script to setup your containers and manage WireGuard', epilog='NOTE: start with \'./setup.py -i\' to stage initial settings')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--initialize', help='initialize .env file with pihole and WireGuard settings',
                        action="store_true")
    group.add_argument('-u', '--update', help='bring down containers / update containers / bring containers back up ',
                        action="store_true")
    group.add_argument('-a', '--add-peer', dest='add', nargs='+', metavar=('WG_INTERFACE', 'PEER'),
                        help='add WireGuard peer to your instance (outputs [WG_INTERFACE]-cli-[PEER].conf) the WireGuard container will restart automatically')
    group.add_argument('-d', '--delete-peer', dest='delete', nargs='+', metavar=('WG_INTERFACE', 'PUBLIC_KEY'),
                        help='delete WireGuard peers with the interface and PublicKeys listed with --list-peers the WireGuard container will restart automatically')
    group.add_argument('-l', '--list-peers', dest='list', nargs=1, metavar='WG_INTERFACE',
                        help='list all WireGuard peers on specified interface')
    parsed_args = parser.parse_args()

    try:
        if parsed_args.initialize:
            setup()
        elif parsed_args.add:
            iface = parsed_args.add.pop(0)
            add_wireguard_peer(iface, parsed_args.add)
        elif parsed_args.delete:
            iface = parsed_args.delete.pop(0)
            delete_peer(iface, parsed_args.delete)
        elif parsed_args.list:
            list_peers(parsed_args.list[0])
        elif parsed_args.update:
            update_services()
    except KeyboardInterrupt:
        print('\n\n\tGoodbye!\n')

if __name__ == "__main__":
    main()
