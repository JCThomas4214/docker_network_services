Pihole, WireGuard, and Cloudflared network services using docker and docker-compose.

# Ingredients

- Linux (w/ wireguard kernel module)
- Python 3.7+ (w/ pip3)
- Docker 
- Docker-Compose

# Quick Start Recipe

Make sure to have the WireGuard kernel module installed. This is preinstalled in kernel 5.6+. Visit [here](https://www.wireguard.com/install/) for more info.

1. Clone repo
2. Install python requirements 
3. Run initial setup
4. Add peers to WireGuard (use the \*-cli-\*.conf to configure client)
5. Start containers

```sh
git clone https://github.com/JCThomas4214/docker_network_services.git && cd docker_network_services && \
pip3 install -r requirements.txt && \
./setup.py -i && \
./setup.py -a wg0 John_Doe Mary_Sue && \
docker-compose up -d
```

# Full Course Meal

Inital setup and manager for your WireGuard instance
```sh
$ ./setup -h
usage: setup.py [-h] (-i | -u | -a WG_INTERFACE [PEER ...] | -d WG_INTERFACE [PUBLIC_KEY ...] | -l WG_INTERFACE)

Script to setup your containers and manage WireGuard

optional arguments:
  -h, --help            show this help message and exit
  -i, --initialize      initialize .env file with pihole and WireGuard settings
  -u, --update          bring down containers / update containers / bring containers back up
  -a WG_INTERFACE [PEER ...], --add-peer WG_INTERFACE [PEER ...]
                        add WireGuard peer to your instance (outputs [WG_INTERFACE]-cli-[PEER].conf) the WireGuard
                        container will restart automatically
  -d WG_INTERFACE [PUBLIC_KEY ...], --delete-peer WG_INTERFACE [PUBLIC_KEY ...]
                        delete WireGuard peers with the interface and PublicKeys listed with --list-peers the
                        WireGuard container will restart automatically
  -l WG_INTERFACE, --list-peers WG_INTERFACE
                        list all WireGuard peers on specified interface

NOTE: start with './setup.py -i' to stage initial settings
```

- Make sure to enable IPv4 Forwarding and it persists on reboot.
- Read the WireGuard [documentation](https://www.wireguard.com/)!

## Initialization

Initialization with `./setup -i` will ask you a series of questions to stage your `.env` file for docker-compose.

- PiHole Web Password
  - Password used to login into PiHoles webapp
- Your public IP address
  - Your outward facing IP address (ISP). This is for Wireguard config files.
- Host interface name
  - The name of the NIC used on your server to host services. Used for PiHole packet trafficing.
- WireGuard interface name
  - The name of the WireGuard virtual tun interface that will be created.
- Wireguard interface tunnel IPv4 address
  - The gateway IP for the WireGuard virtual tun interface.
- Wireguard interface port
  - Port used to traffic VPN on Public IP and virtual tun interface

Once all is said and done the `.env` file should be generated and look like the following.
```sh
WEBPASSWORD=y0urPa55w0rd

PublicIP=111.111.111.111
ServerIP=192.168.0.2
IPv6=False
TZ=America/Chicago
DNS1=127.0.0.1#5053
DNS2=127.0.0.1#5054
DNSMASQ_USER=pihole
DNSMASQ_LISTENING=local
INTERFACE=eth0
WG_PORT=51820
```

## References
- https://www.wireguard.com/
- https://github.com/cmulk/wireguard-docker
- https://github.com/pi-hole/docker-pi-hole
- https://github.com/visibilityspots/dockerfile-cloudflared
