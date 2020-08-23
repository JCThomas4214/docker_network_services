# Docker Network Services
Pihole, WireGuard, and Cloudflared network services using docker and docker-compose.

## Ingredients

- Linux (w/ wireguard kernel module)
- Python 3.7+ (w/ pip3)
- Docker 
- Docker-Compose

## Quick Start Recipe

Make sure to have the WireGuard kernel module installed. This is preinstalled in kernel 5.6+. Visit [here](https://www.wireguard.com/install/) for more info.

1. Clone repo
2. Install python requirements 
3. Run initial setup
4. Add peers to WireGuard (use the *-cli-*.conf to configure client)
5. Start containers

```sh
git clone https://github.com/JCThomas4214/docker_network_services.git && cd docker_network_services && \
pip3 install -r requirements.txt && \
./setup.py -i && \
./setup.py -a wg0 John_Doe Mary_Sue && \
docker-compose up -d
```

## Full Course Meal

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

## References
- https://www.wireguard.com/
- https://github.com/cmulk/wireguard-docker
- https://github.com/pi-hole/docker-pi-hole
- https://github.com/visibilityspots/dockerfile-cloudflared
