# pfsense-netbox-sync

Allows to synchronize NetBox IPAM DNS information to a pfSense instance.
This allows automatic DNS resolution on the pfSense based on the DNS names stored in Netbox.

## How does it work?

This script work by pulling IP addresses with DNS name from NetBox (source of truth) and create/update/delete
corresponding DNS entries on pfSense DNS resolver.

## Installation

## Configuration

### On NetBox

You'll need to create a dedicated user (ex: pfsense-netbox-sync) on your NetBox instance and then create a read only API
token.

The following env variables will need to be set:

- **NB_API_URL**: The URL to your NetBox instance. (Example: https://netbox.example.org)
- **NB_API_TOKEN**: The token created previously. (Example: f74cb99cf552b7005fd1a616b53efba2ce0c9656)

### On pfSense

pfSense does not provide any REST API out of the box. Therefore, you'll first need to install
the [pfrest package](https://pfrest.org/INSTALL_AND_CONFIG/#).

## Executing the script

```
PF_API_URL=xx PF_API_USER=xx PF_API_PASS=xx NB_API_URL=xx NB_API_TOKEN=xx python3 -m app
```