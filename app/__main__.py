import os

import pynetbox
import requests
from requests.auth import HTTPBasicAuth


def main():
    # Instantiate connection to the Netbox API
    nb_api = pynetbox.api(
        url=os.environ['NB_API_URL'],
        token=os.environ['NB_API_TOKEN'],
    )

    # First, built the host overrides using Netbox as source
    nb_host_overrides = {}
    for nb_ip_address in nb_api.ipam.ip_addresses.all():
        if nb_ip_address.dns_name is None or nb_ip_address.dns_name == '':
            continue

        host = nb_ip_address.dns_name.split('.')[0]

        nb_host_overrides[nb_ip_address.dns_name] = {
            'host': host,
            'domain': nb_ip_address.dns_name.replace(f'{host}.', ''),
            'ip': [
                nb_ip_address.address.split('/')[0],
            ],
            'descr': '[pfsense-netbox-sync]',
            'aliases': None,
        }

    # Then fetch the actual host overrides from pfSense API
    r = requests.get(
        f'{os.environ["PF_API_URL"]}/api/v2/services/dns_resolver/host_overrides',
        auth=HTTPBasicAuth(os.environ['PF_API_USER'], os.environ['PF_API_PASS']),
        verify=False,
    )

    if r.status_code != 200:
        print(f'Error while requesting host overrides from pfSense ({r.status_code})')
        exit(1)

    pf_host_overrides = {}
    for pf_host_override in r.json()['data']:
        # Only track the entry the script have created
        if pf_host_override['descr'] != '[pfsense-netbox-sync]':
            continue

        pf_host_overrides[pf_host_override['host'] + '.' + pf_host_override['domain']] = pf_host_override

    new_host_overrides = []
    changed_host_overrides = []
    deleted_host_overrides = []

    for (host, nb_host_override) in nb_host_overrides.items():
        if host not in pf_host_overrides:
            new_host_overrides.append(nb_host_override)
        elif nb_host_override['ip'] != pf_host_overrides[host]['ip']:
            changed_host_overrides.append(nb_host_override)

    for (host, pf_host_override) in pf_host_overrides.items():
        if host not in nb_host_overrides:
            deleted_host_overrides.append(pf_host_override)

    print(f'{len(new_host_overrides)} new host overrides')
    print(f'{len(changed_host_overrides)} changed host overrides')
    print(f'{len(deleted_host_overrides)} deleted host overrides')

    if len(new_host_overrides) == 0 and len(changed_host_overrides) == 0 and len(deleted_host_overrides) == 0:
        print('no changes detected.')
        exit(0)

    print()

    # First process the new host overrides
    for host_override in new_host_overrides:
        print(f'[+] {host_override["host"]}.{host_override["domain"]} {host_override["ip"]}')

        r = requests.post(
            f'{os.environ["PF_API_URL"]}/api/v2/services/dns_resolver/host_override',
            auth=HTTPBasicAuth(os.environ['PF_API_USER'], os.environ['PF_API_PASS']),
            verify=False,
            json=host_override,
        )

        if r.status_code != 200:
            print(f'Error while creating host override ({r.status_code})')
            exit(1)

    # Then process the changed host overrides
    for host_override in changed_host_overrides:
        pf_host_override = pf_host_overrides[host_override['host'] + '.' + host_override['domain']]

        print(
            f'[*] {host_override["host"]}.{host_override["domain"]} {pf_host_override["ip"]} -> {host_override["ip"]}'
        )

        host_override['id'] = pf_host_override['id']

        r = requests.patch(
            f'{os.environ["PF_API_URL"]}/api/v2/services/dns_resolver/host_override',
            auth=HTTPBasicAuth(os.environ['PF_API_USER'], os.environ['PF_API_PASS']),
            verify=False,
            json=host_override,
        )

        if r.status_code != 200:
            print(f'Error while updating host override ({r.status_code})')
            exit(1)

    # Finally process the deleted host overrides
    for host_override in deleted_host_overrides:
        print(f'[-] {host_override["host"]}.{host_override["domain"]} {host_override["ip"]}')

        r = requests.delete(
            f'{os.environ["PF_API_URL"]}/api/v2/services/dns_resolver/host_override?id={host_override["id"]}',
            auth=HTTPBasicAuth(os.environ['PF_API_USER'], os.environ['PF_API_PASS']),
            verify=False,
        )

        if r.status_code != 200:
            print(f'Error while deleting host override ({r.status_code})')
            exit(1)

    # Finally restart the DNS resolver
    r = requests.post(
        f'{os.environ["PF_API_URL"]}/api/v2/services/dns_resolver/apply',
        auth=HTTPBasicAuth(os.environ['PF_API_USER'], os.environ['PF_API_PASS']),
        verify=False,
    )

    if r.status_code != 200:
        print(f'Error while restarting DNS resolver ({r.status_code})')
        exit(1)


if __name__ == '__main__':
    main()
