# pylint: disable=wrong-import-order

"""
pfsense-netbox-sync: Allows to synchronize NetBox IPAM DNS information to a pfSense instance
"""

import os
from typing import List

import pynetbox
import requests
import sys
import urllib3
from requests.auth import HTTPBasicAuth


def _fetch_netbox_host_overrides(nb_api: pynetbox.api) -> dict:
    """
    Fetch and build a list of host override from a NetBox instance
    :param nb_api: the NetBox API client
    :return: the list of host overrides mapped by their hostname
    """

    nb_host_overrides = {}
    for nb_ip_address in nb_api.ipam.ip_addresses.filter(status='active'):
        if nb_ip_address.dns_name is None or nb_ip_address.dns_name == '':
            continue

        host = nb_ip_address.dns_name.split('.')[0]
        domain = '.'.join(nb_ip_address.dns_name.split('.')[1:])

        nb_host_overrides[nb_ip_address.dns_name] = {
            'host': host,
            'domain': domain,
            'ip': [
                nb_ip_address.address.split('/')[0],
            ],
            'descr': '[pfsense-netbox-sync]',
            'aliases': None,
        }

    return nb_host_overrides


def _fetch_pfsense_host_overrides() -> dict:
    """
    Fetch and build a list of host override from a pfSense instance
    :return: the list of host overrides mapped by their hostname
    """

    r = requests.get(
        f'{os.environ["PF_API_URL"]}/api/v2/services/dns_resolver/host_overrides',
        auth=HTTPBasicAuth(os.environ['PF_API_USER'], os.environ['PF_API_PASS']),
        verify=False,
        timeout=int(os.environ.get('HTTP_TIMEOUT', '5')),
    )

    if r.status_code != 200:
        print(f'Error while requesting host overrides from pfSense ({r.status_code})')
        sys.exit(1)

    pf_host_overrides = {}
    for pf_host_override in r.json()['data']:
        # Only track the entry the script have created
        if pf_host_override['descr'] != '[pfsense-netbox-sync]':
            continue

        pf_host_overrides[pf_host_override['host'] + '.' + pf_host_override['domain']] = pf_host_override

    return pf_host_overrides


def _compute_host_overrides_changes(
        netbox_host_overrides: dict,
        pfsense_host_overrides: dict,
) -> (List[dict], List[dict], List[dict]):
    """
    Compute the changes between the host overrides from NetBox (source of truth) and pfSense (real)
    :param netbox_host_overrides: the source host overrides from NetBox
    :param pfsense_host_overrides: the source host overrides from pfSense
    :return: the changes
    """

    new_host_overrides = []
    changed_host_overrides = []
    deleted_host_overrides = []

    for (host, nb_host_override) in netbox_host_overrides.items():
        if host not in pfsense_host_overrides:
            new_host_overrides.append(nb_host_override)
        elif nb_host_override['ip'] != pfsense_host_overrides[host]['ip']:
            changed_host_overrides.append(nb_host_override)

    for (host, pf_host_override) in pfsense_host_overrides.items():
        if host not in netbox_host_overrides:
            deleted_host_overrides.append(pf_host_override)

    return new_host_overrides, changed_host_overrides, deleted_host_overrides


def process_new_host_overrides(host_overrides: List[dict]):
    """
    Process the new host overrides. This will create them into the pfSense instance
    :param host_overrides: the new host overrides
    """

    for host_override in host_overrides:
        print(f'[+] {host_override["host"]}.{host_override["domain"]} {host_override["ip"]}')

        r = requests.post(
            f'{os.environ["PF_API_URL"]}/api/v2/services/dns_resolver/host_override',
            auth=HTTPBasicAuth(os.environ['PF_API_USER'], os.environ['PF_API_PASS']),
            verify=False,
            json=host_override,
            timeout=int(os.environ.get('HTTP_TIMEOUT', '5')),
        )

        if r.status_code != 200:
            print(f'Error while creating host override {host_override["host"]} ({r.status_code})')
            sys.exit(1)


def _process_changed_host_overrides(pf_host_overrides: dict, host_overrides: List[dict]):
    """
    Process the changed host overrides. This will update them into the pfSense instance
    :param pf_host_overrides: the actual host overrides coming from the pfSense instance
    :param host_overrides: the changed host overrides
    """

    for host_override in host_overrides:
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
            timeout=int(os.environ.get('HTTP_TIMEOUT', '5')),
        )

        if r.status_code != 200:
            print(f'Error while updating host override {host_override["host"]} ({r.status_code})')
            sys.exit(1)


def _process_deleted_host_overrides(host_overrides: List[dict]):
    """
    Process the deleted host overrides. This will delete them from the pfSense instance
    :param host_overrides: the deleted host overrides
    """

    for host_override in host_overrides:
        print(f'[-] {host_override["host"]}.{host_override["domain"]} {host_override["ip"]}')

        r = requests.delete(
            f'{os.environ["PF_API_URL"]}/api/v2/services/dns_resolver/host_override?id={host_override["id"]}',
            auth=HTTPBasicAuth(os.environ['PF_API_USER'], os.environ['PF_API_PASS']),
            verify=False,
            timeout=int(os.environ.get('HTTP_TIMEOUT', '5')),
        )

        if r.status_code != 200:
            print(f'Error while deleting host override {host_override["host"]} ({r.status_code})')
            sys.exit(1)


def main():
    """
    pfsense-netbox-sync main entrypoint
    """

    # Instantiate connection to the Netbox API
    nb_api = pynetbox.api(
        url=os.environ['NB_API_URL'],
        token=os.environ['NB_API_TOKEN'],
    )

    # First, built the host overrides using Netbox as source
    nb_host_overrides = _fetch_netbox_host_overrides(nb_api)

    # Then fetch the actual host overrides from pfSense API
    pf_host_overrides = _fetch_pfsense_host_overrides()

    # Compute the changes
    (new_host_overrides, changed_host_overrides, deleted_host_overrides) = _compute_host_overrides_changes(
        nb_host_overrides,
        pf_host_overrides,
    )

    print(f'{len(new_host_overrides)} new host overrides')
    print(f'{len(changed_host_overrides)} changed host overrides')
    print(f'{len(deleted_host_overrides)} deleted host overrides')

    if len(new_host_overrides) == 0 and len(changed_host_overrides) == 0 and len(deleted_host_overrides) == 0:
        print('no changes detected.')
        sys.exit(0)

    print()

    # First process the new host overrides
    process_new_host_overrides(new_host_overrides)

    # Then process the changed host overrides
    _process_changed_host_overrides(pf_host_overrides, changed_host_overrides)

    # Once it's done, re-fetch the actual host overrides from pfSense API (because the ID may have changed)
    pf_host_overrides = _fetch_pfsense_host_overrides()

    # Re-compute the changes (only for the deleted this time)
    (_, _, deleted_host_overrides) = _compute_host_overrides_changes(
        nb_host_overrides,
        pf_host_overrides,
    )

    # Finally process the deleted host overrides
    _process_deleted_host_overrides(deleted_host_overrides)

    # Finally restart the DNS resolver
    r = requests.post(
        f'{os.environ["PF_API_URL"]}/api/v2/services/dns_resolver/apply',
        auth=HTTPBasicAuth(os.environ['PF_API_USER'], os.environ['PF_API_PASS']),
        verify=False,
        timeout=int(os.environ.get('HTTP_TIMEOUT', '5')),
    )

    if r.status_code != 200:
        print(f'Error while restarting DNS resolver ({r.status_code})')
        sys.exit(1)


if __name__ == '__main__':
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    main()
