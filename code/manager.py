#!/usr/bin/env python3

# -*- coding: utf-8 -*-

"""NuvlaBox Peripheral Manager Network
This service provides network devices discovery.
"""

import logging
import requests
import sys
import time
from threading import Event, Thread
import json
from nuvla.api import Api
import os
import xmltodict
import re

# Packages for Service Discovery
from ssdpy import SSDPClient
from xml.dom import minidom
from urllib.parse import urlparse
from wsdiscovery.discovery import ThreadedWSDiscovery as WSDiscovery
import zeroconf

scanning_interval = 30


def init_logger():
    """ Initializes logging """

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(levelname)s - %(funcName)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)


def wait_bootstrap(context_file, peripheral_path, peripheral_paths):
    """
    Waits for the NuvlaBox to finish bootstrapping, by checking
        the context file.
    :returns
    """
    is_context_file = False

    while not is_context_file:
        time.sleep(5)
        if os.path.isfile(context_file):
            is_context_file = True
            logging.info('Context file found...')

    is_peripheral = False

    while not is_peripheral:

        logging.info('Waiting for peripheral directory...')
        
        if os.path.isdir(peripheral_path):
            for path in peripheral_paths:
                new_peripheral_path = peripheral_path + path

                if not os.path.isdir(new_peripheral_path):
                    os.mkdir(new_peripheral_path)
                    logging.info('PERIPHERAL: {}'.format(new_peripheral_path))
                
            is_peripheral = True

        time.sleep(5)

    logging.info('NuvlaBox has been initialized.')
    return


def network_per_exists_check(peripheral_dir, protocol, device_addr):
    """ 
    Checks if peripheral already exists 
    """
    file_path = '{}{}/{}'.format(peripheral_dir, protocol, device_addr)
    if file_path in os.listdir(peripheral_dir):
        file_content = readDeviceFile(device_addr, protocol, peripheral_dir)

        return True, file_content.get('resource-id')
    return False


def createDeviceFile(protocol, device_addr, device_file, peripheral_dir):
    """
    Creates a device file on peripheral folder.
    """

    file_path = '{}{}/{}'.format(peripheral_dir, protocol, device_addr)

    with open(file_path, 'w') as outfile:
        json.dump(device_file, outfile)


def removeDeviceFile(protocol, device_addr, peripheral_dir):
    """
    Removes a device file from the peripheral folder
    """

    file_path = '{}{}/{}'.format(peripheral_dir, protocol, device_addr)

    os.unlink(file_path)


def readDeviceFile(device_addr, protocol, peripheral_dir):
    """
    Reads a device file from the peripheral folder.
    """

    file_path = '{}{}/{}'.format(peripheral_dir, protocol, device_addr)

    return json.load(open(file_path))


def get_ssdp_device_xml_as_json(url):
    """
    Requests and parses XML file with information from SSDP
    """

    if not url:
        return {}

    parsed_url = urlparse(url)
    if not parsed_url.schema:
        url = f'http://{url}'

    try:
        r = requests.get(url)
        device_xml = minidom.parseString(r.content).getElementsByTagName('device')[0]

        device_json = xmltodict.parse(device_xml.toxml())

        return device_json.get('device', {})
    except:
        logging.exception(f"Cannot get and parse XML for SSDP device info from {url}")
        return {}


def ssdpManager(nuvlabox_id, nuvlabox_version):
    """
    Manages SSDP discoverable devices (SSDP and UPnP devices)
    """

    client = SSDPClient()
    devices = client.m_search("ssdp:all")
    output = {
        'peripherals': {},
        'xml': {}
    }

    for device in devices:
        try:
            usn = device['usn']
        except KeyError:
            logging.warning(f'SSDP device {device} missinng USN field, and thus is considered not compliant. Ignoring')
            continue

        if ":device:" in usn:
            # normally, USN = "uuid:XYZ::urn:schemas-upnp-org:device:DEVICETYPE:1"
            # if this substring is not there, then we are not interested (it might be a service)
            # TODO: consider aggregating all services being provided by a device
            try:
                device_class = usn.split(':device:')[1].split(':')[0]
            except IndexError:
                logging.exception(f'Failed to infer device class for from USN {usn}')
                continue
        else:
            continue

        try:
            identifier = usn.replace("uuid:", "").split(":")[0]
        except IndexError:
            logging.warning(f'Cannot parse USN {usn}. Continuing with raw USN value as identifier')
            identifier = usn

        if identifier in output['peripherals']:
            # ssdp device has already been identified. This entry might simply be another service/class
            # of the same device let's just see if there's an update to the classes and move on

            existing_classes = output['peripherals'][identifier]['classes']
            if device_class in existing_classes:
                continue
            else:
                output['peripherals'][identifier]['classes'].append(device_class)
        else:
            # new device
            location = device.get('location')
            device_from_location = get_ssdp_device_xml_as_json(location)    # always a dict
            name = device_from_location.get('friendlyName',
                                            device.get('x-friendly-name', usn))
            description = device_from_location.get('modelDescription',
                                                   device.get('server', name))

            output['peripherals'][identifier] = {
                "parent": nuvlabox_id,
                "version": nuvlabox_version,
                'classes': [device_class],
                'available': True,
                'identifier': identifier,
                'interface': 'SSDP',
                'name': name,
                'description': description
            }

            if location:
                output['peripherals'][identifier]['device-path'] = location

            vendor = device_from_location.get('manufacturer')
            if vendor:
                output['peripherals'][identifier]['vendor'] = vendor

            product = device_from_location.get('modelName')
            if product:
                output['peripherals'][identifier]['product'] = product

            serial = device_from_location.get('serialNumber')
            if serial:
                output['peripherals'][identifier]['serial-number'] = serial

    return output['peripherals']


def wsDiscoveryManager(nuvlabox_id, nuvlabox_version):
    """
    Manages WSDiscovery discoverable devices
    """
    manager = {}

    wsd = WSDiscovery()
    wsd.start()
    services = wsd.searchServices()
    for service in services:
        identifier = str(service.getEPR()).split(':')[-1]
        classes = [ re.split("/|:", str(c))[-1] for c in service.getTypes() ]
        name = " | ".join(classes) + " [wsdiscovery peripheral]"
        if identifier not in manager.keys():
            output = {
                "parent": nuvlabox_id,
                "version": nuvlabox_version,
                "available": True,
                "name": name,
                "description": name + f" - {str(service.getEPR())} - Scopes: {', '.join([str(s) for s in service.getScopes()])}",
                "classes": classes,
                "identifier": identifier,
                "interface": 'WS-Discovery',
            }

            if len(service.getXAddrs()) > 0:
                output['device-path'] = ", ".join([str(x) for x in service.getXAddrs()])

            manager[identifier] = output

    wsd.stop()

    return manager


def convertZeroConfAddr(addr_list):
    """
    Converts IP Addresses from Zeroconf
    """
    addrs = []
    for addr in addr_list:
        addrs.append('.'.join([str(i) for i in list(addr)]))

    return addrs


def zeroConfManager(url, nuvlabox_id, nuvlabox_version, peripheral_path):
    """
    Manages ZeroConf discoverable devices (Bonjour and Avahi)
    This manager is run in side thread as its asynchrounous callback based
        execution.
    """

    services = {}
    class MyListener:

        def remove_service(self, zeroconf, type, name):
            if ethernetCheck(peripheral_path, 'zeroconf', name):

                remove(services[name]['resource_id'], 'https://nuvla.io', activated_path, cookies_file)
                print('REMOVING: {}'.format(services[name]), flush=True)
                removeDeviceFile('zeroconf', name, peripheral_path)
                del services[name]

        def add_service(self, zeroconf, type, name):
            if not ethernetCheck(peripheral_path, 'zeroconf', name):

                info = zeroconf.get_service_info(type, name)
                output = {
                    "parent": nuvlabox_id,
                    "version": nuvlabox_version,
                    "available": True,
                    "name": name,
                    "classes": [],
                    "identifier": convertZeroConfAddr(info.addresses)[0],
                    "interface": 'ZeroConf (Bonjour, Avahi)',
                }

                resource_id = add(output, 'https://nuvla.io', activated_path, cookies_file)
                services[name] = {'resource_id': resource_id, 'message': output}
                createDeviceFile('zeroconf', name, output, peripheral_path)
                print('PUBLISHING: {}'.format(services[name], flush=True))

    zc = zeroconf.Zeroconf()
    listener = MyListener()
    browser = zeroconf.ServiceBrowser(zc, "_http._tcp.local.", listener)
    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        zc.close() 


def network_manager(nuvlabox_id, nuvlabox_version):
    """
    Runs and manages the outputs from the discovery.
    """

    output = {}

    ssdp_output = ssdpManager(nuvlabox_id, nuvlabox_version)
    ws_discovery_output = wsDiscoveryManager(nuvlabox_id, nuvlabox_version)
    output['ssdp'] = ssdp_output
    output['ws-discovery'] = ws_discovery_output
    return output


def add(data, api_url, activated_path, cookies_file):
    """
    Sends information from ethernet devices to Nuvla.
    """
    api = Api(api_url)

    activated = json.load(open(activated_path))
    api_key = activated['api-key']
    secret_key = activated['secret-key']
    
    api.login_apikey(api_key, secret_key)

    response = api.add('nuvlabox-peripheral', data).data
    return response['resource-id']


def remove(resource_id, api_url, activated_path, cookies_file):
    """
    Removes a ethernet device from  Nuvla.
    """
    api = Api(api_url)

    activated = json.load(open(activated_path))
    api_key = activated['api-key']
    secret_key = activated['secret-key']
    
    api.login_apikey(api_key, secret_key)

    response = api.delete(resource_id).data
    return response['resource-id']


def authenticate(url, insecure, activated_path):
    """ Uses the NB ApiKey credential to authenticate against Nuvla

    :return: Api client
    """
    api_instance = Api(endpoint='https://{}'.format(url),
                       insecure=insecure, reauthenticate=True)

    if os.path.exists(activated_path):
        with open(activated_path) as apif:
            apikey = json.loads(apif.read())
    else:
        return None

    api_instance.login_apikey(apikey['api-key'], apikey['secret-key'])

    return api_instance


if __name__ == "__main__":

    activated_path = '/srv/nuvlabox/shared/.activated'
    context_path = '/srv/nuvlabox/shared/.context'
    cookies_file = '/srv/nuvlabox/shared/cookies'
    peripheral_path = '/srv/nuvlabox/shared/.peripherals/'
    e = Event()

    logging.info('NETWORK PERIPHERAL MANAGER STARTED')

    init_logger()

    nuvla_endpoint_insecure = os.environ["NUVLA_ENDPOINT_INSECURE"] if "NUVLA_ENDPOINT_INSECURE" in os.environ else False
    if isinstance(nuvla_endpoint_insecure, str):
        if nuvla_endpoint_insecure.lower() == "false":
            nuvla_endpoint_insecure = False
        else:
            nuvla_endpoint_insecure = True
    else:
        nuvla_endpoint_insecure = bool(nuvla_endpoint_insecure)

    API_URL = os.getenv("NUVLA_ENDPOINT", "nuvla.io")
    while API_URL[-1] == "/":
        API_URL = API_URL[:-1]

    API_URL = API_URL.replace("https://", "")

    api = None

    wait_bootstrap(context_path, peripheral_path, ['ssdp', 'ws-discovery', 'zeroconf'])

    while True:
        try:
            with open(context_path) as c:
                context = json.loads(c.read())
            NUVLABOX_VERSION = context['version']
            NUVLABOX_ID = context['id']
            break
        except (json.decoder.JSONDecodeError, KeyError):
            logging.exception(f"Waiting for {context_path} to be populated")
            e.wait(timeout=5)

    old_devices = {'ssdp': {}, 'ws-discovery': {}}

    zeroconf_target_service_types = [
        '_airdroid._tcp.local.',
        '_airdrop._tcp.local.',

    ]
    zero_conf_thread = Thread(target=zeroConfManager, args=(API_URL, NUVLABOX_ID, NUVLABOX_VERSION, peripheral_path))
    zero_conf_thread.start()

    api = authenticate(API_URL, nuvla_endpoint_insecure, activated_path)

    while True:

        current_devices = network_manager(NUVLABOX_ID, NUVLABOX_VERSION)
        logging.info('CURRENT DEVICES: {}\n'.format(current_devices))

        for protocol in current_devices:

            if current_devices[protocol] != old_devices[protocol] and current_devices[protocol]:

                old_devices_set = set(old_devices[protocol].keys())
                current_devices_set = set(current_devices[protocol].keys())

                publishing = current_devices_set - old_devices_set
                removing = old_devices_set - current_devices_set

                for device in publishing:

                    peripheral_already_registered, res_id = \
                        network_per_exists_check(peripheral_path, protocol, current_devices[protocol][device])

                    old_devices[protocol][device] = current_devices[protocol][device]

                    if not peripheral_already_registered:

                        logging.info('PUBLISHING: {}'.format(current_devices[protocol][device]))
                        try:
                            resource_id = api.add('nuvlabox-peripheral', current_devices[protocol][device]).data['resource-id']
                        except:
                            logging.exception(f'Unable to publish peripheral {device}')
                            continue

                        createDeviceFile(protocol,
                                         device,
                                         {'resource_id': resource_id,
                                          'message': current_devices[protocol][device]},
                                         peripheral_path)

                for device in removing:

                    logging.info('REMOVING: {}'.format(old_devices[protocol][device]))

                    peripheral_already_registered, res_id = \
                        network_per_exists_check(peripheral_path, protocol, current_devices[protocol][device])

                    if res_id:
                        r = api.delete(res_id).data
                    else:
                        logging.warning(f'Unable to retrieve ID of locally registered device {device}. Local delete only')

                    try:
                        removeDeviceFile(device, protocol, peripheral_path)
                    except FileNotFoundError:
                        logging.warning(f'Peripheral file {device} does not exist. Considered deleted')

                    del old_devices[device]

        e.wait(timeout=scanning_interval)
