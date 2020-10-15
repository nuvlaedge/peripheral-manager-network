#!/usr/bin/env python3

# -*- coding: utf-8 -*-

"""NuvlaBox Peripheral Manager Ethernet
This service provides ethernet device discovery.
"""

import logging
import requests
import sys
import time
from threading import Event, Thread
import json
from nuvla.api import Api
import os

# Packages for Service Discovery
from ssdpy import SSDPClient
from xml.dom import minidom
from urllib.parse import urlparse
from wsdiscovery.discovery import ThreadedWSDiscovery as WSDiscovery
import zeroconf


def init_logger():
    """ Initializes logging """

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(levelname)s - %(funcName)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)


def wait_bootstrap(context_file, base_peripheral_path, peripheral_path, peripheral_paths):
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

    if not os.path.isdir(base_peripheral_path):
        os.mkdir(base_peripheral_path)


    peripheral = False

    if not os.path.isdir(peripheral_path) or peripheral_path not in os.listdir(peripheral_path):
        while not peripheral:
            logging.info('Wating for peripheral directory...')
            if os.path.isdir(base_peripheral_path):
                for path in peripheral_paths:
                    new_peripheral_path = peripheral_path + '/' +path
                    os.mkdir(new_peripheral_path)
                    logging.info('PERIPHERAL: {}'.format(peripheral)

                peripheral = True

    logging.info('NuvlaBox has been initialized.')
    return


def ethernetCheck(peripheral_dir, protocol, device_addr):
    """ 
    Checks if peripheral already exists 
    """
    file_path = '{}{}/{}'.format(peripheral_dir, protocol, device_addr)
    if file_path in os.listdir(peripheral_dir):
        return True
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


def XMLGetNodeText(node):
    """
    Return text contents of an XML node.
    """
    text = []

    for childNode in node.childNodes:
        if childNode.nodeType == node.TEXT_NODE:
            text.append(childNode.data)

    return(''.join(text))


def getDeviceSchema(path):
    """
    Requests and parses XML file with information from SSDP
    """
    print(path)
    r = requests.get(path)
    tree = minidom.parseString(r.content)
    return tree


def getBaseIP(schema, location):
    """
    Returns the IP address from SSDP.
    """
    base_url_elem = schema.getElementsByTagName('URLBase')

    if base_url_elem:
        base_url = XMLGetNodeText(base_url_elem[0]).rstrip('/')
    else:
        url = urlparse(location)
        base_url = '%s://%s' % (url.scheme, url.netloc)

    return base_url


def ssdpManager(nuvlabox_id, nuvlabox_version):
    """
    Manages SSDP discoverable devices (SSDP and UPnP devices)
    """

    client = SSDPClient()
    devices = client.m_search("ssdp:all")
    manager = {}

    for device in devices:
        try:
            schema = getDeviceSchema(device['location'])
            ip = getBaseIP(schema, device['location'])
            device_info = schema.getElementsByTagName('device')[0]
            name =  XMLGetNodeText(device_info.getElementsByTagName('friendlyName')[0])

            if name not in manager.keys():
                output = {
                    "parent": nuvlabox_id,
                    "version": nuvlabox_version,
                    "available": True,
                    "name": name,
                    "classes": [],
                    "identifier": ip,
                    "interface": 'SSDP',
                }

                manager[name] = output
        except:
            pass

    return manager


def wsDiscoveryManager(nuvlabox_id, nuvlabox_version):
    """
    Manages WSDiscovery discoverable devices
    """
    manager = {}

    wsd = WSDiscovery()
    wsd.start()
    services = wsd.searchServices()
    for service in services:
        if service.getEPR() not in manager.keys():
            output = {
                    "parent": nuvlabox_id,
                    "version": nuvlabox_version,
                    "available": True,
                    "name": service.getEPR(),
                    "classes": [str(c) for c in service.getTypes()],
                    "identifier": service.getXAddrs()[0],
                    "interface": 'WSDiscovery',
                }
            manager[service.getEPR()] = output

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


def ethernetManager(nuvlabox_id, nuvlabox_version):
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


if __name__ == "__main__":

    activated_path = '/home/pi/shared/.activated'
    context_path = '/home/pi/shared/.context'
    cookies_file = '/home/pi/shared/cookies'
    peripheral_path = '/home/pi/shared/.peripherals/'

    print('ETHERNET MANAGER STARTED')

    init_logger()

    API_URL = "https://nuvla.io"

    wait_bootstrap(context_path, peripheral_path, ['ssdp', 'ws-discovery', 'zeroconf'])

    context = json.load(open(context_path))

    NUVLABOX_VERSION = context['version']
    NUVLABOX_ID = context['id']

    e = Event()

    devices = {'ssdp': {}, 'ws-discovery': {}}

    zero_conf_thread = Thread(target=zeroConfManager, args=(API_URL, NUVLABOX_ID, NUVLABOX_VERSION, peripheral_path))
    zero_conf_thread.start()

    while True:

        current_devices = ethernetManager(NUVLABOX_ID, NUVLABOX_VERSION)
        print('CURRENT DEVICES: {}\n'.format(current_devices), flush=True)

        for protocol in current_devices:

            if current_devices[protocol] != devices[protocol] and current_devices[protocol]:

                devices_set = set(devices[protocol].keys())
                current_devices_set = set(current_devices[protocol].keys())

                publishing = current_devices_set - devices_set
                removing = devices_set - current_devices_set

                for device in publishing:

                    peripheral_already_registered = \
                        ethernetCheck(peripheral_path, protocol, current_devices[protocol][device])

                    resource_id = ''

                    if not peripheral_already_registered:

                        print('PUBLISHING: {}'.format(current_devices[protocol][device]), flush=True)

                        resource_id = add(current_devices[protocol][device], API_URL, activated_path, cookies_file)
                        
                    devices[protocol][device] = {'resource_id': resource_id, 'message': current_devices[protocol][device]}
                    createDeviceFile(protocol, device, devices[protocol][device], peripheral_path)

                for device in removing:

                    peripheral_already_registered = \
                        ethernetCheck(peripheral_path, protocol, current_devices[protocol][device])

                    if peripheral_already_registered:

                        print('REMOVING: {}'.format(devices[device]), flush=True)

                        read_file = readDeviceFile(device, protocol, peripheral_path)
                        remove(read_file['resource_id'], API_URL, activated_path, cookies_file)

                    del devices[device]
                    removeDeviceFile(device, protocol, peripheral_path)

        e.wait(timeout=90)