#!/usr/bin/env python3

# -*- coding: utf-8 -*-

"""NuvlaBox Peripheral Manager Ethernet
This service provides ethernet device discovery.
"""

# TODO:
#  - Add check if device exists
#  - Test full execution
#  - Create Device file
#  - Remove Device file


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
from zeroconf import ServiceBrowser, Zeroconf
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


def wait_bootstrap(context_file):
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

    logging.info('NuvlaBox has been initialized.')
    return


def ethernetCheck(peripheral_dir, mac_addr):
    """ Checks if peripheral already exists """
    # TODO
    return True

def createDeviceFile(device_mac_addr, device_file, peripheral_dir):
    """
    Creates a device file on peripheral folder.
    """

    #TODO: filepath
    file_path = ''

    with open(file_path, 'w') as outfile:
        json.dump(device_file, outfile)


def removeDeviceFile(device_mac_addr, peripheral_dir):
    """
    Removes a device file from the peripheral folder
    """
    #TODO: filepath
    file_path = ''

    os.unlink(file_path)


def readDeviceFile(device_mac_addr, peripheral_dir):
    """
    Reads a device file from the peripheral folder.
    """

    #TODO: filepath
    file_path = ''
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
    r = requests.get(path)
    tree = minidom.parseString(r.content)
    return tree


def getBaseIP(schema, location):
    base_url_elem = schema.getElementsByTagName('URLBase')
    if base_url_elem:
        base_url = XMLGetNodeText(base_url_elem[0]).rstrip('/')
    else:
        url = urlparse(location)
        base_url = '%s://%s' % (url.scheme, url.netloc)

    return base_url

def ssdpManager():
    """
    Manages SSDP discoverable devices (SSDP and UPnP devices)
    """
    client = SSDPClient()
    devices = client.m_search("ssdp:all")
    manager = {}

    for device in devices:
        schema = getDeviceSchema(device['location'])
        ip = getBaseIP(schema, device['location'])
        device_info = schema.getElementsByTagName('device')[0]
        name =  XMLGetNodeText(device_info.getElementsByTagName('friendlyName')[0])
        if name not in manager.keys():
            output = {
                "parent": '',
                "version": '',
                "available": True,
                "name": name,
                "classes": [],
                "identifier": ip,
                "interface": 'SSDP',
            }
            manager[name] = output
    return manager


def wsDiscoveryManager():
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
                    "parent": '',
                    "version": '',
                    "available": True,
                    "name": service.getEPR(),
                    "classes": service.getTypes(),
                    "identifier": service.getXAddrs(),
                    "interface": 'WSDiscovery',
                }
            manager[service.getEPR()] = output

    return manager


def convertZeroConfAddr(addr_list):
    addrs = []
    for addr in addr_list:
        addrs.append('.'.join([str(i) for i in list(addr)]))

    return addrs


def zeroConfManager():
    """
    Manages ZeroConf discoverable devices (Bonjour and Avahi)
    This manager is run in side thread as its asynchrounous callback based
        execution.
    """

    services = {}

    class MyListener:

        def remove_service(self, zeroconf, type, name):
            remove(services[name]['resource_id'], 'https://nuvla.io', activated_path, cookies_file)
            print("Service %s removed" % (name,))

        def add_service(self, zeroconf, type, name):
            info = zeroconf.get_service_info(type, name)
            output = {
                "parent": '',
                "version": '',
                "available": True,
                "name": name,
                "classes": [],
                "identifier": convertZeroConfAddr(info.addresses),
                "interface": 'ZeroConf (Bonjour, Avahi)',
            }

            resource_id = add(output, 'https://nuvla.io', activated_path, cookies_file)
            services[name] = {'resource_id': resource_id}
            print("Service %s added, service info: %s" % (name, info))


    zeroconf = Zeroconf()
    listener = MyListener()
    browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        zeroconf.close() 


def ethernetManager(nuvlabox_id, nuvlabox_version):

    output = {}
    ssdp_output = ssdpManager()
    ws_discovery_output = wsDiscoveryManager()
    output.update(ssdp_output)
    output.update(ws_discovery_output)
    return output


def add(data, api_url, activated_path, cookies_file):

    api = Api(api_url)

    activated = json.load(open(activated_path))
    api_key = activated['api-key']
    secret_key = activated['secret-key']
    
    api.login_apikey(api_key, secret_key)

    response = api.add('nuvlabox-peripheral', data).data
    return response['resource-id']


def remove(resource_id, api_url, activated_path, cookies_file):
    
    api = Api(api_url)

    activated = json.load(open(activated_path))
    api_key = activated['api-key']
    secret_key = activated['secret-key']
    
    api.login_apikey(api_key, secret_key)

    response = api.delete(resource_id).data
    return response['resource-id']


if __name__ == "__main__":

    activated_path = '/srv/nuvlabox/shared/.activated'
    context_path = '/srv/nuvlabox/shared/.context'
    cookies_file = '/srv/nuvlabox/shared/cookies'
    peripheral_path = '/srv/nuvlabox/shared/peripherals'

    context = json.load(open(context_path))

    NUVLABOX_VERSION = context['version']
    NUVLABOX_ID = context['id']

    print('ETHERNET MANAGER STARTED')
    zeroConfManager()
       
    init_logger()

    API_URL = "https://nuvla.io"

    wait_bootstrap(context_path)

    e = Event()

    devices = {}
    zero_conf_thread = Thread(target=zeroConfManager, args=(1,))

    while True:

        current_devices = ethernetManager(NUVLABOX_ID, NUVLABOX_VERSION)
        print('CURRENT DEVICES: {}\n'.format(current_devices), flush=True)
        
        if current_devices != devices and current_devices:

            devices_set = set(devices.keys())
            current_devices_set = set(current_devices.keys())

            publishing = current_devices_set - devices_set
            removing = devices_set - current_devices_set

            for device in publishing:

                peripheral_already_registered = \
                    ethernetCheck(API_URL, current_devices[device])

                if not peripheral_already_registered:

                    print('PUBLISHING: {}'.format(current_devices[device]), flush=True)
                    resource_id = add(current_devices[device], 'https://nuvla.io', activated_path, cookies_file)
                    devices[device] = {'resource_id': resource_id, 'message': current_devices[device]}
                    createDeviceFile(device, devices[device], peripheral_path)


            for device in removing:

                peripheral_already_registered = \
                    ethernetCheck(API_URL, devices[device])

                if peripheral_already_registered:
                    print('REMOVING: {}'.format(devices[device]), flush=True)
                    read_file = readDeviceFile(device, peripheral_path)
                    remove(read_file['resource_id'], API_URL, activated_path, cookies_file)
                    del devices[device]
                    removeDeviceFile(device, peripheral_path)
        e.wait(timeout=90)
