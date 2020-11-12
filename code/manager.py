#!/usr/bin/env python3

# -*- coding: utf-8 -*-

"""NuvlaBox Peripheral Manager Network
This service provides network devices discovery.
"""

import logging
import requests
import time
import json
import os
import xmltodict
import re
from threading import Event
from nuvla.api import Api
# Packages for Service Discovery
from ssdpy import SSDPClient
from xml.dom import minidom
from urllib.parse import urlparse
from wsdiscovery.discovery import ThreadedWSDiscovery as WSDiscovery
from zeroconf import ZeroconfServiceTypes, ServiceBrowser, Zeroconf

scanning_interval = 30
logging.basicConfig(level=logging.INFO)


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
    if device_addr in os.listdir(f'{peripheral_dir}{protocol}'):
        file_content = readDeviceFile(device_addr, protocol, peripheral_dir)

        return True, file_content.get('resource-id')
    return False, None


def get_saved_peripherals(peripheral_dir, protocol):
    """
    To be used at bootstrap, to check for existing peripherals, just to make sure we delete old and only insert new
    peripherals, that have been modified during the NuvlaBox shutdown

    :param peripheral_dir: base peripheral dir in shared volume
    :param protocol: protocol name
    :return: map of device identifiers and content
    """
    output = {}

    for identifier in os.listdir(f'{peripheral_dir}{protocol}'):
        file_content = readDeviceFile(identifier, protocol, peripheral_dir)
        if 'message' in file_content:
            output[identifier] = file_content['message']
        else:
            continue

    return output


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


def wsDiscoveryManager(nuvlabox_id, nuvlabox_version, wsdaemon):
    """
    Manages WSDiscovery discoverable devices
    """
    manager = {}

    wsdaemon.start()

    services = wsdaemon.searchServices(timeout=6)
    for service in services:
        identifier = str(service.getEPR()).split(':')[-1]
        classes = [ re.split("/|:", str(c))[-1] for c in service.getTypes() ]
        name = " | ".join(classes)
        if identifier not in manager.keys():
            output = {
                "parent": nuvlabox_id,
                "version": nuvlabox_version,
                "available": True,
                "name": name,
                "description": f"[wsdiscovery peripheral] {str(service.getEPR())} | Scopes: {', '.join([str(s) for s in service.getScopes()])}",
                "classes": classes,
                "identifier": identifier,
                "interface": 'WS-Discovery',
            }

            if len(service.getXAddrs()) > 0:
                output['device-path'] = ", ".join([str(x) for x in service.getXAddrs()])

            manager[identifier] = output

    wsdaemon.stop()

    return manager


class ZeroConfListener:
    all_info = {}
    listening_to = {}

    def remove_service(self, zeroconf, type, name):
        logging.info(f"[zeroconf] Service {name} removed")
        if name in self.all_info:
            self.all_info.pop(name)

    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        logging.info(f"[zeroconf] Service {name} added")
        self.all_info[name] = info


def format_zeroconf_services(nb_id, nb_version, services):
    """ Formats the Zeroconf listener services into a Nuvla compliant data format

    :param services: list of zeroconf services from lister, i.e. list = {'service_name': ServiceInfo, ...}
    :return: Nuvla formatted peripheral data
    """

    output = {}

    for service_name, service_data in services.items():
        try:
            identifier = service_data.server

            if identifier not in output:
                output[identifier] = {
                    'parent': nb_id,
                    'name': service_data.server,
                    'description': f'{service_name}:{service_data.port}',
                    'version': nb_version,
                    'identifier': identifier,
                    'available': True,
                    'interface': "Bonjour/Avahi",
                    'classes': [service_data.type]
                }

            if service_data.type not in output[identifier]['classes']:
                output[identifier]['classes'].append(service_data.type)

            if service_data.parsed_addresses() and 'device-path' not in output[identifier]:
                output[identifier]['device-path'] = service_data.parsed_addresses()[0]

            if service_name not in output[identifier]['description']:
                output[identifier]['description'] += f' | {service_name}:{service_data.port}'

            try:
                properties = service_data.properties
                if properties and isinstance(properties, dict):
                    dict_properties = dict(map(lambda tup:
                                               map(lambda el: el.decode('ascii', errors="ignore"), tup),
                                               properties.items()))

                    # Try to find a limited and predefined list of known useful attributes:

                    # for the device model name:
                    product_name_known_keys = ['model', 'ModelName', 'am', 'rpMd', 'name']
                    matched_keys = list(product_name_known_keys & dict_properties.keys())
                    if matched_keys:
                        output[identifier]['name'] = output[identifier]['product'] = dict_properties[matched_keys[0]]

                    # for additional description
                    if 'uname' in dict_properties:
                        output[identifier]['description'] += f'. OS: {dict_properties["uname"]}'

                    if 'description' in dict_properties:
                        output[identifier]['description'] += f'. Extra description: {dict_properties["description"]}'

                    # for additional classes
                    if 'class' in dict_properties:
                        output[identifier]['class'].append(dict_properties['class'])
            except:
                # this is only to get additional info on the peripheral, if it fails, we can live without it
                pass
        except:
            logging.exception(f'Unable to categorize Zeroconf peripheral {service_name} with data: {service_data}')
            continue

    return output


def parse_zeroconf_devices(nb_id, nb_version, zc, listener):
    """ Manages the Zeroconf listeners and parse the existing broadcasted services

    :param nb_id: nuvlabox id
    :param nb_version: nuvlabox version
    :param zc: zeroconf object
    :param listener: zeroconf listener instance
    :return: list of peripheral documents
    """

    service_types_available = set(ZeroconfServiceTypes.find())

    old_service_types = set(listener.listening_to) - service_types_available
    new_service_types = service_types_available - set(listener.listening_to)

    for new in new_service_types:
        listener.listening_to[new] = ServiceBrowser(zc, new, listener)

    for old in old_service_types:
        listener.listening_to[old].cancel()
        logging.info(f'Removing Zeroconf listener for service type {old}: {listener.listening_to.pop(old)}')

    return format_zeroconf_services(nb_id, nb_version, listener.all_info)


def network_manager(nuvlabox_id, nuvlabox_version, zc_obj, zc_listener, wsdaemon):
    """
    Runs and manages the outputs from the discovery.
    """

    output = {}

    zeroconf_output = parse_zeroconf_devices(nuvlabox_id, nuvlabox_version, zc_obj, zc_listener)
    ssdp_output = ssdpManager(nuvlabox_id, nuvlabox_version)
    ws_discovery_output = wsDiscoveryManager(nuvlabox_id, nuvlabox_version, wsdaemon)
    output['ssdp'] = ssdp_output
    output['ws-discovery'] = ws_discovery_output
    output['zeroconf'] = zeroconf_output
    return output


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

    old_devices = {'ssdp': get_saved_peripherals(peripheral_path, 'ssdp'),
                   'ws-discovery': get_saved_peripherals(peripheral_path, 'ws-discovery'),
                   'zeroconf': get_saved_peripherals(peripheral_path, 'zeroconf')}

    logging.info(f'Peripherals registered from the previous run: {old_devices}')

    zeroconf = Zeroconf()
    zeroconf_listener = ZeroConfListener()

    wsdaemon = WSDiscovery()

    api = authenticate(API_URL, nuvla_endpoint_insecure, activated_path)

    while True:

        current_devices = network_manager(NUVLABOX_ID, NUVLABOX_VERSION, zeroconf, zeroconf_listener, wsdaemon)
        logging.info('CURRENT DEVICES: {}'.format(current_devices))

        for protocol in current_devices:

            if current_devices[protocol] != old_devices[protocol]:

                old_devices_set = set(old_devices[protocol].keys())
                current_devices_set = set(current_devices[protocol].keys())

                publishing = current_devices_set - old_devices_set
                removing = old_devices_set - current_devices_set

                for device in publishing:

                    peripheral_already_registered, res_id = \
                        network_per_exists_check(peripheral_path, protocol, device)

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
                        network_per_exists_check(peripheral_path, protocol, device)

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
