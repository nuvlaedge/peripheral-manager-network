

import nmap
import pynmcli
import socket
import subprocess
import logging
import requests
import sys
import time
from threading import Event
import os
import json


identifier = 'ethernet'

def init_logger():
    """ Initializes logging """

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(levelname)s - %(funcName)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)


def wait_bootstrap(healthcheck_endpoint="http://agent/api/healthcheck"):
    """ Simply waits for the NuvlaBox to finish bootstrapping, by pinging the Agent API
    :returns
    """

    logging.info("Checking if NuvlaBox has been initialized...")

    r = requests.get(healthcheck_endpoint)
    
    while not r.ok:
        time.sleep(5)
        r = requests.get(healthcheck_endpoint)

    logging.info('NuvlaBox has been initialized.')
    return

def send(url, assets):
    """ Sends POST request for registering new peripheral """

    logging.info("Sending GPU information to Nuvla")
    return publish(url, assets)


def ethernetCheck(api_url, currentNetwork):
    """ Checks if peripheral already exists """

    logging.info('Checking if Network Devices are already published')

    get_ethernet = requests.get(api_url + '?identifier_pattern=' + identifier)
    
    logging.info(get_ethernet.json())

    if not get_ethernet.ok or not isinstance(get_ethernet.json(), list) or len(get_ethernet.json()) == 0:
        logging.info('No Network Device published.')
        return True
    
    elif get_ethernet.json() != currentNetwork:
        logging.info('Network has changed')
        return True

    logging.info('Network Devices were already been published.')
    return False


def wifi_card():
    
    wifi = str(subprocess.run(["nmcli", "r", "wifi"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout).replace("b'", "")[:-3]
    
    if wifi == 'enabled':
        return True
    
    return False


def wifi_connection():

    return pynmcli.get_data(pynmcli.NetworkManager.Device().wifi().execute())


def publish(url, assets):
    """
    API publishing function.
    """

    x = requests.post(url, json=assets)
    return x.json()


def ipAddr():

    ip = str(subprocess.run(["hostname", "-I"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout).split(' ')[0].replace("b'", "")
    return ip


def searchIP(deviceIp):
    
    search = '{}.0/24'
    ip = '.'.join(deviceIp.split('.')[:-1])
    return search.format(ip)


def nmapLocalSearch(searchIP):

    output = {}

    nm = nmap.PortScanner()

    scan = nm.scan(hosts=searchIP, arguments='-n -sP')

    for i in scan['scan']:

        try:
            hostname = socket.gethostbyaddr(i)[0]
        except:
            hostname = ''
        output[i] = {'status': scan['scan'][i]['status'], 'hostnames': hostname}
    
    return output


def networkManager():

    localIP = searchIP(ipAddr())

    nmapSearch = nmapLocalSearch(localIP)
    wifiSearch = wifi_connection()

    output = {
            'available': True,
            'name': 'Network',
            'classes': ['network'],
            'identifier': identifier,
            'additional-assets': {'ethernet-devices': nmapSearch, 'wifi-devices': wifiSearch}
        }
    
    return output
    

if __name__ == "__main__":

    init_logger()

    API_BASE_URL = "http://agent/api"

    wait_bootstrap()

    API_URL = API_BASE_URL + "/peripheral"

    e = Event()

    while True:

        current_network = networkManager()

        if current_network:
            peripheral_already_registered = ethernetCheck(API_URL, current_network)

            if peripheral_already_registered:
                send(API_URL, current_network)

        e.wait(timeout=90)


