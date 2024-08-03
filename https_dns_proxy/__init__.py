import time
import requests
import json
import signal
import base64
import os
import datetime
import sys
import logging

from configparser import ConfigParser

from dnslib.server import DNSServer
from dnslib.server import BaseResolver
from dnslib.server import DNSLogger
from dnslib.server import RR
from dnslib import QTYPE


# Configure logger
logging.basicConfig(level=logging.INFO)

# Read from config file.
myconfig = ConfigParser()
config_name = 'config.ini'
config_path = os.path.join(sys.path[0], config_name)
myconfig.read_file(open(config_path))

if len(sys.argv) == 2:
    ENVIRONMENT=str(sys.argv[1])
else:
    ENVIRONMENT='DNS1'

GOOGLE_DNS_URL = myconfig.get(ENVIRONMENT, 'GOOGLE_DNS_URL')
PINNED_CERT = myconfig.get(ENVIRONMENT, 'PINNED_CERT').encode('utf-8')
DNS_PORT = int(myconfig.get(ENVIRONMENT, 'DNS_PORT'))
EXIT_ON_MITM = myconfig.get(ENVIRONMENT, 'EXIT_ON_MITM')


HTTPResponse = requests.packages.urllib3.response.HTTPResponse
orig_HTTPResponse__init__ = HTTPResponse.__init__
def new_HTTPResponse__init__(self, *args, **kwargs):
    orig_HTTPResponse__init__(self, *args, **kwargs)
    try:
        self.peercert = base64.b64encode(self._connection.sock.getpeercert(True))
    except AttributeError:
        pass
HTTPResponse.__init__ = new_HTTPResponse__init__


HTTPAdapter = requests.adapters.HTTPAdapter
orig_HTTPAdapter_build_response = HTTPAdapter.build_response
def new_HTTPAdapter_build_response(self, request, resp):
    response = orig_HTTPAdapter_build_response(self, request, resp)
    try:
        response.peercert = resp.peercert
    except AttributeError:
        pass
    return response
HTTPAdapter.build_response = new_HTTPAdapter_build_response


CACHE = {}


class HTTPSResolver(BaseResolver):

    def resolve(self, request, handler):
        hostname = str(request.q.qname)
        ltype = request.q.qtype
        headers = {"Host": "dns.google"}

        try:
            if CACHE[hostname]['dt'] > datetime.datetime.now() - datetime.timedelta(minutes=5):
                logging.info("Cache Hit: %s" % hostname)
                answer = CACHE[hostname][ltype]
            else:
                logging.info("Cache Expired: %s" % hostname)
                del CACHE[hostname]
                raise Exception("Cache Expired")
        except:
            lookup_resp = requests.get(
                '%sname=%s&type=%s' % (
                    GOOGLE_DNS_URL,
                    hostname,
                    ltype
                ),
                headers=headers,
                verify=False
            )

            if PINNED_CERT != lookup_resp.peercert:
                logging.info(lookup_resp.peercert)
                if EXIT_ON_MITM:
                    logging.error("REMOTE SSL CERT DID NOT MATCH EXPECTED (PINNED) "
                           "SSL CERT, EXITING IN CASE OF MAN IN THE MIDDLE ATTACK")
                    my_pid = os.getpid()
                    os.kill(my_pid, signal.SIGINT)
                else:
                    logging.warning("REMOTE SSL CERT DID NOT MATCH EXPECTED (PINNED) "
                           "SSL CERT. NOT EXITING, BECAUSE YOU SAID SO IN YOUR CONFIG")


            if lookup_resp.status_code == 200:
                try:
                    logging.info("Cache Miss: %s" % hostname)
                    answer = json.loads(lookup_resp.text)['Answer']
                    CACHE[hostname] = {ltype: answer, "dt": datetime.datetime.now()}
                except:
                    answer = []
            else:
                answer = []

        reply = request.reply()
        for record in answer:
            rtype = QTYPE[record['type']]
            zone = "%s %s %s %s" % (str(record['name']),
                                    record['TTL'],
                                    rtype,
                                    str(record['data']))
            reply.add_answer(*RR.fromZone(zone))

        return reply


class DNSProxy(object):

    def __init__(self):
        self.is_running = True

    def run_dns_proxy(self):
        resolver = HTTPSResolver()
        logger = DNSLogger()

        server = DNSServer(resolver,
                           port=DNS_PORT,
                           address='localhost',
                           logger=logger)

        server.start_thread()
        while self.is_running:
            # this just keeps the thing alive...
            time.sleep(5)
        server.stop()

    def stop(self, signal, handler):
        self._stop()

    def _stop(self):
        self.is_running = False


def run():
    logging.info("DNS Proxy Listening on Port %s" % DNS_PORT)
    logging.info("Test using following DIG command...")
    logging.info("dig @localhost -p8053 google.com")
    dns_proxy = DNSProxy()
    signal.signal(signal.SIGINT, dns_proxy.stop)
    dns_proxy.run_dns_proxy()


if __name__ == "__main__":
    run()
