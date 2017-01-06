import time
import requests
import json
import signal
from dnslib.server import DNSServer
from dnslib.server import BaseResolver
from dnslib.server import DNSLogger
from dnslib.server import RR
from dnslib import QTYPE

GOOGLE_DNS_URL = 'https://dns.google.com/resolve?'


class HTTPSResolver(BaseResolver):

    def resolve(self, request, handler):
        hostname = '.'.join(request.q.qname.label)
        ltype = request.q.qtype
        lookup_resp = requests.get('%sname=%s&type=%s' % (GOOGLE_DNS_URL,
                                                          hostname,
                                                          ltype))

        reply = request.reply()
        if lookup_resp.status_code == 200:
            try:
                answer = json.loads(lookup_resp.text)['Answer']
                for record in answer:
                    rtype = QTYPE[record['type']]
                    zone = "%s %s %s %s" % (str(record['name']),
                                            record['TTL'],
                                            rtype,
                                            str(record['data']))
                    reply.add_answer(*RR.fromZone(zone))
            except:
                pass

        return reply


class DNSProxy(object):

    def __init__(self):
        self.is_running = True

    def run_dns_proxy(self):
        resolver = HTTPSResolver()
        logger = DNSLogger()

        server = DNSServer(resolver,
                           port=8053,
                           address='localhost',
                           logger=logger)

        server.start_thread()
        while self.is_running:
            # this just keeps the thing alive...
            time.sleep(5)
        server.stop()

    def stop(self, signal, handler):
        self.is_running = False


if __name__ == "__main__":
    dns_proxy = DNSProxy()
    signal.signal(signal.SIGINT, dns_proxy.stop)
    dns_proxy.run_dns_proxy()
