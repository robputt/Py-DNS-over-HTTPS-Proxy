import time
import requests
import json
from dnslib.server import DNSServer
from dnslib.server import BaseResolver
from dnslib.server import DNSLogger
from dnslib.server import RR
from dnslib import QTYPE

GOOGLE_DNS_URL = 'https://dns.google.com/resolve?'

class HTTPSResolver(BaseResolver):
    
    def resolve(self, request, handler):
        hostname = '.'.join(request.q.qname.label)
        lookup_resp = requests.get('%sname=%s' % (GOOGLE_DNS_URL, hostname))
        reply = request.reply()
        if lookup_resp.status_code == 200:
            print lookup_resp.text
            try:
                answer = json.loads(lookup_resp.text)['Answer']
                for record in answer:
                    print record
                    type = QTYPE[record['type']]
                    reply.add_answer(*RR.fromZone("%s %s %s %s" % (str(record['name']),
                                                                      record['TTL'],
                                                                      type,
                                                                      str(record['data']))))
            except:
                pass

        return reply


resolver = HTTPSResolver()
logger = DNSLogger()

server = DNSServer(resolver,
                   port=8053,
                   address='localhost',
                   logger=logger)

server.start_thread()

while True:
    # this just keeps the thing alive...
    time.sleep(5)
