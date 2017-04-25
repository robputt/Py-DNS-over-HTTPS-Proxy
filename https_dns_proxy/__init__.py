import time
import requests
import json
import signal
import base64
import os
import datetime
from dnslib.server import DNSServer
from dnslib.server import BaseResolver
from dnslib.server import DNSLogger
from dnslib.server import RR
from dnslib import QTYPE


GOOGLE_DNS_URL = 'https://216.58.212.110/resolve?'

PINNED_CERT = ("MIIHXDCCBkSgAwIBAgIIT8oHuVk3XwgwDQYJKoZIhvcNAQELBQAwSTELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRlcm5ldCBBdXRob3JpdHkgRzIwHhcNMTcwNDEyMTMzNzMwWhcNMTcwNzA1MTMyODAwWjBmMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEVMBMGA1UEAwwMKi5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIw8cmFSZx6YFPuXs/mnipdeqIqSWOlmUrbk27oy7u8Br2Aov0pfgPxorThxZLSsTke6nE0lRGfftRDmtA6ESFaOCBPQwggTwMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjALBgNVHQ8EBAMCB4AwggOzBgNVHREEggOqMIIDpoIMKi5nb29nbGUuY29tgg0qLmFuZHJvaWQuY29tghYqLmFwcGVuZ2luZS5nb29nbGUuY29tghIqLmNsb3VkLmdvb2dsZS5jb22CDiouZ2NwLmd2dDIuY29tghYqLmdvb2dsZS1hbmFseXRpY3MuY29tggsqLmdvb2dsZS5jYYILKi5nb29nbGUuY2yCDiouZ29vZ2xlLmNvLmlugg4qLmdvb2dsZS5jby5qcIIOKi5nb29nbGUuY28udWuCDyouZ29vZ2xlLmNvbS5hcoIPKi5nb29nbGUuY29tLmF1gg8qLmdvb2dsZS5jb20uYnKCDyouZ29vZ2xlLmNvbS5jb4IPKi5nb29nbGUuY29tLm14gg8qLmdvb2dsZS5jb20udHKCDyouZ29vZ2xlLmNvbS52boILKi5nb29nbGUuZGWCCyouZ29vZ2xlLmVzggsqLmdvb2dsZS5mcoILKi5nb29nbGUuaHWCCyouZ29vZ2xlLml0ggsqLmdvb2dsZS5ubIILKi5nb29nbGUucGyCCyouZ29vZ2xlLnB0ghIqLmdvb2dsZWFkYXBpcy5jb22CDyouZ29vZ2xlYXBpcy5jboIUKi5nb29nbGVjb21tZXJjZS5jb22CESouZ29vZ2xldmlkZW8uY29tggwqLmdzdGF0aWMuY26CDSouZ3N0YXRpYy5jb22CCiouZ3Z0MS5jb22CCiouZ3Z0Mi5jb22CFCoubWV0cmljLmdzdGF0aWMuY29tggwqLnVyY2hpbi5jb22CECoudXJsLmdvb2dsZS5jb22CFioueW91dHViZS1ub2Nvb2tpZS5jb22CDSoueW91dHViZS5jb22CFioueW91dHViZWVkdWNhdGlvbi5jb22CCyoueXRpbWcuY29tghphbmRyb2lkLmNsaWVudHMuZ29vZ2xlLmNvbYILYW5kcm9pZC5jb22CG2RldmVsb3Blci5hbmRyb2lkLmdvb2dsZS5jboIcZGV2ZWxvcGVycy5hbmRyb2lkLmdvb2dsZS5jboIEZy5jb4IGZ29vLmdsghRnb29nbGUtYW5hbHl0aWNzLmNvbYIKZ29vZ2xlLmNvbYISZ29vZ2xlY29tbWVyY2UuY29tghhzb3VyY2UuYW5kcm9pZC5nb29nbGUuY26CCnVyY2hpbi5jb22CCnd3dy5nb28uZ2yCCHlvdXR1LmJlggt5b3V0dWJlLmNvbYIUeW91dHViZWVkdWNhdGlvbi5jb20waAYIKwYBBQUHAQEEXDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0GA1UdDgQWBBTHwj4BpNP0Tt5Zf5gxfcCLiMUdmjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMCEGA1UdIAQaMBgwDAYKKwYBBAHWeQIFATAIBgZngQwBAgIwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3BraS5nb29nbGUuY29tL0dJQUcyLmNybDANBgkqhkiG9w0BAQsFAAOCAQEAYfeUmVjHeq2ZRffJQwxujBrYDHyWUSm4ARst+8Toq7qswLBpSTqMgWc8PXQNC+UNmAQyq1LK0R69miRDmaszt6N3HitO+0cO8y5EWCsv7rOrn+3k1jebzEITUxhN61cpcf8uPXkoCsMwNt/AolnLTWl0o5ROZKDQtVUisoA+L0olFUlXNT2EJsY69mc4vvFJNQEX1KeiNaPWntgqFf3q5Yg0acLZ9gefbM16YB4o4+jjO/p6GYm6Qwz5KsFhn4Dawgph6cAxZNzwwTwB5YOoiXlDI0iI++aMCA7hHlFf8cURScDm8+gtMOaLJs75VYPI8rK2xuhOU9bm1fiy+MMjYQ==")


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
        hostname = '.'.join(request.q.qname.label)
        ltype = request.q.qtype
        headers = {"Host": "dns.google.com"}

        try:
            if CACHE[hostname]['dt'] > datetime.datetime.now() - datetime.timedelta(minutes=30):
                print "Cache Hit: %s" % hostname
                answer = CACHE[hostname][ltype]
            else:
                print "Cache Expired: %s" % hostname
                del CACHE[hostname]
                raise Exception("Cache Expired")
        except:
            lookup_resp = requests.get('%sname=%s&type=%s' % (GOOGLE_DNS_URL,
                                                          hostname,
                                                          ltype),
                                   headers=headers,
                                   verify=False)

            if PINNED_CERT != lookup_resp.peercert:
                print lookup_resp.peercert
                print ("WARNING: REMOTE SSL CERT DID NOT MATCH EXPECTED (PINNED) "
                       "SSL CERT, EXITING IN CASE OF MAN IN THE MIDDLE ATTACK")
                my_pid = os.getpid()
                os.kill(my_pid, signal.SIGINT)

            if lookup_resp.status_code == 200:
                try:
                    print "Cache Miss: %s" % hostname
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
                           port=8053,
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
    dns_proxy = DNSProxy()
    signal.signal(signal.SIGINT, dns_proxy.stop)
    dns_proxy.run_dns_proxy()


if __name__ == "__main__":
    run()
