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

PINNED_CERT = ('MIIH4jCCBsqgAwIBAgIIJURJ2M4nnrIwDQYJKoZIhvcNAQELBQAwSTELMAkGA1U'
               'EBhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbn'
               'Rlcm5ldCBBdXRob3JpdHkgRzIwHhcNMTcwMjAxMTM0NzE4WhcNMTcwNDI2MTMyM'
               'TAwWjBmMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UE'
               'BwwNTW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEVMBMGA1UEAww'
               'MKi5nb29nbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhW'
               'ayKI6kpw0lVhKVIq18f57ALtZCBFNmuE2C9TDYqZHloxfr48mA+/zOJ63Y7TJB+'
               '3XfzD09HJTKPP44RAr7e96Q6zaMrTDVBDTmgORMn6qp10CK4lyKIWNfIv1glVnG'
               'nVLVyiLbT7jqaF4vlzQMP/QBtgzpFZTnqJtHO0INJSguGOaV1+uCIZ3V9L3OCM9'
               '+Eg84m+OLOjRPr5Bbq16CwXw1g6b5IYTT6jnZOwXtQE6JVIFzhmjPAkkCNRg9i+'
               'hxXtwmNGR0Nj/rC358dKwQSsD4trrv0qX0I8ovazwx/TlHMA9j3u+OyiNkf/Tga'
               'R6rCcPVDdC/YrCgZzSplvKB5wIDAQABo4IErzCCBKswHQYDVR0lBBYwFAYIKwYB'
               'BQUHAwEGCCsGAQUFBwMCMIIDewYDVR0RBIIDcjCCA26CDCouZ29vZ2xlLmNvbYI'
               'NKi5hbmRyb2lkLmNvbYIWKi5hcHBlbmdpbmUuZ29vZ2xlLmNvbYISKi5jbG91ZC'
               '5nb29nbGUuY29tgg4qLmdjcC5ndnQyLmNvbYIWKi5nb29nbGUtYW5hbHl0aWNzL'
               'mNvbYILKi5nb29nbGUuY2GCCyouZ29vZ2xlLmNsgg4qLmdvb2dsZS5jby5pboIO'
               'Ki5nb29nbGUuY28uanCCDiouZ29vZ2xlLmNvLnVrgg8qLmdvb2dsZS5jb20uYXK'
               'CDyouZ29vZ2xlLmNvbS5hdYIPKi5nb29nbGUuY29tLmJygg8qLmdvb2dsZS5jb2'
               '0uY2+CDyouZ29vZ2xlLmNvbS5teIIPKi5nb29nbGUuY29tLnRygg8qLmdvb2dsZ'
               'S5jb20udm6CCyouZ29vZ2xlLmRlggsqLmdvb2dsZS5lc4ILKi5nb29nbGUuZnKC'
               'CyouZ29vZ2xlLmh1ggsqLmdvb2dsZS5pdIILKi5nb29nbGUubmyCCyouZ29vZ2x'
               'lLnBsggsqLmdvb2dsZS5wdIISKi5nb29nbGVhZGFwaXMuY29tgg8qLmdvb2dsZW'
               'FwaXMuY26CFCouZ29vZ2xlY29tbWVyY2UuY29tghEqLmdvb2dsZXZpZGVvLmNvb'
               'YIMKi5nc3RhdGljLmNugg0qLmdzdGF0aWMuY29tggoqLmd2dDEuY29tggoqLmd2'
               'dDIuY29tghQqLm1ldHJpYy5nc3RhdGljLmNvbYIMKi51cmNoaW4uY29tghAqLnV'
               'ybC5nb29nbGUuY29tghYqLnlvdXR1YmUtbm9jb29raWUuY29tgg0qLnlvdXR1Ym'
               'UuY29tghYqLnlvdXR1YmVlZHVjYXRpb24uY29tggsqLnl0aW1nLmNvbYIaYW5kc'
               'm9pZC5jbGllbnRzLmdvb2dsZS5jb22CC2FuZHJvaWQuY29tghtkZXZlbG9wZXIu'
               'YW5kcm9pZC5nb29nbGUuY26CBGcuY2+CBmdvby5nbIIUZ29vZ2xlLWFuYWx5dGl'
               'jcy5jb22CCmdvb2dsZS5jb22CEmdvb2dsZWNvbW1lcmNlLmNvbYIKdXJjaGluLm'
               'NvbYIKd3d3Lmdvby5nbIIIeW91dHUuYmWCC3lvdXR1YmUuY29tghR5b3V0dWJlZ'
               'WR1Y2F0aW9uLmNvbTBoBggrBgEFBQcBAQRcMFowKwYIKwYBBQUHMAKGH2h0dHA6'
               'Ly9wa2kuZ29vZ2xlLmNvbS9HSUFHMi5jcnQwKwYIKwYBBQUHMAGGH2h0dHA6Ly9'
               'jbGllbnRzMS5nb29nbGUuY29tL29jc3AwHQYDVR0OBBYEFNu2vHcVGVm8ike6ur'
               'NCMKN/zKzkMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUSt0GFhu89mi1dvWBt'
               'rtiGrpagS8wIQYDVR0gBBowGDAMBgorBgEEAdZ5AgUBMAgGBmeBDAECAjAwBgNV'
               'HR8EKTAnMCWgI6Ahhh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3JsMA0'
               'GCSqGSIb3DQEBCwUAA4IBAQBsRcPps7oA5w+qoxYt4TOo1AX/xGaEKN6TCkuXMM'
               '6/kqCt+KIkiGF6li9vs0ygLaURjW/spmEQq78yAvqtGxcFhczBXkSJTGoGlX/xj'
               'dHlGVE2H9ZoEf8fE5erJnehvsEBjV3Dotbes1HzcmZiMX1vQfh8ZDxb6Ah+o/cp'
               'Nonr8E7GZysgsIo0S7dy+NBGdpLK6TnGgh+u7X5dRN49grjp52Ltf3hLP64PN+n'
               'MSOqXxfvKEwGUfSDZv8EPelp1wTdh/X+OTuYJPFLRKT1O5tSGLsBtsVpL5C23k/'
               'fjSXqoiU9MYN3+XiJnKjN4rBWGiOnZa8bQ5lCJItCoXvM2wWGq')


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
