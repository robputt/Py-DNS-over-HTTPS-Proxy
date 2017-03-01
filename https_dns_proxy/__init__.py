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

PINNED_CERT = ("MIIH4jCCBsqgAwIBAgIIMfyNK/Ybs1gwDQYJKoZIhvcNAQELBQAwSTELMAkGA1"
               "UEBhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJ"
               "bnRlcm5ldCBBdXRob3JpdHkgRzIwHhcNMTcwMjIyMDkxMjI3WhcNMTcwNTE3MD"
               "g1NzAwWjBmMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQG"
               "A1UEBwwNTW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEVMBMGA1"
               "UEAwwMKi5nb29nbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC"
               "AQEAxKa6UzbwAQVYojezXSdHAzFeX9+Jv0LKIuOFZ1IIGdpi5TyHptYnKilwcA"
               "GYQ8PVsnjHOEWBftQ+GJgHG0lgbCE3XDLCMHJ8dwS30GZteazvhZC9ogVSN7/t"
               "99ls7UBQlvtcOeumcmbi3guV4dHpKuZiz6gXh40pdNeH6tL6PhSq+3hwmPCT4k"
               "O/qYKT/bT6nwAhbG9zPlz2tHNx6xlMgpBMNVRnOGjIGfvz1HAzY/qba6egwb4v"
               "xH2BgsO7kg/jE4xBwNYeUtEGPLS46VlJtRA2hMxbjWfnNJJ/en/i/CPAf2ijDc"
               "CfadHTFA7RdLieNKY1BDMDXfufiQQXhH9qfQIDAQABo4IErzCCBKswHQYDVR0l"
               "BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMIIDewYDVR0RBIIDcjCCA26CDCouZ2"
               "9vZ2xlLmNvbYINKi5hbmRyb2lkLmNvbYIWKi5hcHBlbmdpbmUuZ29vZ2xlLmNv"
               "bYISKi5jbG91ZC5nb29nbGUuY29tgg4qLmdjcC5ndnQyLmNvbYIWKi5nb29nbG"
               "UtYW5hbHl0aWNzLmNvbYILKi5nb29nbGUuY2GCCyouZ29vZ2xlLmNsgg4qLmdv"
               "b2dsZS5jby5pboIOKi5nb29nbGUuY28uanCCDiouZ29vZ2xlLmNvLnVrgg8qLm"
               "dvb2dsZS5jb20uYXKCDyouZ29vZ2xlLmNvbS5hdYIPKi5nb29nbGUuY29tLmJy"
               "gg8qLmdvb2dsZS5jb20uY2+CDyouZ29vZ2xlLmNvbS5teIIPKi5nb29nbGUuY2"
               "9tLnRygg8qLmdvb2dsZS5jb20udm6CCyouZ29vZ2xlLmRlggsqLmdvb2dsZS5l"
               "c4ILKi5nb29nbGUuZnKCCyouZ29vZ2xlLmh1ggsqLmdvb2dsZS5pdIILKi5nb2"
               "9nbGUubmyCCyouZ29vZ2xlLnBsggsqLmdvb2dsZS5wdIISKi5nb29nbGVhZGFw"
               "aXMuY29tgg8qLmdvb2dsZWFwaXMuY26CFCouZ29vZ2xlY29tbWVyY2UuY29tgh"
               "EqLmdvb2dsZXZpZGVvLmNvbYIMKi5nc3RhdGljLmNugg0qLmdzdGF0aWMuY29t"
               "ggoqLmd2dDEuY29tggoqLmd2dDIuY29tghQqLm1ldHJpYy5nc3RhdGljLmNvbY"
               "IMKi51cmNoaW4uY29tghAqLnVybC5nb29nbGUuY29tghYqLnlvdXR1YmUtbm9j"
               "b29raWUuY29tgg0qLnlvdXR1YmUuY29tghYqLnlvdXR1YmVlZHVjYXRpb24uY2"
               "9tggsqLnl0aW1nLmNvbYIaYW5kcm9pZC5jbGllbnRzLmdvb2dsZS5jb22CC2Fu"
               "ZHJvaWQuY29tghtkZXZlbG9wZXIuYW5kcm9pZC5nb29nbGUuY26CBGcuY2+CBm"
               "dvby5nbIIUZ29vZ2xlLWFuYWx5dGljcy5jb22CCmdvb2dsZS5jb22CEmdvb2ds"
               "ZWNvbW1lcmNlLmNvbYIKdXJjaGluLmNvbYIKd3d3Lmdvby5nbIIIeW91dHUuYm"
               "WCC3lvdXR1YmUuY29tghR5b3V0dWJlZWR1Y2F0aW9uLmNvbTBoBggrBgEFBQcB"
               "AQRcMFowKwYIKwYBBQUHMAKGH2h0dHA6Ly9wa2kuZ29vZ2xlLmNvbS9HSUFHMi"
               "5jcnQwKwYIKwYBBQUHMAGGH2h0dHA6Ly9jbGllbnRzMS5nb29nbGUuY29tL29j"
               "c3AwHQYDVR0OBBYEFOsnCPaT5ZLy3gb9H5qJn/bkl1EwMAwGA1UdEwEB/wQCMA"
               "AwHwYDVR0jBBgwFoAUSt0GFhu89mi1dvWBtrtiGrpagS8wIQYDVR0gBBowGDAM"
               "BgorBgEEAdZ5AgUBMAgGBmeBDAECAjAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi"
               "8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQAV"
               "b1pRqPRZMOH3nXxzt1LHbKqrs2S7GbhIIEx8VlLk1b97iZa7XeNL/2eMiYhtIK"
               "R17yN/3TD+fwVKmvFmsVWi1HmdSJ8IuZ1d+Y2T/0C0w9OhRKTzQfsGs/xieiJw"
               "vlPEEGRxXuN7oq8Mi+HCJGwwNVba5f3dd0HtT6bZtjvyyZo6HjWR1QZo8Zttn7"
               "2BoVFFtRzyUm2Z+/wh7LdztJ1lk5YjzF0InsAHGBHaCV8K1fDxwXEFqq6Vf03T"
               "1jXr0eOg6NGcvB7Z/PcmXFxmRD2iqUiWhJ+gjOBdC/7w5Dv4kJwfLb4pV9py/8"
               "bLI/zKiKdX10QcfEYD4FUglAQIiB2z")


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
