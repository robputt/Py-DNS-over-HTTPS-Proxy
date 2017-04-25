# Py-DNS-over-HTTPS-Proxy
Provides a simple Python based proxy for running DNS over HTTPS to Google's DNS over HTTPS service.

Recently I wrote a blog post which probably gives you just enough information to get this up and running on a Mac / Linux box... https://www.robertputt.co.uk/2017/01/06/securing-dns-traffic-with-dns-over-https/, please note this script only seems to play nice with Python2.7 not Python 3.x

Configuration can be easily done with virtualenv:

```
virtualenv dns_proxy
cd dns_proxy/
source bin/activate
pip install dnslib requests
git clone https://github.com/robputt796/Py-DNS-over-HTTPS-Proxy.git
cat Py-DNS-over-HTTPS-Proxy/https_dns_proxy/config.ini
python Py-DNS-over-HTTPS-Proxy/https_dns_proxy/__init__.py &
dig @localhost -p8053 A robertputt.co.uk
```
