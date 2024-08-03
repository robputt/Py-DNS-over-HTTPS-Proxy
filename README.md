# Py-DNS-over-HTTPS-Proxy
Provides a simple Python based proxy for running DNS over HTTPS to Google's DNS over HTTPS service.

Recently I wrote a blog post which probably gives you just enough information to get this up and running on a Mac / Linux box... https://robertputt.co.uk/securing-dns-traffic-with-dns-over-https.html, This script plays nice with both Python2.7 and Python 3.x

Configuration can be easily done with virtualenv:

```
python -m venv dns_proxy
cd dns_proxy/
source bin/activate
git clone https://github.com/robputt796/Py-DNS-over-HTTPS-Proxy.git
cd Py-DNS-over-HTTPS-Proxy
pip install -r requirements.txt
cat https_dns_proxy/config.ini
python https_dns_proxy/__init__.py &
dig @localhost -p8053 A robertputt.co.uk
```
