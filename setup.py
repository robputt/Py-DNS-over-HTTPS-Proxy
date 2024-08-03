from setuptools import setup, find_packages


setup(
    name="https_dns_proxy",
    description='Proxies UDP DNS requests to Google DNS over HTTPS Service',
    version="1.0.0",
    packages=find_packages(),
    entry_points = {
        'console_scripts': ['https_dns_proxy=https_dns_proxy:run'],
    },
    install_requires=[
        'configparser==7.0.0',
        'requests==2.19.0',
        'dnslib==0.9.25'
    ],
    python_requires='>=3.8'
)
