__author__ = 'Robert Cope'


class PyDNSConfig(object):
    DNS_PROTOCOLS = 'udp', 'tcp'
    DNS_BIND_ADDRESS = 'localhost'
    DNS_BIND_PORT = 9000

    USE_RESOLV_CONF = True
    RESOLV_CONF_LOCATIONS = ['/etc/resolv.conf']

