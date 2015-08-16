from PyDNS.models.parsers import parse_dns_message

__author__ = 'Robert Cope'

import socket
import threading
import struct


class DNSServer(threading.Thread):
    @staticmethod
    def handle_dns(raw_data, connection, address):
        message = parse_dns_message(raw_data)
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        s.sendto(raw_data, ('8.8.8.8', 53))
        new_data = s.recv(8152)
        new_message = parse_dns_message(new_data)
        connection.sendto(new_data, address)


def build_udp_dns_server(config, shutdown_event, worker_pool):
    class UDPDNSServer(DNSServer):
        def run(self):
            # punt_to_job_queue = worker_pool.job_queue.put
            handler_function = self.handle_dns
            shutdown_triggered = shutdown_event.is_set
            udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            udp_socket.bind((config.DNS_BIND_ADDRESS, config.DNS_BIND_PORT))
            udp_socket_recvfrom = udp_socket.recvfrom
            while not shutdown_triggered():
                raw_data, address = udp_socket_recvfrom(1024)
                handler_function(raw_data, udp_socket, address)
                # punt_to_job_queue((handler_function, connection, address, True))

    return UDPDNSServer


def build_tcp_dns_server(config, shutdown_event, worker_pool):
    class TCPDNSServer(DNSServer):
        @staticmethod
        def handle_tcp_dns(connection, address):
            message_len = struct.unpack("!H", connection.recv(2))
            raw_data = connection.recv(message_len)

        def run(self):
            punt_to_job_queue = worker_pool.job_queue.put
            handler_function = self.handle_dns
            shutdown_triggered = shutdown_event.is_set
            tcp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
            tcp_socket.bind((config.dns_bind_address, config.dns_bind_port))
            tcp_socket.listen(socket.SOMAXCONN)
            tcp_socket.settimeout(5.0)
            tcp_socket_accept = tcp_socket.accept
            while not shutdown_triggered():
                connection, address = tcp_socket_accept()
                punt_to_job_queue((handler_function, connection, address, False))

    return TCPDNSServer


class WorkerThreadPool(object):
    pass

if __name__ == "__main__":
    from PyDNS.default_config import PyDNSConfig
    import time
    event = threading.Event()
    t = build_udp_dns_server(PyDNSConfig, event, None)()
    t.daemon = True
    t.start()
    r = raw_input("Stop> ")
    event.set()
    time.sleep(1)
