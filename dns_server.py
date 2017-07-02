import socket
import argparse
import sys
from select import select
from concurrent.futures import ThreadPoolExecutor
from dns_cache import DNSCache
from dns_packet import DNSPacket, Header, TYPES
from threading import Lock


class DNSServer:
    def __init__(self, *, forward=None, listen_port=53):
        if forward:
            self.forward_address = DNSServer.parse_forward_address(forward)
        self.listen_port = listen_port
        self.cache = DNSCache()
        self.lock_put = Lock()
        self.lock_get = Lock()

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_sock:
            server_sock.bind(('', self.listen_port))
            with ThreadPoolExecutor(max_workers=50) as executor:
                print('Server start:' + repr(self.listen_port))
                while True:
                    if select([server_sock], [], [], 2)[0]:
                        data, addr = server_sock.recvfrom(1024)
                        executor.submit(self.client_thread, data, addr, server_sock)

    def client_thread(self, dns_req, addr, server_socket):
        req_packet = DNSPacket.from_binary(dns_req)
        if self.cache.contains(req_packet.question):
            with self.lock_get:
                obsolete_records = self.cache.get_obsolete_records(req_packet.question)
            if obsolete_records:
                self.update_send_to_forward(dns_req, req_packet, server_socket, addr)
            else:
                dns_response = self.build_response(req_packet)
                self.send(server_socket, addr, dns_response)
                DNSServer.output(addr, req_packet.question, 'cache')
        else:
            self.update_send_to_forward(dns_req, req_packet, server_socket, addr)

    def update_send_to_forward(self, dns_req, req_packet, server_socket, addr):
        dns_response, error_code = self.update_cache(dns_req)
        if error_code == 0:
            self.send(server_socket, addr, dns_response)
            DNSServer.output(addr, req_packet.question, 'forwarder')
        else:
            resp_error = DNSServer.build_error_message(req_packet)
            try:
                self.send(server_socket, addr, resp_error)
            except Exception as e:
                print(e)

    def send(self, sock, addr, response):
        try:
            inp, write, ex = select([], [sock], [])
            write[0].sendto(response, addr)
        except socket.error:
            pass

    def appeal_to_forward(self, request):
        error_code = 0
        resp = b''
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as send_sock:
            send_sock.sendto(request, self.forward_address)
            if select([send_sock], [], [], 3)[0]:
                resp, addr = send_sock.recvfrom(1024)
            else:
                error_code = 2
        return resp, error_code

    def update_cache(self, dns_req):
        dns_response, error_code = self.appeal_to_forward(dns_req)
        if error_code == 0:
            resp_packet = DNSPacket.from_binary(dns_response)
            self.put_in_cache(resp_packet)
        else:
            dns_response = None
        return dns_response, error_code

    def put_in_cache(self, dns_packet):
        with self.lock_put:
            self.cache.put(dns_packet.question,
                           dns_packet.answers + dns_packet.authorities + dns_packet.additionals)

    def build_response(self, req_packet):
        response = req_packet.question.to_binary()
        with self.lock_get:
            records, ancount, nscount, arcount = self.cache.get(req_packet.question)
        resource_records = b''
        for record in records:
            resource_records += record.to_binary()
        response += resource_records
        header = Header(
            id_p=req_packet.header.id,
            query=1,
            opcode=req_packet.header.opcode,
            authority_answer=0,
            truncation=0,
            recursion_desired=req_packet.header.recurs_desired,
            recursion_available=1,
            z=0,
            rcode=0,
            qdcount=req_packet.header.qdcount,
            ancount=ancount,
            nscount=nscount,
            arcount=arcount
            ).to_binary()
        return header + response

    @staticmethod
    def build_error_message(req_packet):
        header = Header(
            id_p=req_packet.header.id,
            query=1,
            opcode=req_packet.header.opcode,
            authority_answer=0,
            truncation=0,
            recursion_desired=req_packet.header.recurs_desired,
            recursion_available=1,
            z=0,
            rcode=2,
            qdcount=0,
            ancount=0,
            nscount=0,
            arcount=0
        ).to_binary()
        return header + req_packet.question.to_binary()

    @staticmethod
    def parse_forward_address(forward):
        if forward.find(':') == -1:
            address = socket.gethostbyname(forward)
            port = 53
        else:
            full_address = forward.split(':')
            address, port = socket.gethostbyname(full_address[0]), full_address[1]
        return address, port

    @staticmethod
    def output(addr, question, source):
        print('{}, {}, {}, {}'.
              format(addr[0], TYPES[question.rec_type],
                     question.decode_name(), source))


def print_help(filename):
    with open(filename) as file:
        for line in file:
            print(line)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, action='store', dest='port')
    parser.add_argument('-f', '--forwarder', action='store', dest='forwarder')
    args = sys.argv[1:]
    if args[0] == '-h' or args[0] == '--help':
        print_help('README.txt')
    else:
        args = parser.parse_args(sys.argv[1:])
        if args.port:
            server = DNSServer(forward=args.forwarder, listen_port=args.port)
        else:
            server = DNSServer(forward=args.forwarder)
        server.run()

