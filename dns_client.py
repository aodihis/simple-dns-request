import random
import socket
import struct
from typing import Tuple


class DNSClient:
    def __init__(self, server_ip, server_port=53):
        self.server_ip = server_ip
        self.server_port = server_port

    def send_query(self, query: bytes) -> bytes:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(query, (self.server_ip, self.server_port))
        response, _ = sock.recvfrom(512)
        return response


    def resolve(self, hostname):
        query = self.create_query(hostname)
        response = self.send_query(query)
        return DNSClient.process_response(response)

    @staticmethod
    def process_response(response: bytes):
        ret = {}
        header = response[:12]
        transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', header)

        ret['header'] = {
            'transaction_id': transaction_id,
            'flags': flags,
            'qdcount': qdcount,
            'ancount': ancount,
            'nscount': nscount,
            'arcount': arcount
        }


        offset = 12
        ret['question'] = []
        for _ in range(qdcount):
            offset, question = DNSClient.parse_dns_question(response, offset)
            ret['question'].append(question)

        ret['answers'] = []
        for i in range(ancount):
            offset, answer = DNSClient.parse_dns_answer(response, offset)
            ret['answers'].append(answer)
        return ret


    @staticmethod
    def create_query(hostname: str, record_type='A') -> bytes:
        ID = random.randint(0, 65535)

        FLAGS = 0x0100  # Standard query
        QDCOUNT = 1  # Number of questions
        ANCOUNT = 0  # Number of answer resource records
        NSCOUNT = 0  # Number of authority resource records
        ARCOUNT = 0  # Number of additional resource records

        header = struct.pack('!HHHHHH', ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

        query = b''
        for part in hostname.split('.'):
            query += struct.pack('!B', len(part)) + part.encode('utf-8')
        query += struct.pack('!B', 0)  # End of domain name

        QTYPE = 1 if record_type == 'A' else 28
        QCLASS = 1  # IN (Internet)

        query += struct.pack('!HH', QTYPE, QCLASS)

        return header + query

    @staticmethod
    def parse_dns_question(response: bytes, offset: int):
        name, offset = DNSClient.parse_dns_name(response, offset)
        q_type, q_class = struct.unpack('!HH', response[offset:offset + 4])
        return offset+4, {'name': name, 'type': q_type, 'class': q_class}

    @staticmethod
    def parse_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
        name = []
        while True and data:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length >= 192:  # Pointer to another location in the message
                pointer = struct.unpack('!H', data[offset:offset + 2])[0]
                pointer &= 0x3FFF
                sub_name, _ = DNSClient.parse_dns_name(data, pointer)
                name.append(sub_name)
                offset += 2
                break
            else:
                offset += 1
                name.append(data[offset:offset + length].decode('utf-8'))
                offset += length
        return '.'.join(name), offset


    @staticmethod
    def parse_dns_answer(response: bytes, offset: int) -> (int, dict):
        name, offset = DNSClient.parse_dns_name(response, offset)
        atype, aclass, ttl, rdlength = struct.unpack('!HHIH', response[offset:offset + 10])
        offset += 10
        data = response[offset:offset + rdlength]
        offset += rdlength

        if atype == 1:  # (IPv4 address)
            decoded_data = '.'.join(map(str, struct.unpack('!BBBB', data)))
        elif atype == 28:  # (IPv6 address)
            decoded_data = ':'.join(f'{i:x}' for i in struct.unpack('!HHHHHHHH', data))
        elif atype == 15:  # (Mail exchange)
            preference, exchange = struct.unpack('!H', data[:2]), DNSClient.parse_dns_name(response, offset)[0]
            decoded_data = f"Preference: {preference}, Mail Exchange: {exchange}"
        elif atype == 5:
            name, _ = DNSClient.parse_dns_name(response, offset)
            decoded_data = name
        else:
            decoded_data = data.decode('utf-8', errors='ignore')

        return offset, {
            'name': name,
            'type': atype,
            'class': aclass,
            'ttl': ttl,
            'data': decoded_data,
        }