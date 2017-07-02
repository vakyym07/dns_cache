from struct import pack, unpack, calcsize, error
from time import time
from decimal import Decimal


TYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 28: 'AAAA', 255: 'ANY'}
CLASSES = {'IN': 1, 'ANY': 255, '*': 255}
OPCODES = {0: 'QUERY', 1: 'IQUERY', 2: 'STATUS'}
RCODES = {0: 'No error', 1: 'Format error', 2: 'Server failure', 3: 'Name Error', 4: 'Not Implemented', 5: 'Refused'}
MESSAGE_TYPE = {0: 'QUERY', 1: 'RESPONSE'}


class Header:
    """
    opcode is copied
    id is copied
    recursion is copied
    """
    HEADER_FORMAT = '>HHHHHH'

    def __init__(self, id_p=None, opcode=None, authority_answer=None,
                 truncation=None, recursion_desired=None, rcode=None,
                 qdcount=None, ancount=None, nscount=None, arcount=None,
                 recursion_available=1, z=0, query=1):
        self.id = id_p
        self.query = query
        self.opcode = opcode
        self.auth_ans = authority_answer
        self.trunc = truncation
        self.recurs_desired = recursion_desired
        self.recurs_available = recursion_available
        self.z = z
        self.rcode = rcode
        self.option = (self.query << 15) | (self.opcode << 11) | \
                      (self.auth_ans << 10) | (self.trunc << 9) | \
                      (self.recurs_desired << 8) | (self.recurs_available << 7) | \
                      (self.z << 4) | self.rcode
        self.qdcount = qdcount
        self.ancount = ancount
        self.nscount = nscount
        self.arcount = arcount

    def to_binary(self):
        return pack(Header.HEADER_FORMAT,
                    self.id,
                    self.option,
                    self.qdcount,
                    self.ancount,
                    self.nscount,
                    self.arcount)

    @staticmethod
    def from_binary(data):
        try:
            id_p, option, qdcount, ancount, nscount, arcount = \
                unpack(Header.HEADER_FORMAT, data[:Header.length()])
        except error:
            pass
        query, opcode, auth_ans, trunc, recurs_desired, recurs_available, z, rcode = \
            option >> 15, (option >> 11) & 0xf, (option >> 10) & 0xf, \
            (option >> 9) & 0xf, (option >> 8) & 0xf, (option >> 7) & 0xf, \
            (option >> 4) & 0xf, option & 0xf
        return Header(id_p, opcode, auth_ans,
                      trunc, recurs_desired, rcode,
                      qdcount, ancount, nscount, arcount,
                      recursion_available=recurs_available, z=z, query=query)

    @staticmethod
    def length():
        return calcsize(Header.HEADER_FORMAT)


class Question:
    def __init__(self, name, record_type, record_class):
        self.name = name
        self.rec_type = record_type
        self.rec_class = record_class

    @staticmethod
    def from_binary(data):
        name = data[:data.find(0x00) + 1]
        r_type, r_class = unpack('>HH', data[len(name):])
        return Question(name, r_type, r_class)

    def to_binary(self):
        return self.name + pack('>HH', self.rec_type, self.rec_class)

    def decode_name(self):
        decode_name = ''
        pointer = 0
        while self.name[pointer] != 0:
            val = self.name[pointer]
            decode_name += self.name[pointer + 1: pointer + val + 1].decode('utf-8')
            decode_name += '.'
            pointer += val + 1
        return decode_name

    def __eq__(self, other):
        if self.name == other.name and \
            self.rec_type == self.rec_type and \
                self.rec_class == self.rec_class:
            return True
        return False

    def __hash__(self):
        return 31 * ((hash(self.name) +
                      hash(self.rec_type)) ** 2 +
                     hash(self.rec_class)) ** 3


class ResourceRecord:
    def __init__(self, binary_name=None, r_type=None, r_class=None, ttl=None,
                 rdlen=None, rdata=None,
                 section_type=None, bad_data=False, binary_bad_data=None):
        self.bin_name = binary_name
        self.r_type = r_type
        self.r_class = r_class
        if ttl:
            self.ttl = Decimal(ttl)
        self.rdlen = rdlen
        self.rdata = rdata
        if not bad_data:
            self.last_update = Decimal(time())
        self.section = section_type
        self.bad_data = bad_data
        self.binary_bad_data = binary_bad_data

    @staticmethod
    def from_binary(data, len_name, section_type):
        name = data[:len_name]
        try:
            type_r, class_r, ttl_r, rdlen = unpack('>HHIH', data[len_name: len_name + 10])
            rdata = data[len_name + 10: len_name + 10 + rdlen]
            return ResourceRecord(name, type_r, class_r, ttl_r, rdlen, rdata, section_type)
        except error:
            return ResourceRecord(bad_data=True, binary_bad_data=data)

    def length(self):
        return len(self.bin_name) + 10 + len(self.rdata)

    def to_binary(self):
        if not self.bad_data:
            packet = self.bin_name
            packet += pack('>HHIH', self.r_type, self.r_class, int(self.ttl), self.rdlen)
            packet += self.rdata
            return packet
        else:
            return self.binary_bad_data

    def is_obsolete(self):
        try:
            if self.ttl - (Decimal(time()) - self.last_update) < 2:
                return True
        except AttributeError:
            pass
        return False

    def change_ttl(self, ttl, last_update):
        self.ttl = ttl
        self.last_update = last_update


class DNSPacket:
    def __init__(self, header, question, answers, authorities, additionals):
        self.header = header
        self.question = question
        self.answers = answers
        self.authorities = authorities
        self.additionals = additionals

    def to_binary(self):
        packet = self.header.to_binary() + self.question.to_binary()
        for obj in self.answers + self.authorities + self.additionals:
            packet += obj.to_binary()
        return packet

    @staticmethod
    def from_binary(request):
        bin_header = request[:Header.length()]

        question_b = request[Header.length():
                             Header.length() +
                             request[Header.length():].find(0x00) + 5]

        header = Header.from_binary(bin_header)
        question = Question.from_binary(question_b)
        past_request = request[len(bin_header) + len(question_b):]

        pointer = b'\xc0\x0c'
        resource_records = list(map(lambda x: pointer + x, past_request.split(pointer)))[1:]
        if resource_records:
            len_last_record = ResourceRecord.from_binary(
                resource_records[len(resource_records) - 1], 2, 'AN').length()

            if len_last_record < len(resource_records[len(resource_records) - 1]):
                record = resource_records[len(resource_records) - 1]
                resource_records[len(resource_records) - 1] = record[:len_last_record]
                resource_records.append(record[len_last_record:])
        else:
            resource_records = [past_request]

        return DNSPacket(
            header,
            question,
            DNSPacket.pick_resource_records(header.ancount, 'AN', resource_records),
            DNSPacket.pick_resource_records(header.nscount, 'NS', resource_records),
            DNSPacket.pick_resource_records(header.arcount, 'AR', resource_records)
        )

    @staticmethod
    def pick_resource_records(count, r_type, queue):
        records = []
        for i in range(count):
            ans = queue.pop(0)
            records.append(ResourceRecord.from_binary(ans, 2, r_type))
        return records
