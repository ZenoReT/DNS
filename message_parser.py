import struct
from enum import IntEnum as Enum


class HaveStatus(Enum):
    NO = 0
    YES = 1


class MessageType(Enum):
    QUERY = 0
    ANSWER = 1


class Opcode(Enum):
    STANDART_QUERY = 0
    INVERSE_QUERY = 1
    SERVER_STATUS_REQUEST = 2


class RCode(Enum):
    NO_ERROR = 0
    DOMAIN_NAME_ERROR = 3
    REFUSED = 5


class ResourceType(Enum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    HINFO = 13
    MX = 15
    AAAA = 28
    AXFR = 252
    ANY = 255


class ResourceClass(Enum):
    RESERVED = 0
    INTERNET = 1
    CHAOS = 3
    HESIOD = 4


class Query:
    def __init__(self, name, query_type, query_class):
        self.name = name
        self.query_type = query_type
        self.query_class = query_class

class Resource:
    def __init__(self, name, r_type, r_class, ttl, r_data):
        self.name = name
        self.resource_type = r_type
        self.resource_class = r_class
        self.ttl = ttl
        self.resource_data = r_data


class MessageParser:
    def __init__(self):
        self.message = b''
        self.transaction_id = ''
        self.query_type = MessageType.QUERY
        self.opcode = Opcode.INVERSE_QUERY
        self.authoritative_answer = HaveStatus.NO
        self.truncated = HaveStatus.NO
        self.recursion_required = HaveStatus.NO
        self.recursion_available = HaveStatus.NO
        self.rcode = RCode.NO_ERROR
        self.questions_num = 1
        self.answers_num = 0
        self.resources_rights_num = 0
        self.additional_resources_num = 0
        self.queries = []
        self.answers = []
        self.resources_rights = []
        self.additional_resources = []

    def from_bytes(self, message):
        self.message = message
        self.transaction_id = struct.unpack('>h', message[0:2])[0]
        self.query_type = MessageType((message[2] & 0b10000000) >> 7)
        self.opcode = Opcode((message[2] & 0b01111000) >> 3)
        self.authoritative_answer = HaveStatus((message[2] & 0b00000100) >> 2)
        self.truncated = HaveStatus((message[2] & 0b00000010) >> 1)
        self.recursion_required = HaveStatus(message[2] & 0b00000001)
        self.recursion_available = HaveStatus((message[3] & 0b10000000) >> 7)
        self.rcode = RCode(message[3] & 0b00001111)
        self.questions_num = struct.unpack('>h', message[4:6])[0]
        self.answers_num = struct.unpack('>h', message[6:8])[0]
        self.resources_rights_num = struct.unpack('>h', message[8:10])[0]
        self.additional_resources_num = struct.unpack('>h', message[10:12])[0]
        pointer = 12
        for i in range(self.questions_num):
            pointer = self.parse_queries(pointer)
        for i in range(self.answers_num):
            pointer = self.parse_resources(pointer, self.answers)
        for i in range(self.resources_rights_num):
            pointer = self.parse_resources(pointer, self.resources_rights)
        for i in range(self.additional_resources_num):
            pointer = self.parse_resources(pointer, self.additional_resources)

    def parse_queries(self, from_id):
        name, pointer = self._get_name_with_pointer(from_id)
        t = struct.unpack('>h', self.message[pointer: pointer + 2])[0]
        query_type = ResourceType(struct.unpack('>h', self.message[pointer: pointer+2])[0])
        query_class = ResourceClass(struct.unpack('>h', self.message[pointer+2: pointer+4])[0])
        pointer += 4
        self.queries.append(Query(name, query_type, query_class))
        return pointer

    def parse_resources(self, from_id, container):
        name, pointer = self._get_name_with_pointer(from_id)
        r_type = ResourceType(struct.unpack('>h', self.message[pointer: pointer+2])[0])
        r_class = ResourceClass(struct.unpack('>h', self.message[pointer+2: pointer+4])[0])
        ttl = struct.unpack('>l', self.message[pointer+4: pointer+8])[0]
        data_length = struct.unpack('>h', self.message[pointer+8: pointer+10])[0]
        r_data = b''
        pointer += 10
        if r_type == ResourceType.NS:
            r_data, pointer = self._get_name_with_pointer(pointer)
        else:
            r_data = self.message[pointer: pointer+data_length]
            pointer += data_length
        container.append(Resource(name, r_type, r_class, ttl, r_data))
        return pointer

    def _get_name_with_pointer(self, pointer):
        name = b''
        index = pointer
        current_byte = self.message[pointer]
        was_link = False
        while int(current_byte) != 0:
            if current_byte & 0b11000000 == 0b11000000:
                index = ((current_byte & 0b00111111) << 8) + self.message[index + 1]
                if not was_link:
                    pointer += 1
                was_link = True
            part_name, index = self._get_name_part_and_pointer(index)
            if not was_link:
                pointer = index
            current_byte = self.message[index]
            name += part_name + b'.'
        pointer += 1
        return name, pointer

    def _get_name_part_and_pointer(self, index):
        name_part_length = int(self.message[index])
        name = self.message[index + 1: index + name_part_length + 1]
        index += name_part_length + 1
        return name, index

    @staticmethod
    def get_name_in_bytes(name):
        name_in_bytes = []
        splited_name = name.split('.')
        splited_name = splited_name[0: -1]
        for part in splited_name:
            name_in_bytes.append(len(part))
            for i in range(len(part)):
                name_in_bytes.append(ord(part[i]))
        name_in_bytes.append(0)
        return bytearray(name_in_bytes)

    @staticmethod
    def get_resource_type_to_bytes(resource_record):
        resource_bytes = []
        resource_bytes.extend(MessageParser.get_name_in_bytes(resource_record.address))

        type_bytes = struct.pack('>h', int(resource_record.resource_type))
        resource_bytes.append(type_bytes[0])
        resource_bytes.append(type_bytes[1])

        class_bytes = struct.pack('>h', int(resource_record.resource_class))
        resource_bytes.append(class_bytes[0])
        resource_bytes.append(class_bytes[1])

        ttl_bytes = struct.pack('>l', int(resource_record.ttl))
        for byte in ttl_bytes:
            resource_bytes.append(byte)

        if resource_record.resource_type == ResourceType.NS:
            name_in_bytes = MessageParser.get_name_in_bytes(resource_record.data.decode())
            length_bytes = struct.pack('>h', len(name_in_bytes))
            resource_bytes.append(length_bytes[0])
            resource_bytes.append(length_bytes[1])
            resource_bytes.extend(name_in_bytes)
        else:
            length_bytes = struct.pack('>h', len(resource_record.data))
            resource_bytes.append(length_bytes[0])
            resource_bytes.append(length_bytes[1])
            for byte in resource_record.data:
                resource_bytes.append(byte)
        return bytearray(resource_bytes)

    @staticmethod
    def to_bytes(
            transaction_id,
            query_type,
            opcode,
            truncated,
            recursion_required,
            recursion_available,
            rcode,
            queries,
            answers,
            questions_num=1,
            answers_num=1,
            resources_rights_num = 0,
            additional_resources_num = 0,
            authoritative_answer = HaveStatus.NO
            ):
        message = []
        byte_id = struct.pack('>h', transaction_id)
        message.append(byte_id[0])
        message.append(byte_id[1])

        message.append(query_type << 7 |
                     opcode << 3 |
                     authoritative_answer << 2 |
                     truncated << 1 |
                     recursion_required)
        message.append(recursion_available << 7 | rcode)

        questions_num_byte = struct.pack('>h', questions_num)
        message.append(questions_num_byte[0])
        message.append(questions_num_byte[1])

        answers_num_byte = struct.pack('>h', answers_num)
        message.append(answers_num_byte[0])
        message.append(answers_num_byte[1])

        resources_rights_num_byte =  struct.pack('>h', resources_rights_num)
        message.append(resources_rights_num_byte[0])
        message.append(resources_rights_num_byte[1])

        additional_resources_num_byte =  struct.pack('>h', additional_resources_num)
        message.append(additional_resources_num_byte[0])
        message.append(additional_resources_num_byte[1])
        message.extend(queries)
        for answer in answers:
            message.extend(MessageParser.get_resource_type_to_bytes(answer))
        return bytes(message)
