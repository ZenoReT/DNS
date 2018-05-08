import socket
import sys
import time
from socket import AF_INET, SOCK_DGRAM
from cache import Cache
from message_parser import\
    MessageParser,\
    ResourceType,\
    MessageType,\
    HaveStatus,\
    RCode


class Resolver:
    def __init__(self, next_dns_addr = '212.193.163.6', cash_file_name='cache.txt'):
        self._port = 53
        self._cache = Cache(cash_file_name)
        self._dns_listener = Resolver.bind_server()
        self._next_dns_addr = next_dns_addr
        self._message_parser = MessageParser()
        self._client_addr = None

    @staticmethod
    def bind_server(addr='localhost', port=53):
        server = socket.socket(AF_INET, SOCK_DGRAM)
        server.bind((addr, port))
        server.settimeout(10)
        return server

    def try_find_info(self, query):
        domain_addr = query.name.decode()
        for record in self._cache.records:
            if domain_addr == record.address and query.query_type == record.resource_type:
                return record
        return False

    def start_listening(self):
        try:
            while True:
                data, addr = self._dns_listener.recvfrom(1024)
                if len(data) > 0:
                    self._client_addr = addr
                    self._message_parser.from_bytes(data)
                    have_all_data = True
                    answers = []
                    for query in self._message_parser.queries:
                        info = self.try_find_info(query)
                        if query.query_type == ResourceType.PTR:
                            try:
                                self.treat_data_from_receive(data)
                                have_all_data = False
                                break
                            except socket.error:
                                continue
                        if not info:
                            self.treat_data_from_receive(data)
                            have_all_data = False
                            break
                        else:
                            answers.append(info)
                    if have_all_data and len(answers) > 0:
                        answer = MessageParser.to_bytes(
                            self._message_parser.transaction_id,
                            MessageType.ANSWER,
                            self._message_parser.opcode,
                            HaveStatus.NO,
                            self._message_parser.recursion_required,
                            self._message_parser.recursion_available,
                            RCode.NO_ERROR,
                            self._message_parser.message[12:],
                            answers_num=len(answers),
                            answers=answers
                        )
                        self._dns_listener.sendto(answer, self._client_addr)
                        self._client_addr = None
                self._cache.update_cache()
        finally:
            if self._client_addr is not None:
                answer = MessageParser.to_bytes(
                    self._message_parser.transaction_id,
                    MessageType.ANSWER,
                    self._message_parser.opcode,
                    HaveStatus.NO,
                    self._message_parser.recursion_required,
                    self._message_parser.recursion_available,
                    RCode.REFUSED,
                    self._message_parser.message[12:],
                    answers_num=0,
                    answers=[]
                )
                self._dns_listener.sendto(answer, self._client_addr)
            sys.stderr.write('The server was stopped.'
                             'All useful data will be serialized')
            self._cache.serialize_cache()

    def treat_data_from_receive(self, data):
        try:
            sender = socket.socket(AF_INET, SOCK_DGRAM)
            sender.connect((self._next_dns_addr, self._port))
            sender.settimeout(5)
            sender.send(data)
            data = sender.recv(1024)
            sender.close()
        except socket.error:
            sys.stderr.write('There were some problems on the send/receive stage, '
                             'please, resend your query.')
            return
        self._dns_listener.sendto(data, self._client_addr)
        answer_info = MessageParser()
        answer_info.from_bytes(data)
        for container in [
                answer_info.answers,
                answer_info.resources_rights,
                answer_info.additional_resources]:
            for resource in container:
                self._cache.add_record(
                    resource.ttl,
                    resource.name.decode(),
                    resource.resource_type,
                    resource.resource_data,
                    resource.resource_class)
        self._client_addr = None
