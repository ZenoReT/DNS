import socket
import sys
import time
from socket import AF_INET, SOCK_DGRAM
from cache import Cache
from pynput import keyboard
from message_parser import\
    MessageParser,\
    ResourceType,\
    MessageType,\
    HaveStatus,\
    RCode


class Resolver:
    def __init__(self, next_dns_addr, cash_file_name='cache.txt'):
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
        return server

    def on_press(self, key):
        try:
            k = key.char
            if k == 'c':
                self._dns_listener.close()
        except:
            pass

    def try_find_info(self, query, answers):
        new_answers = []
        domain_addr = query.name.decode()
        for record in self._cache.records:
            if domain_addr == record.address and query.query_type == record.resource_type:
                new_answers.append(record)
        answers.extend(new_answers)
        return len(new_answers) > 0

    def start_listening(self):
        lis = keyboard.Listener(on_press=self.on_press)
        lis.start()
        try:
            while True:
                self._cache.update_cache()
                data, addr = self._dns_listener.recvfrom(1024)
                if len(data) > 0:
                    self._client_addr = addr
                    self._message_parser.from_bytes(data)
                    have_all_data = True
                    answers = []
                    for query in self._message_parser.queries:
                        have_info = self.try_find_info(query, answers)
                        if query.query_type == ResourceType.PTR:
                                continue
                        if not have_info:
                            self.treat_data_from_receive(data)
                            have_all_data = False
                            break
                    if have_all_data and len(answers) > 0:
                        if query.query_type == ResourceType.NS:
                            print('Тю')
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
        finally:
            sys.stderr.write('\nThe server was stopped. '
                  'All useful data will be serialized\n')
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
                             'please, check your connection.\n')
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
