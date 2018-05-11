import sys
import os
import time
from message_parser import MessageParser, ResourceClass, ResourceType


class CacheInfo:
    def __init__(
            self,
            address,
            resource_type,
            data,
            ttl,
            resource_class
            ):
        self.death_time = time.time() + ttl
        self.address = address
        self.resource_type = resource_type
        self.resource_class = resource_class
        self.ttl = ttl
        self.data = data


class Cache:
    def __init__(self, cache_file_name):
        self.records = []
        self.cash_file_name = cache_file_name
        self.try_initilize_cache()

    def try_initilize_cache(self):
        try:
            with open(os.path.join(self.cash_file_name), 'r') as file:
                address = ''
                death_time = 0
                resource_type = ResourceType.A
                data = ''
                resource_class = ResourceClass.INTERNET
                ttl = 0
                for line in file.readlines():
                    if line != '\n':
                        line = line.split(':')
                        if line[0] == 'A':
                            address = line[1][0:-1]
                        if line[0] == 'DT':
                            death_time = float(line[1])
                        if line[0] == 'RT':
                            resource_type = ResourceType(int(line[1]))
                        if line[0] == 'TTL':
                            ttl = int(line[1])
                        if line[0] == 'D':
                            temp_data = line[1][0:-1].split(',')
                            data = []
                            for byte in temp_data:
                                data.append(int(byte))
                            data = bytes(data)
                        if line[0] == 'RC':
                            resource_class = ResourceClass(int(line[1]))
                    else:
                        self.add_record(
                            ttl, address, resource_type, data, resource_class)
                        self._set_death_time(
                            death_time, self.records[len(self.records) - 1])
        except IOError:
            sys.stderr.write('Not correct path or file is not supported {0}\n\
                             \rPlease check the correctness of the path\n\
                             \ryou entered, the presence of the file\n\
                             \rin the destination folder and the type\n\
                             \rof this file\n').format(self.cash_file_name)
            print('Cache will be initilize as clear')

    def _set_death_time(self, death_time, record):
        record.death_time = death_time

    def add_record(self, ttl, address, resource_type, data, resource_class):
        if ttl < 1000:
            ttl = 1000
        was_founded = False
        for record in self.records:
            if record.address == address and\
                    record.resource_type == resource_type and\
                    record.resource_class == resource_class and\
                    record.data == data:
                was_founded = True
                record.ttl = ttl
                self._set_death_time(time.time() + ttl, record)
        if not was_founded:
            self.records.append(CacheInfo(
                address,
                resource_type,
                data,
                ttl,
                resource_class))

    def update_cache(self):
        new_cache = []
        for record in self.records:
            if record.death_time > time.time():
                new_cache.append(record)
        self.records = new_cache

    def serialize_cache(self):
        with open(os.path.join(self.cash_file_name), 'w') as file:
            for record in self.records:
                file.write('A:{0}\n'.format(record.address))
                file.write('DT:{0}\n'.format(record.death_time))
                file.write('RT:{0}\n'.format(record.resource_type))
                list_bytes = []
                for byte in record.data:
                    list_bytes.append(str(byte))
                file.write('D:{0}\n'.format(','.join(list_bytes)))
                file.write('RC: {0}\n'.format(record.resource_class))
                file.write('TTL: {0}\n'.format(record.ttl))
                file.write('\n')
