from time import time
from decimal import Decimal


class DNSCache:
    def __init__(self):
        self.cache = {}

    def put(self, key, list_value):
        self.cache[key] = list_value

    def get(self, key):
        ancount = 0
        nscount = 0
        arcount = 0

        for record in self.cache[key]:
            if not record.bad_data:
                cur_time = Decimal(time())
                record.change_ttl(record.ttl - (cur_time - record.last_update), cur_time)
                if record.section == 'AN':
                    ancount += 1
                if record.section == 'NS':
                    nscount += 1
                if record.section == 'AR':
                    arcount += 1
        return self.cache[key], ancount, nscount, arcount

    def contains(self, key):
        try:
            if self.cache.get(key):
                return True
            return False
        except Exception as e:
            print(e)

    def get_obsolete_records(self, question):
        records = []
        for record in self.cache[question]:
            if record.is_obsolete():
                records.append(record)
        return records
