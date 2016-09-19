#!/usr/bin/python3
# -*- coding: utf-8 -*-


import time
import sys
import logging
import socket
import signal
import json
from time import sleep
from dnslib.server import DNSServer, BaseResolver, DNSLogger
from dnslib.dns import DNSError, QTYPE, RCODE, RR, A
from dnslib import DNSRecord

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.INFO)

class CachedReply(object):
    '''
    A cached DNS reply, for making replies from cache
    '''
    def __init__(self, reply, ttl_lower_bound=60):
        self.access_time = time.time()
        for x in reply.rr:
            x.ttl = max(x.ttl, ttl_lower_bound)
        minttl = min([x.ttl for x in reply.rr])
        self.expire_time = self.access_time + minttl
        self.reply = reply

    def make_reply(self, request):
        header = request.reply().header
        self.reply.header = header
        #Change reply header in order to match request
        now = time.time()
        for rr in self.reply.rr:
            delta = int(now - self.access_time)
            rr.ttl -= delta
            #Modify TTL
        self.access_time = now
        return self.reply

    def is_valid(self):
        return time.time() < self.expire_time


class Node(object):
    '''
    One node in cache/double-linked list, contain key and value
    '''
    def __init__(self, key, value):
        self.prev = self.next = None
        self.key = key
        self.value = value

    def __str__(self):
        return "<Node {}>".format(self.key)


class DNSCache(object):

    def __init__(self, capacity):
        self.size = 0
        self.capacity = capacity
        self.dict = {}
        self.head = Node('HEAD', None)
        self.tail = Node('TAIL', None)
        self.head.next = self.tail
        self.tail.prev = self.head

    def __len__(self):
        return self.size

    def __contains__(self, key):
        return key in self.dict

    def __unlink_node(self, node):
        self.size -= 1
        logging.debug("Unlink {}".format(node))
        node.prev.next = node.next
        node.next.prev = node.prev
        node.prev = node.next = None
        return node

    def __remove_oldest(self):
        node = self.tail.prev
        logging.debug("Remove {} from cache".format(node))
        assert node is not self.head
        self.__unlink_node(node)
        self.dict.pop(node.key)

    def __insert_node_first(self, node):
        self.size += 1
        logging.debug("Inserting {} to first".format(node))
        node.next = self.head.next
        self.head.next.prev = node
        node.prev = self.head
        self.head.next = node

    def __setitem__(self, key, value):
        if key in self.dict:
            node = self.__unlink_node(self.dict[key])
            logging.debug("Updating {}".format(node))
            node.value = value
            self.__insert_node_first(node)
        else:
            item = Node(key, value)
            self.dict[key] = item
            self.__insert_node_first(item)
            if self.size > self.capacity:
                self.__remove_oldest()

    def __getitem__(self, key):
        #Client should handle KeyError exception
        t = self.dict[key]
        self.__unlink_node(t)
        self.__insert_node_first(t)
        return t.value

    def __delitem__(self, key):
        node = self.dict[key]
        self.dict.pop(key)
        self.__unlink_node(node)



class MyResolver(BaseResolver):

    def __init__(self, filename, cache_size=1000):
        super().__init__()
        self.load_config(filename)
        self.cache = DNSCache(cache_size)

    @staticmethod
    def load_list_from_file(filename):
        '''
        File contains multiple lines of domain names
        The return value is a Set
        '''
        ret = set()
        with open(filename) as f:
            for x in f.readlines():
                l = x.strip()
                if l:
                    ret.add(l)
        return ret

    def load_config(self, filename):
        with open(filename) as f:
            self.upstreams = json.load(f)
            logging.info(self.upstreams)
        self.domains = {}
        for name, val in self.upstreams.items():
            if name != 'default':
                self.domains[name] = self.load_list_from_file(val["file"])
                logging.info("loaded {} domains from {}".format(len(self.domains[name]), val["file"]))

    @staticmethod
    def domain_match_set(domain_tuple, target_set, depth=5):
        tmpstr = None
        # logging.debug(domain_tuple)
        for x in reversed(domain_tuple[-depth:]):
            if not tmpstr:
                tmpstr = x.decode().lower()
            else:
                tmpstr = x.decode().lower()+"."+tmpstr
            # print(tmpstr)
            # logging.debug("Checking", tmpstr)
            if tmpstr in target_set:
                # logging.info("{} matched.".format(tmpstr))
                return True
        return False

    def resolve_from_upstream(self, request, name):
        try:
            r = request.send(self.upstreams[name]['server'],
                             self.upstreams[name].get('port', 53),
                             timeout=self.upstreams[name].get('timeout', 1))
            reply = DNSRecord.parse(r)
        except socket.timeout:
            logging.warning("{} timed out for {}".format(self.upstreams[name]['server'], request.q.qname))
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
        return reply

    def resolve(self, request, handler):
        #Try to fetch from cache
        key = (request.q.qname, request.q.qtype)

        if key in self.cache and self.cache[key].is_valid():
            logging.debug("Cache hit for {}".format(request.q.qname))
            return self.cache[key].make_reply(request)

        #Do actual query
        try:
            domain_tuple = request.q.qname.label
            for name, domain_set in self.domains.items():
                if self.domain_match_set(domain_tuple, domain_set):
                    logging.debug("{} matched in {} list".format(request.q.qname, name))
                    reply = self.resolve_from_upstream(request, name)
                    if reply.header.rcode == RCODE.NOERROR and reply.rr:
                        self.cache[key] = CachedReply(reply, self.upstreams[name].get("ttl", 10))
                    break
            else:
                logging.debug("resolve {} from default server".format(request.q.qname))
                reply = self.resolve_from_upstream(request, 'default')
                if reply.header.rcode == RCODE.NOERROR and reply.rr:
                    self.cache[key] = CachedReply(reply, self.upstreams['default'].get("ttl", 10))

        except Exception as e:
            logging.error(e)
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
        return reply


class MyDNSLogger(DNSLogger):

    def log_request(self, handler, request):
        logging.info("{} requests {}".format(handler.client_address[0], request.q.qname))

myresolver = MyResolver("config.json")
dns_server = DNSServer(myresolver, port=1053, logger=MyDNSLogger("request"))

def main():
    dns_server.start()

if __name__ == '__main__':
    main()
