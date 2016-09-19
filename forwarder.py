#!/usr/bin/python3
# -*- coding: utf-8 -*-


import time
import sys
import logging
import json
import redis
import pickle
import socket
from dnslib.server import DNSServer, BaseResolver, DNSLogger
from dnslib.dns import DNSError, QTYPE, RCODE, RR, A
from dnslib import DNSRecord

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

class CachedReply(object):
    '''
    A cached DNS reply, for making replies from cache
    '''
    def __init__(self, reply):
        self.reply = reply

    def make_reply(self, request):
        header = request.reply().header
        self.reply.header = header
        return self.reply


class MyResolver(BaseResolver):

    def __init__(self, filename, cache_size=1000):
        super().__init__()
        self.load_config(filename)
        # self.cache = DNSCache(cache_size)
        self.redis = redis.StrictRedis(host='localhost')

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
        key = "{}:{}".format(request.q.qname, request.q.qtype)
        logging.debug(key)

        cached = self.redis.get(key)
        if cached:
            obj = pickle.loads(cached)
            logging.debug("Cache hit for {}".format(key))
            return obj.make_reply(request)

        #Do actual query
        try:
            domain_tuple = request.q.qname.label
            for name, domain_set in self.domains.items():
                if self.domain_match_set(domain_tuple, domain_set):
                    logging.debug("{} matched in {} list".format(request.q.qname, name))
                    reply = self.resolve_from_upstream(request, name)
                    if reply.header.rcode == RCODE.NOERROR and reply.rr:
                        self.redis.set(key, pickle.dumps(CachedReply(reply)), ex=self.upstreams['default'].get("ttl", 10))
                    break
            else:
                logging.debug("resolve {} from default server".format(request.q.qname))
                reply = self.resolve_from_upstream(request, 'default')
                if reply.header.rcode == RCODE.NOERROR and reply.rr:
                    self.redis.set(key, pickle.dumps(CachedReply(reply)), ex=self.upstreams['default'].get("ttl", 10))

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
