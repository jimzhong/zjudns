#!/usr/bin/python3
# -*- coding: utf-8 -*-


import time
import sys
import logging
import json
import redis
import pickle
import socket
import select
# from dnslib.server import DNSServer, BaseResolver, DNSLogger
from dnslib.dns import DNSError, QTYPE, RCODE, RR, A
from dnslib import DNSRecord

ALLOWED_QTYPE = (QTYPE.A, QTYPE.AAAA, QTYPE.MX, QTYPE.CNAME, QTYPE.NS, QTYPE.SRV)

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

class Server(object):

    def __init__(self, filename):
        self.load_config(filename)
        self.load_hosts_file("hosts.txt")
        self.redis = redis.StrictRedis(host='localhost')

    def load_hosts_file(self, filename):
        self.hosts = {}
        try:
            with open(filename) as f:
                for x in f.readlines():
                    l = x.strip()
                    if l:
                        name, ip = l.split()
                        self.hosts[tuple(reversed(name.split(".")))] = ip
        except IOError:
            logging.warning("Host file not found.")
        logging.debug(self.hosts)

    def load_from_hosts(self, request):
        matched = self.domain_match_set(request.q.qname.label, self.hosts)
        if matched:
            # logging.debug("{} found in hosts".format(request.q.qname))
            ip = self.hosts[matched]
            reply = request.reply()
            reply.add_answer(RR(request.q.qname, QTYPE.A, ttl=60, rdata=A(ip)))
            return reply
        else:
            return None

    @staticmethod
    def load_list_from_file(filename):
        '''
        File contains multiple lines of domain names
        The return value is a Set of tuples
        '''
        ret = set()
        with open(filename) as f:
            for x in f.readlines():
                l = x.strip()
                if l:
                    ret.add(tuple(reversed(l.split("."))))
        # logging.debug(ret)
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
        try:
            rv = tuple(map(bytes.decode, reversed(domain_tuple)))
            for l in range(1, depth):
                k = rv[0:l]
                if k in target_set:
                    logging.debug("{} matched".format(k))
                    return k
        except Exception as e:
            logging.error(e)
            return False
        return False

    def send_to_upstream(self, request, name, client_addr):
        self.trans_id = (self.trans_id + 1) & 0xffff
        try:
            server_addr = (self.upstreams[name]['server'], self.upstreams.get('port', 53))
            self.waiting[(self.trans_id, server_addr)] = (request,
                                                          client_addr,
                                                          time.time() + self.upstreams[name].get('timeout', 5),
                                                          self.upstreams[name].get('ttl', 60),
                                                          request.header.id)
            request.header.id = self.trans_id
            logging.debug("sending {} to {}".format(request.q.qname, server_addr))
            self.query_sock.sendto(request.pack(), server_addr)
        except socket.error as e:
            logging.error(e)

    def save_to_cache(self, key, reply):
        self.redis.set(key, pickle.dumps(reply), ex=ttl)

    def load_from_cache(self, key, request):
        cached = self.redis.get(key)
        if cached:
            reply = pickle.loads(cached)
            reply.header = request.reply().header
            return reply
        return None

    def send_reply_to(self, reply, addr):
        try:
            self.server_sock.sendto(reply.pack(), addr)
        except Exception as e:
            logging.error(e)

    def handle_client_request(self, data, addr):

        try:
            request = DNSRecord.parse(data)
        except Exception as e:
            logging.error(e)

        logging.info("request for {} from {}".format(request.q.qname, addr))

        if request.q.qtype not in ALLOWED_QTYPE:
            logging.info("not allowed qtype of {}".format(request.q.qtype))
            reply = request.reply()
            reply.header.rcode = RCODE.REFUSED
            self.send_reply_to(reply, addr)
            return

        if request.q.qtype == QTYPE.A:
            reply = self.load_from_hosts(request)
            if reply:
                logging.info("found {} in hosts".format(request.q.qname))
                self.send_reply_to(reply, addr)
                return

        #Try to fetch from cache
        key = "dns:{}:{}".format(request.q.qname, request.q.qtype)

        cached = self.load_from_cache(key, request)
        if cached:
            # TODO: Add TTL adjust
            logging.info("cache hit on {}".format(request.q.qname))
            self.send_reply_to(cached, addr)
            return

        #Do actual query based on qname
        try:
            domain_tuple = request.q.qname.label
            for name, domain_set in self.domains.items():
                if self.domain_match_set(domain_tuple, domain_set):
                    logging.debug("{} matched in {} list".format(request.q.qname, name))
                    self.send_to_upstream(request, name, addr)
                    break
            else:
                logging.debug("resolve {} from default server".format(request.q.qname))
                self.send_to_upstream(request, 'default', addr)

        except Exception as e:
            logging.error(e)
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            self.send_reply_to(reply, addr)


    def sweep_waiting_list(self):
        tmplist = []
        now = time.time()
        for k, v in self.waiting.items():
            if now > v[2]:
                fail = v[0].reply()
                fail.header.id = v[4]
                fail.header.rcode = RCODE.SERVFAIL
                self.server_sock.sendto(fail.pack(), v[1])
                logging.warning("{} timed out for {}".format(k, v[0].q.qname))
                tmplist.append(k)
        for x in tmplist:
            self.waiting.pop(x)


    def serve_forever(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_sock.bind(("", 1053))
        self.query_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.waiting = {}
        self.trans_id = 0
        while True:
            readable, _, _ = select.select([self.server_sock, self.query_sock], [], [], 1)
            if self.server_sock in readable:
                data, addr = self.server_sock.recvfrom(1024)
                self.handle_client_request(data, addr)

            if self.query_sock in readable:
                data, addr = self.query_sock.recvfrom(4096)
                self.handle_server_reply(data, addr)

            self.sweep_waiting_list()


    def handle_server_reply(self, data, addr):
        try:
            reply = DNSRecord.parse(data)
        except Exception as e:
            logging.error(e)

        logging.info("reply for {} from {}".format(reply.q.qname, addr))

        if (reply.header.id, addr) in self.waiting:
            info = self.waiting.pop((reply.header.id, addr))
            reply.header.id = info[4]
            self.send_reply_to(reply, info[1])
            if reply.header.rcode == RCODE.NOERROR:
                # Cache positive result
                key = "dns:{}:{}".format(info[0].q.qname, info[0].q.qtype)
                logging.debug("add {} to cache, ttl={}".format(key, info[3]))
                self.redis.set(key, pickle.dumps(reply), ex=info[3])


if __name__ == '__main__':
    server = Server("config.json")
    server.serve_forever()
