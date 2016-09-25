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

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

class Server(object):

    def __init__(self, filename):
        self.load_config(filename)
        self.load_hosts("hosts.txt")
        self.redis = redis.StrictRedis(host='localhost')

    def load_hosts(self, filename):
        self.hosts = {}
        try:
            with open(filename) as f:
                for x in f.readlines():
                    l = x.strip()
                    if l:
                        name, ip = l.split()
                        self.hosts[name] = ip
        except IOError:
            logging.warning("Host file not found.")

    def load_from_hosts(self, request):
        matched = self.domain_match_set(request.q.qname.label, self.hosts)
        if matched:
            logging.debug("{} found in hosts".format(request.q.qname))
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
            if tmpstr in target_set:
                # logging.info("{} matched.".format(tmpstr))
                return tmpstr
        return False

    def send_to_upstream(self, request, name):
        try:
            self.query_sock.sendto(request.pack(), (self.upstreams[name]['server'], self.upstreams[name].get('port', 53)))
        except socket.error:
            pass

    def save_to_cache(self, key, reply, ttl):
        self.redis.set(key, pickle.dumps(reply), ex=ttl)

    def load_from_cache(self, key, request):
        cached = self.redis.get(key)
        if cached:
            reply = pickle.loads(cached)
            reply.header = request.reply().header
            return reply
        return None

    def resolve(self, request):

        if request.q.qtype == QTYPE.A:
            reply = self.load_from_hosts(request)
            if reply:
                return reply

        #Try to fetch from cache
        key = "{}:{}".format(request.q.qname, request.q.qtype)
        logging.debug(key)

        cached = self.load_from_cache(key, request)
        if cached:
            # TODO: Add TTL adjust
            return cached

        #Do actual query
        try:
            domain_tuple = request.q.qname.label

            for name, domain_set in self.domains.items():
                if self.domain_match_set(domain_tuple, domain_set):
                    logging.debug("{} matched in {} list".format(request.q.qname, name))
                    self.send_to_upstream(request, name)
                    break
            else:
                logging.debug("resolve {} from default server".format(request.q.qname))
                self.send_to_upstream(request, 'default')

        except Exception as e:
            logging.error(e)
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply


    def sweep_waiting_list(self):
        tmplist = []
        now = time.time()
        for k, v in self.waiting.items():
            if now - v[2] > 5:
                fail = v[3].reply()
                fail.header.rcode = RCODE.SERVFAIL
                fail.header.id = v[1]
                self.server_sock.sendto(fail.pack(), v[0])
                logging.warning("#{} timed out".format(k))
                tmplist.append(k)
        for x in tmplist:
            self.waiting.pop(x)


    def serve_forever(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_sock.bind(("", 1053))
        self.query_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.waiting = {}
        trans_id = 1
        while True:
            readable, _, _ = select.select([self.server_sock, self.query_sock], [], [], 1)
            if self.server_sock in readable:
                data, addr = self.server_sock.recvfrom(1024)
                try:
                    query = DNSRecord.parse(data)
                except Exception as e:
                    logging.error(e)
                    continue
                old_id = query.header.id
                query.header.id = trans_id
                trans_id = (trans_id + 1) & 0xffff
                reply = self.resolve(query)
                if reply:
                    reply.header.id = old_id
                    self.server_sock.sendto(reply.pack(), addr)
                else:
                    self.waiting[query.header.id] = (addr, old_id, time.time(), query)

            if self.query_sock in readable:
                data, addr = self.query_sock.recvfrom(1024)
                try:
                    reply = DNSRecord.parse(data)
                except Exception as e:
                    logging.error(e)
                    continue
                if reply.header.id in self.waiting:
                    info = self.waiting.pop(reply.header.id)
                    reply.header.id = info[1]
                    if reply.header.rcode == RCODE.NOERROR:
                        key = "{}:{}".format(info[3].q.qname, info[3].q.qtype)
                        logging.debug("add {} to cache".format(key))
                        self.redis.set(key, pickle.dumps(reply), ex=60)
                    try:
                        self.server_sock.sendto(reply.pack(), info[0])
                    except:
                        pass

            self.sweep_waiting_list()

if __name__ == '__main__':
    server = Server("config.json")
    server.serve_forever()
