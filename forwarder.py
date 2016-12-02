#!/usr/bin/python3

import time
import os
import sys
import logging
import configparser
import redis
import pickle
import socket
import select
import random
import argparse
from dnslib.dns import DNSError, QTYPE, RCODE, RR, A
from dnslib import DNSRecord

# from ratelimit import RateLimit

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

class Server(object):

    def __init__(self, directory, filename='dns.conf'):
        os.chdir(directory)
        self.load_config(filename)

    def load_hosts_file(self, filename):
        self.hosts = {}
        try:
            with open(filename) as f:
                for x in f.readlines():
                    l = x.strip()
                    if l:
                        name, ips = l.split(maxsplit=1)
                        logging.info("redirect {} to {}".format(name, ips))
                        self.hosts[tuple((name.split(".")))] = tuple(map(str.strip, ips.split(",")))
        except IOError:
            logging.warning("Host file not found.")

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
                    ret.add(tuple(l.split(".")))
        # logging.debug(ret)
        return ret

    def load_config(self, filename):

        try:
            f = open(filename)
            f.close()
        except:
            logging.error("{} does not exist".format(filename))
            sys.exit(-1)

        config = configparser.ConfigParser()
        try:
            config.read(filename)
        except:
            logging.error("error loading config from {}".format(filename))
            sys.exit(-2)

        # reset logging level
        logging.getLogger().setLevel(getattr(logging, config['global']['log_level']))
        self.load_hosts_file(config['global'].get('hosts_file', '/dev/null'))
        self.allowed_qtype = tuple(getattr(QTYPE, x) for x in map(str.strip, config['global']['allowed_qtype'].split(",")))
        self.server_port = int(config['global'].get('port', 1053))
        self.redis_unixsocket = config['global']['unixsocket']
        self.max_cache_ttl = config['global'].get("max_cache_ttl", 3600 * 24 * 7)

        self.upstreams = {}

        def extract_servers(string):
            '''
            From "127.0.0.1#5353, 1.2.3.4#53"
            To [("127.0.0.1", 5353), ("1.2.3.4", 53)]

            '''
            servers = []
            if not string:
                return servers
            for addr in string.split(','):
                ip = addr.split("#")[0].strip()
                port = int(addr.split("#")[1])
                servers.append((ip, port))
            return servers

        for x in config.sections():
            if x != 'global':
                self.upstreams[x] = {
                    "file": config[x].get('file', '/dev/null'),
                    "ttl": int(config[x]['ttl']),
                    'timeout': int(config[x]['timeout'])
                    }
                # primary servers
                self.upstreams[x]['servers'] = tuple(extract_servers(config[x]['servers']))
                # backup server
                self.upstreams[x]['backups'] = tuple(extract_servers(config[x].get("backups", None)))

        self.domains = {}
        for name, val in self.upstreams.items():
            if name != 'default':
                tmpset = self.load_list_from_file(val["file"])
                for x in tmpset:
                    self.domains[x] = name
                logging.info("loaded {} domains from {}".format(len(tmpset), val["file"]))

    def load_from_hosts(self, request):
        ips = self.match_domain_in_dict(request.q.qname.label, self.hosts)
        if ips:
            # logging.debug("{} found in hosts".format(request.q.qname))
            reply = request.reply()
            for ip in ips:
                reply.add_answer(RR(request.q.qname, QTYPE.A, ttl=60, rdata=A(ip)))
            return reply
        else:
            return None

    def load_from_cache(self, request):
        key = "dns:{}:{}".format(request.q.qname, request.q.qtype)
        cached = self.redis.get(key)
        if cached:
            reply = pickle.loads(cached)
            reply.header = request.reply().header
            return reply
        return None

    def load_from_cache_failed(self, request):
        key = "dns-fail:{}:{}".format(request.q.qname, request.q.qtype)
        cached = self.redis.get(key)
        if cached:
            reply = pickle.loads(cached)
            reply.header = request.reply().header
            return reply
        return None

    def save_to_cache(self, key, reply):
        self.redis.set(key, pickle.dumps(reply), ex=ttl)

    @staticmethod
    def match_domain_in_dict(domain_tuple, target_dict, depth=5):
        '''
        If the domain is in target_dict, return the corresponding value, else return None
        '''
        try:
            rv = tuple(map(bytes.decode, domain_tuple))
            for l in range(1, depth):
                k = rv[-l:]
                if k in target_dict:
                    logging.debug("{} matched".format(k))
                    return target_dict[k]
        except Exception as e:
            logging.error(e)
            return None
        return None

    def get_random_server_addr(self, name):
        return tuple(random.choice(self.upstreams[name]['servers']))

    def send_to_upstream(self, request, name, client_addr):
        self.trans_id = (self.trans_id + 1) & 0xffff
        try:
            server_addr = self.get_random_server_addr(name)
            self.waiting[(self.trans_id, server_addr)] = (request,
                                                          client_addr,
                                                          time.time() + self.upstreams[name].get('timeout', 5),
                                                          self.upstreams[name].get('ttl', 60),
                                                          request.header.id)
            # reassign trans_id to void collision, assign back in reply handler
            request.header.id = self.trans_id
            logging.debug("sending {} to {}".format(request.q.qname, server_addr))
            k = random.choice(self.query_sock_pool)
            k.sendto(request.pack(), server_addr)
        except Exception as e:
            logging.error(e)

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
            return

        logging.info("request for {} from {}".format(request.q.qname, addr))

        if request.q.qtype not in self.allowed_qtype:
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

        cached = self.load_from_cache(request)
        if cached:
            # TODO: Add TTL adjustment
            logging.info("cache hit on {}".format(request.q.qname))
            self.send_reply_to(cached, addr)
            return

        #Do actual query based on qname
        try:
            upstream_name = self.match_domain_in_dict(request.q.qname.label, self.domains)
            if upstream_name is None:
                logging.debug("resolve {} from default server".format(request.q.qname))
                self.send_to_upstream(request, 'default', addr)
            else:
                logging.debug("resolve {} from {}".format(request.q.qname, upstream_name))
                self.send_to_upstream(request, upstream_name, addr)
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
                logging.warning("{} timed out for".format(k, v[0].q.qname))
                resp = self.load_from_cache_failed(v[0])
                if not resp:
                    logging.warning("And not found in cache.")
                    resp = v[0].reply()
                    resp.header.id = v[4]
                    resp.header.rcode = RCODE.SERVFAIL
                else:
                    logging.warning("But found in cache.")
                self.server_sock.sendto(resp.pack(), v[1])
                tmplist.append(k)
        for x in tmplist:
            self.waiting.pop(x)

    def handle_server_reply(self, data, addr):
        try:
            reply = DNSRecord.parse(data)
        except Exception as e:
            logging.error(e)
            return

        logging.info("reply for {} from {}".format(reply.q.qname, addr))

        if (reply.header.id, addr) in self.waiting:
            info = self.waiting.pop((reply.header.id, addr))
            reply.header.id = info[4]
            self.send_reply_to(reply, info[1])
            if info[3] > 0 and reply.header.rcode in (RCODE.NOERROR, RCODE.NXDOMAIN):
                #only cache if TTL in config > 0
                key = "dns:{}:{}".format(info[0].q.qname, info[0].q.qtype)
                logging.debug("add {} to cache, ttl={}".format(key, info[3]))
                dumped = pickle.dumps(reply)
                self.redis.set(key, dumped, ex=info[3])
                key = "dns-fail:{}:{}".format(info[0].q.qname, info[0].q.qtype)
                logging.debug("add {} to cache, ttl={}".format(key, self.max_cache_ttl))
                self.redis.set(key, dumped, ex=self.max_cache_ttl)


    def serve_forever(self, pool_size=10):
        self.redis = redis.StrictRedis(unix_socket_path=self.redis_unixsocket)

        # self.limiter = RateLimit(self.redis, "dns", max_requests=50, expire=3)
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_sock.bind(("", self.server_port))
        self.query_sock_pool = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(pool_size)]
        self.waiting = {}
        # key is (trans_id, server_addr), value is (request, client_addr, old_trans_id, timeout)
        self.trans_id = 0
        # TODO: use a random trans_id to avoid spoofing

        epoll = select.epoll()
        epoll.register(self.server_sock, select.EPOLLIN)
        for x in self.query_sock_pool:
            epoll.register(x, select.EPOLLIN)

        logging.info("server started on port {}".format(self.server_port))

        while True:
            events = epoll.poll(timeout=1)
            # logging.debug(events)
            for fd, event in events:
                if fd == self.server_sock.fileno():
                    data, addr = self.server_sock.recvfrom(4096)
                    self.handle_client_request(data, addr)

                for sock in self.query_sock_pool:
                    if sock.fileno() == fd:
                        data, addr = sock.recvfrom(4096)
                        self.handle_server_reply(data, addr)
                        break

            self.sweep_waiting_list()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="A DNS relay")
    parser.add_argument("-d", "--directory", help="directory of config files", default='/etc/zjudns/')
    args = parser.parse_args()
    server = Server(args.directory)
    server.serve_forever()
