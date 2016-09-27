#!/usr/bin/env python
#  -*- coding: utf-8 -*-
from hashlib import sha1
from redis.exceptions import NoScriptError
from redis import StrictRedis

# Adapted from http://redis.io/commands/incr#pattern-rate-limiter-2
INCREMENT_SCRIPT = b"""
    local current
    current = tonumber(redis.call("incr", KEYS[1]))
    if current == 1 then
        redis.call("expire", KEYS[1], ARGV[1])
    end
    return current
"""
INCREMENT_SCRIPT_HASH = sha1(INCREMENT_SCRIPT).hexdigest()


class RateLimit(object):
    """
    This class offers an abstraction of a Rate Limit algorithm implemented on
    top of Redis >= 2.6.0.
    """
    def __init__(self, redis, resource, max_requests, expire=1):
        """
        Class initialization method checks if the Rate Limit algorithm is
        actually supported by the installed Redis version and sets some
        useful properties.

        If Rate Limit is not supported, it raises an Exception.
        :param redis: redis connection instance
        :param resource: resource identifier string (i.e. ‘user_pictures’)
        :param max_requests: integer (i.e. ‘10’)
        :param expire: seconds to wait before resetting counters (i.e. ‘60’)
        """
        self.redis = redis
        self.resource = resource
        self.max_requests = max_requests
        self.expire = expire

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def consume(self, client):
        """
        Calls a LUA script that should increment the resource usage by client.

        If the resource limit overflows the maximum number of requests, this
        method returns False
        
        :param client: client identifier string (i.e. ‘192.168.0.10’)
        :return: True/False
        """
        
        rate_limit_key = "ratelimit:{}:{}".format(self.resource, client)
        try:
            current_usage = self.redis.evalsha(INCREMENT_SCRIPT_HASH, 1, rate_limit_key, self.expire)
        except NoScriptError:
            current_usage = self.redis.eval(INCREMENT_SCRIPT, 1, rate_limit_key, self.expire)

        if int(current_usage) > self.max_requests:
            return False

        return True

            
if __name__ == "__main__":
    import time
    redis = StrictRedis("localhost")
    limiter = RateLimit(redis, "test", 80, 1)
    while True:
        print(limiter.consume(10))
        time.sleep(0.01)

