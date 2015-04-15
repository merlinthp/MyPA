def load_session_store(conf):
    backend = conf.get('session', 'store')

    if backend == 'redis':
        import redis
        from simplekv.memory.redisstore import RedisStore
        return RedisStore(redis.StrictRedis(host=conf.get('session', 'host'),
                          port=conf.get('session', 'port')))
    elif backend == 'memcached':
        import memcache
        from simplekv.memory.memcachestore import MemcacheStore
        server = "%s:%s" % (conf.get('session', 'host'),
                            conf.get('session', 'port'))
        return MemcacheStore(memcache.Client([server]))
    else:
        raise Exception('No/unknown session backend defined')
