# docker-redis-cluster

Hub: [https://hub.docker.com/r/osssanitizer/docker-redis-cluster/](https://hub.docker.com/r/osssanitizer/docker-redis-cluster/])

# Quick Note

- This is a combination inspired from Grokzen's [docker-redis-cluster](https://github.com/Grokzen/docker-redis-cluster) 
and MyPureCloud's [fork](https://github.com/MyPureCloud/docker-redis-cluster).

- There are a few key differences between this docker config and Grokzen's, namely:
    - There are 3 clusters, yielding index, version, result database separately
    - Advertise IP address to work with both host and bridge networking

- Run with compose
    - If NAT is involved (docker-machine, etc), use host networking. For example,
        - ```REDIS_CLUSTER_ADVERTISED_IP=<IP> REDIS_CLUSTER_DOCKER_NET_MODE=host docker-compose up```
    - If no NAT is involved (native/linux platform), 
        - ```docker-compose up```


# How to migrate

Migrating Redis Data: [http://sorentwo.com/2015/09/15/migrating-redis-data.html](http://sorentwo.com/2015/09/15/migrating-redis-data.html)
