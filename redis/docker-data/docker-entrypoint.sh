#!/bin/sh

IP=$REDIS_CLUSTER_ADVERTISED_IP
if [ -z "$IP" ]; then
    echo "REDIS_CLUSTER_ADVERTISED_IP not provided. Assuming eth0 interface address"
    IP=`ifconfig | grep "inet addr:17" | cut -f2 -d ":" | cut -f1 -d " "`
fi

if [ "$1" = 'redis-cluster' ]; then
    for port in $(seq 6000 6008) $(seq 7000 7008); do
      mkdir -p /redis-conf/${port}
      mkdir -p /redis-data/${port}

      if [ -e /redis-data/${port}/nodes.conf ]; then
        rm /redis-data/${port}/nodes.conf
      fi

      PORT=${port} envsubst < /redis-conf/redis-cluster.tmpl > /redis-conf/${port}/redis.conf
    done

    # supervisor
    supervisord -c /etc/supervisor/supervisord.conf
    sleep 3

    # index
    echo "yes" | ruby /redis/src/redis-trib.rb create --replicas 1 ${IP}:7000 ${IP}:7001 ${IP}:7002 ${IP}:6000 ${IP}:6001 ${IP}:6002
    # version
    echo "yes" | ruby /redis/src/redis-trib.rb create --replicas 1 ${IP}:7003 ${IP}:7004 ${IP}:7005 ${IP}:6003 ${IP}:6004 ${IP}:6005
    # result
    echo "yes" | ruby /redis/src/redis-trib.rb create --replicas 1 ${IP}:7006 ${IP}:7007 ${IP}:7008 ${IP}:6006 ${IP}:6007 ${IP}:6008

    tail -f /var/log/supervisor/redis*.log
else
  exec "$@"
fi
