#!/bin/bash
echo -n "Removing Triumph from Redis Cluster..."
redis-trib.py quit 143.215.130.32:6380 &> log
if [ $? -ne 0 ]; then
	echo "Failed (port 6380)"
	exit
fi

echo -n "."
redis-trib.py quit 143.215.130.32:6381 &> log
if [ $? -ne 0 ]; then
	echo "Failed (port 6381)"
	exit
fi

echo -n "."
redis-trib.py quit 143.215.130.32:6382 &> log
if [ $? -ne 0 ]; then
	echo "Failed (port 6382)"
	exit
fi

echo -n "."
redis-trib.py quit 143.215.130.32:6383 &> log
if [ $? -ne 0 ]; then
	echo "Failed (port 6383)"
	exit
fi
echo "Done"

# RUIAN
echo -n "Removing Ruian from Redis Cluster..."

redis-trib.py quit 143.215.130.109:6380 &> log
if [ $? -ne 0 ]; then
	echo "Failed (port 6380)"
	exit
fi
echo "Done"

# SACK
echo -n "Removing Sack from Redis Cluster "
redis-trib.py quit 128.61.240.63:6380 &> log
if [ $? -ne 0 ]; then
	echo "Failed (port 6380)"
	exit
fi

echo -n "."
redis-trib.py quit 128.61.240.63:6381 &> log
if [ $? -ne 0 ]; then
	echo "Failed (port 6381)"
	exit
fi

echo -n "."
redis-trib.py quit 128.61.240.63:6382 &> log
if [ $? -ne 0 ]; then
	echo "Failed (port 6382)"
	exit
fi

echo -n "."
redis-trib.py quit 128.61.240.63:6383 &> log
if [ $? -ne 0 ]; then
	echo "Failed (port 6383)"
	exit
fi

echo "Done"

# MOON
echo -n "Removing Moon from Redis Cluster..."

redis-trib.py shutdown 128.61.240.68:6380 &> log
if [ $? -ne 0 ]; then
	echo "Failed (port 6380)"
	exit
fi

# Cluster down now
echo "Redis Cluster Down"

# Bring up the cluster again
echo -n "Restarting Redis Cluster..." &> log

redis-trib.py start_multi 143.215.130.32:6380 143.215.130.32:6381 143.215.130.32:6382 143.215.130.32:6383 143.215.130.109:6380 128.61.240.63:6380 128.61.240.63:6381 128.61.240.63:6382 128.61.240.63:6383 128.61.240.68:6380

if [ $? -ne 0 ]; then
	echo "Failed"
else
	echo "Done"
fi
