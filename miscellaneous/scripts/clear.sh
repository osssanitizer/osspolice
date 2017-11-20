killall celery
#python flush.py
rm -f /tmp/index_*
rm -f /tmp/search_*
rm -f /tmp/worker_*
rm -rf /tmp/only*
#redis-cli FLUSHDB &> /dev/null; redis-cli FLUSHDB &> /dev/null; rm -f repos.db
