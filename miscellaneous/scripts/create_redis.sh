if [[ "$#" -ne 6  && "$#" -ne 3 ]]; then
    echo "Create Usage: $0 src_redis src_port src_bin des_redis des_port des_bin"
    echo "Cleanup Usage: $0 des_redis des_port des_bin"
    exit 1
fi

if [ "$#" -eq 6 ]; then
    echo "Create redis server"
    SRC_REDIS=$1
    if [ "$SRC_REDIS" = "redis" ]; then
        echo "Don't use redis as src_redis=$SRC_REDIS, this will cause ambiguity in the following scripts"
        exit 1
    fi
    SRC_PORT=$2
    SRC_BIN=$3
    DES_REDIS=$4
    DES_PORT=$5
    DES_BIN=$6

    DES_REDIS_ETC=/etc/$DES_REDIS
    DES_VAR_RUN=/var/run/$DES_REDIS
    DES_VAR_LOG=/var/log/$DES_REDIS
    DES_VAR_DIR=/var/lib/$DES_REDIS
    DES_BIN_INIT=/etc/init.d/$DES_BIN

    echo "Change /etc/"
    sudo cp -r /etc/$SRC_REDIS /etc/$DES_REDIS
    sudo sed -i.bak "s/$SRC_REDIS/$DES_REDIS/g;s/$SRC_PORT/$DES_PORT/g" /etc/$DES_REDIS/redis.conf
    sudo chown -R redis:redis /etc/$DES_REDIS

    echo "Make dirs in /var/"
    sudo mkdir $DES_VAR_RUN; 
    sudo chown redis:redis $DES_VAR_RUN
    sudo mkdir $DES_VAR_LOG; 
    sudo chown redis:redis $DES_VAR_LOG
    sudo chmod 770 $DES_VAR_LOG
    sudo mkdir $DES_VAR_DIR;
    sudo chown redis:redis $DES_VAR_DIR
    sudo chmod 770 $DES_VAR_DIR

    echo "Create init script"
    sudo cp /etc/init.d/$SRC_BIN /etc/init.d/$DES_BIN
    sudo sed -i.bak "s/$SRC_REDIS/$DES_REDIS/g;s/$SRC_PORT/$DES_PORT/g;s/$SRC_BIN/$DES_BIN/g" /etc/init.d/$DES_BIN

    echo "Start the new redis-cluster"
    sudo /etc/init.d/$DES_BIN start

    # Hint
    echo "maybe you want to run redis-trib.py to start cluster manually"
elif [ "$#" -eq 3 ]; then
    echo "Cleanup redis server"
    DES_REDIS=$1
    DES_PORT=$2
    DES_BIN=$3

    DES_REDIS_ETC=/etc/$DES_REDIS
    DES_VAR_RUN=/var/run/$DES_REDIS
    DES_VAR_LOG=/var/log/$DES_REDIS
    DES_VAR_DIR=/var/lib/$DES_REDIS
    DES_BIN_INIT=/etc/init.d/$DES_BIN

    sudo rm -r $DES_REDIS_ETC $DES_VAR_RUN $DES_VAR_LOG $DES_VAR_DIR $DES_BIN_INIT
fi
