sudo rabbitmqctl add_user gplviolation GPLViolationsJuly2016
sudo rabbitmqctl add_vhost gplviolation
sudo rabbitmqctl set_permissions -p gplviolation gplviolation ".*" ".*" ".*"
sudo rabbitmqctl stop_app
sudo rabbitmqctl start_app
sudo rabbitmqctl list_users
sudo rabbitmqctl add_user test test
sudo rabbitmqctl set_user_tags test administrator
sudo rabbitmqctl set_permissions -p / test ".*" ".*" ".*"
