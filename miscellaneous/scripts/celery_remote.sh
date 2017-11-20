sudo rabbitmqctl add_user celery_scaling celery_scaling 
sudo rabbitmqctl add_vhost celery_scaling
sudo rabbitmqctl set_permissions -p celery_scaling celery_scaling ".*" ".*" ".*"
sudo rabbitmqctl stop_app
sudo rabbitmqctl start_app
sudo rabbitmqctl list_users
