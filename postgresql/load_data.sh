#!/bin/bash
# load environment variables
source .env
export PGPASSWORD=$POSTGRES_PASSWORD

# the databases to create and initialize
DBS=( "fdroid" "github" "maven" "jcenter" "google" )
DB_LINK_BASE="https://archive.org/download/OpenSourceSoftwareData/"
DB_LINKS=( "fdroid-apps-versions.tar" "github-repos-licenses-versions-stats.tar" "maven-jars-versions-licenses.tar" "jcenter-jars-versions-licenses.tar" "google-jars-versions-licenses.tar" )

# download database
function download_db() {
    echo "Downloading $1 from $2"
    wget $2 -O /tmp/$1.tar
}

# create database
function create_db() {
    echo "Creating $1"
    local DB_NAME=$1
    CURRENT_IP=$(hostname --ip-address)
    psql -d $POSTGRES_DB -U $POSTGRES_USER -h $CURRENT_IP -c "CREATE DATABASE $DB_NAME"
    psql -d $POSTGRES_DB -U $POSTGRES_USER -h $CURRENT_IP -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $POSTGRES_USER;"
}

# load database
function load_db() {
    echo "Loading $1"
    psql -d $1 -U $POSTGRES_USER -h $CURRENT_IP -c "CREATE TYPE CRAWL_SOURCE AS ENUM ('google-play', 'github', 'bitbucket', 'f-droid', 'android-arsenal', 'maven', 'jcenter');"
    pg_restore -d $1 -U $POSTGRES_USER -h $CURRENT_IP /tmp/$1.tar
}

function remove_db() {
    echo "Removing $1.tar"
    rm /tmp/$1.tar
}

for ((i=0; i<${#DBS[@]}; ++i));
do
    DB_NAME=${DBS[i]}
    DB_LINK=$DB_LINK_BASE${DB_LINKS[i]}
    download_db $DB_NAME $DB_LINK
    create_db $DB_NAME
    load_db $DB_NAME
    remove_db $DB_NAME
done
