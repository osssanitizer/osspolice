# Introduction #

This is the open source repository for OSSPolice presented in paper: Identifying Open-Source License Violation and 1-day 
Security Risk at Large Scale [[pdf]](https://acmccs.github.io/papers/p2169-duanA.pdf). For technical details, please refer to the paper.

The project consists of four components: **osspolice**, **redis**, **postgresql** and **rabbitmq**. 
For quick usage, please skip to the **Usage** section.

1. **osspolice** is the main code base for this project. It can be configured using *main/config*, a template with explanation on the config options is available in *main/config.tmpl*. *osspolice* is used to index new C/C++ repos and Java artifacts, as well as query apk/jar/so/dex against the indexed database to find reused Open Source Software (OSS) and their versions.
    - For feature extractor, java parser is located in main/java_parser, and native parser is located in main/native_parser. The former is open source and the latter is not because (a) there are many good alternatives for native (C/C++) parser, such as ctags, gtags etc, (b) we have other works in progress. In the native parser, you can easily adapt the current code to use other parsers.
2. **rabbitmq** is the scheduler/broker for distributed deployment. The option *CELERY_BROKER_URL* in **osspolice** should be set to the link of the scheduler.
3. **redis** is the in-memory database used for indexing and searching. The option *NATIVE_NODES*,  *NATIVE_VERSION_NODES*, *JAVA_NODES*, *JAVA_VERSION_NODES* and *RESULT_NODES* in **osspolice** should be set to the setup of redis database. Since there is no key collision between all these databases, they can be merged together.
    - *NATIVE_NODES* are prefixed with str-, func-, var-, file-, dir-, branch-, repo-. Reverse mapping replaces '-' with '_'.
    - *JAVA_NODES* are prefixed with strings-, classes-, normclasses-, centroids-, files-, dirs-, repo-. Reverse mapping prepends 'r-'.
    - *NATIVE_VERSION_NODES* and *JAVA_VERSION_NODES* are prefixed with software-, softwareversion-.
4. **postgresql** is the database used for storing repo and artifact information. The option *NATIVE_DBS* and *JAVA_DBS* in **osspolice** should be set to the setup of postgresql database.


# Dependencies #

docker, docker-compose


# Usage #

If you are simply interested in testing the tool for your app, we are working on an online service. Please check back later!

If you are interested in building your own hierarchical indexing database, prebuilt **postgresql** databases are provided. You can load them using *postgresql/load_data.sh*. List of repos/artifacts used in the paper are also provided in the data folder. You can use them to build your own database. 

If you are interested in comparing with our tool, we also have a prebuilt indexing database available. Please shoot us an email at osssanitizer@gmail.com for how to set this database up.

1. start rabbitmq scheduler
    - ```cd rabbitmq && docker-compose up```
2. start redis database
    - ```cd redis && docker-compose up```
3. start postgresql database and load data
    - In one terminal, ```cd postgresql && docker-compose up```
    - After postgresql starts, in another terminal, ```./load_data.sh```
4. start osspolice 
    - customized your *main/config* from *main/config.tmpl*, point the broker to rabbitmq, redis cluster to redis databases, and postgresql to postgresql database.
    - start osspolice worker
        - ```docker-compose up```
    - start osspolice master
        - Start osspolice interactively, ```docker-compose run osspolice /bin/bash```
        - Add jobs to broker, ```python detector.py apk_search $PATH_TO_APK```

# Helper Scripts #

- Create GitHub accounts automatically. This script exploits the fact that GitHub accounts can be created with invalid email address.
    - main/create-github-account.py
- Check the status of redis database. This script prints the status of indexed Native and Java database. 
    - main/redis_check.py


# TODO #

1. Support iOS and Windows app binaries
2. Robustness of native_parser and java_parser
3. Add support for Python, JS etc.


# License #

This software is licensed under GPL-3.0. Please check the terms and restrictions at [https://www.gnu.org/licenses/gpl-3.0.html](https://www.gnu.org/licenses/gpl-3.0.html).

