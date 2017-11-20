FROM redis:3.2

MAINTAINER Ruian Duan <duanruian@gmail.com>

# Some Environment Variables
ENV HOME /root
ENV DEBIAN_FRONTEND noninteractive

# Install system dependencies
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -yqq \
      net-tools supervisor ruby rubygems locales gettext-base wget && \
    apt-get clean -yqq
RUN apt-get install -y gcc make g++ build-essential libc6-dev tcl git supervisor
RUN apt-get install -yqq zlib1g zlib1g-dev openssl libssl-dev

# Ensure UTF-8 lang and locale
RUN locale-gen en_US.UTF-8
ENV LANG       en_US.UTF-8
ENV LC_ALL     en_US.UTF-8

# Install latest version of ruby as required by redis
WORKDIR /ruby
RUN wget https://cache.ruby-lang.org/pub/ruby/2.2/ruby-2.2.2.tar.gz -O ruby-2.2.2.tar.gz
RUN tar -zxf ruby-2.2.2.tar.gz && cd ruby-2.2.2 && ./configure && make && make install
# RUN cd ruby-2.2.2/ext/zlib && ruby ./extconf.rb && make && make install
# RUN cd ruby-2.2.2/ext/openssl && ruby ./extconf.rb && make && make install

RUN gem install redis

# Install the requested version of redis
ARG redis_version=4.0.2

RUN wget -qO redis.tar.gz http://download.redis.io/releases/redis-${redis_version}.tar.gz \
    && tar xfz redis.tar.gz -C / \
    && mv /redis-$redis_version /redis

RUN (cd /redis && make)

RUN mkdir /redis-conf
RUN mkdir /redis-data

COPY ./docker-data/redis-cluster.tmpl /redis-conf/redis-cluster.tmpl
COPY ./docker-data/redis.tmpl /redis-conf/redis.tmpl

# Add supervisord configuration
COPY ./docker-data/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Add startup script
COPY ./docker-data/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod 755 /docker-entrypoint.sh

EXPOSE 6000-6008 7000-7008

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["redis-cluster"]
