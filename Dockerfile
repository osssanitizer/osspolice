FROM jack482653/android-ndk-docker
ENV NDK_ROOT=/opt/android-ndk-r12b/
#FROM ubuntu:16.04

#######################
# Install dependencies
#######################
RUN apt-get -yqq update

# Generic dependencies
RUN apt-get -yqq install python python-pip python-dev pkg-config python-matplotlib libfreetype6 libfreetype6-dev software-properties-common libpq-dev gcc git vim cmake libtool autoconf

# Dependencies from proj-crawler and violation-validation
RUN apt-get -yqq install md5deep libblas-dev liblapack-dev libatlas-base-dev gfortran libxml2-dev libxslt1-dev zlib1g-dev libffi6 build-essential libssl-dev libffi-dev language-pack-en

# Dependencies from indexing, clang tool
WORKDIR /opt/android-ndk-r12b/build/tools/
RUN python make_standalone_toolchain.py --arch=arm --stl=gnustl --install-dir=/opt/android-ndk-r12b/toolchains/arm-linux-androidabi-clang/ --api=21
ENV NDK_TOOLCHAIN=/opt/android-ndk-r12b/toolchains/arm-linux-androidabi-clang/
ENV PATH /opt/android-ndk-r12b/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin:$PATH

# Dependencies for nomos
#install deps
RUN dpkg-reconfigure locales
RUN apt-get update -yqq
RUN apt-get install -yqq debhelper libglib2.0-dev libmagic-dev libxml2-dev libtext-template-perl librpm-dev subversion rpm libpcre3-dev libssl-dev php-pgsql php-pear php-cli apache2 libapache2-mod-php binutils bzip2 cabextract cpio sleuthkit genisoimage poppler-utils rpm upx-ucl unrar-free unzip p7zip-full p7zip wget subversion libpq-dev postgresql nodejs node-gyp npm git
#linux binary fix
RUN ln -s /usr/bin/nodejs /usr/bin/node
ENV IN_DOCKER_CONTAINER true
RUN git clone https://github.com/lingfennan/srclib-nomos.git /nomos_src/
#make nomos binary
WORKDIR /nomos_src/nomos
RUN make clean
RUN make CFLAGS=-I/usr/include/glib-2.0
RUN ln -s /nomos_src/nomos/nomossa /usr/local/bin/nomos
# Dependencies for ninka
RUN apt-get install -yqq cpanminus
RUN cpanm IO::CaptureOutput
RUN git clone https://github.com/dmgerman/ninka.git /ninka_src && cd /ninka_src && perl Makefile.PL && make && make install


#######################
# Install Java. https://github.com/William-Yeh/docker-java8/blob/master/Dockerfile
#######################
# add webupd8 repository
RUN \
    echo "===> add webupd8 repository..."  && \
    echo "deb http://ppa.launchpad.net/webupd8team/java/ubuntu trusty main" | tee /etc/apt/sources.list.d/webupd8team-java.list  && \
    echo "deb-src http://ppa.launchpad.net/webupd8team/java/ubuntu trusty main" | tee -a /etc/apt/sources.list.d/webupd8team-java.list  && \
    apt-key adv --keyserver keyserver.ubuntu.com --recv-keys EEA14886  && \
    apt-get update  && \
    \
    echo "===> install Java"  && \
    echo debconf shared/accepted-oracle-license-v1-1 select true | debconf-set-selections  && \
    echo debconf shared/accepted-oracle-license-v1-1 seen true | debconf-set-selections  && \
    DEBIAN_FRONTEND=noninteractive  apt-get install -yqq  oracle-java8-installer oracle-java8-set-default  && \
    \
    \
    echo "===> clean up..."  && \
    rm -rf /var/cache/oracle-jdk8-installer  && \
    apt-get clean  && \
    rm -rf /var/lib/apt/lists/*

# Define commonly used JAVA_HOME variable
# ENV JAVA_HOME /usr/lib/jvm/java-8-oracle

###############################
# INSTALL the dependencies from dependencies/
###############################
COPY dep/ /home/user/dependencies
WORKDIR /home/user/dependencies
RUN apt-get update
# TODO: Need a comprehensive list that can be installed!
# RUN cat available-devs.txt | xargs apt-get install -yqq
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# COPY the actual code into docker
COPY . /home/user/osspolice
WORKDIR /home/user/osspolice/main/

# Setup language
ENV LANG en_US.UTF-8

#######################
# Add user
#######################
RUN groupadd user && useradd --create-home --home-dir /home/user -g user user
RUN chown -R user:user /home/user/
USER user

#######################
# Add ENV and ENTRYPOINT
#######################
CMD ["celery", "worker", "-A", "celery_tasks"]

