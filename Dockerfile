FROM ubuntu:22.04

RUN apt-get update && apt-get install -y python3 sudo python3-pip
RUN pip3 install cryptography PyCryptodome

RUN apt-get update && apt-get install -y locales sudo && rm -rf /var/lib/apt/lists/* \
	&& localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG en_US.utf8

RUN useradd -ms /bin/bash simplechatter
WORKDIR /home/simplechatter/

ENTRYPOINT [ "bash" ]