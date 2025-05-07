#!/bin/sh
set -e
set -x

docker build -t compe560_linux .

docker run --rm -it -d --net=host -v $(pwd):/home/simplechatter/ --name simple_chat compe560_linux

docker exec -it simple_chat bash