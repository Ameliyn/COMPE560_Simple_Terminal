docker build -t compe560_linux .

docker run --rm -it -d --net=host -v %cd%:/COMPE560 --name simple_chat compe560_linux

docker exec -it simple_chat bash