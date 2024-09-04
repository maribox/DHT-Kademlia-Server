FROM ubuntu:22.04
#LABEL authors="joern"
# at the beginning of the dockerfile specifiy the base image
# put the Dockerfile file in the root of your project.
# You can't copy stuff with cp ../ since the context (default: dir of the Dockerfile) is first copied to docker
# create a .dockerignore file to exclude things from being copied to docker

# Update the list of known packages and install needed dependencies non-interactively
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y install cmake libboost-all-dev libssl-dev libspdlog-dev build-essential git

#Adding (copying, but entirety) a directory is more efficient and less error-prone:
ADD ./src /server/src
ADD ./docs /server/docs
ADD ./tests /server/tests
# copying individual files:
COPY CMakeLists.txt /server/CMakeLists.txt
COPY LICENSE /server/LICENSE
#COPY README.md /server/README.md

RUN cd /server/
RUN mkdir /server/build
RUN cmake /server -S /server -B /server/build
RUN cmake --build /server/build/ --target dht_server -j
ENTRYPOINT ["/server/build/dht_server"]
#ENTRYPOINT ["/bin/bash"]

## Creating an entrypoint.sh file in the root of the container is a common best practice.
## This file is run when the built image starts.
#COPY entrypoint.sh /entrypoint.sh
## must make the entrypoint.sh file executable
## RUN chmod +x /entrypoint.sh
#
## Basically does nothing useful besides document that you use port 5000
## See https://forums.docker.com/t/what-is-the-use-of-expose-in-docker-file/37726/2 for useful launch argument
#EXPOSE 5000
#
## Tell Docker what it should do when the container starts
## The first line in entrypoint.sh makes it so the script is run with bash.
## Therefore it's unnecessary to use the Docker SHELL command to allow for bash commands inside entrypoint.sh.
#ENTRYPOINT ["/entrypoint.sh"]