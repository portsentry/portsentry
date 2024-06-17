#!/bin/sh

if [ "$1" = "make_docker_container" ]; then
  docker build -t portsentry/portsentry:v1.2 -f docker/Dockerfile .
elif [ "$1" = "run_docker_container" ]; then
  docker run --rm -it --network=host --name portsentry portsentry/portsentry:v1.2
elif [ "$1" = "make_dev_env" ]; then
  docker build -t portsentrydev:latest -f docker/Dockerfile.dev .
elif [ "$1" = "run_dev_env" ]; then
  docker run --rm -it --mount type=bind,src=.,dst=/src --name portsentrydev portsentrydev:latest
else
  echo "Usage: ./build.sh [make_docker_container|run_docker_container|make_dev_env|run_dev_env]"
fi
