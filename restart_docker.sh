#!/bin/sh

docker system prune -a -f

./run_docker_compose.sh
