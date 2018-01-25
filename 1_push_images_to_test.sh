#!/bin/bash

DOCKERHUB="dougburks"

echo
echo "This script will push all Docker images to:"
echo "https://hub.docker.com/u/${DOCKERHUB}/."
echo
echo "Press Enter to continue or Ctrl-c to cancel."
read PAUSE
echo

docker push --disable-content-trust=false ${DOCKERHUB}/so-elasticsearch:latest
docker push --disable-content-trust=false ${DOCKERHUB}/so-logstash:latest
docker push --disable-content-trust=false ${DOCKERHUB}/so-kibana:latest
docker push --disable-content-trust=false ${DOCKERHUB}/so-elastalert:latest
docker push --disable-content-trust=false ${DOCKERHUB}/so-curator:latest
docker push --disable-content-trust=false ${DOCKERHUB}/so-freqserver:latest
docker push --disable-content-trust=false ${DOCKERHUB}/so-domainstats:latest
