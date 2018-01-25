#!/bin/bash

VERSION=6.1.2
DOCKERHUB="dougburks"

echo
echo "This script will build all Docker images for Security Onion."
echo
echo "It is currently set to build Elastic stack version ${VERSION}."
echo
echo "Press Enter to continue or Ctrl-c to cancel."
read PAUSE
echo

sed -i "s|X.Y.Z|$VERSION|g" so-elasticsearch/Dockerfile so-logstash/Dockerfile so-kibana/Dockerfile

docker build -t dougburks/so-elasticsearch so-elasticsearch/ &&
docker build -t dougburks/so-logstash so-logstash/ && 
docker build -t dougburks/so-kibana so-kibana/ && 
docker build -t dougburks/so-curator so-curator/ && 
docker build -t dougburks/so-elastalert so-elastalert/ && 
docker build -t dougburks/so-domainstats so-domainstats/ && 
docker build -t dougburks/so-freqserver so-freqserver/

sed -i "s|$VERSION|X.Y.Z|g" so-elasticsearch/Dockerfile so-logstash/Dockerfile so-kibana/Dockerfile

echo
docker images
