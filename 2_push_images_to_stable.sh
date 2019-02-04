#!/bin/bash

DOCKERHUBTEST="securityonionsolutionstest"
DOCKERHUBPROD="securityonionsolutions"
if [ $# -eq 2 ]; then
	DOCKERHUBTEST=$1
	DOCKERHUBPROD=$2
fi

echo "This script will push latest images from ${DOCKERHUBTEST} to ${DOCKERHUBPROD}."
echo
echo "Press Enter to continue or Ctrl-c to cancel."
read input

for i in so-elasticsearch so-logstash so-kibana so-elastalert so-curator so-freqserver so-domainstats; do
	docker tag ${DOCKERHUBTEST}/${i}:latest	${DOCKERHUBPROD}/${i}:latest
	docker push --disable-content-trust=false ${DOCKERHUBPROD}/${i}:latest
done
