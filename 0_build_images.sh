#!/bin/bash
#
# Copyright 2014,2015,2016,2017,2018,2019,2020,2021 Security Onion Solutions, LLC
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Set defaults and allow overriding via conf file
VERSION=7.10.2
FLAVOR="-oss"
DOCKERHUB="securityonionsolutionstest"
[ $# -eq 1 ] && [ -f $1 ] && source $1

echo
echo "This script will build all Docker images for Security Onion using the following settings:"
echo "Elastic stack version: ${VERSION}"
echo "Docker hub: ${DOCKERHUB}"
echo "Flavor: ${FLAVOR}"
echo
echo "Press Enter to continue or Ctrl-c to cancel."
read PAUSE
echo

# Create backup copy of Dockerfiles that we're about to edit
cp so-elasticsearch/Dockerfile 	so-elasticsearch/Dockerfile.bak
cp so-logstash/Dockerfile 	so-logstash/Dockerfile.bak
cp so-kibana/Dockerfile 	so-kibana/Dockerfile.bak

# Update FLAVOR in Dockerfiles
sed -i "s|ELASTICSEARCHFLAVOR|elasticsearch${FLAVOR}|g" so-elasticsearch/Dockerfile
sed -i "s|LOGSTASHFLAVOR|logstash${FLAVOR}|g" 		so-logstash/Dockerfile
sed -i "s|KIBANAFLAVOR|kibana${FLAVOR}|g" 		so-kibana/Dockerfile

# Update VERSION in Dockerfiles
sed -i "s|X.Y.Z|${VERSION}|g" so-elasticsearch/Dockerfile so-logstash/Dockerfile so-kibana/Dockerfile

# Our current Dockerfiles pull FROM Elastic's Docker images.
# However, Elastic currently does not sign their Docker images.
# https://github.com/elastic/elasticsearch-docker/issues/158
export DOCKER_CONTENT_TRUST=0

# Build Elasticsearch, Logstash, and Kibana
docker build -t ${DOCKERHUB}/so-elasticsearch 	so-elasticsearch/ 
docker build -t ${DOCKERHUB}/so-logstash 	so-logstash/
docker build -t ${DOCKERHUB}/so-kibana 		so-kibana/

# If building -oss, then build Curator, ElastAlert, DomainStats, and FreqServer
# Otherwise, no need to build those last 4 Docker images as we've already built them in the -oss run and will just tag them with new names
if [ "${FLAVOR}" == "-oss" ]; then

	docker build -t ${DOCKERHUB}/so-curator 	so-curator/
	docker build -t ${DOCKERHUB}/so-elastalert 	so-elastalert/
	docker build -t ${DOCKERHUB}/so-domainstats 	so-domainstats/
	docker build -t ${DOCKERHUB}/so-freqserver 	so-freqserver/
fi

# Clean up for next run
mv so-elasticsearch/Dockerfile.bak 	so-elasticsearch/Dockerfile
mv so-logstash/Dockerfile.bak 		so-logstash/Dockerfile
mv so-kibana/Dockerfile.bak 		so-kibana/Dockerfile

# Display the resulting images
echo
docker images
