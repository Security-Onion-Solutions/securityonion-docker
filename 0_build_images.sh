#!/bin/bash
#
# Copyright 2014,2015,2016,2017,2018,2019 Security Onion Solutions, LLC
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
VERSION=6.6.0
FLAVOR="-oss"
DOCKERHUB="dougburks"
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
cp so-elasticsearch/Dockerfile so-elasticsearch/Dockerfile.bak
cp so-logstash/Dockerfile so-logstash/Dockerfile.bak
cp so-kibana/Dockerfile so-kibana/Dockerfile.bak

# Update FLAVOR in Dockerfiles
sed -i "s|ELASTICSEARCHFLAVOR|elasticsearch${FLAVOR}|g" so-elasticsearch/Dockerfile
sed -i "s|LOGSTASHFLAVOR|logstash${FLAVOR}|g" so-logstash/Dockerfile
sed -i "s|KIBANAFLAVOR|kibana${FLAVOR}|g" so-kibana/Dockerfile

# Update VERSION in Dockerfiles and Kibana plugin
sed -i "s|X.Y.Z|${VERSION}|g" so-elasticsearch/Dockerfile so-logstash/Dockerfile so-kibana/Dockerfile so-kibana/bin/kibana/securityonion_links/package.json

# Now that we've updated the VERSION, build a zip file for the new Kibana plugin
cd so-kibana/bin
zip -r so-kibana-plugin.zip kibana
cd - >/dev/null

# Build the Elastic Stack Docker images
docker build -t ${DOCKERHUB}/so-elasticsearch so-elasticsearch/ &&
docker build -t ${DOCKERHUB}/so-logstash so-logstash/ && 
docker build -t ${DOCKERHUB}/so-kibana so-kibana/

# Build the remaining Docker images
if [ "${FLAVOR}" = "-oss" ]; then
	docker build -t ${DOCKERHUB}/so-curator so-curator/ && 
	docker build -t ${DOCKERHUB}/so-elastalert so-elastalert/ && 
	docker build -t ${DOCKERHUB}/so-domainstats so-domainstats/ && 
	docker build -t ${DOCKERHUB}/so-freqserver so-freqserver/
fi

# Clean up for next run
rm -f so-kibana/bin/so-kibana-plugin.zip
sed -i "s|${VERSION}|X.Y.Z|g" so-kibana/bin/kibana/securityonion_links/package.json
mv so-elasticsearch/Dockerfile.bak so-elasticsearch/Dockerfile
mv so-logstash/Dockerfile.bak so-logstash/Dockerfile
mv so-kibana/Dockerfile.bak so-kibana/Dockerfile

# Display the resulting images
echo
docker images
