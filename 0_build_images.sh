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

VERSION=6.6.0
DOCKERHUB="dougburks"

echo
echo "This script will build all Docker images for Security Onion."
echo
echo "It is currently set to build Elastic stack version ${VERSION}."
echo
echo "Press Enter to continue or Ctrl-c to cancel."
read PAUSE
echo

# Update VERSION for each component
sed -i "s|X.Y.Z|$VERSION|g" so-elasticsearch/Dockerfile so-logstash/Dockerfile so-kibana/Dockerfile so-kibana/bin/kibana/securityonion_links/package.json

# Now that we've updated the VERSION, build a zip file for the new Kibana plugin
cd so-kibana/bin
zip -r so-kibana-plugin.zip kibana
cd - >/dev/null

# Build the Docker images
docker build -t dougburks/so-elasticsearch so-elasticsearch/ &&
docker build -t dougburks/so-logstash so-logstash/ && 
docker build -t dougburks/so-kibana so-kibana/ && 
docker build -t dougburks/so-curator so-curator/ && 
docker build -t dougburks/so-elastalert so-elastalert/ && 
docker build -t dougburks/so-domainstats so-domainstats/ && 
docker build -t dougburks/so-freqserver so-freqserver/

# Clean up for next run
rm -f so-kibana/bin/so-kibana-plugin.zip
sed -i "s|$VERSION|X.Y.Z|g" so-elasticsearch/Dockerfile so-logstash/Dockerfile so-kibana/Dockerfile so-kibana/bin/kibana/securityonion_links/package.json

# Display the resulting images
echo
docker images
