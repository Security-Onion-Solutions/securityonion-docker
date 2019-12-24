#!/bin/bash
#
# Copyright 2014,2015,2016,2017,2018,2019,2020 Security Onion Solutions, LLC
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

DOCKERHUB="securityonionsolutionstest"
[ $# -eq 1 ] && DOCKERHUB=$1

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
