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
