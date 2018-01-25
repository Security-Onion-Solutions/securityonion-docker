#!/bin/bash

sudo docker stop so-bro
sudo cp /opt/bro/share/bro/securityonion/add-interface-to-logs.bro.orig /opt/bro/share/bro/securityonion/add-interface-to-logs.bro
sudo sed -i 's|BRO_ENABLED=no|BRO_ENABLED=yes|g' /etc/nsm/securityonion.conf
sudo chown -R sguil:sguil /nsm/bro/logs
sudo chown -R sguil:sguil /nsm/bro/spool
sudo broctl deploy
