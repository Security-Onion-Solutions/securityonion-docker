#!/bin/bash

echo "Stopping the current running Bro..."
sudo broctl stop

echo
echo "Disabling original Bro..."
sudo sed -i 's|BRO_ENABLED=yes|BRO_ENABLED=no|g' /etc/nsm/securityonion.conf

echo
echo "Creating the bro group..."
groupadd --gid 937 bro \

echo
echo "Creating the bro user..."
useradd --uid 937 --gid 937 --home-dir /opt/bro --no-create-home bro

echo
echo "Setting permissions on /nsm/bro/logs/ and /nsm/bro/spool to bro:bro..."
chown -R bro:bro /nsm/bro/logs
chown -R bro:bro /nsm/bro/spool

echo
echo "Backing up /opt/bro/share/bro/securityonion/add-interface-to-logs.bro to /opt/bro/share/bro/securityonion/add-interface-to-logs.bro.orig..."
sudo cp -av /opt/bro/share/bro/securityonion/add-interface-to-logs.bro /opt/bro/share/bro/securityonion/add-interface-to-logs.bro.orig

echo
echo "Backing up /opt/bro/share/bro/securityonion/sensortab.bro to /opt/bro/share/bro/securityonion/sensortab.bro..."
sudo cp -av /opt/bro/share/bro/securityonion/sensortab.bro /opt/bro/share/bro/securityonion/sensortab.bro.orig

echo
echo "Copying /opt/bro/etc/node.cfg to /opt/bro/etc/afpnode.cfg..."
sudo cp -av /opt/bro/etc/node.cfg /opt/bro/etc/afpnode.cfg

echo
echo "Downloading Bro container..."
sudo docker pull --disable-content-trust=false toosmooth/so-bro:test1
