#!/bin/bash

echo
echo "Creating new SO Config Location..."
mkdir /opt/so

echo
echo "Creating the socore group..."
groupadd --gid 939 socore \

echo
echo "Creating the socore user..."
useradd --uid 939 --gid 939 --home-dir /opt/so --no-create-home socore

echo
echo "Assigning correct permissions..."
chown 939:939 /opt/so
