#!/bin/bash

echo
echo "Syncing base files with the host OS"
rsync -a /opt/socore/ /opt/so

echo
echo "Running Security Onion"
/bin/bash
