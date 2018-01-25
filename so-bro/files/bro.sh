#!/bin/bash

setcap cap_net_raw,cap_net_admin=eip /opt/bro/bin/bro
setcap cap_net_raw,cap_net_admin=eip /opt/bro/bin/capstats
runuser bro -c '/opt/bro/bin/broctl deploy'
/bin/bash
