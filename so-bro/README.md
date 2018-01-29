Bro 2.5.2 with AF_Packet Docker Container
NOTE: This will only work on boxes with the elastic features enabled.

Clone this git repo:
```
git clone https://github.com/Security-Onion-Solutions/securityonion-docker.git
```

Run `trybro.sh`:
```
sudo bash securityonion-docker/so-bro/trybro.sh
```

Then copy `add-interface-to-logs.bro` and `sensortab.bro` from this repo to `/opt/bro/share/bro/securityonion/`:
```
sudo cp securityonion-docker/so-bro/*.bro /opt/bro/share/bro/securityonion/add-interface-to-logs.bro
```

Modify `/opt/bro/etc/afpnode.cfg` to look similar to the following (replacing `eth1` with your actual sniffing interface). If you have `type=standalone`, comment out all 4 standalone lines and add the below with at least 2 lb_procs:
```
[manager]
type=manager
host=localhost

[proxy]
type=proxy
host=localhost

[sotest-eth1]
type=worker
host=localhost
interface=af_packet::eth1
lb_method=custom
lb_procs=2
af_packet_fanout_id=23
af_packet_fanout_mode=AF_Packet::FANOUT_HASH
af_packet_buffer_size=128*1024*1024
```

Then run the following:
```
sudo docker run --privileged=true -v /nsm/bro/logs:/nsm/bro/logs -v /nsm/bro/spool:/nsm/bro/spool -v /opt/bro/etc:/opt/bro/etc -v /opt/bro/etc/afpnode.cfg:/opt/bro/etc/node.cfg -v /opt/bro/share/bro:/opt/bro/share/bro -v /etc/nsm:/etc/nsm --net=host --name=so-bro -t -d toosmooth/so-bro:test1
```

To revert back to the original Bro config:
```
sudo bash securityonion-docker/so-bro/revert.sh
```
