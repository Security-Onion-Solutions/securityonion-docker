FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="SO Core 0.0.1"
LABEL description="Security Onion Core Functions"

RUN yum update -y && yum install cron iproute tcpdump python &&\
    yum clean all


VOLUME ["/nsm/sensor_data"]

# Create socore user.
RUN groupadd --gid 938 pcap && \
    adduser --uid 938 --gid 938 \
    --home-dir /nsm/sensor_data --no-create-home pcap

ENTRYPOINT ["/bin/bash"]
