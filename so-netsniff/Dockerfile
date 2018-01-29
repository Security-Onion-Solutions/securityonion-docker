FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="Netsniff-ng 0.6.4"
LABEL description="Netsniff-ng 0.6.4 running in a docker for use with Security Onion"

RUN yum update -y &&\
    yum clean all

# Install the Netsniff package
RUN rpm -i https://github.com/Security-Onion-Solutions/securityonion-docker-rpm/releases/download/netsniff-ng_0.6.4/securityonion-netsniff-ng-0.6.4.0-securityonion.rpm

VOLUME ["/nsm/sensor_data"]

# Create pcap user.
RUN groupadd --gid 938 pcap && \
    adduser --uid 938 --gid 938 \
    --home-dir /nsm/sensor_data --no-create-home pcap

ENTRYPOINT ["/bin/bash"]
