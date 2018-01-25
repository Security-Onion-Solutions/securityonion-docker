FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="Netsniff-ng 0.6.4"
LABEL description="Netsniff-ng 0.6.4 running in a docker for use with Security Onion"

RUN yum update -y && yum install cron &&\
    yum clean all

# Copy over the Netsniff package
ADD https://github.com/Security-Onion-Solutions/securityonion-docker/releases/download/netsniff-ng_0.6.4.0/securityonion-netsniff-ng-0.6.4.0-securityonion.rpm /tmp/securityonion-netsniff-ng-0.6.4.0-securityonion.rpm

# Install the Netsniff package
RUN rpm -i /tmp/securityonion-netsniff-ng-0.6.4.0-securityonion.rpm
RUN rm /tmp/securityonion*

VOLUME ["/nsm/sensor_data"]

# Create pcap user.
RUN groupadd --gid 938 pcap && \
    adduser --uid 938 --gid 938 \
    --home-dir /nsm/sensor_data --no-create-home pcap

ENTRYPOINT ["/bin/bash"]
