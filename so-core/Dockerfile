FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="SO Core 0.0.1"
LABEL description="Security Onion Core Functions"

RUN yum update -y && yum install iproute tcpdump python &&\
    yum clean all


VOLUME ["/opt/so"]

# Create socore user.
RUN groupadd --gid 939 socore && \
    adduser --uid 939 --gid 939 \
    --home-dir /opt/so --no-create-home socore

ENTRYPOINT ["/bin/bash"]
