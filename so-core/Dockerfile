FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="SO Core 0.0.1"
LABEL description="Security Onion Core Functions"

RUN yum update -y && yum -y install iproute tcpdump rsync &&\
    yum clean all

RUN mkdir -p /opt/socore/bin && mkdir /opt/socore/conf && mkdir /opt/socore/bro
COPY bin/* /opt/socore/bin/

# This is temp
COPY files/securityonion.conf /opt/socore/conf
COPY files/startso.sh /opt/socore/
COPY bro /opt/socore/bro
RUN chmod +x /opt/socore/bin/*

VOLUME ["/opt/so"]

# Create socore user.
RUN groupadd --gid 939 socore && \
    adduser --uid 939 --gid 939 \
    --home-dir /opt/so --no-create-home socore

ENTRYPOINT ["/opt/socore/startso.sh"]
