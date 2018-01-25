FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="Bro 2.5.2"
LABEL description="Bro 2.5.2 running in a docker for use with Security Onion."

RUN yum update -y && \
    yum clean all

# Install epel
RUN yum -y install epel-release bash libpcap iproute jemalloc numactl libnl3 libdnet gdb GeoIP && \
    yum clean all

# Install the Bro package
RUN rpm -i https://github.com/Security-Onion-Solutions/securityonion-docker-rpm/releases/download/Bro_2.5.2/securityonion-bro-2.5.2.1-securityonion.rpm

# Replace local.bro with the SO one (This will need reworked)
#COPY files/local.bro /opt/bro/share/bro/site/local.bro

# Replace node.cfg with the SO one (This will need reworked)
#COPY files/node.cfg /opt/bro/etc/node.cfg

#RUN mkdir /opt/bro/share/bro/securityonion
#COPY policy/ /opt/bro/share/bro/

VOLUME ["/nsm/bro/logs", "/nsm/bro/spool", "/opt/bro/share/bro", "/opt/bro/etc/"]

# Create Bro User.
RUN groupadd --gid 937 bro && \
    adduser --uid 937 --gid 937 \
    --home-dir /opt/bro --no-create-home bro

# Fix those perms.. big worm
RUN chown -R 937:937 /opt/bro && \
    chown -R 937:937 /nsm/bro

# Copy over the entry script.
COPY files/bro.sh /usr/local/sbin/bro.sh
RUN chmod +x /usr/local/sbin/bro.sh

ENTRYPOINT ["/usr/local/sbin/bro.sh"]
