# This Dockerfile was based on the official Logstash Docker image:
# https://github.com/elastic/logstash-docker

FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"

# Install Java and the "which" command, which is needed by Logstash's shell
# scripts.
RUN yum update -y && \
    yum install -y java-1.8.0-openjdk-devel which && \
    yum clean all

# Provide a non-root user to run the process.
RUN groupadd --gid 931 logstash && \
    adduser --uid 931 --gid 931 \
      --home-dir /usr/share/logstash --no-create-home \
      logstash

# Add Logstash itself.
RUN curl -Lo - https://artifacts.elastic.co/downloads/logstash/logstash-X.Y.Z.tar.gz | \
    tar zxf - -C /usr/share && \
    mv /usr/share/logstash-X.Y.Z /usr/share/logstash && \
    chown --recursive logstash:logstash /usr/share/logstash/ && \
    ln -s /usr/share/logstash /opt/logstash
ENV PATH=/usr/share/logstash/bin:$PATH

# Provide a minimal configuration, so that simple invocations will provide
# a good experience.
ADD config/logstash.yml config/log4j2.properties /usr/share/logstash/config/
ADD pipeline/default.conf /usr/share/logstash/pipeline/logstash.conf
RUN chown --recursive logstash:logstash /usr/share/logstash/config/ /usr/share/logstash/pipeline/

# Ensure Logstash gets a UTF-8 locale by default.
ENV LANG='en_US.UTF-8' LC_ALL='en_US.UTF-8'

# Place the startup wrapper script.
ADD bin/docker-entrypoint /usr/local/bin/
RUN chmod 0755 /usr/local/bin/docker-entrypoint

USER logstash

# RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install x-pack
RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-translate
RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-tld
RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-elasticsearch
RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-rest

# ADD env2yaml/env2yaml /usr/local/bin/

EXPOSE 9600 5044

ENTRYPOINT ["/usr/local/bin/docker-entrypoint"]
