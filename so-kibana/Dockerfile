# This Dockerfile was based on the official Kibana Docker image:
# https://github.com/elastic/kibana-docker

FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"

EXPOSE 5601

# Add Reporting dependencies.
RUN yum update -y && \
    yum install -y fontconfig freetype && \
    yum clean all

WORKDIR /usr/share/kibana
RUN curl -Ls https://artifacts.elastic.co/downloads/kibana/KIBANAFLAVOR-X.Y.Z-linux-x86_64.tar.gz | tar --strip-components=1 -zxf - && \
    ln -s /usr/share/kibana /opt/kibana

ENV PATH=/usr/share/kibana/bin:$PATH

# Set some Kibana configuration defaults.
ADD config/kibana.yml /usr/share/kibana/config/

# Add the launcher/wrapper script. It knows how to interpret environment
# variables and translate them to Kibana CLI options.
ADD bin/kibana-docker /usr/local/bin/

# Add our custom Security Onion links to Kibana
ADD bin/so-kibana-add-links /usr/local/bin/
ADD bin/so-kibana-plugin.zip /usr/local/bin/
RUN /usr/local/bin/so-kibana-add-links

# Add a self-signed SSL certificate for use in examples.
ADD ssl/kibana.example.org.* /usr/share/kibana/config/

# Provide a non-root user to run the process.
RUN groupadd --gid 932 kibana && \
    useradd --uid 932 --gid 932 \
      --home-dir /usr/share/kibana --no-create-home \
      kibana

# Files are owned by 1000:1000 by default.
# This causes Kibana to fail on startup.
# Set ownership to kibana:kibana.
RUN chown --recursive kibana:kibana /usr/share/kibana/*

# Switch to limited user and run process.
USER kibana
CMD /usr/local/bin/kibana-docker
