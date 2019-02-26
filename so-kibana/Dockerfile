FROM docker.elastic.co/kibana/KIBANAFLAVOR:X.Y.Z

USER 932

# Add our custom Security Onion links to Kibana
ADD bin/so-kibana-add-links /usr/local/bin/
ADD bin/so-kibana-plugin.zip /usr/local/bin/
RUN /usr/local/bin/so-kibana-add-links
