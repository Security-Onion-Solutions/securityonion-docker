FROM docker.elastic.co/logstash/LOGSTASHFLAVOR:X.Y.Z

USER 931

# Install plugins
RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-translate
RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-tld
RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-elasticsearch
RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-rest
