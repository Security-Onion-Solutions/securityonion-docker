FROM docker.elastic.co/logstash/logstash-oss:6.6.1

USER 931

# Install plugins
RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-translate
RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-tld
RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-elasticsearch
RUN cd /usr/share/logstash && LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-rest
