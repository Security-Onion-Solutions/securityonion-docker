FROM docker.elastic.co/logstash/LOGSTASHFLAVOR:X.Y.Z

USER 931

# Install plugins
RUN cd /usr/share/logstash \
	&& LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-translate  	\
	&& LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-tld 		\
	&& LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-elasticsearch 	\
	&& LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-rest 		\
	&& LOGSTASH_PACK_URL=https://artifacts.elastic.co/downloads/logstash-plugins logstash-plugin install logstash-filter-prune		\
	&& rm -rf /tmp/bundler
