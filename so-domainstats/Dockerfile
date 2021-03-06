FROM centos:7

# Originally developed by Justin Henderson justin@hasecuritysolutions.com
LABEL maintainer "Security Onion Solutions, LLC"

# Create a common centos update layer
RUN yum update -y && \
    yum clean all

# Create a common python/git layer
RUN yum update -y && \
    yum install -y python python-six git && \
    yum clean all

# Create user
RUN groupadd --gid 936 domainstats && \
    adduser --uid 936 --gid 936 \
      --home-dir /usr/share/domainstats --no-create-home \
      domainstats

# Install and set perms in same layer to save space
RUN curl https://bootstrap.pypa.io/2.7/get-pip.py -o get-pip.py && \
	python get-pip.py && \
	cd /opt && \
	git clone -b domain_stats_1 https://github.com/MarkBaggett/domain_stats.git && \
	pip install python-whois && \
	mkdir /var/log/domain_stats && \
	ln -sf /dev/stderr /var/log/domain_stats/domain_stats.log && \
	chown -R domainstats: /opt/domain_stats

USER domainstats

EXPOSE 20000

STOPSIGNAL SIGTERM

CMD /usr/bin/python /opt/domain_stats/domain_stats.py -ip 0.0.0.0 20000 -a /opt/domain_stats/top-1m.csv --preload 0
