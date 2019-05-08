FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"

# Create a common centos update layer
RUN yum update -y && \
    yum clean all

# Create user
RUN groupadd --gid 934 curator && \
    adduser --uid 934 --gid 934 \
      --home-dir /usr/share/curator --no-create-home \
      curator

# Install and set perms in same layer to save space
RUN curl --silent --show-error --retry 5 https://bootstrap.pypa.io/get-pip.py | python && \
	pip install elasticsearch-curator && \
	chown -R curator: /usr/bin/curator*

USER curator

ENTRYPOINT ["/bin/bash"]
