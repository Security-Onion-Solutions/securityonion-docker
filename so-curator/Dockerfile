FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"

RUN yum update -y && \
    yum clean all

RUN curl --silent --show-error --retry 5 https://bootstrap.pypa.io/get-pip.py | python

RUN pip install elasticsearch-curator
#RUN useradd -ms /bin/bash curator
RUN groupadd --gid 934 curator && \
    adduser --uid 934 --gid 934 \
      --home-dir /usr/share/curator --no-create-home \
      curator
RUN chown -R curator: /usr/bin/curator*
USER curator

ENTRYPOINT ["/bin/bash"]
