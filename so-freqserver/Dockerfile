FROM centos:7

# Originally developed by Justin Henderson justin@hasecuritysolutions.com
LABEL maintainer "Security Onion Solutions, LLC"

RUN yum update -y && \
    yum install -y python git && \
    yum clean all
RUN cd /opt && git clone https://github.com/SMAPPER/freq_server
RUN mkdir /var/log/freq_server
RUN ln -sf /dev/stderr /var/log/freq_server/freq_server.log
#RUN useradd -ms /bin/bash freq_server
RUN groupadd --gid 935 freqserver && \
    adduser --uid 935 --gid 935 \
      --home-dir /usr/share/freqserver --no-create-home \
      freqserver
RUN chown -R freqserver: /opt/freq_server
USER freqserver

EXPOSE 10004

STOPSIGNAL SIGTERM

CMD /usr/bin/python /opt/freq_server/freq/freq_server.py -ip 0.0.0.0 10004 /opt/freq_server/freq/freq_table.freq
