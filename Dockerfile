FROM ubuntu:lastest

RUN apt-get update && \
    apt-get install -y \
    zip \
    unzip \
    python3 \
    python3-pyx \
    python3-matplotlib \
    tcpdump \
    python3-crypto \
    graphviz \
    imagemagick \
    gnuplot \
    python-gnuplot \
    libpcap-dev && apt-get clean
    apt-get -qq -y install \
    bridge-utils \
    net-tools \
    iptables \
    tcpdump \
    build-essential \
    python3-dev \
    libnetfilter-queue-dev \
    python3-pip

RUN python3 -m pip install scapy==2.4.2
RUN python3 -m pip install netfilterqueue


ADD . /dnsdeciver
WORKDIR /dnsdeciver
CMD ["python3", "dnsdeciver.py"]

