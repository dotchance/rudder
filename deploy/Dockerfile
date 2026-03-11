FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    libbpf-dev \
    linux-tools-generic \
    clang llvm \
    iproute2 tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /rudder
COPY requirements.txt .
RUN pip3 install --break-system-packages -r requirements.txt

COPY . .

CMD ["/bin/bash"]
