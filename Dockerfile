FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    libelf-dev \
    zlib1g-dev \
    gcc \
    gcc-aarch64-linux-gnu \
    gcc-x86-64-linux-gnu \
    make \
    iproute2 \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

CMD ["/bin/bash"]
