# Use the official Rocky Linux 8 image as the base image
FROM rockylinux:8

# Install necessary dependencies
RUN yum -y update && \
    yum -y install \
    gcc \
    gcc-c++ \
    make \
    cmake \
    openssl-devel \
    pkgconfig \
    git \
    curl \
    file \
    which \
    tar \
    xz \
    perl \
    perl-IPC-Cmd

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set the working directory
WORKDIR /opt

# Copy the project files to the container
COPY . .

# Build the project
RUN cargo build --release

# Copy the binary to a known location
RUN mkdir -p /opt/bin && cp /opt/target/release/netgauze-collector /opt/bin/

# Set the entrypoint to run the application
ENTRYPOINT ["/opt/bin/netgauze-collector", "crates/collector/config_vmware_full.yaml"]