# Use the official Rocky Linux 8 image as the base image
FROM rockylinux:8

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# Install necessary dependencies
RUN yum -y update && \
    yum -y install \
    wget \
    ca-certificates \
    gcc \
    gcc-c++ \
    make \
    cmake \
    perl \
    perl-IPC-Cmd

# Install Rust using rustup
RUN url="https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init" && \
    wget "$url" && \
    chmod +x rustup-init && \
    ./rustup-init -y --no-modify-path --default-toolchain beta --default-host x86_64-unknown-linux-gnu && \
    rm rustup-init && \
    chmod -R a+w $RUSTUP_HOME $CARGO_HOME

# Verify Rust installation
RUN rustup --version && \
    cargo --version && \
    rustc --version

# Set the working directory
RUN mkdir -p /opt
WORKDIR /opt

# Copy the project files to the container
COPY . .

# Build the project
RUN cargo build -p netgauze-collector --profile=release

# Copy the binary to a known location
RUN mkdir -p /opt/bin && cp /opt/target/release/netgauze-collector /opt/bin/

# Set the entrypoint to run the application
ENTRYPOINT ["/opt/bin/netgauze-collector", "crates/collector/config_vmware_full.yaml"]