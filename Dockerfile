FROM ubuntu:22.04

# set non-interactive shell
ENV DEBIAN_FRONTEND noninteractive

# Args
ARG CMAKE_BUILD_TYPE="Release"

# Set working directory
WORKDIR /opt/tx-processor

# Copy source
COPY . .

# configure
RUN bash scripts/configure.sh

# Update submodules
RUN git submodule init && git submodule update

# Build binaries
RUN mkdir build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE} .. && \
    make -j$(nproc)
