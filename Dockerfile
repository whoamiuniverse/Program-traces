FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    autopoint \
    build-essential \
    ca-certificates \
    cmake \
    git \
    libtool \
    pkg-config \
    python3 \
    zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src

RUN bash /src/scripts/build_deps_linux.sh --clean
RUN cmake -S /src -B /src/build -DCMAKE_BUILD_TYPE=Release
RUN cmake --build /src/build -j4

CMD ["/src/build/program_traces", "--help"]
