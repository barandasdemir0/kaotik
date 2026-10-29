FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN apt-get update && apt-get install -y --no-install-recommends zip && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 https://github.com/barandasdemir0/kaotik kaotik
WORKDIR $SRC/kaotik
COPY build.sh $SRC/
