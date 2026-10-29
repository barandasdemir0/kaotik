FROM gcr.io/oss-fuzz-base/base-builder-rust
RUN apt-get update && apt-get install -y --no-install-recommends zip && rm -rf /var/lib/apt/lists/*
COPY . $SRC/kaotik
WORKDIR $SRC/kaotik
COPY .clusterfuzzlite/build.sh $SRC/
