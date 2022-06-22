# select build image
FROM rust:alpine as build

# install gcc related stuff
RUN apk add --no-cache build-base protoc

# create a new empty shell project
RUN \
    USER=root cargo new --bin app && \
    echo 'dotenv="*"' >> /app/Cargo.toml
WORKDIR /app

# this build step will cache your crates.io cache
RUN cargo build --release

# copy over your manifests
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock

# this build step will cache your dependencies
RUN cargo build --release
RUN rm src/*.rs

# copy your source tree
COPY ./templates ./templates
COPY ./assets ./assets
COPY ./src ./src

# build for release
RUN rm ./target/release/deps/ifconfig*
RUN cargo build --release

# our final base
FROM alpine

# copy the build artifact from the build stage
COPY --from=build /app/target/release/ifconfig /app/ifconfig

# add user for rootless + curl for healthcheck
RUN \
    addgroup -S ifconfig && \
    adduser -S ifconfig ifconfig && \
    apk add --no-cache dumb-init curl

# user to use to run software
USER ifconfig

# port to connect to
EXPOSE 3000
ENV LISTEN_ADDR=0.0.0.0:3000 \
    HOSTNAME=localhost \
    RUST_LOG=info \
    DB_FILE=

# healthcheck command
HEALTHCHECK --interval=10s --timeout=5s \
    CMD /usr/bin/curl --fail --silent --show-error http://localhost:${LISTEN_ADDR} || exit 1

# configures the startup!
ENTRYPOINT [ "/usr/bin/dumb-init", "--" ]

# set the startup command to run your binary
CMD [ "/app/ifconfig" ]
