# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS build
ARG BUILDKIT_SYNTAX
ARG MILK_BUILDKIT_IMAGE_REFERENCE
ARG MILK_SOURCE_COMMIT
ARG MILK_SOURCE_CONTEXT_SHA256
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY LICENSE ./
COPY crates/dragontales-gateway ./crates/dragontales-gateway
COPY deploy/licenses/bundle-rust.sh ./deploy/licenses/bundle-rust.sh
RUN cargo build --locked --release --package dragontales-gateway --jobs 4 && \
    /bin/sh deploy/licenses/bundle-rust.sh /src/THIRD_PARTY_LICENSES.txt

FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:d0046044cd28948d3380eb0d98709dc7e63f98161fe7105135e1025650bad17a
COPY --from=build --chmod=0555 /src/target/release/dragontales-gateway /usr/local/bin/dragontales-gateway
COPY --from=build --chmod=0444 /src/LICENSE /src/THIRD_PARTY_LICENSES.txt /usr/share/licenses/dragontales/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/dragontales-gateway"]
CMD ["serve"]
