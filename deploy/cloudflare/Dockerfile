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
COPY crates/milk-carton/Cargo.toml ./crates/milk-carton/Cargo.toml
RUN mkdir -p crates/milk-carton/src && \
    printf 'fn main() {}\n' > crates/milk-carton/src/main.rs && \
    cargo build --locked --release --package milk-carton --jobs 4
COPY LICENSE ./
COPY crates/milk-carton/src ./crates/milk-carton/src
COPY deploy/licenses/bundle-rust.sh ./deploy/licenses/bundle-rust.sh
RUN cargo clean --release --package milk-carton && \
    cargo build --locked --release --package milk-carton --jobs 4 && \
    /bin/sh deploy/licenses/bundle-rust.sh /src/THIRD_PARTY_LICENSES.txt

FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:d0046044cd28948d3380eb0d98709dc7e63f98161fe7105135e1025650bad17a
COPY --from=build --chmod=0555 /src/target/release/milk-carton /usr/local/bin/milk-carton
COPY --from=build --chmod=0444 /src/LICENSE /src/THIRD_PARTY_LICENSES.txt /usr/share/licenses/milk-carton/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/milk-carton"]
CMD ["serve"]
