FROM node:24-alpine AS web
WORKDIR /src
COPY web/package.json web/package-lock.json ./web/
RUN cd web && npm ci
COPY . .
RUN cd web && npm run build && cp -rf dist /src/dist

FROM rust:1.88-alpine AS build
ARG TARGET=x86_64-unknown-linux-musl
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static ca-certificates perl make g++ zlib-dev zlib-static protobuf-dev protoc cmake clang lld pkgconf file
RUN rustup target add ${TARGET}
WORKDIR /src
COPY --from=web /src /src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/target \
    cargo build --release --target ${TARGET} --target-dir /target --features full --bin pingap-waf \
    && cp /target/${TARGET}/release/pingap-waf /src/pingap-waf \
    && file /src/pingap-waf \
    && (file /src/pingap-waf | grep -qE 'statically linked|static-pie linked' || ldd /src/pingap-waf 2>&1 | grep -q 'not a dynamic executable')

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/pingap-waf /usr/local/bin/pingap-waf
COPY --from=web /src/dist /opt/pingap/dist
VOLUME ["/var/lib/pingap", "/opt/pingap/conf"]
EXPOSE 80 443
ENTRYPOINT ["/usr/local/bin/pingap-waf"]
