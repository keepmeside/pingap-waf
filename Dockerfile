FROM node:24-alpine AS web
WORKDIR /src
COPY web/package.json web/package-lock.json ./web/
RUN cd web && npm ci
COPY . .
RUN cd web && npm run build && cp -rf dist /src/dist

FROM rust:1.88-alpine AS build
ARG TARGET=x86_64-unknown-linux-musl
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static ca-certificates perl make g++ zlib-dev zlib-static protobuf-dev protoc cmake clang lld pkgconf
RUN rustup target add ${TARGET}
WORKDIR /src
COPY --from=web /src /src
RUN cargo build --release --target ${TARGET} --features full --bin pingap-waf \
    && file target/${TARGET}/release/pingap-waf \
    && ldd target/${TARGET}/release/pingap-waf 2>&1 | grep -q 'not a dynamic executable'

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/pingap-waf /usr/local/bin/pingap-waf
COPY --from=web /src/dist /opt/pingap/dist
VOLUME ["/var/lib/pingap", "/opt/pingap/conf"]
EXPOSE 80 443
ENTRYPOINT ["/usr/local/bin/pingap-waf"]
