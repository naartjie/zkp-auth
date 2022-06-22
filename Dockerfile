FROM rust:1.61.0-bullseye AS builder
RUN apt-get update && apt-get -y install cmake
WORKDIR /app
COPY . .

RUN cargo build --release

FROM gcr.io/distroless/cc
WORKDIR /app
COPY --from=builder /app/target/release/client ./
COPY --from=builder /app/target/release/server ./

CMD ["/app/server"]
# ENTRYPOINT [ "executable" ]
