### gRPC

The client / server use gRPC, via the [tonic](https://docs.rs/tonic/0.7.2/tonic/index.html) library.

### Client

Username and password are set to default values in [`Dockerfile.client`](./Dockerfile.client) but set them to your own values:

```sh
AUTH_USER=foo AUTH_PASS=bar cargo run --bin client
# or using docker
docker run -e AUTH_USER=Mike -e AUTH_PASS=Snow -ti --rm zkp-auth.client
```

### Server

```sh
cargo run --bin server
# or
docker run -ti --rm zkp-auth.server
```
