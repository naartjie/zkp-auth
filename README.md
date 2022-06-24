### Run it

To run both client and server

```sh
docker-compose up
# if you've made some changes, rebuild the images
docker-compose up --build
# cleanup afterwards
docker-compose down
```

### gRPC

The client / server use gRPC, via the [tonic](https://docs.rs/tonic/0.7.2/tonic/index.html) library. The protocol definition is in [`zkp-auth.proto`](./zkp-auth.proto).

### Client

Set the username and password using environment vars:

```sh
AUTH_USER=foo AUTH_PASS=7 cargo run --bin client
```

### Server

```sh
cargo run --bin server
```

### Next steps

- cryptographically secure random numbers
- timeout challenges
- use a real database to store usernames / commits
- experiment with a streaming gRPC API which would allow to not store the challenges, they'd be part of the stream state
