use std::env;
use zkp_auth::auth_client::AuthClient;
use zkp_auth::auth_server::Auth;
use zkp_auth::{Committs, RegisterRequest};

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

pub struct AuthenticationRequest {
    todo: bool,
}
pub struct Challenge {
    todo: bool,
}

pub struct Answer {
    todo: bool,
}

fn create_register_commits() -> Committs {
    let p: u64 = 23;
    let q: u64 = 11;
    let g: u64 = 4;
    let h: u64 = 9;

    // secret (aka password)
    let x: u32 = 6;

    // publish
    // 𝑦1 = 𝑔𝑥 mod 𝑝 = 46 mod 23 = 2
    // 𝑦2 = ℎ𝑥 mod 𝑝 = 96 mod 23 = 3
    let y1 = g.pow(x).rem_euclid(p);
    let y2 = h.pow(x).rem_euclid(p);

    // pick a random k
    let k: u32 = 7;

    // 𝑟1 = 𝑔𝑘 mod 𝑝
    // 𝑟2 = ℎ𝑘 mod 𝑝
    let r1: u64 = g.pow(k).rem_euclid(p);
    let r2: u64 = h.pow(k).rem_euclid(p);

    Committs {
        r1,
        r2,
        y1,
        y2,
        g,
        h,
    }
}

fn create_authentication_request() -> AuthenticationRequest {
    AuthenticationRequest { todo: true }
}

fn prove_authentication(challenge: Challenge) -> Answer {
    Answer { todo: true }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let username = env::var("AUTH_USER").expect("please set $AUTH_USER env var");
    let password = env::var("AUTH_PASS").expect("please set $AUTH_PASS env var");
    println!("USERNAME={username} PASSWORD={password}");

    let mut auth_service = AuthClient::connect("http://[::1]:50051").await?;

    let request = tonic::Request::new(RegisterRequest {
        username: username,
        committs: Some(create_register_commits()),
    });

    let response = auth_service.register(request).await?;
    let result = response.into_inner().result;
    println!("auth service register() -> {result}");

    Ok(())
}
