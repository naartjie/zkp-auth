use std::env;
use tokio::time::{sleep, Duration};
use uuid::Uuid;
use zkp_auth::auth_client::AuthClient;
use zkp_auth::{
    AuthenticationChallengeRequest, Committs, RegisterRequest, VerifyAuthenticationRequest,
};

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}

fn create_register_commits(secret: u32) -> Committs {
    // secret (aka password)
    let x: u32 = secret;

    let p: u64 = 23;
    // TODO
    let q: u64 = 11;
    let g: u64 = 4;
    let h: u64 = 9;

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

fn prove_authentication(password: u32, challenge: u32) -> u32 {
    // 𝑠 = (𝑘 − 𝑐 ⋅ 𝑥) mod 𝑞
    let k: i64 = 7;
    let q: i64 = 11;
    let c: i64 = challenge.into();
    let x: i64 = password.into();

    (k - c * x).rem_euclid(q).try_into().unwrap()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let username = &env::var("AUTH_USER").expect("please set $AUTH_USER env var");
    let password = env::var("AUTH_PASS")
        .expect("please set $AUTH_PASS env var")
        .parse::<u32>()
        .expect("password must be an integer");

    println!("USERNAME={username} PASSWORD={password}");

    let server: &str = &env::var("AUTH_SERVER").unwrap_or("localhost".to_string());
    let uri = format!("http://{server}:50051");
    println!("connecting to {uri}");
    let mut auth_service = AuthClient::connect(uri).await?;

    let request = tonic::Request::new(RegisterRequest {
        username: username.to_string(),
        committs: Some(create_register_commits(password)),
    });

    let response = auth_service.register(request).await?;
    let result = response.into_inner().result;

    if result {
        println!("registered successfully");

        let request_id = Uuid::new_v4();
        let request = tonic::Request::new(AuthenticationChallengeRequest {
            username: username.to_string(),
            authentication_request_id: request_id.to_string(),
        });
        let response = auth_service
            .create_authentication_challenge(request)
            .await?;
        let challenge = response.into_inner().challenge;

        println!("got challenge {challenge}");

        let request = tonic::Request::new(VerifyAuthenticationRequest {
            authentication_request_id: request_id.to_string(),
            username: username.to_string(),
            answer: prove_authentication(password, challenge),
        });

        let response = auth_service.verify_authentication(request).await?;
        let login_result = response.into_inner().result;

        if login_result {
            println!("login successful, sleeping...");
            sleep(Duration::new(u64::MAX, 1_000_000_000 - 1)).await;
        } else {
            println!("login failed");
        }

        Ok(())
    } else {
        println!("failed to register, does the username exist already?");
        Ok(())
    }
}
