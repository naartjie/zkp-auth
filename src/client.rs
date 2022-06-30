use num_bigint::BigUint;
use num_traits::FromPrimitive;
use std::env;
use tokio::time::{sleep, Duration};
use zkp_auth::proto::auth_client::AuthClient;
use zkp_auth::proto::{
    AuthenticationChallengeRequest, RegisterRequest, VerifyAuthenticationRequest,
};

use zkp_auth::crypto;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let username = &env::var("AUTH_USER").expect("please set $AUTH_USER env var");
    let password = env::var("AUTH_PASS").expect("please set $AUTH_PASS env var");
    let password = &BigUint::parse_bytes(password.as_bytes(), 10)
        .expect("$AUTH_PASS must be a (large) integer");

    println!("client starting: USERNAME={username} PASSWORD={password}");

    let server: &str = &env::var("AUTH_SERVER").unwrap_or("localhost".to_string());
    let uri = format!("http://{server}:50051");
    println!("connecting to {uri}");
    let mut auth_service = AuthClient::connect(uri).await?;

    // TODO
    let consts = crypto::Consts {
        g: BigUint::from_u32(4).unwrap(),
        h: BigUint::from_u32(9).unwrap(),
        p: BigUint::from_u32(23).unwrap(),
    };

    let request = tonic::Request::new(RegisterRequest {
        username: username.to_string(),
        committs: Some(crypto::create_register_commits(consts, password.clone()).into()),
    });

    let response = auth_service.register(request).await?;
    let result = response.into_inner().result;

    if !result {
        println!("failed to register, does the username exist already?");
    } else {
        println!("registered successfully");

        let r1 = BigUint::from(8_u32);
        let r2 = BigUint::from(4_u32);

        let request = tonic::Request::new(AuthenticationChallengeRequest {
            username: username.to_string(),
            auth_request: Some((r1, r2).into()),
        });
        let response = auth_service
            .create_authentication_challenge(request)
            .await?;

        let challenge_c = &BigUint::from_bytes_be(&response.into_inner().challenge_c);
        println!("got challenge {challenge_c}");

        let k: BigUint = 4_u32.into();
        let q: BigUint = 11_u32.into();
        let request = tonic::Request::new(VerifyAuthenticationRequest {
            username: username.to_string(),
            challenge_c: BigUint::to_bytes_be(challenge_c),
            answer_s: crypto::prove_authentication(k, q, password.clone(), challenge_c.clone())
                .to_bytes_be(),
        });

        let response = auth_service.verify_authentication(request).await?;
        let login_result = response.into_inner().result;

        if login_result {
            println!("login successful, sleeping...");
            sleep(Duration::new(u64::MAX, 1_000_000_000 - 1)).await;
        } else {
            println!("login failed");
        }
    }

    Ok(())
}
