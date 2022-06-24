use num_bigint::{BigUint, ToBigUint};
use std::env;
use tokio::time::{sleep, Duration};
use uuid::Uuid;
use zkp_auth::proto::auth_client::AuthClient;
use zkp_auth::proto::{
    AuthenticationChallengeRequest, RegisterRequest, VerifyAuthenticationRequest,
};
use zkp_auth::Committs;

fn create_register_commits(secret: &BigUint) -> Committs {
    // secret (aka password)
    let x: &BigUint = secret;

    let p = 23_u64.to_biguint().unwrap();
    // TODO: q is unused?
    // let q = 11_u64.to_biguint().unwrap();
    let g = 4_u64.to_biguint().unwrap();
    let h = 9_u64.to_biguint().unwrap();

    // publish
    // 𝑦1 = 𝑔𝑥 mod 𝑝 = 46 mod 23 = 2
    // 𝑦2 = ℎ𝑥 mod 𝑝 = 96 mod 23 = 3
    let y1 = g.modpow(x, &p);
    let y2 = h.modpow(x, &p);

    // TODO: pick a random number
    // let k = 7_u64.to_biguint().unwrap();

    // 𝑟1 = 𝑔𝑘 mod 𝑝
    // 𝑟2 = ℎ𝑘 mod 𝑝
    // let r1 = g.modpow(&k, &p);
    // let r2 = h.modpow(&k, &p);

    Committs { y1, y2 }
}

fn prove_authentication(password: &BigUint, challenge: &BigUint) -> BigUint {
    use num_traits::identities::One;

    // 𝑠 = (𝑘 − 𝑐 ⋅ 𝑥) mod 𝑞
    let k = &7_u64.to_biguint().unwrap();
    let q = &11_u64.to_biguint().unwrap();

    (k - challenge.modpow(password, q)).modpow(&BigUint::one(), q)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let username = &env::var("AUTH_USER").expect("please set $AUTH_USER env var");

    let password = env::var("AUTH_PASS").expect("please set $AUTH_PASS env var");
    let password = &BigUint::parse_bytes(password.as_bytes(), 10)
        .expect("$AUTH_PASS must be a (large) integer");

    println!("USERNAME={username} PASSWORD={password}");

    let server: &str = &env::var("AUTH_SERVER").unwrap_or("localhost".to_string());
    let uri = format!("http://{server}:50051");
    println!("connecting to {uri}");
    let mut auth_service = AuthClient::connect(uri).await?;

    let request = tonic::Request::new(RegisterRequest {
        username: username.to_string(),
        committs: Some(create_register_commits(password).into()),
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

        let challenge = &BigUint::from_bytes_be(&response.into_inner().challenge);
        println!("got challenge {challenge}");

        let request = tonic::Request::new(VerifyAuthenticationRequest {
            authentication_request_id: request_id.to_string(),
            username: username.to_string(),
            answer: prove_authentication(password, &challenge).to_bytes_be(),
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
