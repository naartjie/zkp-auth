use num_bigint::{BigUint, RandBigInt, ToBigUint};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tonic::{transport::Server, Request, Response, Status};
use zkp_auth::proto::auth_server::{Auth, AuthServer};
use zkp_auth::proto::{
    AuthenticationChallengeReply, AuthenticationChallengeRequest, RegisterReply, RegisterRequest,
    VerifyAuthenticationReply, VerifyAuthenticationRequest,
};
use zkp_auth::Committs;

mod lib;

pub struct ZkpAuthService {
    db: Arc<Mutex<HashMap<String, Committs>>>,
    // challenges: Arc<Mutex<HashMap<String, uint64>>>,
}

fn verify_authentication(
    committs: &Committs,
    r1: &BigUint,
    r2: &BigUint,
    challenge: &BigUint,
    answer: &BigUint,
) -> bool {
    let s = answer;
    let c = challenge;
    // let r1 = &BigUint::parse_bytes(&committs.r1, 10).unwrap();
    // let r2 = &BigUint::parse_bytes(&committs.r2, 10).unwrap();
    let y1 = &committs.y1;
    let y2 = &committs.y2;
    // let g = &BigUint::parse_bytes(&committs.g, 10).unwrap();
    // let h = &BigUint::parse_bytes(&committs.h, 10).unwrap();

    let g = 4_u64.to_biguint().unwrap();
    let h = 9_u64.to_biguint().unwrap();

    // TODO
    let p = &23_u64.to_biguint().unwrap();
    // 𝑟1 = 8 is the same as 𝑔𝑠 ⋅ 𝑦𝑐1 mod 𝑝 = 45 ⋅ 24 mod 23 = 8
    let r1_calc = g.modpow(s, p).modpow(&y1.modpow(c, p), p);
    // 𝑟2 = 4 is the same as ℎ𝑠 ⋅ 𝑦𝑐2 mod 𝑝 = 95 ⋅ 34 mod 23 = 4
    let r2_calc = h.modpow(s, p).modpow(&y2.modpow(c, p), p);

    r1.eq(&r1_calc) && r2.eq(&r2_calc)
}

#[tonic::async_trait]
impl Auth for ZkpAuthService {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterReply>, Status> {
        let args = request.into_inner();
        let username = args.username;

        let committs: Committs = args.committs.unwrap().into();
        println!("register({username})");

        let mut db = self.db.lock().unwrap();
        let result = if db.contains_key(&username) {
            println!("can't register username '{username}', it exists already");
            false
        } else {
            db.insert(username, committs);
            true
        };
        Ok(Response::new(RegisterReply { result }))
    }

    async fn create_authentication_challenge(
        &self,
        request: Request<AuthenticationChallengeRequest>,
    ) -> Result<Response<AuthenticationChallengeReply>, Status> {
        let username = request.into_inner().username;

        let db = self.db.lock().unwrap();

        match db.get(&username) {
            Some(committs) => {
                println!("got committs for {username} {:?}", committs);

                let mut rng = rand::thread_rng();
                let _a = rng.gen_biguint(1000);

                // TODO use random number
                let challenge = 4_u64.to_biguint().unwrap();
                let reply = AuthenticationChallengeReply {
                    challenge: challenge.to_bytes_be(),
                };
                Ok(Response::new(reply))
            }
            None => {
                println!("username doesn't exist");
                Err(Status::new(tonic::Code::NotFound, "username not found"))
            }
        }
    }

    async fn verify_authentication(
        &self,
        request: Request<VerifyAuthenticationRequest>,
    ) -> Result<Response<VerifyAuthenticationReply>, Status> {
        let data = request.into_inner();
        let _id = data.authentication_request_id;
        let username = data.username;
        let answer = &BigUint::from_bytes_be(&data.answer);
        // TODO lookup from hashmap
        let challenge = &4_u64.to_biguint().unwrap();
        let db = self.db.lock().unwrap();
        let committs = db.get(&username);

        let r1 = &0_u64.to_biguint().unwrap();
        let r2 = &0_u64.to_biguint().unwrap();

        let result = match committs {
            Some(committs) => verify_authentication(committs, r1, r2, challenge, answer),
            None => false,
        };

        Ok(Response::new(VerifyAuthenticationReply { result }))
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_service = ZkpAuthService {
        db: Arc::new(Mutex::new(HashMap::new())),
    };

    let addr = "0.0.0.0:50051".parse().unwrap();
    println!("gRPC server listening on {}", addr);

    Server::builder()
        .add_service(AuthServer::new(auth_service))
        .serve(addr)
        .await?;

    Ok(())
}
