use num_bigint::{BigUint, RandBigInt};
use num_traits::FromPrimitive;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tonic::{transport::Server, Request, Response, Status};
use zkp_auth::crypto;
use zkp_auth::proto::auth_server::{Auth, AuthServer};
use zkp_auth::proto::{
    AuthenticationChallengeReply, AuthenticationChallengeRequest, RegisterReply, RegisterRequest,
    VerifyAuthenticationReply, VerifyAuthenticationRequest,
};

struct UserData {
    pub y1y2: crypto::NumTuple,
    pub r1r2: Option<crypto::NumTuple>,
    pub challenge: Option<BigUint>,
}

pub struct ZkpAuthService {
    // TODO: rename
    // username -> (y1, y2)
    db: Arc<Mutex<HashMap<String, crypto::NumTuple>>>,
    // TODO: better name?
    // (username, challenge_c) -> (r1, r2)
    // challenge_c -> username, (r1, r2)
    // challenges: Arc<Mutex<HashMap<String, crypto::NumTuple>>>,
    // challenges.set(^^) -> setTimeout(() => challenges.delete())
    // username -> challenge_c, (r1, r2)
    // challenges.get((username, challenge_c)) => Option<(r1, r2)>
}

#[tonic::async_trait]
impl Auth for ZkpAuthService {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterReply>, Status> {
        let args = request.into_inner();
        let username = args.username;

        let (y1, y2): (BigUint, BigUint) = args.commits.unwrap().into();
        println!("register({username})");

        let mut db = self.db.lock().unwrap();
        let result = if db.contains_key(&username) {
            println!("can't register username '{username}', it exists already");
            false
        } else {
            db.insert(username, (y1, y2));
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
            Some(commits) => {
                println!("got (y1, y2) commits for {username} {:?}", commits);

                let mut rng = rand::thread_rng();
                let _a = rng.gen_biguint(1000);

                // TODO use random number
                let challenge_c = BigUint::from_u32(4).unwrap();
                let reply = AuthenticationChallengeReply {
                    challenge_c: challenge_c.to_bytes_be(),
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
        let username = data.username;
        let challenge_c: BigUint = BigUint::from_bytes_be(&data.challenge_c);
        let answer_s = BigUint::from_bytes_be(&data.answer_s);

        // TODO
        let consts = crypto::Consts {
            g: BigUint::from(4_u32),
            h: BigUint::from(9_u32),
            p: BigUint::from(23_u32),
        };

        // TODO lookup from hashmap
        let r1: BigUint = 8_u32.into();
        let r2 = BigUint::from(4_u32);

        let db = self.db.lock().unwrap();
        let commits = db.get(&username);

        let result = match commits {
            Some((y1, y2)) => crypto::verify_authentication(
                consts,
                y1.clone(),
                y2.clone(),
                r1,
                r2,
                challenge_c,
                answer_s,
            ),
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
