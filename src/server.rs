use num_bigint::BigUint;
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

pub struct ZkpAuthService {
    // TODO: rename
    // username -> (y1, y2)
    db: Arc<Mutex<HashMap<String, crypto::NumTuple>>>,

    // TODO: better name?
    // TODO: challenges.set(^^) -> setTimeout(() => challenges.delete())
    // (username, challenge_c) -> (r1, r2)
    challenges: Arc<Mutex<HashMap<(String, BigUint), crypto::NumTuple>>>,
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
        let body = request.into_inner();
        let username = body.username;
        let (r1, r2) = body.auth_request.unwrap().into();
        let db = self.db.lock().unwrap();
        match db.get(&username) {
            Some(_) => {
                // TODO use random number
                // let mut rng = rand::thread_rng();
                // let _a = rng.gen_biguint(1000);
                let challenge_c = BigUint::from_u32(4).unwrap();
                let mut challenges = self.challenges.lock().unwrap();
                challenges.insert((username, challenge_c.clone()), (r1, r2));

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
            q: BigUint::from(11_u32),
        };

        let db = self.db.lock().unwrap();
        let challenges = self.challenges.lock().unwrap();

        let ys = db.get(&username);
        let rs = challenges.get(&(username.clone(), challenge_c.clone()));

        let result = match (ys, rs) {
            (Some((y1, y2)), Some((r1, r2))) => crypto::verify_authentication(
                consts,
                y1.clone(),
                y2.clone(),
                r1.clone(),
                r2.clone(),
                challenge_c,
                answer_s,
            ),
            _ => false,
        };

        Ok(Response::new(VerifyAuthenticationReply { result }))
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_service = ZkpAuthService {
        db: Arc::new(Mutex::new(HashMap::new())),
        challenges: Arc::new(Mutex::new(HashMap::new())),
    };

    let addr = "0.0.0.0:50051".parse().unwrap();
    println!("gRPC server listening on {}", addr);

    Server::builder()
        .add_service(AuthServer::new(auth_service))
        .serve(addr)
        .await?;

    Ok(())
}
