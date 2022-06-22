use rand::Rng;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tonic::{transport::Server, Request, Response, Status};
use zkp_auth::auth_server::{Auth, AuthServer};
use zkp_auth::{
    AuthenticationChallengeReply, AuthenticationChallengeRequest, Committs, RegisterReply,
    RegisterRequest, VerifyAuthenticationReply, VerifyAuthenticationRequest,
};

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}
pub struct ZkpAuthService {
    db: Arc<Mutex<HashMap<String, Committs>>>,
    // challenges: Arc<Mutex<HashMap<String, uint64>>>,
}

fn verify_authentication(committs: &Committs, challenge: u32, answer: u32) -> bool {
    let s: u32 = answer;
    let c: u32 = challenge;
    let Committs {
        r1,
        r2,
        y1,
        y2,
        g,
        h,
    } = committs;

    // TODO
    let p = 23;
    // 𝑟1 = 8 is the same as 𝑔𝑠 ⋅ 𝑦𝑐1 mod 𝑝 = 45 ⋅ 24 mod 23 = 8
    let r1_calc = (g.pow(s) * y1.pow(c)).rem_euclid(p);
    // 𝑟2 = 4 is the same as ℎ𝑠 ⋅ 𝑦𝑐2 mod 𝑝 = 95 ⋅ 34 mod 23 = 4
    let r2_calc = (h.pow(s) * y2.pow(c)).rem_euclid(p);

    *r1 == r1_calc && *r2 == r2_calc
}

#[tonic::async_trait]
impl Auth for ZkpAuthService {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterReply>, Status> {
        let args = request.into_inner();
        let username = args.username;
        let committs = args.committs.unwrap();
        println!(
            "register({username}) [r1:{} r2:{} y1:{} y2:{} g:{} h:{}]",
            committs.r1, committs.r2, committs.y1, committs.y2, committs.g, committs.h
        );

        let mut db = self.db.lock().unwrap();
        let result = if db.contains_key(&username) {
            println!("can't register username '{username}', it exists already");
            false
        } else {
            db.insert(username, committs);
            true
        };
        Ok(Response::new(zkp_auth::RegisterReply { result }))
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

                let _challenge: u32 = rand::thread_rng().gen();
                let challenge = 4;
                let reply = zkp_auth::AuthenticationChallengeReply { challenge };
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
        let answer = data.answer;
        let challenge = 4;
        let db = self.db.lock().unwrap();
        let committs = db.get(&username);

        let result = match committs {
            Some(committs) => verify_authentication(committs, challenge, answer),
            None => false,
        };

        Ok(Response::new(zkp_auth::VerifyAuthenticationReply {
            result,
        }))
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
