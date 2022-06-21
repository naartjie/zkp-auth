use tonic::{transport::Server, Request, Response, Status};

use zkp_auth::auth_server::{Auth, AuthServer};
use zkp_auth::{RegisterReply, RegisterRequest};

pub mod zkp_auth {
    tonic::include_proto!("zkp_auth");
}
#[derive(Default)]
pub struct ZkpAuthService {}

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

        let reply = zkp_auth::RegisterReply { result: true };
        Ok(Response::new(reply))
    }

    // fn create_authentication_challenge(
    //     user: User,
    //     auth_request: AuthenticationRequest,
    // ) -> Challenge {
    //     let ch = Challenge {};
    //     ch
    // }

    // fn verify_authentication(user: User, answer: Answer) -> bool {
    //     false
    // }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse().unwrap();
    let auth_service = ZkpAuthService::default();

    println!("gRPC server listening on {}", addr);

    Server::builder()
        .add_service(AuthServer::new(auth_service))
        .serve(addr)
        .await?;

    Ok(())
}
