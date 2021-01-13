use std::net::SocketAddr;
use std::sync::Arc;

use ethash::types::BlockHeader;
use ethash::{EthereumPatch, Patch};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Error, Request, Response, Server};
use parking_lot::RwLock;

mod service;
use service::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // init log adapter.
    env_logger::init();
    // the server should only be running locally.
    let port = std::env::var("SERVER_PORT")
        .unwrap_or_else(|_| String::from("3000"))
        .parse()
        .unwrap_or(3000); // fail-safe and silently.

    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let state = Arc::new(RwLock::new(State::default()));

    let make_service = make_service_fn(move |_| {
        let state = state.clone();
        async move { Ok::<_, Error>(service_fn(move |req| handle(req, state.clone()))) }
    });

    let server = Server::bind(&addr).serve(make_service);

    println!("Listening on http://{}", addr);
    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
    Ok(())
}

async fn handle(req: Request<Body>, state: ServerState) -> Result<Response<Body>, Error> {
    use hyper::Method;
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/proofs") => generate_proofs(req, state).await,
        _ => Ok(Response::builder().status(404).body(Body::empty()).unwrap()),
    }
}

#[derive(Debug, serde::Deserialize)]
struct ProofsPayload {
    rlp: String,
}

#[derive(Debug, PartialEq, Eq)]
enum CurrentState {
    Idle,
    GeneratingDag,
    GeneratingProofs,
}

#[derive(Debug, PartialEq, Eq)]
struct State {
    proof_service: ProofGeneratorService,
    current_state: CurrentState,
}

type ServerState = Arc<RwLock<State>>;

impl Default for State {
    fn default() -> Self {
        Self {
            proof_service: ProofGeneratorService::new(DagGeneratorService::new(0)),
            current_state: CurrentState::Idle,
        }
    }
}

// where the magic happens.
async fn generate_proofs(req: Request<Body>, state: ServerState) -> Result<Response<Body>, Error> {
    // get the request body bytes.
    let body = hyper::body::to_bytes(req).await?;
    let s = state.read();
    log::debug!("Current State: {:?}", s.current_state);
    // if we are currently generating dag for example.
    if s.current_state != CurrentState::Idle {
        // return that we are busy (423 Locked).
        return Ok(Response::builder().status(423).body(Body::empty()).unwrap());
    }
    // parse the json to `ProofsPayload`
    let payload: ProofsPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return Ok(Response::builder().status(400).body(Body::empty()).unwrap()),
    };

    // then decode the rlp hex to bytes.
    let header_bytes = match hex::decode(&payload.rlp) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(Response::builder().status(400).body(Body::empty()).unwrap()),
    };

    // good good, now try to decode the rlp itself to `BlockHeader`.
    let header: BlockHeader = match rlp::decode(&header_bytes) {
        Ok(header) => header,
        Err(_) => return Ok(Response::builder().status(400).body(Body::empty()).unwrap()),
    };

    // at this point we have an input to work with.
    // calculate the epoch from the block number.
    let epoch = header.number / EthereumPatch::epoch_length();

    let dag_loaded = s.proof_service.is_loaded();
    // done with this guard.
    // drop it then!
    drop(s);

    // if the DAG (cache and dataset) is not there yet.
    if !dag_loaded {
        // get our state.
        let mut s = state.write();
        // set it that we are currently generating the DAG.
        // so the next Http call returns immediately
        // without dublicating the work.
        s.current_state = CurrentState::GeneratingDag;
        drop(s);

        // clone the state to sent to the other task.
        let state = state.clone();
        std::thread::spawn(move || {
            let mut dag_service = service::DagGeneratorService::new(epoch.as_usize());
            // warm up
            // try to reload the dag from the disk;
            let _ = dag_service.reload().is_ok();
            let mut proof_service = ProofGeneratorService::new(dag_service);
            proof_service.build_merkle_tree();
            let mut s = state.write();
            s.proof_service = proof_service;
            // now set that we are Idle, waiting for the next http request.
            s.current_state = CurrentState::Idle;
            drop(s);
        });
        // again here, we return after started the DAG generation.
        return Ok(Response::builder().status(423).body(Body::empty()).unwrap());
    } else {
        // nice we have DAG ready.
        let mut s = state.write();
        // set our state that we are generating proofs.
        s.current_state = CurrentState::GeneratingProofs;
        drop(s); // drop here to make a chance for other threads to catch up.
        let mut s = state.write();
        let proofs = s.proof_service.proofs(header);
        let json = serde_json::to_string(&proofs).unwrap();
        // set us back as Idle waiting for next request.
        s.current_state = CurrentState::Idle;
        return Ok(Response::builder()
            .status(200)
            .body(Body::from(json))
            .unwrap());
    }
}
