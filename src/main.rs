use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use ethash::types::BlockHeader;
use ethash::{EthereumPatch, Patch};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Error, Request, Response, Server};
use parking_lot::RwLock;

mod service;
mod storage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    GeneratingDag,
    GeneratingProofs,
}

type ServerState = Arc<RwLock<State>>;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    // init log adapter.
    tracing_subscriber::fmt()
        .with_env_filter("debug")
        .pretty()
        .with_target(true)
        .init();

    // the server should only be running locally.
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let state = Arc::new(RwLock::new(State::Idle));

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

// where the magic happens.
async fn generate_proofs(req: Request<Body>, state: ServerState) -> Result<Response<Body>, Error> {
    // get the request body bytes.
    let body = hyper::body::to_bytes(req).await?;
    let s = state.read();
    // if we are currently generating dag for example.
    if *s != State::Idle {
        // return that we are busy (423 Locked).
        return Ok(Response::builder().status(423).body(Body::empty()).unwrap());
    }
    // done with this guard.
    // drop it then!
    drop(s);

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

    // paths will be created when DAG generation is started.
    let cache_path = PathBuf::from(format!("data/{}/cache.bin", epoch));
    let dataset_path = PathBuf::from(format!("data/{}/dataset.bin", epoch));
    let dag_exist = cache_path.exists() && dataset_path.exists();

    let storage = storage::DagStorage::new(cache_path, dataset_path);
    let dag_service = service::DagGeneratorService::new(storage);

    // if the DAG (cache and dataset) is not there yet.
    if !dag_exist {
        // get our state.
        let mut s = state.write();
        // set it that we are currently generating the DAG.
        // so the next Http call returns immediately
        // without dublicating the work.
        *s = State::GeneratingDag;

        // clone the state to sent to the other task.
        let state = state.clone();
        std::thread::spawn(move || {
            // this starts generating the cache for `epoch`
            let _ = dag_service.cache(epoch.as_usize());
            // and then generate the dataset for `epoch`.
            let _ = dag_service.dataset(epoch.as_usize());
            let mut s = state.write();
            // now set that we are Idle, waiting for the next http request.
            *s = State::Idle;
        });
        // again here, we return after started the DAG generation.
        return Ok(Response::builder().status(423).body(Body::empty()).unwrap());
    } else {
        // nice we have DAG ready.
        let mut s = state.write();
        // set our state that we are generating proofs.
        *s = State::GeneratingProofs;
        drop(s);
        let proof_service = service::ProofGeneratorService::new(dag_service);
        let proofs = proof_service.proofs(header);
        let json = serde_json::to_string(&proofs).unwrap();
        let mut s = state.write();
        // set us back as Idle waiting for next request.
        *s = State::Idle;
        return Ok(Response::builder()
            .status(200)
            .body(Body::from(json))
            .unwrap());
    }
}
