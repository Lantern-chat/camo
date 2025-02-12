extern crate camo_proxy;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use reqwest::{
    header::{HeaderName, HeaderValue},
    Client,
};

use ftl::extract::State;
use ftl::http::{Request, StatusCode};
use ftl::response::{IntoResponse, Response};
use ftl::{body::Body, http::HeaderMap};

use std::{net::SocketAddr, str::FromStr, sync::Arc, time::Duration};

use hmac::{digest::Key, Mac};
type Hmac = hmac::SimpleHmac<sha1::Sha1>;

struct CamoState {
    signing_key: Key<Hmac>,
    client: reqwest::Client,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().expect("Unable to use .env");

    let state = Arc::new(CamoState {
        signing_key: {
            let hex_key = std::env::var("CAMO_SIGNING_KEY").expect("CAMO_SIGNING_KEY not found");
            let mut raw_key = Key::<Hmac>::default();
            // keys are allowed to be shorter than the entire raw key. Will be padded internally.
            hex::decode_to_slice(&hex_key, &mut raw_key[..hex_key.len() / 2]).expect("Could not parse signing key!");

            raw_key
        },

        client: reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::limited(1))
            .connect_timeout(std::time::Duration::from_secs(10))
            .danger_accept_invalid_certs(false)
            .http2_adaptive_window(true)
            .build()
            .expect("Unable to build primary client"),
    });

    use ftl::handler::HandlerIntoResponse;
    use ftl::router::{FromHandler, HandlerService};

    let router = HandlerService::from_handler(HandlerIntoResponse(root), state);

    let addr = std::env::var("CAMO_BIND_ADDRESS").expect("CAMO_BIND_ADDRESS not found");
    let addr = SocketAddr::from_str(&addr).expect("Unable to parse bind address");

    let mut server = ftl::serve::Server::bind([addr]);

    let handle = server.handle();

    // setup graceful shutdown on ctrl-c
    server.handle().shutdown_on(async { _ = tokio::signal::ctrl_c().await });
    server.handle().set_shutdown_timeout(Duration::from_secs(1));

    // configure the server properties, such as HTTP/2 adaptive window and connect protocol
    server
        .http1()
        .writev(true)
        .pipeline_flush(true)
        .http2()
        .max_concurrent_streams(Some(400))
        .adaptive_window(true)
        .enable_connect_protocol(); // used for HTTP/2 Websockets

    tokio::spawn({
        use ftl::serve::accept::{NoDelayAcceptor, PeekingAcceptor, TimeoutAcceptor};

        let acceptor = TimeoutAcceptor::new(
            // 4 second timeout for the entire connection accept process
            Duration::from_secs(4),
            // TCP_NODELAY, and peek at the first byte of the stream
            PeekingAcceptor(NoDelayAcceptor),
        );

        use ftl::layers::{
            catch_panic::CatchPanic, cloneable::Cloneable, convert_body::ConvertBody, deferred::DeferredEncoding,
            normalize::Normalize, resp_timing::RespTimingLayer, Layer,
        };

        let layers = (
            RespTimingLayer::default(),  // logs the time taken to process each request
            CatchPanic::default(),       // spawns each request in a separate task and catches panics
            Cloneable::default(),        // makes the service layered below it cloneable
            Normalize::default(),        // normalizes the response structure
            ConvertBody::default(),      // converts the body to the correct type
            DeferredEncoding::default(), // encodes deferred responses
        );

        server.acceptor(acceptor).serve(layers.layer(router))
    });

    // wait for the servers to finish
    handle.wait().await;
}

use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};

async fn root(State(state): State<Arc<CamoState>>, req: Request<Body>) -> impl IntoResponse {
    let path = req.uri().path();

    // very early filtering for requests that start with /camo/http (base64)
    if !path.starts_with("/camo/aHR0c") {
        return Err(("Not Found", StatusCode::NOT_FOUND));
    }

    // separate encoded url and encoded signature
    let Some((raw_url, raw_sig)) = path["/camo/".len()..].split_once('/') else {
        return Err(("Missing signature", StatusCode::BAD_REQUEST));
    };

    // skip anything after the signature
    let Some(raw_sig) = raw_sig.split('/').next() else {
        return Err(("This shouldn't happen", StatusCode::INTERNAL_SERVER_ERROR));
    };

    // decode url
    let url = match URL_SAFE_NO_PAD.decode(raw_url) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(url) => url,
            Err(_) => return Err(("Invalid UTF-8", StatusCode::BAD_REQUEST)),
        },
        Err(_) => return Err(("Invalid Encoding", StatusCode::BAD_REQUEST)),
    };

    // decode signature
    let Ok(sig) = URL_SAFE_NO_PAD.decode(raw_sig) else {
        return Err(("Invalid Encoding", StatusCode::BAD_REQUEST));
    };

    if Hmac::new(&state.signing_key).chain_update(&url).verify_slice(&sig).is_err() {
        return Err(("Incorrect Signature", StatusCode::UNAUTHORIZED));
    };

    Ok(proxy(&state.client, &url, req).await)
}

async fn proxy(client: &Client, url: &str, mut req: Request<Body>) -> impl IntoResponse {
    let mut headers = std::mem::take(req.headers_mut());

    for (_, name) in &camo_proxy::BAD_REQUEST_HEADERS {
        headers.remove(name);
    }

    // force DNT header, despite it being deprecated
    headers.insert(HeaderName::from_static("dnt"), HeaderValue::from_static("1"));

    match client.get(url).headers(headers).send().await {
        Err(e) => {
            let code = match e.status() {
                Some(code) => code,
                _ if e.is_redirect() => StatusCode::LOOP_DETECTED,
                _ => StatusCode::NOT_FOUND,
            };

            (Err(()), code, HeaderMap::new())
        }
        Ok(mut resp) => {
            use http_body_util::BodyExt;

            let mut headers = std::mem::take(resp.headers_mut());
            for (_, name) in &camo_proxy::BAD_RESPONSE_HEADERS {
                headers.remove(name);
            }

            let status = resp.status();

            // map the reqwest response body's error type to the ftl body error type
            let body = reqwest::Body::from(resp).map_err(|e: reqwest::Error| ftl::body::BodyError::Generic(e.into()));

            (Ok(Response::new(Body::wrap(body))), status, headers)
        }
    }
}
