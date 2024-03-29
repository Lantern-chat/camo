use hmac::{digest::Key, Mac};
use worker::*;

mod utils;

fn log_request(req: &Request) {
    let coord_region = req.cf().map(|cf| (cf.coordinates(), cf.region()));

    console_log!(
        "{} - [{}], located at: {:?}, within: {}",
        Date::now().to_string(),
        req.path(),
        coord_region.as_ref().and_then(|(coord, _)| *coord).unwrap_or_default(),
        coord_region.and_then(|(_, region)| region).unwrap_or_else(|| "unknown region".into())
    );
}

use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    if req.method() != Method::Get {
        return Response::error("Method Not Allowed", 405);
    }

    let path = req.path();

    // very early filtering for requests that start with /camo/http (base64)
    if !path.starts_with("/camo/aHR0c") {
        return Response::error("Not Found", 404);
    }

    // separate encoded url and encoded signature
    let Some((raw_url, raw_sig)) = path["/camo/".len()..].split_once('/') else {
        return Response::error("Missing signature", 400);
    };

    // skip anything after the signature
    let Some(raw_sig) = raw_sig.split('/').next() else {
        return Response::error("This shouldn't happen", 500);
    };

    utils::set_panic_hook();

    // decode url
    let url = match URL_SAFE_NO_PAD.decode(raw_url) {
        Ok(bytes) => match String::from_utf8(bytes) {
            Ok(url) => url,
            Err(_) => return Response::error("Invalid UTF-8", 400),
        },
        Err(_) => return Response::error("Invalid Encoding", 400),
    };

    // early check for non-http urls
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Response::error("Not Found", 404);
    }

    // decode signature
    let Ok(sig) = URL_SAFE_NO_PAD.decode(raw_sig) else {
        return Response::error("Invalid Encoding", 400);
    };

    // parse key and build hmac
    let hmac = {
        type Hmac = hmac::SimpleHmac<sha1::Sha1>;

        let hex_key = env.secret("CAMO_SIGNING_KEY")?.to_string();
        let mut raw_key = Key::<Hmac>::default();

        // keys are allowed to be shorter than the entire raw key. Will be padded internally.
        if hex::decode_to_slice(&hex_key, &mut raw_key[..hex_key.len() / 2]).is_err() {
            return Response::error("", 500);
        }

        Hmac::new(&raw_key)
    };

    if hmac.chain_update(&url).verify_slice(&sig).is_err() {
        return Response::error("Incorrect Signature", 401);
    };

    log_request(&req);
    let mut resp = Fetch::Request(Request::new_with_init(
        &url,
        &RequestInit {
            headers: {
                let mut headers = req.headers().clone();
                for (name, _) in &crate::BAD_REQUEST_HEADERS {
                    _ = headers.delete(name);
                }
                headers
            },
            ..Default::default()
        },
    )?)
    .send()
    .await?;

    for (name, _) in &crate::BAD_RESPONSE_HEADERS {
        _ = resp.headers_mut().delete(name);
    }

    Ok(resp)
}
