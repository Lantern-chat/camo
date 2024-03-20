//! camo-proxy
//! ==========
//!
//! Standalone and Cloudflare-worker microservice for proxying cryptographically signed URLs. This helps protect users' privacy with untrusted embeds.
//!
//! This server accepts requests in the form of `GET /camo/:base64_url/:base64_signature` and
//! proxies the request to the given URL. The signature is generated using an HMAC-SHA1 hash
//! of the URL and a secret key. Both the URL and signature are base64 encoded with the
//! [`URL_SAFE_NO_PAD`](base64::engine::general_purpose::URL_SAFE_NO_PAD) base64 encoding scheme.
//!
//! The server is designed to be used as a privacy and security layer for image requests,
//! as it removes cookies and other sensitive information from the request and response headers.
//!
//! Example path generation:
//! ```
//! # fn main() {
//! use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
//!
//! use hmac::{digest::Key, Mac};
//! pub type Hmac = hmac::SimpleHmac<sha1::Sha1>;
//!
//! let key = "59d273a2641327d005b255bb7dc89a9f";
//! let url = "https://raw.githubusercontent.com/Lantern-chat/server/master/Cargo.toml";
//!
//! let mut decoded_key = Key::<Hmac>::default();
//! // keys are allowed to be shorter than the entire raw key. Will be padded internally.
//! hex::decode_to_slice(key, &mut decoded_key[..key.len() / 2]).unwrap();
//!
//! let signature = URL_SAFE_NO_PAD.encode(Hmac::new(&decoded_key).chain_update(url).finalize().into_bytes());
//! let path = format!("/camo/{}/{}", URL_SAFE_NO_PAD.encode(url), signature);
//! assert_eq!(path, "/camo/aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0xhbnRlcm4tY2hhdC9zZXJ2ZXIvbWFzdGVyL0NhcmdvLnRvbWw/JvEspwk6jNaE6SpGG2r861A6reM");
//! # }
//! ````
//!
//! Run your camo proxy instance somewhere and request
//! `https://camo.mysite.com/camo/aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0xhbnRlcm4tY2hhdC9zZXJ2ZXIvbWFzdGVyL0NhcmdvLnRvbWw/JvEspwk6jNaE6SpGG2r861A6reM`
//!
//! # Shared Configuration (CF Worker and Standalone)
//!
//! ### `CAMO_SIGNING_KEY`
//! 128-bit signing key encoded as a hexidecimal string.
//!
//! ## Standalone Configuration
//!
//! ### `CAMO_BIND_ADDRESS`
//! Sets the bind address for this microservice.
//!
//! Example `.env`:
//!
//! ```ini
//! CAMO_SIGNING_KEY = "59d273a2641327d005b255bb7dc89a9f" # Example key
//! CAMO_BIND_ADDRESS = "127.0.0.1:8765"
//! ```

#[cfg(feature = "cf")]
pub mod cf;

// Setup types and values for headers to remove from the request and response.

#[cfg(feature = "standalone")]
use reqwest::header::HeaderName;
#[cfg(not(feature = "standalone"))]
type HeaderName = ();

const fn make_header(_name: &'static str) -> HeaderName {
    #[cfg(feature = "standalone")]
    HeaderName::from_static(_name)
}

macro_rules! decl_headers {
    (@COUNT $($header:expr,)*) => { 0 $(+ {_ = $header; 1})* };
    (
        $(#[$meta:meta])*
        $vis:vis static $name:ident = [ $($header:expr,)* ];
    ) => {
        $(#[$meta])*
        $vis static $name: [(&'static str, HeaderName); decl_headers!(@COUNT $($header,)*)] =
            [$(($header, make_header($header))),*];
    };
}

decl_headers! {
    // Headers to remove from the request to maintain privacy and idempotency.
    pub static BAD_REQUEST_HEADERS = [
        "host",
        "cookie",
        "referer",
        "user-agent",
        "authorization",
        "origin",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "dnt",
    ];
}

decl_headers! {
    // Headers to remove from the response to maintain privacy and idempotency.
    pub static BAD_RESPONSE_HEADERS = [
        "location",
        "set-cookie",
        "set-cookie2",
        "vary",
    ];
}
