//! Camo Proxy
//!
//! Example signature generation:
//! ```
//! # fn main() {
//! use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
//!
//! use hmac::{digest::Key, Mac};
//! pub type Hmac = hmac::SimpleHmac<sha1::Sha1>;
//!
//! // Encode the HMAC-SHA1 digest of the value using the key.
//! pub fn generate_signature(value: &str, key: &Key<Hmac>) -> String {
//!     URL_SAFE_NO_PAD.encode(Hmac::new(key).chain_update(value).finalize().into_bytes())
//! }
//!
//! let key = "59d273a2641327d005b255bb7dc89a9f";
//! let url = "https://raw.githubusercontent.com/Lantern-chat/server/master/Cargo.toml";
//!
//! let mut raw_key = Key::<Hmac>::default();
//! // keys are allowed to be shorter than the entire raw key. Will be padded internally.
//! hex::decode_to_slice(key, &mut raw_key[..key.len() / 2]).unwrap();
//!
//! let path = format!("/camo/{}/{}", URL_SAFE_NO_PAD.encode(url), generate_signature(url, &raw_key));
//! assert_eq!(path, "/camo/aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0xhbnRlcm4tY2hhdC9zZXJ2ZXIvbWFzdGVyL0NhcmdvLnRvbWw/JvEspwk6jNaE6SpGG2r861A6reM");
//! # }
//! ````

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
