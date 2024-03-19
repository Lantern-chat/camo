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
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "vary",
    ];
}
