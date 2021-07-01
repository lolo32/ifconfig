#![deny(
    missing_copy_implementations,
    //missing_docs,
    missing_debug_implementations,
    single_use_lifetimes,
    unsafe_code,
    unused_extern_crates,
    unused_import_braces,
    unused_lifetimes,
    unused_qualifications,
    unused_results,
    clippy::all,
    clippy::pedantic,
    clippy::nursery
)]
#![allow(clippy::cast_possible_truncation, clippy::redundant_pub_crate)]
// Clippy rules in the `Restriction lints`
#![deny(
    clippy::clone_on_ref_ptr,
    clippy::create_dir,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::else_if_without_else,
    clippy::exit,
    clippy::filetype_is_file,
    clippy::float_arithmetic,
    clippy::float_cmp_const,
    clippy::get_unwrap,
    clippy::inline_asm_x86_att_syntax,
    clippy::inline_asm_x86_intel_syntax,
    clippy::let_underscore_must_use,
    clippy::lossy_float_literal,
    clippy::map_err_ignore,
    clippy::mem_forget,
    //clippy::missing_docs_in_private_items,
    clippy::modulo_arithmetic,
    clippy::multiple_inherent_impl,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::pattern_type_mismatch,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::rc_buffer,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::shadow_same,
    clippy::str_to_string,
    clippy::string_to_string,
    clippy::todo,
    clippy::unimplemented,
    clippy::unneeded_field_pattern,
    clippy::unwrap_used,
    clippy::use_debug,
    clippy::verbose_file_reads,
    clippy::wildcard_enum_match_arm,
    clippy::wrong_pub_self_convention
)]

use std::{
    env,
    net::{IpAddr, ToSocketAddrs},
    str::FromStr,
};

use askama::Template;
use async_std::task;
use async_std_resolver::{proto::rr::Name, resolver_from_system_conf, AsyncStdResolver};
use include_flate::flate;
use maxminddb::{geoip2, Reader};
use serde::Serialize;
use tide::{
    http::{headers, mime},
    Request, Response,
};

flate!(static DB_IP: [u8] from "assets/dbip-country-lite.mmdb");

#[derive(Clone)]
struct State {
    resolver: AsyncStdResolver,
    hostname: String,
}

#[derive(Template, Serialize)]
#[template(path = "index.html")]
struct IndexTemplate {
    ip: String,
    host: String,
    port: String,
    ua: String,
    lang: String,
    encoding: String,
    method: String,
    mime: String,
    referer: String,
    forwarded: String,
    country_code: String,
    #[serde(skip)]
    ifconfig_hostname: String,
    #[serde(skip)]
    hash_as_yaml: String,
    #[serde(skip)]
    hash_as_json: String,
}

const UNKNOWN: &str = "unknown";

fn main() -> Result<(), std::io::Error> {
    let listen = env::var("LISTEN_ADDR").unwrap_or_else(|_| "localhost:3000".to_owned());
    let hostname = env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_owned());

    {
        let _a = DB_IP.as_slice();
    }

    task::block_on(async {
        let resolver = resolver_from_system_conf()
            .await
            .expect("resolver initialized");

        let state = State { resolver, hostname };
        let mut app = tide::with_state(state);
        let _ = app.at("/").all(index);
        let _ = app.at("/ip").all(ip);
        let _ = app.at("/host").all(host);
        let _ = app.at("/country_code").all(country_code);
        let _ = app.at("/ua").all(ua);
        let _ = app.at("/port").all(port);
        let _ = app.at("/lang").all(lang);
        let _ = app.at("/encoding").all(encoding);
        let _ = app.at("/mime").all(mime);
        let _ = app.at("/forwarded").all(forwarded);
        let _ = app.at("/all").all(all);
        let _ = app.at("/all.json").all(all_json);

        app.listen(listen.to_socket_addrs()?.collect::<Vec<_>>())
            .await?;
        Ok(())
    })
}

fn peer(remote: Option<&str>) -> (String, String) {
    match remote {
        None => (UNKNOWN.to_owned(), UNKNOWN.to_owned()),
        Some(peer) => match peer.rsplit_once(":") {
            None => (UNKNOWN.to_owned(), UNKNOWN.to_owned()),
            Some((peer, port)) => (
                {
                    let peer = peer.strip_prefix("[").unwrap_or(peer);
                    let peer = peer.strip_suffix("]").unwrap_or(peer);
                    peer.strip_prefix("::ffff:").unwrap_or(peer).to_owned()
                },
                port.to_owned(),
            ),
        },
    }
}

async fn resolve(resolver: &AsyncStdResolver, peer_addr: Option<&str>) -> String {
    match peer_addr {
        None => None,
        Some(addr) => {
            let (addr, _port) = peer(Some(addr));
            let addr = IpAddr::from_str(&addr);

            match addr {
                Err(_) => None,
                Ok(addr) => match resolver.reverse_lookup(addr).await {
                    Ok(resolved_hostnames) => resolved_hostnames.iter().next().map(Name::to_utf8),
                    Err(_) => Some(addr.to_string()),
                },
            }
        }
    }
    .unwrap_or_else(|| "".to_owned())
}

async fn country(peer: &str) -> String {
    match IpAddr::from_str(peer) {
        Err(_) => "".to_owned(),
        Ok(addr) => {
            let reader = Reader::from_source(&*DB_IP).expect("geoip database");
            match reader.lookup::<geoip2::Country>(addr) {
                Err(_) => "".to_owned(),
                Ok(country) => country
                    .country
                    .map_or("", |c| c.iso_code.unwrap_or_default())
                    .to_owned(),
            }
        }
    }
}

async fn fill_struct<'a>(req: Request<State>) -> IndexTemplate {
    let peer = peer(req.remote());

    let ua = req
        .header(headers::USER_AGENT)
        .map(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();

    let resolver = &req.state().resolver;
    let hostname = &req.state().hostname;

    let country_code = country(&peer.0).await;

    IndexTemplate {
        ifconfig_hostname: hostname.clone(),
        ip: peer.0,
        host: resolve(resolver, req.remote()).await,
        port: peer.1,
        ua,
        lang: req
            .header(headers::ACCEPT_LANGUAGE)
            .map_or("", |v| v.as_str())
            .to_owned(),
        encoding: req
            .header(headers::ACCEPT_ENCODING)
            .map_or("", |v| v.as_str())
            .to_owned(),
        method: req.method().to_string(),
        mime: req
            .header(headers::ACCEPT)
            .map_or("", |v| v.as_str())
            .to_owned(),
        referer: req
            .header(headers::REFERER)
            .map_or("", |v| v.as_str())
            .to_owned(),
        forwarded: req
            .header(
                headers::HeaderName::from_bytes(b"X-Forwarded-For".to_vec()).expect("header name"),
            )
            .map_or("", |v| v.as_str())
            .to_owned(),
        country_code,
        hash_as_yaml: "".to_owned(),
        hash_as_json: "".to_owned(),
    }
}

async fn index(req: Request<State>) -> tide::Result<Response> {
    let peer = peer(req.remote());

    let ua = match req.header(headers::USER_AGENT).map(|v| v.as_str()) {
        None => ("", ""),
        Some(ua) => ua
            .split_once('/')
            .map_or_else(|| (ua, ua), |(soft, _)| (soft, ua)),
    };

    if ua.0.is_empty() || "curl" == ua.0 {
        return Ok(Response::builder(200).body(peer.0).build());
    }

    let mut index = fill_struct(req).await;
    index.hash_as_yaml = serde_yaml::to_string(&index).expect("yaml data");
    index.hash_as_json = serde_json::to_string(&index).expect("json data");

    let index = index.render()?;

    Ok(Response::builder(200)
        .body(index)
        .content_type(mime::HTML)
        .build())
}

async fn ip(req: Request<State>) -> tide::Result<String> {
    let peer = peer(req.remote());
    Ok(peer.0)
}

async fn host(req: Request<State>) -> tide::Result<String> {
    let resolver = &req.state().resolver;
    Ok(resolve(resolver, req.remote()).await)
}

async fn country_code(req: Request<State>) -> tide::Result<Response> {
    let peer = peer(req.remote());
    Ok(Response::builder(200)
        .header("X-IP-Geolocation-By", "https://db-ip.com/")
        .body(country(&peer.0).await)
        .build())
}

async fn ua(req: Request<State>) -> tide::Result<String> {
    Ok(req
        .header(headers::USER_AGENT)
        .map_or("", |v| v.as_str())
        .to_owned())
}

async fn port(req: Request<State>) -> tide::Result<String> {
    let peer = peer(req.remote());
    Ok(peer.1)
}

async fn lang(req: Request<State>) -> tide::Result<String> {
    Ok(req
        .header(headers::ACCEPT_LANGUAGE)
        .map_or("", |v| v.as_str())
        .to_owned())
}

async fn encoding(req: Request<State>) -> tide::Result<String> {
    Ok(req
        .header(headers::ACCEPT_ENCODING)
        .map_or("", |v| v.as_str())
        .to_owned())
}

async fn mime(req: Request<State>) -> tide::Result<String> {
    Ok(req
        .header(headers::ACCEPT)
        .map_or("", |v| v.as_str())
        .to_owned())
}

async fn forwarded(req: Request<State>) -> tide::Result<String> {
    Ok(req
        .header(headers::HeaderName::from_bytes(b"X-Forwarded-For".to_vec()).expect("header name"))
        .map_or("", |v| v.as_str())
        .to_owned())
}

async fn all(req: Request<State>) -> tide::Result<Response> {
    Ok(Response::builder(200)
        .content_type("application/yaml")
        .body(serde_yaml::to_string(&fill_struct(req).await)?)
        .build())
}

async fn all_json(req: Request<State>) -> tide::Result<Response> {
    Ok(Response::builder(200)
        .content_type(mime::JSON)
        .body(serde_json::to_string(&fill_struct(req).await)?)
        .build())
}
