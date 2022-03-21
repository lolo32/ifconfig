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
    clippy::nursery,
)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::redundant_pub_crate,
    clippy::unused_async
)]
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
)]

use std::{
    env,
    net::{IpAddr, ToSocketAddrs},
    str::FromStr,
    time::Instant,
};

use async_std::task;
use async_std_resolver::{proto::rr::Name, resolver_from_system_conf, AsyncStdResolver};
use include_flate::flate;
use maxminddb::{geoip2, Reader};
use sailfish::TemplateOnce;
use serde::Serialize;
use tide::{
    http::{headers, mime},
    utils::After,
    Middleware, Next, Request, Response,
};
use tracing_subscriber::EnvFilter;

flate!(static DB_IP: [u8] from "assets/dbip-country-lite-2022-03.mmdb");
const MMDB_DATE: &str = "2022-03";

#[derive(Clone)]
struct State {
    resolver: AsyncStdResolver,
    hostname: String,
}

#[derive(TemplateOnce, Serialize)]
#[template(path = "index.html")]
struct IndexTemplate {
    ip: String,
    host: String,
    port: u16,
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
    #[serde(skip)]
    mmdb_date: &'static str,
}

const UNKNOWN: &str = "unknown";

#[derive(Debug, Copy, Clone)]
pub struct MyLogger;
#[async_trait::async_trait]
impl<State> Middleware<State> for MyLogger
where
    State: Clone + Send + Sync + 'static,
{
    async fn handle(&self, request: Request<State>, next: Next<'_, State>) -> tide::Result {
        let now = Instant::now();
        let path = request.url().path().to_owned();
        let method = request.method().to_string();
        let response = next.run(request).await;
        let status = response.status();
        let duration = now.elapsed();
        tracing::info!(
            method = method.as_str(),
            path = path.as_str(),
            status = status.to_string().as_str(),
            duration = format!("{:?}", duration).as_str(),
        );
        Ok(response)
    }
}

fn main() -> Result<(), std::io::Error> {
    tracing_subscriber::fmt()
        // .json()
        .compact()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(true)
        .with_line_number(false)
        .with_file(false)
        .with_level(true)
        .init();

    let listen = env::var("LISTEN_ADDR").unwrap_or_else(|_| "localhost:3000".to_owned());
    let hostname = env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_owned());

    {
        tracing::debug!("Initialize DB_IP");
        let _a = DB_IP.as_slice();
    }

    task::block_on(async {
        let resolver = resolver_from_system_conf()
            .await
            .expect("resolver initialized");

        let state = State { resolver, hostname };
        let mut app = tide::with_state(state);

        let _ = app.with(MyLogger);
        let _ = app.with(After(|mut response: Response| async move {
            response.insert_header(headers::CACHE_CONTROL, "no-store");
            response.insert_header(headers::PRAGMA, "no-cache");
            response.insert_header(headers::EXPIRES, "-1");
            response.insert_header(headers::CONNECTION, "Close");

            Ok(response)
        }));

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
            .await
    })
}

fn peer(remote: Option<&str>) -> (String, String) {
    match remote {
        None => (UNKNOWN.to_owned(), UNKNOWN.to_owned()),
        Some(peer) => match peer.rsplit_once(':') {
            None => (UNKNOWN.to_owned(), UNKNOWN.to_owned()),
            Some((peer, port)) => (
                {
                    let peer = peer.strip_prefix('[').unwrap_or(peer);
                    let peer = peer.strip_suffix(']').unwrap_or(peer);
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
                    Ok(resolved_hostnames) => resolved_hostnames.iter().next().map(|name| {
                        Name::to_utf8(name)
                            .strip_suffix('.')
                            .expect("peer remote name")
                            .to_owned()
                    }),
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

async fn fill_struct(req: Request<State>) -> IndexTemplate {
    let peer = peer(req.remote());

    let ua = extract_header(&req, headers::USER_AGENT);

    let resolver = &req.state().resolver;
    let hostname = match extract_header(&req, headers::HOST).as_str() {
        "" => req.state().hostname.clone(),
        hostname => hostname.to_owned(),
    };

    let country_code = country(&peer.0).await;

    IndexTemplate {
        ifconfig_hostname: hostname,
        ip: peer.0,
        host: resolve(resolver, req.remote()).await,
        port: peer.1.parse().expect("port number"),
        ua,
        lang: extract_header(&req, headers::ACCEPT_LANGUAGE),
        encoding: extract_header(&req, headers::ACCEPT_ENCODING),
        method: req.method().to_string(),
        mime: extract_header(&req, headers::ACCEPT),
        referer: extract_header(&req, headers::REFERER),
        forwarded: extract_header(&req, "X-Forwarded-For"),
        country_code,
        hash_as_yaml: "".to_owned(),
        hash_as_json: "".to_owned(),
        mmdb_date: MMDB_DATE,
    }
}

#[inline]
fn extract_header(req: &Request<State>, header_name: impl Into<headers::HeaderName>) -> String {
    req.header(header_name)
        .map_or("", |v| v.as_str())
        .to_owned()
}

async fn index(req: Request<State>) -> tide::Result<Response> {
    let peer = peer(req.remote());

    let ua = extract_header(&req, headers::USER_AGENT);
    let ua = match ua.as_str() {
        "" => ("", ""),
        ua => ua
            .split_once('/')
            .map_or_else(|| (ua, ua), |(soft, _)| (soft, ua)),
    };

    if ua.0.is_empty() || "curl" == ua.0 {
        return Ok(Response::builder(200).body(peer.0).build());
    }

    let mut index = fill_struct(req).await;
    index.hash_as_yaml = serde_yaml::to_string(&index).expect("yaml data");
    index.hash_as_json = serde_json::to_string(&index).expect("json data");

    let index = index.render_once()?;

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
        .header("X-IP-Geolocation-Date", MMDB_DATE)
        .body(country(&peer.0).await)
        .build())
}

async fn ua(req: Request<State>) -> tide::Result<String> {
    Ok(extract_header(&req, headers::USER_AGENT))
}

async fn port(req: Request<State>) -> tide::Result<String> {
    let peer = peer(req.remote());
    Ok(peer.1)
}

async fn lang(req: Request<State>) -> tide::Result<String> {
    Ok(extract_header(&req, headers::ACCEPT_LANGUAGE))
}

async fn encoding(req: Request<State>) -> tide::Result<String> {
    Ok(extract_header(&req, headers::ACCEPT_ENCODING))
}

async fn mime(req: Request<State>) -> tide::Result<String> {
    Ok(extract_header(&req, headers::ACCEPT))
}

async fn forwarded(req: Request<State>) -> tide::Result<String> {
    Ok(extract_header(&req, "X-Forwarded-For"))
}

async fn all(req: Request<State>) -> tide::Result<Response> {
    Ok(Response::builder(200)
        .content_type("application/yaml")
        .header("X-IP-Geolocation-By", "https://db-ip.com/")
        .header("X-IP-Geolocation-Date", MMDB_DATE)
        .body(serde_yaml::to_string(&fill_struct(req).await)?)
        .build())
}

async fn all_json(req: Request<State>) -> tide::Result<Response> {
    Ok(Response::builder(200)
        .content_type(mime::JSON)
        .header("X-IP-Geolocation-By", "https://db-ip.com/")
        .header("X-IP-Geolocation-Date", MMDB_DATE)
        .body(serde_json::to_string(&fill_struct(req).await)?)
        .build())
}
