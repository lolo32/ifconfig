#![deny(
    missing_copy_implementations,
    //missing_docs,
    missing_debug_implementations,
    //single_use_lifetimes,
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
    sync::Arc,
    time::Instant,
};

use async_std::task;
use async_std_resolver::{resolver_from_system_conf, AsyncStdResolver};
use include_flate::flate;
use maxminddb::{geoip2, MaxMindDBError, Reader};
use regex::Regex;
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

enum DbIp<'data> {
    Inline(Reader<&'data Vec<u8>>),
    External(Reader<Vec<u8>>),
}

impl<'data> DbIp<'data> {
    fn lookup(&'data self, ip: IpAddr) -> Result<geoip2::Country<'data>, MaxMindDBError> {
        match self {
            Self::Inline(reader) => reader.lookup(ip),
            Self::External(reader) => reader.lookup(ip),
        }
    }
}

#[derive(Clone)]
struct State<'data> {
    resolver: AsyncStdResolver,
    hostname: String,
    db_ip: Arc<DbIp<'data>>,
    db_date: &'data str,
}

#[derive(TemplateOnce, Serialize)]
#[template(path = "index.html")]
#[allow(unused_variables)]
struct IndexTemplate<'a> {
    ip: &'a str,
    host: Vec<String>,
    port: u16,
    ua: &'a str,
    lang: &'a str,
    encoding: &'a str,
    method: String,
    mime: &'a str,
    referer: &'a str,
    forwarded: &'a str,
    country_code: &'a str,
    #[serde(skip)]
    ifconfig_hostname: String,
    #[serde(skip)]
    hash_as_yaml: String,
    #[serde(skip)]
    hash_as_json: String,
    #[serde(skip)]
    mmdb_date: &'a str,
    #[serde(skip)]
    host_string: String,
    #[serde(skip)]
    host_json: String,
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

fn string_to_static_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn main() -> Result<(), std::io::Error> {
    let _env = dotenv::dotenv();

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
    let (db_ip, db_date) = match env::var("DB_FILE") {
        Ok(filename) => {
            let reader = DbIp::External(Reader::open_readfile(&filename).expect("Geo IP filename"));
            let date = {
                let re = Regex::new(r#"(\d{4}-\d{2})"#).expect("date regexp");
                let caps = re.captures(&filename);
                match caps {
                    Some(caps) => caps.get(1).expect("date").as_str().to_owned(),
                    None => UNKNOWN.to_owned(),
                }
            };
            (reader, date)
        }
        Err(_) => (
            DbIp::Inline(Reader::from_source(&*DB_IP).expect("geoip database")),
            MMDB_DATE.to_owned(),
        ),
    };

    task::block_on(async {
        let resolver = resolver_from_system_conf()
            .await
            .expect("resolver initialized");

        let state = State {
            resolver,
            hostname,
            db_ip: Arc::new(db_ip),
            db_date: string_to_static_str(db_date),
        };
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

fn peer(remote: Option<&str>) -> (&str, &str) {
    match remote {
        None => (UNKNOWN, UNKNOWN),
        Some(peer) => match peer.rsplit_once(':') {
            None => (UNKNOWN, UNKNOWN),
            Some((peer, port)) => (
                {
                    let peer = peer.strip_prefix('[').unwrap_or(peer);
                    let peer = peer.strip_suffix(']').unwrap_or(peer);
                    peer.strip_prefix("::ffff:").unwrap_or(peer)
                },
                port,
            ),
        },
    }
}

async fn resolve(resolver: &AsyncStdResolver, peer_addr: Option<&str>) -> Vec<String> {
    match peer_addr {
        None => vec![],
        Some(addr) => {
            let (addr, _port) = peer(Some(addr));
            let addr = IpAddr::from_str(addr);

            match addr {
                Err(_) => vec![],
                Ok(addr) => match resolver.reverse_lookup(addr).await {
                    Ok(resolved_hostnames) => resolved_hostnames
                        .iter()
                        .map(|name| {
                            name.to_utf8()
                                .strip_suffix('.')
                                .expect("peer remote name")
                                .to_owned()
                        })
                        .collect::<Vec<_>>(),
                    Err(_) => vec![addr.to_string()],
                },
            }
        }
    }
}

async fn country<'a>(db_ip: &'a DbIp<'_>, peer: &str) -> &'a str {
    match IpAddr::from_str(peer) {
        Err(_) => "",
        Ok(addr) => match db_ip.lookup(addr) {
            Err(_) => "",
            Ok(country) => country
                .country
                .map_or("", |c| c.iso_code.unwrap_or_default()),
        },
    }
}

async fn fill_struct<'a>(req: &'a Request<State<'a>>) -> IndexTemplate<'a> {
    let (ip, port) = peer(req.remote());

    let ua = extract_header(req, headers::USER_AGENT);

    let state = req.state();
    let resolver = &state.resolver;
    let db_ip = &state.db_ip;
    let db_date = state.db_date;

    let hostname = match extract_header(req, headers::HOST) {
        "" => req.state().hostname.clone(),
        hostname => hostname.to_owned(),
    };

    let country_code = country(db_ip, ip).await;
    let host = resolve(resolver, req.remote()).await;

    IndexTemplate {
        ifconfig_hostname: hostname,
        ip,
        host_string: host.join(", "),
        host_json: serde_json::to_string(&host).expect("json hosts array"),
        host,
        port: port.parse().expect("port number"),
        ua,
        lang: extract_header(req, headers::ACCEPT_LANGUAGE),
        encoding: extract_header(req, headers::ACCEPT_ENCODING),
        method: req.method().to_string(),
        mime: extract_header(req, headers::ACCEPT),
        referer: extract_header(req, headers::REFERER),
        forwarded: extract_header(req, "X-Forwarded-For"),
        country_code,
        hash_as_yaml: "".to_owned(),
        hash_as_json: "".to_owned(),
        mmdb_date: db_date,
    }
}

#[inline]
fn extract_header<'a>(
    req: &'a Request<State<'_>>,
    header_name: impl Into<headers::HeaderName>,
) -> &'a str {
    req.header(header_name).map_or("", |v| v.as_str())
}

fn convert_hostnames(hostnames: &[String]) -> String {
    match hostnames.len() {
        0 => "".to_owned(),
        1 => hostnames.get(0).expect("hostname").clone(),
        _ => serde_json::to_string(&hostnames).expect("json hostname list"),
    }
}

async fn index(req: Request<State<'_>>) -> tide::Result<Response> {
    let (ip, _port) = peer(req.remote());

    let ua = extract_header(&req, headers::USER_AGENT);
    let ua = match ua {
        "" => ("", ""),
        user_agent => user_agent
            .split_once('/')
            .map_or_else(|| (user_agent, user_agent), |(soft, _)| (soft, user_agent)),
    };

    if ua.0.is_empty() || "curl" == ua.0 {
        return Ok(Response::builder(200).body(ip).build());
    }

    let mut index = fill_struct(&req).await;
    index.hash_as_yaml = serde_yaml::to_string(&index).expect("yaml data");
    index.hash_as_json = serde_json::to_string(&index).expect("json data");

    let index = index.render_once()?;

    Ok(Response::builder(200)
        .body(index)
        .content_type(mime::HTML)
        .build())
}

async fn ip(req: Request<State<'_>>) -> tide::Result<String> {
    let (ip, _port) = peer(req.remote());
    Ok(ip.to_owned())
}

async fn host(req: Request<State<'_>>) -> tide::Result<String> {
    let resolver = &req.state().resolver;
    let hostnames = resolve(resolver, req.remote()).await;
    Ok(convert_hostnames(&hostnames))
}

async fn country_code(req: Request<State<'_>>) -> tide::Result<Response> {
    let (ip, _port) = peer(req.remote());

    let db_ip = &req.state().db_ip;
    Ok(Response::builder(200)
        .header("X-IP-Geolocation-By", "https://db-ip.com/")
        .header("X-IP-Geolocation-Date", MMDB_DATE)
        .body(country(db_ip, ip).await)
        .build())
}

async fn ua(req: Request<State<'_>>) -> tide::Result<String> {
    Ok(extract_header(&req, headers::USER_AGENT).to_owned())
}

async fn port(req: Request<State<'_>>) -> tide::Result<String> {
    let (_ip, port) = peer(req.remote());
    Ok(port.to_owned())
}

async fn lang(req: Request<State<'_>>) -> tide::Result<String> {
    Ok(extract_header(&req, headers::ACCEPT_LANGUAGE).to_owned())
}

async fn encoding(req: Request<State<'_>>) -> tide::Result<String> {
    Ok(extract_header(&req, headers::ACCEPT_ENCODING).to_owned())
}

async fn mime(req: Request<State<'_>>) -> tide::Result<String> {
    Ok(extract_header(&req, headers::ACCEPT).to_owned())
}

async fn forwarded(req: Request<State<'_>>) -> tide::Result<String> {
    Ok(extract_header(&req, "X-Forwarded-For").to_owned())
}

async fn all(req: Request<State<'_>>) -> tide::Result<Response> {
    Ok(Response::builder(200)
        .content_type("application/yaml")
        .header("X-IP-Geolocation-By", "https://db-ip.com/")
        .header("X-IP-Geolocation-Date", MMDB_DATE)
        .body(serde_yaml::to_string(&fill_struct(&req).await)?)
        .build())
}

async fn all_json(req: Request<State<'_>>) -> tide::Result<Response> {
    Ok(Response::builder(200)
        .content_type(mime::JSON)
        .header("X-IP-Geolocation-By", "https://db-ip.com/")
        .header("X-IP-Geolocation-Date", MMDB_DATE)
        .body(serde_json::to_string(&fill_struct(&req).await)?)
        .build())
}
