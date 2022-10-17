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
    clippy::unused_async,
    unused_variables
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
    convert::TryInto,
    env,
    net::{IpAddr, ToSocketAddrs},
    str::FromStr,
    sync::Arc,
    time::Instant,
};

use async_std::task;
use async_std_resolver::{resolver_from_system_conf, AsyncStdResolver};
use chrono::{DateTime, NaiveDateTime, Utc};
use maxminddb::{geoip2, MaxMindDBError, Metadata, Reader};
use sailfish::TemplateOnce;
use serde::Serialize;
use tide::{
    http::{headers, mime, Method},
    utils::After,
    Middleware, Next, Request, Response, Server,
};
use tracing_subscriber::EnvFilter;

#[cfg(test)]
mod tests;

static DB_IP: &[u8] = include_bytes!("../assets/dbip-country-lite-2022-10.mmdb");

enum DbIp {
    Inline(Reader<&'static [u8]>),
    External(Reader<Vec<u8>>),
}

impl DbIp {
    fn lookup(&self, ip: IpAddr) -> Result<geoip2::Country, MaxMindDBError> {
        match *self {
            Self::Inline(ref reader) => reader.lookup(ip),
            Self::External(ref reader) => reader.lookup(ip),
        }
    }

    const fn metadata(&self) -> &Metadata {
        match *self {
            Self::Inline(ref reader) => &reader.metadata,
            Self::External(ref reader) => &reader.metadata,
        }
    }
}

#[derive(Clone)]
struct State {
    resolver: AsyncStdResolver,
    hostname: String,
    db_ip: Arc<DbIp>,
    db_date: &'static str,
}

#[derive(TemplateOnce, Serialize)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    ip: &'a str,
    host: String,
    ua: &'a str,
    lang: &'a str,
    encoding: &'a str,
    method: String,
    mime: &'a str,
    referer: &'a str,
    country_code: &'a str,
    #[serde(skip)]
    ifconfig_hostname: String,
    #[serde(skip)]
    hash_as_yaml: String,
    #[serde(skip)]
    hash_as_json: String,
    #[serde(skip)]
    mmdb_date: &'a str,
}

const UNKNOWN: &str = "unknown";

#[derive(Debug, Copy, Clone)]
pub struct MyLogger;

#[tide::utils::async_trait]
impl<State> Middleware<State> for MyLogger
where
    State: Clone + Send + Sync + 'static,
{
    async fn handle(&self, request: Request<State>, next: Next<'_, State>) -> tide::Result {
        Ok(match (request.method(), request.url().path()) {
            (Method::Get, "/health") => next.run(request).await,
            (method, path) => {
                let now = Instant::now();
                let path = path.to_owned();
                let method = method.to_string();
                let response = next.run(request).await;
                let status = response.status();
                let duration = now.elapsed();
                tracing::info!(
                    method = method.as_str(),
                    path = path.as_str(),
                    status = status.to_string().as_str(),
                    duration = format!("{:?}", duration).as_str(),
                );
                response
            }
        })
    }
}

fn string_to_static_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

async fn init_app(hostname: String, db_ip: Arc<DbIp>, db_date: String) -> Server<State> {
    let resolver = resolver_from_system_conf()
        .await
        .expect("resolver initialized");

    let state = State {
        resolver,
        hostname,
        db_ip,
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
    let _ = app.at("/lang").all(lang);
    let _ = app.at("/encoding").all(encoding);
    let _ = app.at("/mime").all(mime);
    let _ = app.at("/all").all(all);
    let _ = app.at("/all.json").all(all_json);
    let _ = app.at("/health").get(health);

    app
}

fn get_db(db_file: Option<String>) -> (DbIp, String) {
    let reader = match db_file {
        Some(filename) if !filename.is_empty() => {
            DbIp::External(Reader::open_readfile(&filename).expect("Geo IP filename"))
        }
        // None or no db-filename
        _ => DbIp::Inline(Reader::from_source(DB_IP).expect("geoip database")),
    };

    let date: DateTime<Utc> = DateTime::from_utc(
        NaiveDateTime::from_timestamp(
            reader
                .metadata()
                .build_epoch
                .try_into()
                .expect("db_ip epoch too big"),
            0,
        ),
        Utc,
    );

    (reader, date.format("%Y-%m").to_string())
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

    let (db_ip, db_date) = get_db(env::var("DB_FILE").ok());

    task::block_on(async {
        let app = init_app(hostname, Arc::new(db_ip), db_date).await;

        app.listen(listen.to_socket_addrs()?.collect::<Vec<_>>())
            .await
    })
}

fn peer(req: &Request<State>) -> &str {
    req.header("x-real-ip").map_or_else(
        || {
            req.peer_addr()
                .map(|addr| {
                    let addr = addr.rsplit_once(':').expect("ip address + port").0;
                    match addr.split_once('[') {
                        None => addr,
                        Some(addr) => addr.1.rsplit_once(']').expect("ipv6 addr").0,
                    }
                })
                .expect("peer address")
        },
        |ip| ip.as_str(),
    )
}

async fn resolve(resolver: &AsyncStdResolver, req: &Request<State>) -> Option<String> {
    let addr = peer(req);
    if addr == UNKNOWN {
        None
    } else {
        let addr_ip = IpAddr::from_str(addr);

        if let Ok(addr_ip) = addr_ip {
            if let Ok(resolved_hostnames) = resolver.reverse_lookup(addr_ip).await {
                resolved_hostnames
                    .iter()
                    .take(1)
                    .map(|name| {
                        name.to_utf8()
                            .strip_suffix('.')
                            .expect("peer remote name")
                            .to_owned()
                    })
                    .collect::<Vec<_>>()
                    .get(0)
                    .cloned()
            } else {
                Some(addr.to_owned())
            }
        } else {
            None
        }
    }
}

async fn country<'a>(db_ip: &'a DbIp, peer: &str) -> &'a str {
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

async fn fill_struct(req: &Request<State>) -> IndexTemplate<'_> {
    let ip = peer(req);

    let ua = extract_header(req, headers::USER_AGENT);

    let State {
        ref resolver,
        ref db_ip,
        db_date,
        ..
    } = *req.state();

    let hostname = match extract_header(req, headers::HOST) {
        "" => req.state().hostname.clone(),
        hostname => hostname.to_owned(),
    };

    let country_code = country(db_ip, ip).await;
    let host = resolve(resolver, req).await;

    IndexTemplate {
        ifconfig_hostname: hostname,
        ip,
        host: host.unwrap_or_default(),
        ua,
        lang: extract_header(req, headers::ACCEPT_LANGUAGE),
        encoding: extract_header(req, headers::ACCEPT_ENCODING),
        method: req.method().to_string(),
        mime: extract_header(req, headers::ACCEPT),
        referer: extract_header(req, headers::REFERER),
        country_code,
        hash_as_yaml: "".to_owned(),
        hash_as_json: "".to_owned(),
        mmdb_date: db_date,
    }
}

#[inline]
fn extract_header(req: &Request<State>, header_name: impl Into<headers::HeaderName>) -> &'_ str {
    req.header(header_name).map_or("", |v| v.as_str())
}

async fn index(req: Request<State>) -> tide::Result<Response> {
    let ua = extract_header(&req, headers::USER_AGENT);
    let ua = match ua {
        "" => ("", ""),
        user_agent => user_agent
            .split_once('/')
            .map_or_else(|| (user_agent, user_agent), |(soft, _)| (soft, user_agent)),
    };

    if ua.0.is_empty() || "curl" == ua.0 {
        return ip(req).await;
    }

    let State { db_date, .. } = *req.state();

    let mut index = fill_struct(&req).await;
    index.hash_as_yaml = serde_yaml::to_string(&index).expect("yaml data");
    index.hash_as_json = serde_json::to_string(&index).expect("json data");

    let index = index.render_once()?;

    Ok(Response::builder(200)
        .content_type("text/html")
        .header("X-IP-Geolocation-By", "https://db-ip.com/")
        .header("X-IP-Geolocation-Date", db_date)
        .body(index)
        .content_type(mime::HTML)
        .build())
}

async fn ip(req: Request<State>) -> tide::Result<Response> {
    let ip = peer(&req);
    Ok(ip.into())
}

async fn host(req: Request<State>) -> tide::Result<String> {
    let State { ref resolver, .. } = *req.state();
    let hostnames = resolve(resolver, &req).await;
    Ok(hostnames.unwrap_or_default())
}

async fn country_code(req: Request<State>) -> tide::Result<Response> {
    let ip = peer(&req);

    let State {
        ref db_ip, db_date, ..
    } = *req.state();
    Ok(Response::builder(200)
        .header("X-IP-Geolocation-By", "https://db-ip.com/")
        .header("X-IP-Geolocation-Date", db_date)
        .body(country(db_ip, ip).await)
        .build())
}

async fn ua(req: Request<State>) -> tide::Result<String> {
    Ok(extract_header(&req, headers::USER_AGENT).to_owned())
}

async fn lang(req: Request<State>) -> tide::Result<String> {
    Ok(extract_header(&req, headers::ACCEPT_LANGUAGE).to_owned())
}

async fn encoding(req: Request<State>) -> tide::Result<String> {
    Ok(extract_header(&req, headers::ACCEPT_ENCODING).to_owned())
}

async fn mime(req: Request<State>) -> tide::Result<String> {
    Ok(extract_header(&req, headers::ACCEPT).to_owned())
}

async fn all(req: Request<State>) -> tide::Result<Response> {
    let State { db_date, .. } = *req.state();
    Ok(Response::builder(200)
        .content_type("application/yaml")
        .header("X-IP-Geolocation-By", "https://db-ip.com/")
        .header("X-IP-Geolocation-Date", db_date)
        .body(serde_yaml::to_string(&fill_struct(&req).await)?)
        .build())
}

async fn all_json(req: Request<State>) -> tide::Result<Response> {
    let State { db_date, .. } = *req.state();
    Ok(Response::builder(200)
        .content_type(mime::JSON)
        .header("X-IP-Geolocation-By", "https://db-ip.com/")
        .header("X-IP-Geolocation-Date", db_date)
        .body(serde_json::to_string(&fill_struct(&req).await)?)
        .build())
}

#[inline]
async fn health(_req: Request<State>) -> tide::Result<String> {
    Ok("UP".to_owned())
}
