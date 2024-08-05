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
    convert::{Infallible, TryInto},
    env,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    error_handling::HandleErrorLayer,
    extract::{ConnectInfo, FromRequestParts, State},
    http::{request::Parts, HeaderMap, HeaderValue, Method},
    response::{Html, IntoResponse, Response},
    routing::{any, get},
    Router,
};
use axum_extra::TypedHeader;
use chrono::DateTime;
use headers::UserAgent;
use hyper::{
    header::{self, AsHeaderName},
    StatusCode,
};
use maxminddb::{geoip2, MaxMindDBError, Metadata, Reader};
use sailfish::TemplateOnce;
use serde::{Deserialize, Serialize};
use tower::{BoxError, ServiceBuilder};
use tower_http::{
    set_header::SetResponseHeaderLayer,
    trace::{DefaultMakeSpan, TraceLayer},
};
use tracing::Level;
use tracing_subscriber::EnvFilter;
use trust_dns_resolver::{AsyncResolver, TokioAsyncResolver};
use utoipa::OpenApi;

#[cfg(test)]
mod tests;

static DB_IP: &[u8] = include_bytes!("../assets/dbip-country-lite-2022-11.mmdb");

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
struct MyState {
    resolver: TokioAsyncResolver,
    hostname: String,
    db_ip: Arc<DbIp>,
    db_date: &'static str,
}

#[derive(TemplateOnce, Serialize)]
#[template(path = "index.html")]
struct IndexTemplate<'a> {
    ip: String,
    host: String,
    ua: &'a str,
    lang: &'a str,
    encoding: &'a str,
    method: String,
    mime: &'a str,
    #[serde(skip)]
    referer: &'a str,
    country_code: String,
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

#[derive(Clone, Copy, Debug)]
pub struct DoNotMonitor;

#[derive(Debug, Serialize, Deserialize)]
struct RemoteIp(String);

#[async_trait]
impl<S> FromRequestParts<S> for RemoteIp
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let ip = parts.headers.get("x-real-ip").map_or_else(
            || {
                parts
                    .extensions
                    .get::<ConnectInfo<SocketAddr>>()
                    .expect("remote socket")
                    .0
                    .ip()
                    .to_string()
            },
            |ip| ip.to_str().expect("x-real-ip header value").to_owned(),
        );
        Ok(Self(ip))
    }
}

fn string_to_static_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

async fn handle_errors(err: BoxError) -> impl IntoResponse {
    if err.is::<tower::timeout::error::Elapsed>() {
        (
            StatusCode::REQUEST_TIMEOUT,
            "Request took too long".to_owned(),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unhandled internal error: {err}"),
        )
    }
}

#[derive(OpenApi)]
#[openapi(paths(index, ip, host, country_code, ua, lang, encoding, mime, all, all_json))]
struct ApiDoc;

async fn swagger() -> String {
    ApiDoc::openapi().to_json().expect("JSON swagger")
}

fn init_app(hostname: String, db_ip: Arc<DbIp>, db_date: String) -> Router {
    let resolver = AsyncResolver::tokio_from_system_conf().expect("resolver initialized");

    let state = MyState {
        resolver,
        hostname,
        db_ip,
        db_date: string_to_static_str(db_date),
    };

    // Build our middleware stack
    let middleware = ServiceBuilder::new()
        // Add high level tracing/logging to all requests
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(
                    DefaultMakeSpan::new()
                        .include_headers(false)
                        .level(Level::INFO),
                )
                .on_response(
                    move |response: &Response, latency: Duration, _span: &tracing::Span| {
                        if response.extensions().get::<DoNotMonitor>().is_some() {
                            return;
                        }
                        let latency = format!("{:?} μs", latency.as_micros());
                        tracing::event!(
                            Level::INFO,
                            %latency,
                            status = %response.status(),
                            "response"
                        );
                    },
                ),
        )
        // Handle errors
        .layer(HandleErrorLayer::new(handle_errors))
        // Set a timeout
        .timeout(Duration::from_secs(10))
        // Set the cache headers to always revalidate data
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::PRAGMA,
            HeaderValue::from_static("no-cache"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::EXPIRES,
            HeaderValue::from_static("-1"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONNECTION,
            HeaderValue::from_static("Close"),
        ));

    Router::new()
        .route("/", any(index))
        .route("/ip", any(ip))
        .route("/host", any(host))
        .route("/country_code", any(country_code))
        .route("/ua", any(ua))
        .route("/lang", any(lang))
        .route("/encoding", any(encoding))
        .route("/mime", any(mime))
        .route("/all", any(all))
        .route("/all.json", any(all_json))
        .route("/health", get(health))
        .route("/api", get(swagger))
        .layer(middleware.into_inner())
        .with_state(state)
}

fn get_db(db_file: Option<String>) -> (DbIp, String) {
    let reader = db_file
        .and_then(|filename| match filename.trim() {
            "" => None,
            _ => Some(filename),
        })
        .inspect(|v| tracing::event!(Level::INFO, "Using external Geo IP database: {v}"))
        .map_or_else(
            || DbIp::Inline(Reader::from_source(DB_IP).expect("geoip database")),
            |filename| DbIp::External(Reader::open_readfile(filename).expect("Geo IP filename")),
        );

    let date = DateTime::from_timestamp(
        reader
            .metadata()
            .build_epoch
            .try_into()
            .expect("db_ip epoch too big"),
        0,
    )
    .expect("geoip database timestamp");

    (reader, date.format("%Y-%m").to_string())
}

fn main() -> Result<(), std::io::Error> {
    let _env = dotenv::dotenv();

    let directives = env::var(EnvFilter::DEFAULT_ENV).unwrap_or_else(|_err| String::new());
    let crate_name = module_path!()
        .split(':')
        .next()
        .expect("Could not find crate name in module path")
        .to_string();
    let env_filter_directives =
        format!("warn,tower_http=info,tower=trace,{crate_name}=info,{directives}");
    let env_filter = EnvFilter::builder().parse_lossy(env_filter_directives);

    tracing_subscriber::fmt()
        // .json()
        // .compact()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_line_number(false)
        .with_file(false)
        .with_level(true)
        .init();

    let listen = env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_owned());
    let hostname = env::var("HOSTNAME").unwrap_or_else(|_| "localhost".to_owned());

    let (db_ip, db_date) = get_db(env::var("DB_FILE").ok());

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime builder")
        .block_on(async {
            let app = init_app(hostname, Arc::new(db_ip), db_date);

            let listener = tokio::net::TcpListener::bind(listen).await.unwrap();
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        })
}

async fn resolve(resolver: &TokioAsyncResolver, addr: &RemoteIp) -> Option<String> {
    let addr = &addr.0;
    if addr == UNKNOWN {
        None
    } else {
        let addr_ip = IpAddr::from_str(addr);

        if let Ok(addr_ip) = addr_ip {
            (resolver.reverse_lookup(addr_ip).await).map_or_else(
                |_| Some(addr.clone()),
                |resolved_hostnames| {
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
                },
            )
        } else {
            None
        }
    }
}

async fn country(db_ip: &DbIp, peer: &RemoteIp) -> String {
    IpAddr::from_str(peer.0.as_str()).map_or(String::new(), |addr| match db_ip.lookup(addr) {
        Err(_) => String::new(),
        Ok(country) => country
            .country
            .map_or(String::new(), |c| c.iso_code.unwrap_or_default().to_owned()),
    })
}

async fn fill_struct(
    state: MyState,
    method: Method,
    headers: &HeaderMap,
    addr: RemoteIp,
) -> IndexTemplate<'_> {
    let ua = extract_header(headers, header::USER_AGENT);

    let MyState {
        ref resolver,
        ref db_ip,
        db_date,
        ..
    } = state;

    let hostname = match extract_header(headers, header::HOST) {
        "" => state.hostname.clone(),
        hostname => hostname.to_owned(),
    };

    let country_code = country(db_ip, &addr).await;
    let host = resolve(resolver, &addr).await;

    IndexTemplate {
        ifconfig_hostname: hostname,
        ip: addr.0,
        host: host.unwrap_or_default(),
        ua,
        lang: extract_header(headers, header::ACCEPT_LANGUAGE),
        encoding: extract_header(headers, header::ACCEPT_ENCODING),
        method: method.to_string(),
        mime: extract_header(headers, header::ACCEPT),
        referer: extract_header(headers, header::REFERER),
        country_code,
        hash_as_yaml: String::new(),
        hash_as_json: String::new(),
        mmdb_date: db_date,
    }
}

#[inline]
fn extract_header(headers: &HeaderMap, header_name: impl AsHeaderName) -> &str {
    headers
        .get(header_name)
        .map(|v| v.to_str().unwrap_or_default())
        .unwrap_or_default()
}

#[utoipa::path(
    get,
    path = "/",
    responses(
        (status = 200, description = r#"Provide two information type, depending on user-agent:
- IP address only if no user-agent or empty, or curl
- All the information about your internet connection otherwize"#)
    )
)]
async fn index(
    State(state): State<MyState>,
    method: Method,
    headers: HeaderMap,
    addr: RemoteIp,
) -> Response {
    let ua = extract_header(&headers, header::USER_AGENT);
    let ua = match ua {
        "" => ("", ""),
        user_agent => user_agent
            .split_once('/')
            .map_or_else(|| (user_agent, user_agent), |(soft, _)| (soft, user_agent)),
    };

    if ua.0.is_empty() || "curl" == ua.0 {
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE.as_str(), "text/plain")],
            addr.0,
        )
            .into_response();
    }

    let MyState { db_date, .. } = state;

    let mut index = fill_struct(state, method, &headers, addr).await;
    index.hash_as_yaml = serde_yaml::to_string(&index).expect("yaml data");
    index.hash_as_json = serde_json::to_string(&index).expect("json data");

    let index = index.render_once().expect("template rendered");

    (
        StatusCode::OK,
        [
            ("X-IP-Geolocation-By", "https://db-ip.com/"),
            ("X-IP-Geolocation-Date", db_date),
        ],
        Html(index),
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/ip",
    responses(
        (status = 200, description = "IP address only"),
    )
)]
async fn ip(addr: RemoteIp) -> String {
    addr.0
}

#[utoipa::path(
    get,
    path = "/host",
    responses(
        (status = 200, description = "Reverse hostname"),
    )
)]
async fn host(State(state): State<MyState>, addr: RemoteIp) -> String {
    let resolver = &state.resolver;
    let hostnames = resolve(resolver, &addr).await;
    hostnames.unwrap_or_default()
}

#[utoipa::path(
    get,
    path = "/county_code",
    responses(
        (status = 200, description = "Country code"),
    )
)]
async fn country_code(State(state): State<MyState>, addr: RemoteIp) -> impl IntoResponse {
    let MyState {
        ref db_ip, db_date, ..
    } = state;

    (
        StatusCode::OK,
        [
            ("X-IP-Geolocation-By", "https://db-ip.com/"),
            ("X-IP-Geolocation-Date", db_date),
        ],
        country(db_ip, &addr).await,
    )
}

#[utoipa::path(
    get,
    path = "/ua",
    responses(
        (status = 200, description = "User agent"),
    )
)]
async fn ua(TypedHeader(user_agent): TypedHeader<UserAgent>) -> String {
    user_agent.as_str().to_owned()
}

#[utoipa::path(
    get,
    path = "/lang",
    responses(
        (status = 200, description = "Requested lang"),
    )
)]
async fn lang(headers: HeaderMap) -> String {
    extract_header(&headers, header::ACCEPT_LANGUAGE).to_owned()
}

#[utoipa::path(
    get,
    path = "/encoding",
    responses(
        (status = 200, description = "Accepted encoding"),
    )
)]
async fn encoding(headers: HeaderMap) -> String {
    extract_header(&headers, header::ACCEPT_ENCODING).to_owned()
}

#[utoipa::path(
    get,
    path = "/mime",
    responses(
        (status = 200, description = "Accepted mime"),
    )
)]
async fn mime(headers: HeaderMap) -> String {
    extract_header(&headers, header::ACCEPT).to_owned()
}

#[utoipa::path(
    get,
    path = "/all",
    responses(
        (status = 200, description = "All the informations, in YAML format"),
    )
)]
async fn all(
    State(state): State<MyState>,
    method: Method,
    headers: HeaderMap,
    addr: RemoteIp,
) -> impl IntoResponse {
    let MyState { db_date, .. } = state;
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE.as_str(), "application/yaml"),
            ("X-IP-Geolocation-By", "https://db-ip.com/"),
            ("X-IP-Geolocation-Date", db_date),
        ],
        serde_yaml::to_string(&fill_struct(state, method, &headers, addr).await)
            .expect("sent yaml"),
    )
}

#[utoipa::path(
    get,
    path = "/all_json",
    responses(
        (status = 200, description = "All the informations, in JSON format"),
    )
)]
async fn all_json(
    State(state): State<MyState>,
    method: Method,
    headers: HeaderMap,
    addr: RemoteIp,
) -> impl IntoResponse {
    let MyState { db_date, .. } = state;
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE.as_str(), "application/json"),
            ("X-IP-Geolocation-By", "https://db-ip.com/"),
            ("X-IP-Geolocation-Date", db_date),
        ],
        serde_json::to_string(&fill_struct(state, method, &headers, addr).await)
            .expect("sent json"),
    )
}

#[inline]
async fn health(State(state): State<MyState>) -> Response {
    let mut res = format!("UP\nDB-IP: {}", state.db_date).into_response();
    let _ = res.extensions_mut().insert(DoNotMonitor);
    res
}
