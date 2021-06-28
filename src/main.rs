use async_std_resolver::resolver_from_system_conf;
use async_std_resolver::AsyncStdResolver;
use include_flate::flate;
use std::net::IpAddr;
use std::net::ToSocketAddrs;
use std::str::FromStr;
use tide::http::headers;
use tide::http::headers::HeaderName;
use tide::http::mime;
use tide::Request;
use tide::Response;
use {
    async_std::task::block_on,
    tera::{Context, Tera},
};

#[derive(Clone)]
struct State {
    template: Tera,
    resolver: AsyncStdResolver,
}

flate!(static DB_IP: str from "assets/dbip-country-lite.csv");

const UNKNOWN: &'static str = "unknown";

fn main() -> Result<(), std::io::Error> {
    block_on(async {
        let mut tera = Tera::default();
        tera.add_raw_template("index", include_str!("./templates/index.html"))
            .unwrap();

        let resolver = resolver_from_system_conf().await.unwrap();

        let state = State {
            template: tera,
            resolver,
        };
        let mut app = tide::with_state(state);
        app.at("/").all(index);
        app.at("/ip").all(ip);
        app.at("/host").all(host);
        app.at("/country_code").all(country_code);
        app.at("/ua").all(ua);
        app.at("/port").all(port);
        app.at("/lang").all(lang);
        app.at("/encoding").all(encoding);
        app.at("/mime").all(mime);
        app.at("/forwarded").all(forwarded);
        app.at("/all").all(all);
        app.at("/all.xml").all(all_xml);
        app.at("/all.json").all(all_json);

        app.listen("0.0.0.0:3000".to_socket_addrs()?.collect::<Vec<_>>())
            .await?;
        Ok(())
    })
}

fn peer(remote: Option<&str>) -> (String, String) {
    match remote {
        None => (UNKNOWN.to_owned(), UNKNOWN.to_owned()),
        Some(peer) => match peer.rsplit_once(":") {
            None => (UNKNOWN.to_owned(), UNKNOWN.to_owned()),
            Some((peer, port)) => (peer.to_string(), port.to_string()),
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
                Ok(addr) => resolver
                    .reverse_lookup(addr)
                    .await
                    .unwrap()
                    .iter()
                    .next()
                    .map(|v| v.to_utf8()),
            }
        }
    }
    .unwrap_or("".to_owned())
}
async fn country(peer: &str) -> String {
    "ToDo!".to_owned()
}

async fn index(req: Request<State>) -> tide::Result<Response> {
    let peer = peer(req.peer_addr());

    let ua = match req.header(headers::USER_AGENT).map(|v| v.as_str()) {
        None => ("", ""),
        Some(ua) => ua
            .split_once('/')
            .map(|(soft, _)| (soft, ua))
            .unwrap_or_else(|| (ua, ua)),
    };

    if "" == ua.0 || "curl" == ua.0 {
        return Ok(Response::builder(200).body(peer.0.to_string()).build());
    }

    let resolver = &req.state().resolver;
    let template = &req.state().template;

    let mut context = Context::new();
    context.insert("ifconfig_hostname", "ifconfig_hostname");
    context.insert("ip", &peer.0);
    context.insert("host", &resolve(resolver, req.peer_addr()).await);
    context.insert("port", &peer.1);
    context.insert("ua", ua.1);
    context.insert(
        "lang",
        req.header(headers::ACCEPT_LANGUAGE)
            .map(|v| v.as_str())
            .unwrap_or(""),
    );
    context.insert(
        "encoding",
        req.header(headers::ACCEPT_ENCODING)
            .map(|v| v.as_str())
            .unwrap_or(""),
    );
    context.insert("method", &req.method().to_string());
    context.insert(
        "mime",
        req.header(headers::ACCEPT)
            .map(|v| v.as_str())
            .unwrap_or(""),
    );
    context.insert(
        "referer",
        req.header(headers::REFERER)
            .map(|v| v.as_str())
            .unwrap_or(""),
    );
    context.insert(
        "forwarded",
        req.header(unsafe { HeaderName::from_bytes_unchecked(b"X-Forwarded-For".to_vec()) })
            .map(|v| v.as_str())
            .unwrap_or(""),
    );
    context.insert("country_code", &country(&peer.0).await);
    context.insert("hash_as_yaml", "hash_as_yaml");
    context.insert("hash_as_xml", "hash_as_xmll");
    context.insert("hash_as_json", "hash_as_json");

    Ok(Response::builder(200)
        .body(template.render("index", &context).unwrap())
        .content_type(mime::HTML)
        .build())
}
async fn ip(req: Request<State>) -> tide::Result<String> {
    let peer = peer(req.peer_addr());
    Ok(peer.0)
}
async fn host(req: Request<State>) -> tide::Result<String> {
    let resolver = &req.state().resolver;
    Ok(resolve(resolver, req.peer_addr()).await)
}
async fn country_code(req: Request<State>) -> tide::Result<Response> {
    let peer = peer(req.peer_addr());
    Ok(Response::builder(200)
        .header("X-IP-Geolocation-By", "https://db-ip.com/")
        .body(country(&peer.0).await)
        .build())
}
async fn ua(req: Request<State>) -> tide::Result<String> {
    Ok(req
        .header(headers::USER_AGENT)
        .map(|v| v.as_str())
        .unwrap_or("")
        .to_string())
}
async fn port(req: Request<State>) -> tide::Result<String> {
    let peer = peer(req.peer_addr());
    Ok(peer.1)
}
async fn lang(req: Request<State>) -> tide::Result<String> {
    Ok(req
        .header(headers::ACCEPT_LANGUAGE)
        .map(|v| v.as_str())
        .unwrap_or("")
        .to_string())
}
async fn encoding(req: Request<State>) -> tide::Result<String> {
    Ok(req
        .header(headers::ACCEPT_ENCODING)
        .map(|v| v.as_str())
        .unwrap_or("")
        .to_string())
}
async fn mime(req: Request<State>) -> tide::Result<String> {
    Ok(req
        .header(headers::ACCEPT)
        .map(|v| v.as_str())
        .unwrap_or("")
        .to_string())
}
async fn forwarded(req: Request<State>) -> tide::Result<String> {
    Ok(req
        .header(unsafe { HeaderName::from_bytes_unchecked(b"X-Forwarded-For".to_vec()) })
        .map(|v| v.as_str())
        .unwrap_or("")
        .to_string())
}
async fn all(req: Request<State>) -> tide::Result {
    todo!()
}
async fn all_xml(req: Request<State>) -> tide::Result {
    todo!()
}
async fn all_json(req: Request<State>) -> tide::Result {
    todo!()
}
