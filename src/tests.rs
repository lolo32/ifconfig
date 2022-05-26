use std::net::Ipv4Addr;

use async_std::path::Path;
use pretty_assertions::assert_eq;
use tide::{
    http::{self, Method, Url},
    StatusCode,
};

use super::*;

const LOCALES: &str = "fr_FR; en_US";
const ACCEPT_VALUE: &str =
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
const ENCODING_VALUE: &str = "gzip, deflate, br";
const UA_VALUE:&str="User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:98.0) Gecko/20100101 Firefox/98.0";
const PEER_ADDR: &str = "93.184.216.34";
const PEER_ADDR_GOOGLE_CO_UK: &str = "216.58.213.67";
const PEER_PORT: &str = "65500";

async fn gen_test_app(hostname: Option<&str>) -> Server<State> {
    let (db_ip, db_date) = get_db(None);
    init_app(
        hostname.unwrap_or("test.localhost").to_owned(),
        Arc::new(db_ip),
        db_date,
    )
    .await
}

async fn gen_request(dest: &str) -> http::Request {
    let mut request = http::Request::new(
        Method::Get,
        Url::parse(&format!("http://test.localhost{}", dest)).expect("url"),
    );
    request.set_peer_addr(Some(format!("{}:{}", PEER_ADDR, PEER_PORT)));
    let _none = request.insert_header(headers::HOST, "test.localhost");
    let _none = request.insert_header(headers::ACCEPT_LANGUAGE, LOCALES);
    let _none = request.insert_header(headers::ACCEPT, ACCEPT_VALUE);
    let _none = request.insert_header(headers::ACCEPT_ENCODING, ENCODING_VALUE);
    let _none = request.insert_header(headers::USER_AGENT, UA_VALUE);
    request
}

async fn get_response(hostname: Option<&str>, dest: &str) -> http::Response {
    let request = gen_request(dest).await;
    let app = gen_test_app(hostname).await;
    app.respond(request).await.expect("request handled")
}

#[async_std::test]
async fn test_lang() {
    let mut response = get_response(None, "/lang").await;
    assert_eq!(response.status(), StatusCode::Ok);

    let body = response.body_string().await.expect("body received");

    assert_eq!(&body, LOCALES);
}

#[async_std::test]
async fn test_mime() {
    let mut response = get_response(None, "/mime").await;
    assert_eq!(response.status(), StatusCode::Ok);

    let body = response.body_string().await.expect("body received");

    assert_eq!(&body, ACCEPT_VALUE);
}

#[async_std::test]
async fn test_encoding() {
    let mut response = get_response(None, "/encoding").await;
    assert_eq!(response.status(), StatusCode::Ok);

    let body = response.body_string().await.expect("body received");

    assert_eq!(&body, ENCODING_VALUE);
}

#[async_std::test]
async fn test_ua() {
    let mut response = get_response(None, "/ua").await;
    assert_eq!(response.status(), StatusCode::Ok);

    let body = response.body_string().await.expect("body received");

    assert_eq!(&body, UA_VALUE);
}

#[async_std::test]
async fn test_country_code() {
    {
        // With standard process + example.org
        let mut response = get_response(None, "/country_code").await;
        assert_eq!(response.status(), StatusCode::Ok);
        assert_eq!(
            response.header("X-IP-Geolocation-By").map(|v| v.as_str()),
            Some("https://db-ip.com/")
        );

        let body = response.body_string().await.expect("body received");

        assert_eq!(&body, "US");
    }
    let app = gen_test_app(None).await;
    {
        // With IP of Google.co.uk
        let mut request = gen_request("/country_code").await;
        request.set_peer_addr(Some(format!("{}:{}", PEER_ADDR_GOOGLE_CO_UK, PEER_PORT)));

        let mut response: http::Response = app.respond(request).await.expect("request handled");
        assert_eq!(response.status(), StatusCode::Ok);

        let body = response.body_string().await.expect("body received");

        assert_eq!(&body, "GB");
    }
    {
        // With no country IP (localhost)
        let mut request = gen_request("/country_code").await;
        request.set_peer_addr(Some(format!("127.0.0.1:{}", PEER_PORT)));

        let mut response: http::Response = app.respond(request).await.expect("request handled");
        assert_eq!(response.status(), StatusCode::Ok);

        let body = response.body_string().await.expect("body received");

        assert_eq!(&body, "");
    }
}

#[async_std::test]
async fn test_ip() {
    {
        // With standard process + example.org
        let mut response = get_response(None, "/ip").await;
        assert_eq!(response.status(), StatusCode::Ok);

        let body = response.body_string().await.expect("body received");

        assert_eq!(&body, PEER_ADDR);
    }
    let app = gen_test_app(None).await;
    {
        // With IP of Google.co.uk
        let mut request = gen_request("/ip").await;
        request.set_peer_addr(Some(format!("{}:{}", PEER_ADDR_GOOGLE_CO_UK, PEER_PORT)));

        let mut response: http::Response = app.respond(request).await.expect("request handled");
        assert_eq!(response.status(), StatusCode::Ok);

        let body = response.body_string().await.expect("body received");

        assert_eq!(&body, PEER_ADDR_GOOGLE_CO_UK);
    }
    {
        // With no country IP (localhost)
        let mut request = gen_request("/ip").await;
        request.set_peer_addr(Some(format!("127.0.0.1:{}", PEER_PORT)));

        let mut response: http::Response = app.respond(request).await.expect("request handled");
        assert_eq!(response.status(), StatusCode::Ok);

        let body = response.body_string().await.expect("body received");

        assert_eq!(&body, "127.0.0.1");
    }
    {
        // From Forwarded header, GB instead of US
        let mut request = gen_request("/ip").await;
        request.set_peer_addr(Some(format!("{}:{}", PEER_ADDR, PEER_PORT)));
        let _none_value = request.insert_header("X-Real-Ip", PEER_ADDR_GOOGLE_CO_UK);

        let mut response: http::Response = app.respond(request).await.expect("request handled");
        assert_eq!(response.status(), StatusCode::Ok);

        let body = response.body_string().await.expect("body received");

        assert_eq!(&body, PEER_ADDR_GOOGLE_CO_UK);
    }
}

#[async_std::test]
async fn test_host() {
    let app = gen_test_app(None).await;
    {
        // With Google.co.uk
        let mut request = gen_request("/host").await;
        request.set_peer_addr(Some(format!("188.165.47.122:{}", PEER_PORT)));

        let mut response: http::Response = app.respond(request).await.expect("request handled");
        assert_eq!(response.status(), StatusCode::Ok);

        let body = response.body_string().await.expect("body received");

        assert_eq!(&body, "mx1.ovh.net");
    }
    {
        // With no country IP (localhost)
        let mut request = gen_request("/host").await;
        request.set_peer_addr(Some(format!("127.0.0.1:{}", PEER_PORT)));

        let mut response: http::Response = app.respond(request).await.expect("request handled");
        assert_eq!(response.status(), StatusCode::Ok);

        let body = response.body_string().await.expect("body received");

        assert_eq!(&body, "localhost");
    }
}

#[async_std::test]
async fn test_all_yaml() {
    let mut response = get_response(None, "/all").await;
    assert_eq!(response.status(), StatusCode::Ok);
    assert_eq!(
        response.header("X-IP-Geolocation-By").map(|v| v.as_str()),
        Some("https://db-ip.com/")
    );
    assert_eq!(
        response.header("X-IP-Geolocation-Date").map(|v| v.as_str()),
        Some(MMDB_DATE)
    );

    let body = response.body_string().await.expect("body received");

    assert_eq!(
        &body,
        r#"---
ip: 93.184.216.34
host: 93.184.216.34
ua: "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:98.0) Gecko/20100101 Firefox/98.0"
lang: fr_FR; en_US
encoding: "gzip, deflate, br"
method: GET
mime: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
referer: ""
country_code: US
"#
    );
}

#[async_std::test]
async fn test_all_json() {
    let mut response = get_response(None, "/all.json").await;
    assert_eq!(response.status(), StatusCode::Ok);
    assert_eq!(
        response.header("X-IP-Geolocation-By").map(|v| v.as_str()),
        Some("https://db-ip.com/")
    );
    assert_eq!(
        response.header("X-IP-Geolocation-Date").map(|v| v.as_str()),
        Some(MMDB_DATE)
    );

    let body = response.body_string().await.expect("body received");

    assert_eq!(
        &body,
        r#"{"ip":"93.184.216.34","host":"93.184.216.34","ua":"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:98.0) Gecko/20100101 Firefox/98.0","lang":"fr_FR; en_US","encoding":"gzip, deflate, br","method":"GET","mime":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8","referer":"","country_code":"US"}"#
    );
}

#[async_std::test]
async fn test_all() {
    let mut response = get_response(None, "/").await;
    assert_eq!(response.status(), StatusCode::Ok);
    assert_eq!(
        response.header("X-IP-Geolocation-By").map(|v| v.as_str()),
        Some("https://db-ip.com/")
    );
    assert_eq!(
        response.header("X-IP-Geolocation-Date").map(|v| v.as_str()),
        Some(MMDB_DATE)
    );

    let body = response.body_string().await.expect("body received");

    assert!(body.contains("What is my ip address? - <small>test.localhost</small>\n"));
    // Country
    assert!(body.contains("<div class=\"col-sm-9\">US</div>\n"));
    // IP
    assert!(body.contains(
        "<div class=\"col-sm-3\">IP Address</div><div class=\"col-sm-9\">93.184.216.34</div>\n"
    ));
    // Footer for DB-IP
    assert!(body.contains(&format!("<p><a href='https://db-ip.com'>IP Geolocation by DB-IP</a> &mdash; <em>(in date of {})</em></p>\n", MMDB_DATE)));
}

#[async_std::test]
async fn test_all_curl() {
    let mut request = gen_request("/").await;
    let _old_value = request.insert_header(headers::USER_AGENT, "curl/7.82.0");

    let app = gen_test_app(None).await;
    let mut response: http::Response = app.respond(request).await.expect("request handled");
    assert_eq!(response.status(), StatusCode::Ok);
    assert_eq!(
        response.header("X-IP-Geolocation-By").map(|v| v.as_str()),
        None
    );
    assert_eq!(
        response.header("X-IP-Geolocation-Date").map(|v| v.as_str()),
        None
    );

    let body = response.body_string().await.expect("body received");

    assert_eq!(&body, PEER_ADDR);
}

#[async_std::test]
async fn test_db_ip() {
    let (db_ip, db_date) = get_db(Some(
        Path::new("assets/GeoLite2-Country-Test-2022-02.mmdb")
            .to_str()
            .expect("path to database")
            .to_owned(),
    ));
    assert_eq!(db_date, "2022-02");

    let country = db_ip
        .lookup(IpAddr::V4(Ipv4Addr::new(50, 114, 0, 1)))
        .expect("country")
        .country
        .expect("country")
        .iso_code
        .expect("country code");
    assert_eq!(country, "US");
}
