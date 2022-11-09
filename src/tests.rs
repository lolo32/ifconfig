use std::{net::Ipv4Addr, path::Path};

use axum::{http, RouterService};
use hyper::Body;
use pretty_assertions::assert_eq;
use tower::Service;

use super::*;

const LOCALES: &str = "fr_FR; en_US";
const ACCEPT_VALUE: &str =
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";
const ENCODING_VALUE: &str = "gzip, deflate, br";
const UA_VALUE:&str="User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:98.0) Gecko/20100101 Firefox/98.0";
const PEER_ADDR: &str = "93.184.216.34";
const PEER_ADDR_ELYSEE_FR: &str = "185.194.81.29";
const MMDB_DATE: &str = "2022-11";

fn gen_test_app(hostname: Option<&str>) -> RouterService {
    let (db_ip, db_date) = get_db(None);
    init_app(
        hostname.unwrap_or("test.localhost").to_owned(),
        Arc::new(db_ip),
        db_date,
    )
    .into_service()
}

async fn gen_request(dest: &str) -> http::Request<Body> {
    http::Request::builder()
        .method(Method::GET)
        .uri(format!("http://test.localhost{dest}"))
        .header(header::HOST, "test.localhost")
        .header(header::ACCEPT_LANGUAGE, LOCALES)
        .header(header::ACCEPT, ACCEPT_VALUE)
        .header(header::ACCEPT_ENCODING, ENCODING_VALUE)
        .header(header::USER_AGENT, UA_VALUE)
        .header("x-real-ip", PEER_ADDR)
        .body(Body::empty())
        .expect("request")
    // request.set_peer_addr(Some(format!("{}:{}", PEER_ADDR, PEER_PORT)));
}

#[test]
fn test_lang() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            let mut app = gen_test_app(None);
            let request = gen_request("/lang").await;
            let response = app.call(request).await.expect("request handled");

            assert_eq!(response.status(), StatusCode::OK);

            let body = hyper::body::to_bytes(response.into_body())
                .await
                .expect("Body received");

            assert_eq!(&body[..], LOCALES.as_bytes());
        });
}

#[test]
fn test_mime() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            let mut app = gen_test_app(None);
            let request = gen_request("/mime").await;
            let response = app.call(request).await.expect("request handled");

            assert_eq!(response.status(), StatusCode::OK);

            let body = hyper::body::to_bytes(response.into_body())
                .await
                .expect("body received");

            assert_eq!(&body, ACCEPT_VALUE);
        });
}

#[test]
fn test_encoding() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            let mut app = gen_test_app(None);
            let request = gen_request("/encoding").await;
            let response = app.call(request).await.expect("request handled");

            assert_eq!(response.status(), StatusCode::OK);

            let body = hyper::body::to_bytes(response.into_body())
                .await
                .expect("body received");

            assert_eq!(&body, ENCODING_VALUE);
        });
}

#[test]
fn test_ua() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            let mut app = gen_test_app(None);
            let request = gen_request("/ua").await;
            let response = app.call(request).await.expect("request handled");

            assert_eq!(response.status(), StatusCode::OK);

            let body = hyper::body::to_bytes(response.into_body())
                .await
                .expect("body received");

            assert_eq!(&body, UA_VALUE);
        });
}

#[test]
fn test_country_code() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            let mut app = gen_test_app(None);
            {
                // With standard process + example.org
                let request = gen_request("/country_code").await;
                let response = app.call(request).await.expect("request handled");

                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(
                    response
                        .headers()
                        .get("X-IP-Geolocation-By")
                        .map(|v| v.to_str().expect("header value")),
                    Some("https://db-ip.com/")
                );

                let body = hyper::body::to_bytes(response.into_body())
                    .await
                    .expect("body received");

                assert_eq!(&body, "US");
            }
            {
                // With IP of Google.co.uk
                let mut request = gen_request("/country_code").await;
                let _header = request.headers_mut().insert(
                    "x-real-ip",
                    HeaderValue::from_str(PEER_ADDR_ELYSEE_FR).expect("google.co.uk adddress"),
                );

                let response = app.call(request).await.expect("request handled");
                assert_eq!(response.status(), StatusCode::OK);

                let body = hyper::body::to_bytes(response.into_body())
                    .await
                    .expect("body received");

                assert_eq!(&body, "FR");
            }
            {
                // With no country IP (localhost)
                let mut request = gen_request("/country_code").await;
                let _header = request
                    .headers_mut()
                    .insert("x-real-ip", HeaderValue::from_static("127.0.0.1"));

                let response = app.call(request).await.expect("request handled");
                assert_eq!(response.status(), StatusCode::OK);

                let body = hyper::body::to_bytes(response.into_body())
                    .await
                    .expect("body received");

                assert_eq!(&body, "");
            }
        });
}

#[test]
fn test_ip() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            let mut app = gen_test_app(None);
            {
                // With standard process + example.org
                let request = gen_request("/ip").await;
                let response = app.call(request).await.expect("request handled");

                assert_eq!(response.status(), StatusCode::OK);

                let body = hyper::body::to_bytes(response.into_body())
                    .await
                    .expect("body received");

                assert_eq!(&body, PEER_ADDR);
            }
            {
                // With IP of Google.co.uk
                let mut request = gen_request("/ip").await;
                let _header = request
                    .headers_mut()
                    .insert("x-real-ip", HeaderValue::from_static(PEER_ADDR_ELYSEE_FR));
                let response = app.call(request).await.expect("request handled");

                assert_eq!(response.status(), StatusCode::OK);

                let body = hyper::body::to_bytes(response.into_body())
                    .await
                    .expect("body received");

                assert_eq!(&body, PEER_ADDR_ELYSEE_FR);
            }
            {
                // With no country IP (localhost)
                let mut request = gen_request("/ip").await;
                let _header = request
                    .headers_mut()
                    .insert("x-real-ip", HeaderValue::from_static("127.0.0.1"));

                let response = app.call(request).await.expect("request handled");
                assert_eq!(response.status(), StatusCode::OK);

                let body = hyper::body::to_bytes(response.into_body())
                    .await
                    .expect("body received");

                assert_eq!(&body, "127.0.0.1");
            }
            // {
            //     // From Forwarded header, GB instead of US
            //     let mut request = gen_request("/ip").await;
            //     let _header = request
            //         .headers_mut()
            //         .insert("x-real-ip",
            // HeaderValue::from_static("127.0.0.1"));     request.
            // set_peer_addr(Some(format!("{}:{}", PEER_ADDR, PEER_PORT)));
            //     let _none_value = request.insert_header("X-Real-Ip",
            // PEER_ADDR_GOOGLE_CO_UK);

            //     let mut response: http::Response =
            //         app.respond(request).await.expect("request handled");
            //     assert_eq!(response.status(), StatusCode::OK);

            //     let body = response.body_string().await.expect("body
            // received");

            //     assert_eq!(&body, PEER_ADDR_GOOGLE_CO_UK);
            // }
        });
}

#[test]
fn test_host() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            let mut app = gen_test_app(None);
            {
                // With Google.co.uk
                let mut request = gen_request("/host").await;
                let _header = request
                    .headers_mut()
                    .insert("x-real-ip", HeaderValue::from_static("1.1.1.1"));

                let response = app.call(request).await.expect("request handled");
                assert_eq!(response.status(), StatusCode::OK);

                let body = hyper::body::to_bytes(response.into_body())
                    .await
                    .expect("body received");

                assert_eq!(&body, "one.one.one.one");
            }
            {
                // With no country IP (localhost)
                let mut request = gen_request("/host").await;
                let _header = request
                    .headers_mut()
                    .insert("x-real-ip", HeaderValue::from_static("127.0.0.1"));

                let response = app.call(request).await.expect("request handled");
                assert_eq!(response.status(), StatusCode::OK);

                let body = hyper::body::to_bytes(response.into_body())
                    .await
                    .expect("body received");

                assert_eq!(&body, "localhost");
            }
        });
}

#[test]
fn test_all_yaml() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            let mut app = gen_test_app(None);
            let request = gen_request("/all").await;

            let response = app.call(request).await.expect("request handled");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get("X-IP-Geolocation-By")
                    .map(|v| v.to_str().expect("header value")),
                Some("https://db-ip.com/")
            );
            assert_eq!(
                response
                    .headers()
                    .get("X-IP-Geolocation-Date")
                    .map(|v| v.to_str().expect("header value")),
                Some(MMDB_DATE)
            );

            let body = hyper::body::to_bytes(response.into_body())
                .await
                .expect("body received");

            assert_eq!(
                &body,
                r#"ip: 93.184.216.34
host: 93.184.216.34
ua: 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:98.0) Gecko/20100101 Firefox/98.0'
lang: fr_FR; en_US
encoding: gzip, deflate, br
method: GET
mime: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
country_code: US
"#
            );
        });
}

#[test]
fn test_all_json() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            let mut app = gen_test_app(None);
            let request = gen_request("/all.json").await;

            let response = app.call(request).await.expect("request handled");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get("X-IP-Geolocation-By")
                    .map(|v| v.to_str().expect("header value")),
                Some("https://db-ip.com/")
            );
            assert_eq!(
                response
                    .headers()
                    .get("X-IP-Geolocation-Date")
                    .map(|v| v.to_str().expect("header value")),
                Some(MMDB_DATE)
            );

            let body = hyper::body::to_bytes(response.into_body())
                .await
                .expect("body received");

        assert_eq!(
            &body,
            r#"{"ip":"93.184.216.34","host":"93.184.216.34","ua":"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:98.0) Gecko/20100101 Firefox/98.0","lang":"fr_FR; en_US","encoding":"gzip, deflate, br","method":"GET","mime":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8","country_code":"US"}"#
        );
    });
}

#[test]
fn test_all() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            let mut app = gen_test_app(None);
            let request = gen_request("/").await;

            let response = app.call(request).await.expect("request handled");
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get("X-IP-Geolocation-By")
                    .map(|v| v.to_str().expect("header value")),
                Some("https://db-ip.com/")
            );
            assert_eq!(
                response
                    .headers()
                    .get("X-IP-Geolocation-Date")
                    .map(|v| v.to_str().expect("header value")),
                Some(MMDB_DATE)
            );

        let body = hyper::body::to_bytes(response.into_body()).await.expect("body received");
        let body = String::from_utf8(body.to_vec()).expect("html page");

        assert!(body.contains("What is my ip address? - <small>test.localhost</small>\n"));
        // Country
        assert!(body.contains("<div class=\"col-sm-9\">US</div>\n"));
        // IP
        assert!(body.contains("<div class=\"col-sm-3\">IP Address</div><div class=\"col-sm-9\">93.184.216.34</div>\n"));
        // Footer for DB-IP
        assert!(body.contains(&format!("<p><a href='https://db-ip.com'>IP Geolocation by DB-IP</a> &mdash; <em>(in date of {MMDB_DATE})</em></p>\n")));
    });
}

#[test]
fn test_all_curl() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
            let mut app = gen_test_app(None);
            let mut request = gen_request("/").await;
            let _old_value = request
                .headers_mut()
                .insert(header::USER_AGENT, HeaderValue::from_static("curl/7.82.0"));

            let response = app.call(request).await.expect("request handled");

            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .headers()
                    .get("X-IP-Geolocation-By")
                    .map(|v| v.to_str().expect("header value")),
                None
            );
            assert_eq!(
                response
                    .headers()
                    .get("X-IP-Geolocation-Date")
                    .map(|v| v.to_str().expect("header value")),
                None
            );

            let body = hyper::body::to_bytes(response.into_body())
                .await
                .expect("body received");

            assert_eq!(&body, PEER_ADDR);
        });
}

#[test]
fn test_db_ip() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(async {
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
        });
}
