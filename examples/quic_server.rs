#![deny(warnings)]
extern crate futures;
extern crate hyper;
extern crate pretty_env_logger;
extern crate serde_json;
extern crate quinn;
extern crate failure;
extern crate structopt;
extern crate tokio;
extern crate tokio_current_thread;
#[macro_use]
extern crate log;

use futures::{future, Future, Stream};

use std::{fs, io};
use std::net::SocketAddr;
use std::path::PathBuf;

use failure::{ResultExt};

use structopt::{StructOpt};

use hyper::{Body, Chunk, Method, Request, Response, StatusCode, header};
use hyper::service::service_fn;
use hyper::server::conn::Http;

use tokio::runtime::current_thread::{Runtime};

#[allow(unused, deprecated)]
use std::ascii::AsciiExt;

#[derive(StructOpt, Debug)]
#[structopt(name = "server")]
struct Opt {
    /// file to log TLS keys to for debugging
    #[structopt(long = "keylog")]
    keylog: bool,
    /// TLS private key in PEM format
    #[structopt(parse(from_os_str), short = "k", long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[structopt(parse(from_os_str), short = "c", long = "cert", requires = "key")]
    cert: Option<PathBuf>,
    /// Enable stateless retries
    #[structopt(long = "stateless-retry")]
    stateless_retry: bool,
    /// Address to listen on
    #[structopt(long = "listen", default_value = "[::1]:4433")]
    listen: SocketAddr,
}


static NOT_FOUND: &[u8] = b"Not Found";
static INDEX: &[u8] = b"<h1>IT LIVES</h1>";

fn response_examples(req: Request<Body>)
                     -> Box<Future<Item=Response<Body>, Error=hyper::Error> + Send>
{
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/") | (&Method::GET, "/index.html") => {
            let body = Body::from(INDEX);
            Box::new(future::ok(Response::new(body)))
        },
        (&Method::POST, "/web_api") => {
            // A web api to run against. Uppercases the body and returns it back.
            let body = Body::wrap_stream(req.into_body().map(|chunk| {
                // uppercase the letters
                let upper = chunk.iter().map(|byte| byte.to_ascii_uppercase())
                    .collect::<Vec<u8>>();
                Chunk::from(upper)
            }));
            Box::new(future::ok(Response::new(body)))
        },
        (&Method::GET, "/json") => {
            let data = vec!["foo", "bar"];
            let res = match serde_json::to_string(&data) {
                Ok(json) => {
                    // return a json response
                    Response::builder()
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(json))
                        .unwrap()
                }
                // This is unnecessary here because we know
                // this can't fail. But if we were serializing json that came from another
                // source we could handle an error like this.
                Err(e) => {
                    eprintln!("serializing json: {}", e);

                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from("Internal Server Error"))
                        .unwrap()
                }
            };

            Box::new(future::ok(res))
        }
        _ => {
            // Return 404 not found response.
            let body = Body::from(NOT_FOUND);
            Box::new(future::ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(body)
                .unwrap()))
        }
    }
}

fn main() {
    pretty_env_logger::init();
    let options = Opt::from_args();

    let server_config = quinn::ServerConfig {
        ..Default::default()
    };
    let mut server_config = quinn::ServerConfigBuilder::new(server_config);
    server_config.set_protocols(&[quinn::ALPN_QUIC_HTTP]);

    if options.keylog {
        server_config.enable_keylog();
    }

    if options.stateless_retry {
        server_config.use_stateless_retry(true);
    }

    if let (Some(ref key_path), Some(ref cert_path)) = (options.key, options.cert) {
        let key = fs::read(key_path).context("failed to read private key").unwrap();
        let key = if key_path.extension().map_or(false, |x| x == "der") {
            quinn::PrivateKey::from_der(&key).unwrap()
        } else {
            quinn::PrivateKey::from_pem(&key).unwrap()
        };
        let cert_chain = fs::read(cert_path).context("failed to read certificate chain").unwrap();
        let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
            quinn::CertificateChain::from_certs(quinn::Certificate::from_der(&cert_chain))
        } else {
            quinn::CertificateChain::from_pem(&cert_chain).unwrap()
        };
        server_config.set_certificate(cert_chain, key).context("setting certificates failed").unwrap();
    } else {
        let dirs = directories::ProjectDirs::from("org", "hyper", "hyper-examples").unwrap();
        let path = dirs.data_local_dir();
        let cert_path = path.join("cert.der");
        let key_path = path.join("key.der");
        let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
            Ok(x) => x,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("generating self-signed certificate");
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]);
                let key = cert.serialize_private_key_der();
                let cert = cert.serialize_der();
                fs::create_dir_all(&path).context("failed to create certificate directory").unwrap();
                fs::write(&cert_path, &cert).context("failed to write certificate").unwrap();
                fs::write(&key_path, &key).context("failed to write private key").unwrap();
                (cert, key)
            }
            Err(e) => {
                panic!("failed to read certificate: {}", e);
            }
        };
        let key = quinn::PrivateKey::from_der(&key).unwrap();
        let cert = quinn::Certificate::from_der(&cert).unwrap();
        server_config.set_certificate(quinn::CertificateChain::from_certs(vec![cert]), key).unwrap();
    }

    let mut endpoint = quinn::Endpoint::new();
    // endpoint.logger(log.clone());
    endpoint.listen(server_config.build());

    info!("Listening on {}", options.listen);

    let (_, driver, incoming) = endpoint.bind(options.listen).unwrap();

    let mut runtime = Runtime::new().unwrap();

    runtime.spawn(incoming.for_each( |conn| {
        handle_connection(conn);
        Ok(())
    }));

    runtime.block_on(driver).unwrap();
}

fn handle_connection(conn: quinn::NewConnection) {
    let quinn::NewConnection {
        connection,
        incoming,
    } = conn;

    info!("connection from {}", connection.remote_address());

    // Each stream initiated by the client constitutes a new request.
    tokio_current_thread::spawn(
        incoming
            .map_err(move |e| info!("connection terminated {}", e))
            .for_each(move |stream| {
                handle_request(stream);
                Ok(())
            }),
    );
}

fn handle_request(stream: quinn::NewStream) {
    let stream = match stream {
        quinn::NewStream::Bi(stream) => stream,
        quinn::NewStream::Uni(_) => unreachable!(),
    };

    let c = Http::new().serve_connection(stream, service_fn(move |req| {
        response_examples(req)
    })).map_err(|e| {
        error!("server connection error: {}", e);
    });

    tokio_current_thread::spawn(c)
}