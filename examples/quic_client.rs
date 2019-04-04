#![deny(warnings)]
extern crate hyper;
extern crate futures;
extern crate pretty_env_logger;
extern crate structopt;
extern crate tokio_current_thread;
extern crate quinn;
#[macro_use]
extern crate log;

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use futures::{Poll};
use hyper::client::connect::{Connect, Connected, Destination};
use hyper::rt::{self, Future, Stream};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
#[structopt(name = "quic_client")]
struct Opt {
    /// Perform NSS-compatible TLS key logging to the file specified in `SSLKEYLOGFILE`.
    #[structopt(long = "keylog")]
    keylog: bool,

    url: hyper::Uri,

    /// Custom certificate authority to trust, in DER format
    #[structopt(parse(from_os_str), long = "ca")]
    ca: Option<PathBuf>,
}

#[derive(Clone)]
pub struct QuicConnector {
    endpoint: quinn::Endpoint,
}

impl QuicConnector {

    pub fn new(endpoint: quinn::Endpoint, driver: quinn::Driver) -> Self {
        tokio_current_thread::spawn(driver.map_err(|e| eprintln!("IO error: {}", e)));

        QuicConnector {
            endpoint,
        }
    }
}

impl Connect for QuicConnector
{
    type Transport = quinn::BiStream;
    type Error = io::Error;
    type Future = QuicConnecting<Self::Transport>;

    fn connect(&self, dst: Destination) -> Self::Future {
        let host = dst.host();
        let port = dst.port().unwrap_or(4433);

        // TODO: add code to resolve named hosts
        let ip = std::net::IpAddr::parse(host);
        let remote = std::net::SocketAddr::new(ip, port);

        let connecting = self.endpoint.connect(&remote, host);
        let fut: BoxedFut<Self::Transport> =
            Box::new(connecting.map(|conn| {
                (conn.open_bi(), Connected::new())
            }));

        QuicConnecting(fut)
    }
}

type BoxedFut<T> = Box<Future<Item=(T, Connected), Error=io::Error>>;

pub struct QuicConnecting<T>(BoxedFut<T>);

impl<T> Future for QuicConnecting<T> {
    type Item = (T, Connected);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll()
    }
}

fn main() {
    let options = Opt::from_args();

    pretty_env_logger::init();

    let mut endpoint = quinn::Endpoint::new();
    let mut client_config = quinn::ClientConfigBuilder::new();
    client_config.set_protocols(&[quinn::ALPN_QUIC_HTTP]);
    if options.keylog {
        client_config.enable_keylog();
    }
    if let Some(ca_path) = options.ca {
        client_config
            .add_certificate_authority(quinn::Certificate::from_der(&fs::read(&ca_path)?)?)?;
    } else {
        let dirs = directories::ProjectDirs::from("org", "quinn", "quinn-examples").unwrap();
        match fs::read(dirs.data_local_dir().join("cert.der")) {
            Ok(cert) => {
                client_config.add_certificate_authority(quinn::Certificate::from_der(&cert)?)?;
            }
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("local server certificate not found");
            }
            Err(e) => {
                error!("failed to open local server certificate: {}", e);
            }
        }
    }

    endpoint.default_client_config(client_config.build());

    // Run the runtime with the future trying to fetch and print this URL.
    //
    // Note that in more complicated use cases, the runtime should probably
    // run on its own, and futures should just be spawned into it.
    rt::run(fetch_url(options.url, endpoint));
}

fn fetch_url(url: hyper::Uri, &endpoint_builder: quinn::EndpointBuilder) -> impl Future<Item=(), Error=()> {
    let (endpoint, driver, _) = endpoint_builder.bind("[::]:0")?;

    let quic = QuicConnector::new(endpoint, driver).unwrap();
    let client = hyper::Client::builder()
        .build::<_, hyper::Body>(quic);

    client
        // Fetch the url...
        .get(url)
        // And then, if we get a response back...
        .and_then(|res| {
            println!("Response: {}", res.status());
            println!("Headers: {:#?}", res.headers());

            // The body is a stream, and for_each returns a new Future
            // when the stream is finished, and calls the closure on
            // each chunk of the body...
            res.into_body().for_each(|chunk| {
                io::stdout().write_all(&chunk)
                    .map_err(|e| panic!("example expects stdout is open, error={}", e))
            })
        })
        // If all good, just tell the user...
        .map(|_| {
            println!("\n\nDone.");
        })
        // If there was an error, let the user know...
        .map_err(|err| {
            eprintln!("Error {}", err);
        })
}
