use std::net::SocketAddr;

use hyper::body::Incoming;
use hyper::header::CONTENT_TYPE;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper::Response;
use hyper_util::rt::TokioIo;
use lazy_static::lazy_static;
use prometheus::{Encoder, TextEncoder, IntCounterVec, register_int_counter_vec};
use tokio::net::TcpListener;

type BoxedErr = Box<dyn std::error::Error + Send + Sync + 'static>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MetricsType {
    Success,
    Failure,
}

lazy_static! {
    static ref ISSUE_SUCCESS: IntCounterVec = register_int_counter_vec!(
        "faythe_issue_successes",
        "Succesfully issued certificates.",
        &["cert"]
    )
    .unwrap();
    static ref ISSUE_FAILURE: IntCounterVec = register_int_counter_vec!(
        "faythe_issue_failures",
        "Failed certificate issue attempts.",
        &["cert"]
    )
    .unwrap();
}

pub fn new_event(cert_name: &str, event_type: MetricsType) {
    match event_type {
        MetricsType::Success => ISSUE_SUCCESS.with_label_values(&[cert_name]).inc(),
        MetricsType::Failure => ISSUE_FAILURE.with_label_values(&[cert_name]).inc(),
    }
}

async fn serve_req(req: Request<Incoming>) -> Result<Response<String>, BoxedErr> {
    let _whole_body = req.into_body();
    let encoder = TextEncoder::new();

    let metric_families = prometheus::gather();
    let body = encoder.encode_to_string(&metric_families)?;

    let response = Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .body(body)?;

    Ok(response)
}

pub async fn serve(port: u16) -> Result<(), BoxedErr> {
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    println!("Listening on http://{}", addr);
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        let service = service_fn(serve_req);
        if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
            eprintln!("server error: {:?}", err);
        };
    }
}
