use prometheus_exporter_base::prelude::*;
use prometheus_exporter_base::PrometheusInstance;
use std::collections::HashMap;
use std::sync::RwLock;

use crate::log;

#[derive(Debug, Clone, Default)]
struct MyOptions {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MetricsType {
    Success,
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MetricsEvent {
    pub cert_name: String,
    pub event_type: MetricsType,
}

lazy_static! {
    static ref EVENTS: RwLock<HashMap<MetricsEvent, u64>> = RwLock::new(HashMap::new());
}

pub fn new_event(cert_name: &str, event_type: MetricsType) {
    let event = MetricsEvent {
        cert_name: cert_name.to_string(),
        event_type,
    };
    let mut guard = EVENTS.write().unwrap();
    let new_value = match guard.remove(&event) {
        Some(old_value) => old_value + 1,
        None => 1,
    };
    guard.insert(event, new_value);
}

#[tokio::main]
pub async fn serve(port: u16) {
    let addr = ([0, 0, 0, 0], port).into();
    log::info(&format!("starting metrics server on port: {}", port));

    render_prometheus(
        addr,
        MyOptions::default(),
        |_request, _options| async move {
            let mut successes = PrometheusMetric::build()
                .with_name("faythe_issue_successes")
                .with_metric_type(MetricType::Counter)
                .with_help("Succesfully issued certificates")
                .build();

            let mut failures = PrometheusMetric::build()
                .with_name("faythe_issue_failures")
                .with_metric_type(MetricType::Counter)
                .with_help("Failed certificate issue attempts")
                .build();

            for (event, count) in EVENTS.read().unwrap().iter() {
                match &event.event_type {
                    MetricsType::Success => {
                        successes.render_and_append_instance(
                            &PrometheusInstance::new()
                                .with_label("cert", event.cert_name.as_str())
                                .with_value(count.clone()),
                        );
                    }
                    MetricsType::Failure => {
                        failures.render_and_append_instance(
                            &PrometheusInstance::new()
                                .with_label("cert", event.cert_name.as_str())
                                .with_value(count.clone()),
                        );
                    }
                }
            }
            Ok(format!("{}\n{}", successes.render(), failures.render()))
        },
    )
    .await;
}
