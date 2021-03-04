// #![deny(warnings)]
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate prometheus;
extern crate pretty_env_logger;
#[macro_use]
extern crate log;

use broadcast::{Receiver, Sender};
use futures::{Stream, StreamExt};
use jsonwebtoken::{dangerous_insecure_decode_with_validation, Algorithm, Validation};
use prometheus::{Gauge, Registry};
use std::env;
use std::result::Result;
use std::time::Duration;
use tokio::sync::broadcast;
use warp::{sse::ServerSentEvent, Filter};
use warp::{Rejection, Reply};

use prom_docker_limit_exporter::docker::{Claims, DockerHub, Token};

lazy_static! {
    static ref DOCKER_GAUGE_REMAINING: Gauge = register_gauge!(opts!(
        "dockerhub_limit_remaining_requests_total",
        "Docker Hub Rate Limit Remaining Requests",
        labels! {"docker" => "remaining"}
    ))
    .unwrap();
    static ref DOCKER_GAUGE_LIMIT: Gauge = register_gauge!(opts!(
        "dockerhub_limit_requests_total",
        "Docker Hub Rate Limit Requests",
        labels! {"docker" => "limit"}
    ))
    .unwrap();
    pub static ref REGISTRY: Registry = Registry::new();
}

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    pretty_env_logger::init();

    register_custom_metrics();

    let metrics_route = warp::path!("metrics").and_then(metrics_handler);

    let (tx, mut rx) = broadcast::channel(15);
    let tx1 = tx.clone();

    let username = env::var("DOCKERHUB_USERNAME").unwrap_or_default();
    let password = env::var("DOCKERHUB_PASSWORD").unwrap_or_default();

    let docker_client = DockerHub::new(username, password);

    tokio::spawn(metrics_collector(docker_client.clone(), tx));

    tokio::spawn(async move {
        loop {
            let received = rx.recv().await;
            match received {
                Ok((limit, remain)) => {
                    info!("{}, {}", limit, remain);
                    set_metrics(limit, remain);
                }
                Err(e) => {
                    error!("Error: {:?}", e);
                    std::process::exit(1);
                }
            }
        }
    });

    // TODO: Expose API for limit information. It's incomplete now.
    let tick_route = warp::path("ticks").and(warp::get()).map(move || {
        let rx1 = tx1.subscribe();

        let event_stream = metrics_stream(rx1);
        warp::sse::reply(warp::sse::keep_alive().stream(event_stream))
    });

    let routes = metrics_route.or(tick_route);

    warp::serve(routes).run(([0, 0, 0, 0], 8080)).await;
}

// TODO: Expose API for limit information. It's incomplete now.
fn metrics_stream(
    rx: Receiver<(f64, f64)>,
) -> impl Stream<Item = Result<impl ServerSentEvent + Send + 'static, warp::Error>> + Send + 'static
{
    rx.map(|s| match s {
        Ok((c, _)) => Ok(warp::sse::data(c)),
        Err(e) => {
            error!("Error in receiving: {}", e);
            std::process::exit(1);
        }
    })
}

fn register_custom_metrics() {
    REGISTRY
        .register(Box::new(DOCKER_GAUGE_REMAINING.clone()))
        .expect("collector can be registered");
    REGISTRY
        .register(Box::new(DOCKER_GAUGE_LIMIT.clone()))
        .expect("collector can be registered");
}

async fn metrics_handler() -> Result<impl Reply, Rejection> {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&REGISTRY.gather(), &mut buffer) {
        eprintln!("could not encode custom metrics: {}", e);
    };
    let res = match String::from_utf8(buffer.clone()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("custom metrics could not be from_utf8'd: {}", e);
            String::default()
        }
    };
    buffer.clear();
    Ok(res)
}

async fn metrics_collector(docker_client: DockerHub, tx: Sender<(f64, f64)>) {
    let mut collect_interval = tokio::time::interval(Duration::from_secs(10));

    let mut token = extract_token(&docker_client).await;

    loop {
        collect_interval.tick().await;

        if is_valid_token(&token) {
            let (limit, remain) = extract_limit_remain(&token, &docker_client).await;
            if let Some((l, r)) = cleanup_metrics(limit, remain) {
                tx.send((l, r)).unwrap();
            }
        } else {
            error!("Invalid Token, Renewing");
            token = extract_token(&docker_client).await;
            continue;
        }
    }
}

fn cleanup_metrics(limit: String, remain: String) -> Option<(f64, f64)> {
    if limit.is_empty() && remain.is_empty() {
        warn!("Limit and Remain is Empty.");
        return None;
    }
    let limit_split: Vec<&str> = limit.as_str().split(';').collect();
    let remain_split: Vec<&str> = remain.as_str().split(';').collect();

    if !limit_split.is_empty() && !remain_split.is_empty() {
        let final_limit = limit_split[0].to_string().parse().unwrap();
        let final_remain = remain_split[0].to_string().parse().unwrap();

        Some((final_limit, final_remain))
    } else {
        warn!("Limit Vector and Remain Vector is Empty");
        None
    }
}

fn set_metrics(limit: f64, remain: f64) {
    DOCKER_GAUGE_LIMIT.set(limit);
    DOCKER_GAUGE_REMAINING.set(remain);
}

async fn extract_token(dc: &DockerHub) -> Token {
    let token = match dc.get_token().await {
        Ok(t) => t,
        Err(e) => {
            if let Some(err) = e.downcast_ref::<reqwest::Error>() {
                error!("Request Error: {}", err);
                std::process::exit(1);
            }
            if let Some(err) = e.downcast_ref::<config::ConfigError>() {
                error!("Config Error: {}", err);
                std::process::exit(1);
            }
            error!("Unknown Error: {}", e);
            std::process::exit(1);
        }
    };
    token
}

async fn extract_limit_remain(token: &Token, dc: &DockerHub) -> (String, String) {
    let limit_remain = match dc.get_docker_limits(token.clone()).await {
        Ok(lr) => lr,
        Err(e) => {
            if let Some(err) = e.downcast_ref::<reqwest::Error>() {
                error!("Request Error: {}", err);
                std::process::exit(1);
            }
            if let Some(err) = e.downcast_ref::<config::ConfigError>() {
                error!("Config Error: {}", err);
                std::process::exit(1);
            }
            error!("Unknown Error: {}", e);
            std::process::exit(1);
        }
    };

    limit_remain
}

fn is_valid_token(token: &Token) -> bool {
    let token_validate = dangerous_insecure_decode_with_validation::<Claims>(
        &token.token,
        &Validation::new(Algorithm::RS256),
    );

    if let Err(e) = token_validate {
        match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => return false,
            _ => {
                error!("Unknown Error: {:?}", e);
                std::process::exit(1);
            }
        }
    }
    true
}
