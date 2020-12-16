// #![deny(warnings)]
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate prometheus;
extern crate pretty_env_logger;
#[macro_use]
extern crate log;

use jsonwebtoken::{dangerous_insecure_decode_with_validation, Algorithm, Validation};
use prometheus::{Gauge, Registry};
use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};
use std::env;
use std::result::Result;
use std::time::Duration;
use warp::Filter;
use warp::{Rejection, Reply};

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
        labels! {"docker" => "limits"}
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

    tokio::task::spawn(metrics_collector());

    warp::serve(metrics_route).run(([0, 0, 0, 0], 8080)).await;
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

async fn metrics_collector() {
    let mut collect_interval = tokio::time::interval(Duration::from_secs(15));

    let username = env::var("DOCKERHUB_USERNAME").unwrap_or_default();
    let password = env::var("DOCKERHUB_PASSWORD").unwrap_or_default();

    let docker_client = DockerHub::new(username, password);

    let mut token = extract_token(&docker_client).await;

    loop {
        collect_interval.tick().await;

        if is_valid_token(&token) {
            let (limit, remain) = extract_limit_remain(&token, &docker_client).await;
            set_metrics(limit, remain);
        } else {
            error!("Invalid Token, Renewing");
            token = extract_token(&docker_client).await;
            continue;
        }
    }
}

fn set_metrics(limit: String, remain: String) {
    if limit.is_empty() && remain.is_empty() {
        return;
    }

    let limit_split: Vec<&str> = limit.as_str().split(";").collect();
    let remain_split: Vec<&str> = remain.as_str().split(";").collect();

    if limit_split.len() > 0 && remain_split.len() > 0 {
        let final_limit = limit_split[0].to_string().parse().unwrap();
        let final_remain = remain_split[0].to_string().parse().unwrap();

        info!("{}, {}", final_limit, final_remain);

        DOCKER_GAUGE_LIMIT.set(final_limit);
        DOCKER_GAUGE_REMAINING.set(final_remain);
    } else {
        return;
    }
}

async fn extract_token(dc: &DockerHub) -> Token {
    let token = match dc.get_token().await {
        Ok(t) => t,
        Err(e) => {
            if let Some(err) = e.downcast_ref::<reqwest::Error>() {
                error!("Request Error: {}", err);
            }
            if let Some(err) = e.downcast_ref::<config::ConfigError>() {
                error!("Config Error: {}", err);
            }
            error!("Unknown Error: {}",e);
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
            }
            if let Some(err) = e.downcast_ref::<config::ConfigError>() {
                error!("Config Error: {}", err);
            }
            error!("Unknown Error: {}",e);
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
    return true;
}

struct DockerHub {
    username: String,
    password: String,
}

#[derive(Deserialize, Debug, Clone)]
struct Token {
    token: String,
}

impl DockerHub {
    fn new(username: String, password: String) -> DockerHub {
        // let username = username.clone();
        // let password = password.clone();
        DockerHub { username, password }
    }

    async fn get_token(&self) -> Result<Token, Box<dyn std::error::Error>> {
        let token_url = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:ratelimitpreview/test:pull";

        if !self.username.is_empty() && !self.password.is_empty() {
            info!("Using Authenticated Token");
            let token_response: Token = reqwest::Client::new()
                .get(token_url)
                .basic_auth(&self.username, Some(&self.password))
                .send()
                .await?
                .json()
                .await?;

            return Ok(token_response);
        }

        info!("Using Anonymous Token");
        let token_response: Token = reqwest::Client::new()
            .get(token_url)
            .send()
            .await?
            .json()
            .await?;
        Ok(token_response)
    }

    async fn get_docker_limits(
        &self,
        token: Token,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        let registry_url = "https://registry-1.docker.io/v2/ratelimitpreview/test/manifests/latest";

        let response: reqwest::Response = reqwest::Client::new()
            .head(registry_url)
            .bearer_auth(token.token)
            .send()
            .await?;

        let lm = response
            .headers()
            .get("ratelimit-limit")
            .map(|x| x.to_str())
            .unwrap_or(Ok(""))?
            .into();

        let rm = response
            .headers()
            .get("ratelimit-remaining")
            .unwrap_or(&HeaderValue::from_static(""))
            .to_str()?
            .into();

        Ok((lm, rm))
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    exp: usize,
}
