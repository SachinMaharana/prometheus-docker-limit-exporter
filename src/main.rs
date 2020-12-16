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
use warp::{Filter};
use warp::{Rejection, Reply};

// const TN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlDK2pDQ0FwK2dBd0lCQWdJQkFEQUtCZ2dxaGtqT1BRUURBakJHTVVRd1FnWURWUVFERXpzeVYwNVpPbFZMUzFJNlJFMUVVanBTU1U5Rk9reEhOa0U2UTFWWVZEcE5SbFZNT2tZelNFVTZOVkF5VlRwTFNqTkdPa05CTmxrNlNrbEVVVEFlRncweU1ERXlNREV5TXpJek1ESmFGdzB5TVRFeU1ERXlNekl6TURKYU1FWXhSREJDQmdOVkJBTVRPemRhVFRVNlZVb3pORHBMVlZkTU9rMURSMWs2VkZCQk5EcEZRVkZMT2tSWVRqWTZRMVZWUkRwWU5sbFNPa3hOU0VVNlJFSlFRanBTVGtwRk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBMWRLUC83R2dGMmRLWFY4TnpTZzkyTEJaMDlmVkhHeDZMcklLUHplenVoL2VJZExlUlZ0L1NxVnFBN0J5eU5aVlFGRGs5MjkvUllXYXFlbkFmeUU4Rm56TUtRaDhObHFyKzloNUxVajFCTFdrOHNmMmoyRjdVZ1o1SkU4WGJhZUlYc3F0cHQ4bWEzbHZWNFUyeGovNmp0TWNKc3ZvVXp0dXhOQ1FwSGhBVHA3NVNNWERQUXNPNEFYZEJiQWt1V3QvRW9UMW00TGZHVFkvL2VuSVYxQWlxUTdmdTZyM2F6SWcvUTZOVC9ZanFyV250V1pjS1hvZkh5ZXYyN2tMZGVySEJ4WXRrVWhpQ29JZDJ3VVQrNXN5SDg3elpscnpCeXU2VTlMSDZ2RGNoYkhCUlkxZ0lmOHZnNVBZb0d0UDN6b3VLbXd2RVhQeFpmZ01oZTk0ZFBUNVRRSURBUUFCbzRHeU1JR3ZNQTRHQTFVZER3RUIvd1FFQXdJSGdEQVBCZ05WSFNVRUNEQUdCZ1JWSFNVQU1FUUdBMVVkRGdROUJEczNXazAxT2xWS016UTZTMVZYVERwTlEwZFpPbFJRUVRRNlJVRlJTenBFV0U0Mk9rTlZWVVE2V0RaWlVqcE1UVWhGT2tSQ1VFSTZVazVLUlRCR0JnTlZIU01FUHpBOWdEc3lWMDVaT2xWTFMxSTZSRTFFVWpwU1NVOUZPa3hITmtFNlExVllWRHBOUmxWTU9rWXpTRVU2TlZBeVZUcExTak5HT2tOQk5sazZTa2xFVVRBS0JnZ3Foa2pPUFFRREFnTkpBREJHQWlFQThCZTZjWjRKcHZJVVRXVzhSNFFOODQ3RXE2VXNMcSsyNVhkTkhaRUZEZVlDSVFETlZFaCt6SnhPWVBDcnRhM2xRZUdGTWgwZzVQcGRpdUpsR0l2OTFDMnhPZz09Il19.eyJhY2Nlc3MiOlt7InR5cGUiOiJyZXBvc2l0b3J5IiwibmFtZSI6InJhdGVsaW1pdHByZXZpZXcvdGVzdCIsImFjdGlvbnMiOlsicHVsbCJdLCJwYXJhbWV0ZXJzIjp7InB1bGxfbGltaXQiOiIxMDAiLCJwdWxsX2xpbWl0X2ludGVydmFsIjoiMjE2MDAifX1dLCJhdWQiOiJyZWdpc3RyeS5kb2NrZXIuaW8iLCJleHAiOjE2MDgwOTU0MjcsImlhdCI6MTYwODA5NTEyNywiaXNzIjoiYXV0aC5kb2NrZXIuaW8iLCJqdGkiOiJfYkgzb1ZQQW1YYURaWlh1OTRXRCIsIm5iZiI6MTYwODA5NDgyNywic3ViIjoiIn0.01eUB9hgMAATEfyzBWcon0yeGOzR57o0_0g6xBLvHsS9WWieCt02QuuuE5QxcpgXRUhAESefawMooVOwPSI7z-3gYkMN9Ck4eHU6lAM7W1LbMJUyRiy0c3h_5lZZfVjzNcNASSu7nK8WeO5XMyZaTiPKKXnhK74aQDtXqdT88eRA1zshHpWNm7ARz4vW6qB5ycHbkXxNkFgoxnfC3VFaU3kDV574MAW1uNElWkDN9l-Y6Vwqee_f7RICnyE251ismNmEEvBDtu2kAB7xuOi3Av4PPFMWJa_moZxLeD4aApRFNWI9CB6w3G6djtNwo7tle5O5cjQ5I8Iep1zLJGfyag";

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

fn is_valid_token(token: &Token) -> bool {
    let token_validate = dangerous_insecure_decode_with_validation::<Claims>(
        &token.token,
        &Validation::new(Algorithm::RS256),
    );

    println!("{:?}", token_validate);

    if let Err(e) = token_validate {
        match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => return false,
            _ => {
                println!("{:?}", e);
                std::process::exit(1);
            }
        }
    }
    return true;
}

#[tokio::main]
async fn main() {

    env::set_var("RUST_LOG", "info");
    pretty_env_logger::init();

    register_custom_metrics();

    let metrics_route = warp::path!("metrics").and_then(metrics_handler);

    tokio::task::spawn(data_collector());

    println!("Started on port 8080");
    warp::serve(metrics_route).run(([0, 0, 0, 0], 8080)).await;
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

fn track(limit: String, remain: String) {
    println!("L: {:?}, R: {:?}", limit, remain);
    if limit == "" && remain == "" {
        println!("Empty");
        return;
    }

    let l: Vec<&str> = limit.as_str().split(";").collect();
    let r: Vec<&str> = remain.as_str().split(";").collect();
    if l.len() > 0 && r.len() > 0 {
        let lm = l[0].to_string();
        let rm = r[0].to_string();
        println!("{}, {}", lm, rm);
        DOCKER_GAUGE_LIMIT.set(lm.parse().unwrap());
        DOCKER_GAUGE_REMAINING.set(rm.parse().unwrap());
    } else {
        return;
    }
}

async fn extract_token() -> Token {
    let username = env::var("DOCKERHUB_USERNAME").unwrap_or_default();
    let password = env::var("DOCKERHUB_PASSWORD").unwrap_or_default();

    let docker_client = DockerHub::new(username, password);

    let token = match docker_client.get_token().await {
        Ok(t) => t,
        Err(e) => {
            if let Some(err) = e.downcast_ref::<reqwest::Error>() {
                error!("Request Error: {}", err);
            }
            if let Some(err) = e.downcast_ref::<config::ConfigError>() {
                error!("Config Error: {}", err);
            }
            std::process::exit(1);
        }
    };
    token
}

async fn extract_limit_remain(token: &Token) -> (String, String) {
    let username = env::var("DOCKERHUB_USERNAME").unwrap_or_default();
    let password = env::var("DOCKERHUB_PASSWORD").unwrap_or_default();

    let docker_client = DockerHub::new(username, password);

    let (limit, remain) = match docker_client.get_docker_limits(token.clone()).await {
        Ok(lr) => lr,
        Err(e) => {
            if let Some(err) = e.downcast_ref::<reqwest::Error>() {
                error!("Request Error: {}", err);
            }
            if let Some(err) = e.downcast_ref::<config::ConfigError>() {
                error!("Config Error: {}", err);
            }
            std::process::exit(1);
        }
    };

    (limit, remain)
}

async fn data_collector() {
    let mut collect_interval = tokio::time::interval(Duration::from_secs(10));

    let mut token = extract_token().await;

    loop {
        collect_interval.tick().await;

        if is_valid_token(&token) {
            let (limit, remain) = extract_limit_remain(&token).await;
            println!("Valid Token:Called, {}", remain);
    
            track(limit, remain);
        } else {
            println!("Invalid Token");
            token = extract_token().await;
            continue;
        }

       
    }
}

fn register_custom_metrics() {
    REGISTRY
        .register(Box::new(DOCKER_GAUGE_REMAINING.clone()))
        .expect("collector can be registered");
    REGISTRY
        .register(Box::new(DOCKER_GAUGE_LIMIT.clone()))
        .expect("collector can be registered");
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
        let username = username.clone();
        let password = password.clone();
        DockerHub { username, password }
    }

    async fn get_token(&self) -> Result<Token, Box<dyn std::error::Error>> {
        let token_url = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:ratelimitpreview/test:pull";
        if self.username != "" && self.password != "" {
            info!("Using Authenticated Token");
            let t_r: Token = reqwest::Client::new()
                .get(token_url)
                .basic_auth(&self.username, Some(&self.password))
                .send()
                .await?
                .json()
                .await?;

            return Ok(t_r);
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
    sub: String,
    exp: usize,
}
