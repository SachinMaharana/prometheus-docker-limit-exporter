use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct DockerHub {
    username: String,
    password: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Token {
    pub token: String,
}

impl DockerHub {
    pub fn new(username: String, password: String) -> DockerHub {
        DockerHub { username, password }
    }

    pub async fn get_token(&self) -> Result<Token, Box<dyn std::error::Error>> {
        let token_url = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:ratelimitpreview/test:pull";

        if !self.username.is_empty() && !self.password.is_empty() {
            log::info!("Using Authenticated Token");
            let token_response: Token = reqwest::Client::new()
                .get(token_url)
                .basic_auth(&self.username, Some(&self.password))
                .send()
                .await?
                .json()
                .await?;

            return Ok(token_response);
        }

        log::info!("Using Anonymous Token");
        let token_response: Token = reqwest::Client::new()
            .get(token_url)
            .send()
            .await?
            .json()
            .await?;
        Ok(token_response)
    }

    pub async fn get_docker_limits(
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
pub struct Claims {
    exp: usize,
}
