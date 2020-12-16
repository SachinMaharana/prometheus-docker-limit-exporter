FROM rust:1.48 as builder

RUN USER=root cargo new --bin prom-docker-limit-exporter
WORKDIR ./prom-docker-limit-exporter
COPY ./Cargo.toml ./Cargo.toml
RUN cargo build --release
RUN rm src/*.rs

ADD . ./

# RUN ls ./target/release/deps/
# RUN rm ./target/release/deps/prom-docker-limit-exporter*
RUN cargo clean
RUN cargo build --release


FROM debian:buster-slim
ARG APP=/usr/src/app

RUN apt-get update \
    && apt-get install -y ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8080

ENV TZ=Etc/UTC \
    APP_USER=appuser

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

COPY --from=builder /prom-docker-limit-exporter/target/release/prom-docker-limit-exporter ${APP}/prom-docker-limit-exporter

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

CMD ["./prom-docker-limit-exporter"]