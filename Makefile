IMAGE_NAME=prom-docker-limit-exporter

.PHONY: docker

docker:
	docker build -t $(IMAGE_NAME) .
	docker tag $(IMAGE_NAME) sachinnicky/$(IMAGE_NAME)


