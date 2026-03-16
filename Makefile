IMAGE   := anoopvt/beacon_utils
VERSION ?= latest

.PHONY: build push release run stop logs

build:
	docker build -t $(IMAGE):$(VERSION) .

push:
	docker push $(IMAGE):$(VERSION)

release: build push

run:
	docker compose up -d

stop:
	docker compose down

logs:
	docker compose logs -f
