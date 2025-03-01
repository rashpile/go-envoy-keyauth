build:
	docker build -t go-envoy-keyauth-builder . && docker run --rm -v "$$PWD/dist:/output" go-envoy-keyauth-builder
run:
	cd example; docker compose up
