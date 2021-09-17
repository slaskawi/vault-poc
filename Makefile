GO_FILES=$(shell go list ./... | grep -v /test/sanity)

.PHONY: go-test
go-test:
	go test -count=1 -cover $(GO_FILES) -v

.PHONY: generate
generate:
	protoc \
		-I ./api/v1 \
		--go_out ./api/v1 \
		--go_opt paths=source_relative \
		--go-grpc_out ./api/v1 \
		--go-grpc_opt paths=source_relative \
		--grpc-gateway_out ./api/v1 \
		--grpc-gateway_opt paths=source_relative \
		--grpc-gateway_opt logtostderr=true \
		api/v1/kvservice.proto