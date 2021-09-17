GO_FILES=$(shell go list ./... | grep -v /test/sanity)

.PHONY: go-test
go-test:
	go test -count=1 -cover $(GO_FILES) -v
