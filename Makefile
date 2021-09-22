GO_FILES=$(shell go list ./... | grep -v /test/sanity)

.PHONY: go-test
go-test:
	go test -count=1 -cover $(GO_FILES) -v

.PHONY: deployment-status
deployment-status:
	-@echo "---- CSI Driver ----"
	-@kubectl get pods -n kube-system | grep csi-secrets-store
	-@kubectl logs daemonset/csi-secrets-store -n kube-system
	-@echo "---- Vault Driver ----"
	-@kubectl get pods -n kube-system | grep vault-poc
	-@kubectl logs daemonset/vault-poc -n kube-system
	-@echo "---- Vault Example ----"
	-@kubectl get pods -n vault-poc
	-@kubectl exec -n vault-poc vault-poc -- ls -ltra /mnt/secrets-store
	-@kubectl exec -n vault-poc vault-poc -- cat /mnt/secrets-store/my-secret-key

.PHONY: deploy-example
deploy-example:
	kubectl apply -f ./deploy/example/

.PHONY: deploy-csi
deploy-csi:
	kubectl apply -f ./deploy/secret-store-csi-driver/

.PHONY: deploy-provider
deploy-provider:
	kubectl apply -f ./deploy/vault-poc-driver/

.PHONY: build-image
build-image:
	docker build . -t slaskawi/vault-poc

.PHONY: push-image
push-image: build-image
	docker push slaskawi/vault-poc

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
		api/v1/kstash.proto