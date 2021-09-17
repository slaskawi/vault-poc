# OpenShift Secret Store

## Developing
The following are required:
* Go v1.16+
* Protobuf compiler v3+
    * Fedora: `sudo dnf install protobuf-compiler protobuf-devel`
* Protobuf plugins:
    * `go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26`
    * `go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1`
    * `go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway@v2.6.0`
    * `go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@v2.6.0`
* Ensure Go binaries are added to PATH environment variable (i.e. `echo $(go env GOPATH)/bin`)
    * Fedora: Add the following to the bottom of `~/.bash_profile`:
        * `export PATH=$PATH:$HOME/go/bin`
        * Logout and back in
        * Validate: `which protoc-gen-go` should return the path the to `protoc-gen-go` binary
* To edit `.proto` files from VSCode, recommend installing the `vscode-proto3` plugin

### Generating API Files
Using `protoc`, several files in `api/v1` are generated from the `api/v1/kvservice.proto` file. If any changes are made to this file, you can regenerate code files by running `make generate`.