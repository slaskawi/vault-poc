# Name TDB

# Developing
The following are required:
* Go v1.16+
* Protobuf compiler v3+
    * Fedora: `sudo dnf install protobuf-compiler`
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