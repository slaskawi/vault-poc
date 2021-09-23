# K-Stash
Kubernetes-native secure secrets store.

## Why K-Stash?
In environments where Kubernetes Secrets aren't sufficiently secure, K-Stash provides a secret store that runs in Kubernetes/OpenShift environments, uses platform-native constructs where possible, and comes with its own Container Storage Interface (CSI) Driver for securely accessing secrets within containers.

While HashiCorp Vault and other secret stores can provide some of this functionality, it can be difficult to deploy and manage it outside of a Kubernetes cluster. For example, the open source version of Vault does not provide namespace support, making it more difficult to secure in multi-tenant environments. This service aims to simplify the management of secrets.

## Concepts
There are many concepts and layers introduced by K-Stash. Some are inspired by other secret stores. The below sections explain these concepts using a bottom-to-top approach.

### Storage Backends
Storage backends are very simple wrappers for storing data in various types of engines. Storage backends do not provide any encryption services. The barrier manages encryption for secrets storage.

K-Stash can support multiple storage backends. Currently implemented backends:
* In-Memory (`memory`): Secrets are stored in memory and not persisted to disk. This is useful for testing and should not be used in production.
* Etcd (`etcd`): The Etcd key/value store is the recommended backend for production workloads.

### Barrier
The barrier wraps the simple implementation of a storage backend to provide a layer of encryption on top of the storage engine. All reads and writes that happen through the barrier are encrypted by encryption keys.
The barrier also has a keychain to manage multiple encryption keys to allow for them to be rotated regularly. The barrier's keychain is encrypted using gatekeeper keys.
The gatekeeper keys are never stored directly in the storage backend or in memory, so when K-Stash starts, the barrier is sealed and requires unsealing that results in a gatekeeper key that can be used to decrypt the keychain.
Encrypted read and write operations are not possible until the barrier has been unsealed.

### Encryption Key
Encryption keys are managed by the barrier's keychain. The active encryption key can be rotated at any time to ensure all new writes are encrypted with the new active encryption key. Secrets encrypted with older encryption keys are still readable since those older keys are still stored in the barrier's keychain.

### Gatekeeper Key
The barrier's keychain is encrypted using a gatekeeper key. This allows the keychain and its encryption keys to be managed independently. It also ensures that encryption keys cannot be accessed without first unsealing the barrier using a supported unsealing method.

### Unseal Keys
Unseal keys are based on [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing). The gatekeeper key is split (or sharded) into multiple separate unseal keys.
This allows multiple trusted operators to hold one or more keys without requiring a single operator to have all keys.
By combining a certain number of unseal keys (i.e. the threshold), the gatekeeper key can be reconstructed which allows for the barrier to be unsealed.
Unseal keys should be heavily secured, as they not only allow unsealing of the secret store, but other administrative operations.

Unseal keys can also be used to generate gatekeeper tokens (NOTE: these are different than gatekeeper keys). Gatekeeper tokens can simplify and secure the unsealing process by not exposing the underlying unseal keys.

### Gatekeeper
The gatekeeper manages the barrier and its unsealing methods and administrative operations. Unseal keys and gatekeeper tokens are issued by the gatekeeper. It provides mechanisms to rotate encryption keys, gatekeeper keys, and unseal keys.
Being able to rotate these keys at any given time increases the security of the system and reduces the possibility of data leakage.

### Initializing
When K-Stash is first started, it is uninitialized, meaning that it has no encryption keys, gatekeeper keys, or unseal keys. An initialization must take place where unseal keys are generated for the first time.
As mentioned earlier, unseal keys should be guarded with care. These keys are used to reconstruct the gatekeeper key, which is then used to decrypt the barrier's keychain to allow for encrypted read and write operations.

### Gatekeeper Tokens
Normally, unsealing the barrier requires unseal keys to reconstruct the gatekeeper key. However, when automating the unseal process, you will usually run into the "zero secret" issue, which creates a sort of chicken and egg problem.
In order to use the secret store, you need yet another secret to unlock it. In this case, unseal keys can grant undesired levels of permissions. Gatekeeper tokens provide a way to unseal K-Stash without exposing unseal keys.
These tokens do not serve any purpose other than unsealing the barrier and cannot be used for priviledge escalation. They should still be considered secrets, but do not require the same level of protection that unseal keys do.

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