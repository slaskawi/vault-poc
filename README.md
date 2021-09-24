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
The barrier's keychain is encrypted using a gatekeeper key. This allows the keychain and its encryption keys to be managed independently. It also ensures that encryption keys cannot be accessed without first unsealing the barrier using a supported unsealing method. The gatekeeper key is highly protected, as it is never kept in memory and can never leave the gatekeeper. Whenever this key is needed, it must be reconstructed from unseal keys or gatekeeper tokens.

### Unseal Keys
Unseal keys are based on [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing). The gatekeeper key is split (or sharded) into multiple separate unseal keys.
This allows multiple trusted operators to hold one or more keys without requiring a single operator to have all keys.
By combining a certain number of unseal keys (i.e. the threshold), the gatekeeper key can be reconstructed which allows for the barrier to be unsealed.
Unseal keys should be heavily secured. Rotating unseal keys automatically rotates the gatekeeper key.

Unseal keys can also be used to generate gatekeeper tokens (NOTE: these are different from gatekeeper keys). Gatekeeper tokens can simplify and secure the unsealing process while protecting the unseal keys.
Gatekeeper tokens can only be used for barrier seal/unseal operations and do not grant encrypted read/write permissions to the barrier.

### Access Keys
Access keys are used to generate local access tokens, which can be used to grant root access to data encrypted in the barrier. Access keys should be heavily secured.

### Gatekeeper
The gatekeeper manages the barrier and its unsealing methods and administrative operations. Unseal keys and gatekeeper tokens are issued by the gatekeeper. It provides mechanisms to rotate encryption keys and unseal keys.
Being able to rotate these keys at any given time increases the security of the system and reduces the possibility of data leakage.

### Initializing
When K-Stash is first started, it is uninitialized, meaning that it has no encryption keys or unseal keys. An initialization must take place where unseal keys are generated for the first time.
As mentioned earlier, unseal keys should be guarded with care. These keys are used to reconstruct the gatekeeper key, which is then used to decrypt the barrier's keychain to allow for encrypted read and write operations.

Initializing also provides an access keys, which are used for generating local access tokens. This key should also be guarded with care, as it can generate root and audit access tokens that have access to all data in the barrier.

### Gatekeeper Tokens
Normally, unsealing the barrier requires unseal keys to reconstruct the gatekeeper key. However, when automating the unseal process, you will usually run into the "zero secret" issue, which creates a sort of chicken and egg problem:
In order to use the secret store, you need yet another secret to unlock it. In this case, unseal keys can grant undesired levels of permissions. Gatekeeper tokens provide a way to unseal K-Stash without exposing unseal or gatekeeper keys.
These tokens do not serve any purpose other than sealing/unsealing the barrier and rotating certain keys. They cannot be used for privilege escalation or data access. They should still be considered secrets, but do not require the same level of protection that unseal keys do.

Gatekeeper tokens are designed to be single-use tokens. However, they can be renewed during quick, successive operations to prevent the churn of generating new tokens when multiple operations are required. They can also be rotated.
Ideally, gatekeeper tokens are not used as long-lived tokens, but rather everytime they are used, they get replaced with a rotated token to ensure that compromised tokens have a limited window of usefulness.

Besides automated unsealing, gatekeeper tokens can also be used to provde a production operations team with the ability to manually unseal the barrier without giving them the unseal keys, or access to the data in the barrier.
The K-Stash service owner could provide that team with several "emergency tokens" in the event that K-Stash is restarted and there is no unseal automation, or the automation is not working as expected.

### Access Tokens
Access tokens are generated for consumers to provide them access to the encrypted data within the barrier. Access controls can limit a token's capabilities based on path prefix. By default, they expire after one hour, but can be renewed or revoked as needed.

## Security Considerations
K-Stash takes a separation of concerns approach to ensure data security by defining a list of personas and providing each with the least-privileged access required.

### Personas
#### Service Owners
Service owners install/manages K-Stash instances. This persona is responsible for securing the unseal keys and should distribute them in such a way that there are never enough unseal keys in a single location to unseal the barrier.
This persona needs to seal/unseal the barrier and rotate encryption keys and unseal keys.
This persona does not need access to encrypted data stored in the barrier.

#### Technicians
Technicians are operations or site reliability engineers. In an outage situation they are the first to be engaged. This persona is responsible for some troubleshooting operations and unsealing the barrier if required.
This persona needs to seal/unseal the barrier. In the event of a suspected leakage of keys or tokens, a technician is able to rotate them with the exception of unseal keys.
This persona does not need the unseal keys or access to encrypted data stored in the barrier.

#### Consumers
Consumers, either users or developers are consumers of K-Stash. This persona stores and retrieves secrets from K-Stash with the expectation that they are reasonably secured.
This persona needs read and write access to their encrypted data stored in the barrier.
This persona does not need the unseal keys, gatekeeper tokens, or access to data owned by other consumers/groups of consumers.

#### Auditors
Auditors are consumers of K-Stash. This persona views audit logs and may need to inspect the contents of the encrypted data.
This persona needs read access to all encrypted data stored in the barrier.
This persona does not need the unseal keys, gatekeeper tokens, or write access to the barrier.

#### Privileged
User or automation that need to access to read and write access to all data in the barrier. **NOTE**: This type of use is highly discouraged and should be avoided.
This persona needs read and write access to all encrypted data stored in the barrier.
This persona does not need the unseal keys or gatekeeper tokens.

### Storage Backends
Storage backends should be reasonably secured. The compromise of a storage backend alone is not enough to allow for data leakage as the data is encrypted.
However, with additional information such as unseal keys and/or gatekeeper tokens, it is possible to reconstruct the gatekeeper key which would allow for the decryption of the barrier's keychain and its encryption keys.

### Unseal Keys and Gatekeeper Tokens
Protection of the gatekeeper key is essential. K-Stash never exposes the gatekeeper key directly, but is represented as a set of unseal keys. These keys must be kept secure and should not all be kept in the same place.
A single compromised unseal key is not enough to reconstruct the gatekeeper key. Multiple compromised unseal keys could reconstruct the gatekeeper key, which can be used to seal and unseal the barrier and potentially access encrypted data.
A compromised gatekeeper token cannot reconstruct the gatekeeper key, which makes the the preferred method of sealing and unsealing the barrier.

### Compromise Scenareos
There are several scenareos where a compromise could occur. Understanding some of those scenareos is critical to ensuring the security of the barrier and the data encrypted within it.

#### Unseal Keys
One or more unseal keys have been compromised.

* Severity: High
* Result: An attacker can seal/unseal the barrier and rotate the unseal keys, which could prevent access to barrier, but the data in the barrier cannot be accessed
* Action: Rotate the unseal keys, which will automatically rotate the gatekeeper key and revoke all existing gatekeeper tokens

#### Access Key
One or more access keys have been compromised.

* Severity: High
* Result: An attacker can generate an access token to read and write all data in the barrier, but cannot seal/unseal the barrier
* Action: Rotate the access key and revoke any undesired access tokens that may have been generated

#### Gatekeeper Token
One or more gatekeeper tokens have been compromised.

* Severity: Medium
* Result: An attacker can seal/unseal the barrier and rotate the encryption key, but the data in the barrier cannot be accessed
* Action: Rotate the gatekeeper token

#### Storage Backend
Data from the storage backend has been compromised.

* Severity: High
* Result: An attacker would have access to encrypted data, but would not be able to easily decrypt it
* Action: Secure the storage backend, rotate the encryption key, and re-encrypt existing data

#### Storage Backend + Keys and Tokens
Unseal keys and/or gatekeeper tokens, along with the storage backend have been compromised.

* Severity: Critical
* Result: An attacker can reconstruct the gatekeeper key and use it to decrypt the data from the compromised storage backend
* Action: Secure the storage backend, rotate the unseal keys, rotate the encryption key, and re-encrypt existing data

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