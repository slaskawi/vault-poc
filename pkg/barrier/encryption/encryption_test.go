package encryption

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

var data = []byte("some super secret text I don't want anyone to see!")

func TestEncryption(t *testing.T) {
	defer GinkgoRecover()

	RegisterFailHandler(Fail)
	RunSpecs(t, "encryption")
}

var _ = Describe("encryption", func() {
	key, err := GenerateKey(apiv1.CipherType_AES256_GCM)
	Expect(err).NotTo(HaveOccurred())

	var encrypted []byte

	It("errors on invalid key", func() {
		err := ValidateKey(apiv1.CipherType_AES256_GCM, nil)
		Expect(err).To(HaveOccurred())

		key := []byte("sad face :(")
		err = ValidateKey(apiv1.CipherType_AES256_GCM, key)
		Expect(err).To(HaveOccurred())
	})

	It("encrypts data", func() {
		err := ValidateKey(apiv1.CipherType_AES256_GCM, key)
		Expect(err).NotTo(HaveOccurred())

		encrypted, err = Encrypt(apiv1.CipherType_AES256_GCM, key, data)
		Expect(err).NotTo(HaveOccurred())
		Expect(encrypted).NotTo(BeEmpty())
	})

	It("decrypts data", func() {
		decrypted, err := Decrypt(apiv1.CipherType_AES256_GCM, key, encrypted)
		Expect(err).NotTo(HaveOccurred())
		Expect(decrypted).To(Equal(data))
	})

	It("fails to decrypt with wrong key", func() {
		newKey, err := GenerateKey(apiv1.CipherType_AES256_GCM)
		Expect(err).NotTo(HaveOccurred())

		decrypted, err := Decrypt(apiv1.CipherType_AES256_GCM, newKey, encrypted)
		Expect(err).To(HaveOccurred())
		Expect(decrypted).To(BeEmpty())
	})

	It("fails on unknown cipherType", func() {
		cipherType := apiv1.CipherType(9999)

		err := ValidateKey(cipherType, key)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unknown cipherType"))

		_, err = Encrypt(cipherType, key, data)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unknown cipherType"))

		_, err = Decrypt(cipherType, key, data)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("unknown cipherType"))
	})
})

var _ = Describe("hash", func() {
	It("creates a Hash object", func() {
		h := FromHash(data)
		Expect(h.b).To(Equal(data))
	})

	It("creates a Hash object by performing a SHA-256 hash", func() {
		h := Sha256(data)
		Expect(len(h.b) > 10).To(BeTrue())
		Expect(h.Base64()).To(Equal("VisynIPk-qYz7TbVvqF8KEd0xLtWYZuTiMMbcevYf2s"))
	})

	It("creates a Hash object and validates its encoding functions", func() {
		h := FromHash(data)
		Expect(h.b).To(Equal(data))
		Expect(h.Base32()).To(Equal("EDNMQP90EDQN0PBI41PMAORICLQ20T35F1Q20I90CHNMS9RK41RM2RJK41GMSUBFDPII0T3F41PMAP91"))
		Expect(h.Base64()).To(Equal("c29tZSBzdXBlciBzZWNyZXQgdGV4dCBJIGRvbid0IHdhbnQgYW55b25lIHRvIHNlZSE"))
		Expect(h.Hex()).To(Equal("736f6d65207375706572207365637265742074657874204920646f6e27742077616e7420616e796f6e6520746f2073656521"))
		Expect(h.Uint64()).To(Equal(uint64(12099483423728366993)))
		Expect(h.Uint64String()).To(Equal("12099483423728366993"))
	})
})
