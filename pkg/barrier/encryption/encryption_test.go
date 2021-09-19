package encryption

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	apiv1 "github.com/slaskawi/vault-poc/api/v1"
)

func TestEncryption(t *testing.T) {
	defer GinkgoRecover()

	RegisterFailHandler(Fail)
	RunSpecs(t, "encryption")
}

var _ = Describe("encryption", func() {
	key, err := GenerateKey(apiv1.CipherType_AES256_GCM)
	Expect(err).NotTo(HaveOccurred())

	data := []byte("some super secret text I don't want anyone to see!")
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
