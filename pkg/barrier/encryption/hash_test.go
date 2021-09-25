package encryption

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestHash(t *testing.T) {
	defer GinkgoRecover()

	RegisterFailHandler(Fail)
	RunSpecs(t, "hash")
}

var _ = Describe("hash", func() {
	data := []byte("some super secret text I don't want anyone to see!")

	It("creates a Hash object", func() {
		h := FromHash(data)
		Expect(h.b).To(Equal(data))
	})
})
