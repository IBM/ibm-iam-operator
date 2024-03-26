package migration

import (
	v1schema "github.com/IBM/ibm-iam-operator/migration/schema/v1"
	"github.com/jackc/pgx/v5/pgtype"

	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestAPIs(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Migration Suite")
}

var _ = Describe("Migration", func() {
	Describe("removeInvalidUserPreferences", func() {
		var userPrefs []v1schema.UserPreferences
		Context("When no LastLogin set on UserPreferences", func() {
			BeforeEach(func() {
				userPrefs = []v1schema.UserPreferences{{}}
			})
			It("filters out that entry (empty struct)", func() {
				filtered := removeInvalidUserPreferences(userPrefs)
				Expect(len(filtered)).To(Equal(0))
			})
			It("filters out that entry (partially-filled struct)", func() {
				userPrefs = append(userPrefs, v1schema.UserPreferences{
					UserUID:    "some-id",
					LoginCount: 0,
					LastLogout: &pgtype.Timestamptz{
						Time: time.Now(),
					},
				})
				filtered := removeInvalidUserPreferences(userPrefs)
				Expect(len(filtered)).To(Equal(0))
			})
		})

		Context("When a LastLogin set on UserPreferences", func() {
			BeforeEach(func() {
				userPrefs = []v1schema.UserPreferences{
					{
						LastLogin: &pgtype.Timestamptz{
							Time: time.Now(),
						},
					},
				}
			})

			It("retains that entry", func() {
				filtered := removeInvalidUserPreferences(userPrefs)
				Expect(len(filtered)).To(Equal(1))
			})
		})
	})
})

var _ = DescribeTable("xorDecode",
	func(encoded, decoded string, shouldError bool) {
		value, err := xorDecode(encoded)
		Expect(value).To(Equal(decoded))
		if shouldError {
			Expect(err).To(HaveOccurred())
		} else {
			Expect(err).ToNot(HaveOccurred())
		}
	},
	Entry("Returns the decoded string when it has the prefix", "{xor}LDo8LTor", "secret", false),
	Entry("Returns the decoded string when it does not have the prefix", "LDo8LTor", "secret", false),
	Entry("Returns an empty string when argument is empty", "", "", false),
	Entry("Returns error when input has malformed prefix", "{{xor}", "", true),
	Entry("Returns error when input with prefix is not valid base64", "{xor}&#&(*asdbasdf", "", true),
	Entry("Returns error when input without prefix is not valid base64", "&#&(*asdbasdf", "", true),
)
