package migration

import (
	v1schema "github.com/IBM/ibm-iam-operator/controllers/operator/migration/schema/v1"
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
					UserID:     "some-id",
					LoginCount: 0,
					LastLogout: pgtype.Timestamptz{
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
						LastLogin: pgtype.Timestamptz{
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
