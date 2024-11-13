package operator

import (
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"

	"github.com/IBM/ibm-iam-operator/database/migration"
	v1schema "github.com/IBM/ibm-iam-operator/database/schema/v1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	//"testing"
)

var _ = Describe("Authentication Controller", func() {

	//Describe("", func() {
	//	var r *AuthenticationReconciler
	//	var authCR *operatorv1alpha1.Authentication
	//	var cb fakeclient.ClientBuilder
	//	var cl client.WithWatch
	//	Context("When ", func() {
	//		BeforeEach(func() {
	//			authCR = &operatorv1alpha1.Authentication{
	//				TypeMeta: metav1.TypeMeta{
	//					APIVersion: "operator.ibm.com/v1alpha1",
	//					Kind:       "Authentication",
	//				},
	//				ObjectMeta: metav1.ObjectMeta{
	//					Name:            "example-authentication",
	//					Namespace:       "data-ns",
	//					ResourceVersion: trackerAddResourceVersion,
	//				},
	//			}
	//			scheme := runtime.NewScheme()
	//			Expect(corev1.AddToScheme(scheme)).To(Succeed())
	//			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
	//			cb = *fakeclient.NewClientBuilder().
	//				WithScheme(scheme)
	//			cl = cb.Build()
	//			r = &AuthenticationReconciler{
	//				Client: cl,
	//			}
	//		})
	//		It("", func() {

	//		})
	//	})

	//})

	Describe("setMongoMigrationAnnotations", func() {
		var authCR *operatorv1alpha1.Authentication
		var result *migration.Result
		var previousAnnotations, currentAnnotations map[string]string
		Context("When no migrations have occurred", func() {
			BeforeEach(func() {
				authCR = &operatorv1alpha1.Authentication{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "operator.ibm.com/v1alpha1",
						Kind:       "Authentication",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-authentication",
						Namespace:       "data-ns",
						ResourceVersion: trackerAddResourceVersion,
					},
				}
			})
			It("makes no changes", func() {
				By("skipping processing of nil migration results")
				previousAnnotations = authCR.DeepCopy().GetAnnotations()
				changed := setMongoMigrationAnnotations(authCR, result)
				currentAnnotations = authCR.GetAnnotations()
				Expect(changed).To(BeFalse())
				Expect(currentAnnotations).To(Equal(previousAnnotations))
				Expect(currentAnnotations).To(BeNil())

				By("leaving nil annotations as nil")
				result = &migration.Result{}
				previousAnnotations = authCR.DeepCopy().GetAnnotations()
				changed = setMongoMigrationAnnotations(authCR, result)
				currentAnnotations = authCR.GetAnnotations()
				Expect(changed).To(BeFalse())
				Expect(currentAnnotations).To(Equal(previousAnnotations))
				Expect(currentAnnotations).To(BeNil())

				By("leaving set annotations how they were originally set")
				previousAnnotations = map[string]string{
					operatorv1alpha1.AnnotationAuthDBSchemaVersion:          "0.1.0",
					operatorv1alpha1.AnnotationAuthMigrationComplete:        "true",
					operatorv1alpha1.AnnotationAuthRetainMigrationArtifacts: "true",
				}
				authCR.SetAnnotations(previousAnnotations)
				changed = setMongoMigrationAnnotations(authCR, result)
				currentAnnotations = authCR.GetAnnotations()
				Expect(changed).To(BeFalse())
				Expect(currentAnnotations).To(Equal(previousAnnotations))
			})
		})

		Context("When initEDB migration has occurred successfully", func() {
			BeforeEach(func() {
				authCR = &operatorv1alpha1.Authentication{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "operator.ibm.com/v1alpha1",
						Kind:       "Authentication",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-authentication",
						Namespace:       "data-ns",
						ResourceVersion: trackerAddResourceVersion,
					},
				}
			})
			BeforeEach(func() {
				m := migration.NewMigration().Name("initEDB").Build()
				result = &migration.Result{
					Complete: []*migration.Migration{
						m,
					},
				}

			})
		})

		Context("When MongoToEDBv1 migration has succeeded", func() {
			BeforeEach(func() {
				authCR = &operatorv1alpha1.Authentication{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "operator.ibm.com/v1alpha1",
						Kind:       "Authentication",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-authentication",
						Namespace:       "data-ns",
						ResourceVersion: trackerAddResourceVersion,
					},
				}
				m := migration.NewMigration().Name(v1schema.MongoToEDBv1.Name).Build()
				result = &migration.Result{
					Complete: []*migration.Migration{
						m,
					},
				}
			})

			It("sets the Mongo migration annotations to the Authentication CR", func() {
				By("creating a new annotations map if one is not set")
				authCR.SetAnnotations(nil)
				changed := setMongoMigrationAnnotations(authCR, result)
				currentAnnotations = authCR.GetAnnotations()
				Expect(changed).To(BeTrue())
				Expect(currentAnnotations).ToNot(Equal(previousAnnotations))
				Expect(currentAnnotations[operatorv1alpha1.AnnotationAuthMigrationComplete]).To(Equal("true"))
				Expect(currentAnnotations[operatorv1alpha1.AnnotationAuthRetainMigrationArtifacts]).To(Equal("true"))

				By("inserting the annotations into an existing map if they are not already")
				previousAnnotations = map[string]string{
					operatorv1alpha1.AnnotationAuthDBSchemaVersion: "1.0.0",
				}
				authCR.SetAnnotations(previousAnnotations)
				changed = setMongoMigrationAnnotations(authCR, result)
				currentAnnotations = authCR.GetAnnotations()
				Expect(changed).To(BeTrue())
				Expect(currentAnnotations).ToNot(Equal(previousAnnotations))
				Expect(currentAnnotations[operatorv1alpha1.AnnotationAuthDBSchemaVersion]).
					To(Equal(previousAnnotations[operatorv1alpha1.AnnotationAuthDBSchemaVersion]))
				Expect(currentAnnotations[operatorv1alpha1.AnnotationAuthMigrationComplete]).To(Equal("true"))
				Expect(currentAnnotations[operatorv1alpha1.AnnotationAuthRetainMigrationArtifacts]).To(Equal("true"))

				By("replacing the migration completion annotation if it is set")
				previousAnnotations = map[string]string{
					operatorv1alpha1.AnnotationAuthMigrationComplete:        "false",
					operatorv1alpha1.AnnotationAuthRetainMigrationArtifacts: "true",
				}
				authCR.SetAnnotations(previousAnnotations)
				changed = setMongoMigrationAnnotations(authCR, result)
				currentAnnotations = authCR.GetAnnotations()
				Expect(changed).To(BeTrue())
				Expect(currentAnnotations).ToNot(Equal(previousAnnotations))
				Expect(currentAnnotations[operatorv1alpha1.AnnotationAuthMigrationComplete]).To(Equal("true"))
				Expect(currentAnnotations[operatorv1alpha1.AnnotationAuthRetainMigrationArtifacts]).To(Equal("true"))
			})
		})

		Context("When MongoToEDBv1 migration has failed", func() {
			BeforeEach(func() {
				authCR = &operatorv1alpha1.Authentication{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "operator.ibm.com/v1alpha1",
						Kind:       "Authentication",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:            "example-authentication",
						Namespace:       "data-ns",
						ResourceVersion: trackerAddResourceVersion,
					},
				}
				m := migration.NewMigration().Name(v1schema.MongoToEDBv1.Name).Build()
				result = &migration.Result{
					Incomplete: []*migration.Migration{
						m,
					},
				}
			})

			It("sets the Mongo migration annotations to the Authentication CR", func() {
				By("creating a new annotations map if one is not set")
				authCR.SetAnnotations(nil)
				changed := setMongoMigrationAnnotations(authCR, result)
				currentAnnotations = authCR.GetAnnotations()
				Expect(changed).To(BeTrue())
				Expect(currentAnnotations).ToNot(Equal(previousAnnotations))
				Expect(currentAnnotations[operatorv1alpha1.AnnotationAuthMigrationComplete]).To(Equal("false"))

				By("inserting the annotations into an existing map if they are not already")
				previousAnnotations = map[string]string{
					operatorv1alpha1.AnnotationAuthDBSchemaVersion: "1.0.0",
				}
				authCR.SetAnnotations(previousAnnotations)
				changed = setMongoMigrationAnnotations(authCR, result)
				currentAnnotations = authCR.GetAnnotations()
				Expect(changed).To(BeTrue())
				Expect(currentAnnotations).ToNot(Equal(previousAnnotations))
				Expect(currentAnnotations[operatorv1alpha1.AnnotationAuthDBSchemaVersion]).
					To(Equal(previousAnnotations[operatorv1alpha1.AnnotationAuthDBSchemaVersion]))
				Expect(currentAnnotations[operatorv1alpha1.AnnotationAuthMigrationComplete]).To(Equal("false"))

				By("replacing the migration completion annotation if it is set")
				previousAnnotations = map[string]string{
					operatorv1alpha1.AnnotationAuthMigrationComplete:        "true",
					operatorv1alpha1.AnnotationAuthRetainMigrationArtifacts: "true",
				}
				authCR.SetAnnotations(previousAnnotations)
				changed = setMongoMigrationAnnotations(authCR, result)
				currentAnnotations = authCR.GetAnnotations()
				Expect(changed).To(BeTrue())
				Expect(currentAnnotations).ToNot(Equal(previousAnnotations))
				Expect(currentAnnotations[operatorv1alpha1.AnnotationAuthMigrationComplete]).To(Equal("false"))
				Expect(currentAnnotations[operatorv1alpha1.AnnotationAuthRetainMigrationArtifacts]).To(Equal("true"))
			})
		})
	})

	var _ = DescribeTable("setDBSchemaVersionAnnotation",
		func(authCR *operatorv1alpha1.Authentication, expected bool) {
			changed := setDBSchemaVersionAnnotation(authCR)
			Expect(changed).To(Equal(expected))
			Expect(authCR.GetAnnotations()).
				To(HaveKeyWithValue(operatorv1alpha1.AnnotationAuthDBSchemaVersion, v1schema.SchemaVersion))
		},
		Entry("Returns true if the map has been changed",
			&operatorv1alpha1.Authentication{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "operator.ibm.com/v1alpha1",
					Kind:       "Authentication",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "example-authentication",
					Namespace:       "data-ns",
					ResourceVersion: trackerAddResourceVersion,
				},
			}, true),
		Entry("Returns false if the map has been changed",
			&operatorv1alpha1.Authentication{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "operator.ibm.com/v1alpha1",
					Kind:       "Authentication",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:            "example-authentication",
					Namespace:       "data-ns",
					ResourceVersion: trackerAddResourceVersion,
					Annotations: map[string]string{
						operatorv1alpha1.AnnotationAuthDBSchemaVersion: v1schema.SchemaVersion,
					},
				},
			}, false),
	)
})
