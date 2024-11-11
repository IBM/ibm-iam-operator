package operator

import (
	"context"
	"testing"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	corev1 "k8s.io/api/core/v1"

	testutil "github.com/IBM/ibm-iam-operator/testing"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	//"testing"
)

func TestIsIBMMongoDBOperator(t *testing.T) {
	type test struct {
		name     string
		expected bool
	}

	tests := []test{
		{name: "ibm-mongodb-operator", expected: true},
		{name: "ibm-im-mongodb-operator", expected: true},
		{name: "ibm-operator", expected: false},
		{name: "im-mongodb-operator", expected: false},
		{name: "ibm-im-mongodb", expected: false},
	}

	for _, tc := range tests {
		result := isIBMMongoDBOperator(tc.name)
		if result != tc.expected {
			t.Errorf("Expected %v, got %v", tc.expected, result)
		}
	}
}

// Internal constant from fake library
const trackerAddResourceVersion = "999"

var _ = Describe("OperandRequest handling", func() {
	var r *AuthenticationReconciler
	var authCR *operatorv1alpha1.Authentication
	var cb fakeclient.ClientBuilder
	var cl client.WithWatch
	var scheme *runtime.Scheme

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
		scheme = runtime.NewScheme()
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
		Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
		cb = *fakeclient.NewClientBuilder().
			WithScheme(scheme)
	})

	Describe("addEmbeddedEDBIfNeeded", func() {
		var operands *[]operatorv1alpha1.Operand
		Context("When determining external or embedded EDB", func() {
			BeforeEach(func() {
				operands = &[]operatorv1alpha1.Operand{}
				cb = *fakeclient.NewClientBuilder().
					WithScheme(scheme)
				cl = cb.Build()
				r = &AuthenticationReconciler{
					Client: cl,
				}
			})
			It("should add the embedded EDB entry to the list of Operands", func() {
				By("having im-datastore-edb-cm ConfigMap in the same namespace as the Authentication")
				cm := &corev1.ConfigMap{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "v1",
						Kind:       "ConfigMap",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "im-datastore-edb-cm",
						Namespace: "data-ns",
					},
					Data: map[string]string{
						"IS_EMBEDDED": "",
					},
				}
				err := r.Create(context.Background(), cm)
				Expect(err).ToNot(HaveOccurred())

				By("seeing the value of IS_EMBEDDED field is empty")
				err = r.addEmbeddedEDBIfNeeded(context.Background(), authCR, operands)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(*operands)).To(Equal(1))
				Expect((*operands)[0]).ToNot(BeNil())
				Expect((*operands)[0].Name).To(Equal("common-service-postgresql"))
			})

			It("should add the embedded EDB entry to the list of Operands", func() {
				By("having im-datastore-edb-cm ConfigMap in the same namespace as the Authentication")
				cm := &corev1.ConfigMap{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "v1",
						Kind:       "ConfigMap",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "im-datastore-edb-cm",
						Namespace: "data-ns",
					},
					Data: map[string]string{
						"IS_EMBEDDED": "true",
					},
				}
				err := r.Create(context.Background(), cm)
				Expect(err).ToNot(HaveOccurred())

				By("seeing the value of IS_EMBEDDED field is true")
				err = r.addEmbeddedEDBIfNeeded(context.Background(), authCR, operands)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(*operands)).To(Equal(1))
				Expect((*operands)[0]).ToNot(BeNil())
				Expect((*operands)[0].Name).To(Equal("common-service-postgresql"))
			})

			It("should add the embedded EDB entry to the list of Operands", func() {
				By("not having im-datastore-edb-cm ConfigMap in the same namespace as the Authentication")
				err := r.addEmbeddedEDBIfNeeded(context.Background(), authCR, operands)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(*operands)).To(Equal(1))
				Expect((*operands)[0]).ToNot(BeNil())
				Expect((*operands)[0].Name).To(Equal("common-service-postgresql"))
			})

			It("should NOT add the embedded EDB entry to the list of Operands", func() {
				By("having im-datastore-edb-cm ConfigMap in the same namespace as the Authentication")
				cm := &corev1.ConfigMap{
					TypeMeta: metav1.TypeMeta{
						APIVersion: "v1",
						Kind:       "ConfigMap",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name:      "im-datastore-edb-cm",
						Namespace: "data-ns",
					},
					Data: map[string]string{
						"IS_EMBEDDED": "false",
					},
				}
				err := r.Create(context.Background(), cm)
				Expect(err).ToNot(HaveOccurred())

				By("seeing the value of IS_EMBEDDED field is false")
				err = r.addEmbeddedEDBIfNeeded(context.Background(), authCR, operands)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(*operands)).To(Equal(0))
			})

			It("should NOT add the embedded EDB entry to the list of Operands", func() {
				rFailing := &AuthenticationReconciler{
					Client: &testutil.FakeTimeoutClient{
						Client: cl,
					},
				}
				By("failing to get the ConfigMap for some reason")
				err := rFailing.addEmbeddedEDBIfNeeded(context.Background(), authCR, operands)
				Expect(err).To(HaveOccurred())
				Expect(len(*operands)).To(Equal(0))
			})
		})
	})

	Describe("operandsAreEqual", func() {
		var operandsA []operatorv1alpha1.Operand
		var operandsB []operatorv1alpha1.Operand

		When("Operand list arguments are empty", func() {
			BeforeEach(func() {
				operandsA = []operatorv1alpha1.Operand{}
				operandsB = []operatorv1alpha1.Operand{}
			})
			It("returns true", func() {
				Expect(operandsAreEqual(operandsA, operandsB)).To(BeTrue())
			})
		})

		When("Operand list arguments contain the same elements in the same order", func() {
			BeforeEach(func() {
				operandsA = []operatorv1alpha1.Operand{
					{Name: "example-operator-one"},
					{Name: "example-operator-two"},
				}
				operandsB = []operatorv1alpha1.Operand{
					{Name: "example-operator-one"},
					{Name: "example-operator-two"},
				}
			})
			It("returns true", func() {
				Expect(operandsAreEqual(operandsA, operandsB)).To(BeTrue())
			})
		})

		When("Operand list arguments contain the same elements in a different order", func() {
			BeforeEach(func() {
				operandsA = []operatorv1alpha1.Operand{
					{Name: "example-operator-one"},
					{Name: "example-operator-two"},
					{Name: "example-operator-three"},
				}
				operandsB = []operatorv1alpha1.Operand{
					{Name: "example-operator-three"},
					{Name: "example-operator-one"},
					{Name: "example-operator-two"},
				}
			})
			It("returns true", func() {
				Expect(operandsAreEqual(operandsA, operandsB)).To(BeTrue())
			})
		})

		When("Operand both list arguments are nil", func() {
			BeforeEach(func() {
				operandsA = nil
				operandsB = nil
			})
			It("returns true", func() {
				Expect(operandsAreEqual(operandsA, operandsB)).To(BeTrue())
			})
		})

		When("Operand list arguments contains different Operands", func() {
			BeforeEach(func() {
				operandsA = []operatorv1alpha1.Operand{
					{Name: "example-operator-one"},
				}
				operandsB = []operatorv1alpha1.Operand{
					{Name: "example-operator-two"},
				}
			})
			It("returns false", func() {
				Expect(operandsAreEqual(operandsA, operandsB)).To(BeFalse())
			})
		})

		When("one Operand list argument contains an extra Operand", func() {
			BeforeEach(func() {
				operandsA = []operatorv1alpha1.Operand{
					{Name: "example-operator-one"},
					{Name: "example-operator-two"},
				}
				operandsB = []operatorv1alpha1.Operand{
					{Name: "example-operator-one"},
					{Name: "example-operator-two"},
					{Name: "example-operator-three"},
				}
			})
			It("returns false", func() {
				Expect(operandsAreEqual(operandsA, operandsB)).To(BeFalse())
			})
		})

		When("one Operand list argument is nil", func() {
			BeforeEach(func() {
				operandsA = []operatorv1alpha1.Operand{
					{Name: "example-operator-one"},
				}
				operandsB = nil
			})
			It("returns false", func() {
				Expect(operandsAreEqual(operandsA, operandsB)).To(BeFalse())
			})
		})
	})

	Describe("isConfiguredForExternalEDB", func() {
		var cm *corev1.ConfigMap
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
			cm = &corev1.ConfigMap{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "v1",
					Kind:       "ConfigMap",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "im-datastore-edb-cm",
					Namespace: "data-ns",
				},
				Data: map[string]string{},
			}
			scheme := runtime.NewScheme()
			Expect(corev1.AddToScheme(scheme)).To(Succeed())
			Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
			cb = *fakeclient.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(cm, authCR)
			cl = cb.Build()
			r = &AuthenticationReconciler{
				Client: cl,
			}
		})
		It("returns false when IS_EMBEDDED is not set", func() {
			isExternal, err := r.isConfiguredForExternalEDB(context.Background(), authCR)
			Expect(isExternal).To(BeFalse())
			Expect(err).ToNot(HaveOccurred())
		})
		It("returns false when IS_EMBEDDED is an empty string", func() {
			cm.Data["IS_EMBEDDED"] = ""
			err := r.Update(context.Background(), cm)
			Expect(err).ToNot(HaveOccurred())
			isExternal, err := r.isConfiguredForExternalEDB(context.Background(), authCR)
			Expect(isExternal).To(BeFalse())
			Expect(err).ToNot(HaveOccurred())
		})
		It("returns false when IS_EMBEDDED is \"true\"", func() {
			cm.Data["IS_EMBEDDED"] = "true"
			err := r.Update(context.Background(), cm)
			Expect(err).ToNot(HaveOccurred())
			isExternal, err := r.isConfiguredForExternalEDB(context.Background(), authCR)
			Expect(isExternal).To(BeFalse())
			Expect(err).ToNot(HaveOccurred())
		})
		It("returns true and no error when IS_EMBEDDED is \"false\"", func() {
			cm.Data["IS_EMBEDDED"] = "false"
			err := r.Update(context.Background(), cm)
			Expect(err).ToNot(HaveOccurred())
			isExternal, err := r.isConfiguredForExternalEDB(context.Background(), authCR)
			Expect(isExternal).To(BeTrue())
			Expect(err).ToNot(HaveOccurred())
		})
		It("returns false when the ConfigMap can't be found", func() {
			err := r.Delete(context.Background(), cm)
			Expect(err).ToNot(HaveOccurred())
			isExternal, err := r.isConfiguredForExternalEDB(context.Background(), authCR)
			Expect(isExternal).To(BeFalse())
			Expect(err).ToNot(HaveOccurred())
		})
		It("returns an error when an unexpected error is encountered", func() {
			rFailing := &AuthenticationReconciler{
				Client: &testutil.FakeTimeoutClient{
					Client: cl,
				},
			}
			isExternal, err := rFailing.isConfiguredForExternalEDB(context.Background(), authCR)
			Expect(isExternal).To(BeFalse())
			Expect(err).To(HaveOccurred())
		})
	})

})

var _ = DescribeTable("isIBMMongoDBOperator",
	func(name string, isMongoDB bool) {
		value := isIBMMongoDBOperator(name)
		Expect(value).To(Equal(isMongoDB))
	},
	Entry("When using pre-4.1 MongoDB Operator", "ibm-mongodb-operator", true),
	Entry("When using 4.1 or greater MongoDB Operator", "ibm-im-mongodb-operator", true),
	Entry("When using non-MongoDB Operator", "not-ibm-im-mongodb-operator", false),
	Entry("When using non-MongoDB Operator", "not-ibm-mongodb-operator", false),
)

var _ = Describe("getMongoDBOperatorOperand", func() {
	var opReq *operatorv1alpha1.OperandRequest
	var earlierMongoDBOperand operatorv1alpha1.Operand
	var newerMongoDBOperand operatorv1alpha1.Operand

	BeforeEach(func() {
		opReq = &operatorv1alpha1.OperandRequest{
			Spec: operatorv1alpha1.OperandRequestSpec{},
		}
		earlierMongoDBOperand = operatorv1alpha1.Operand{
			Name: "ibm-mongodb-operator",
		}
		newerMongoDBOperand = operatorv1alpha1.Operand{
			Name: "ibm-im-mongodb-operator",
		}
	})

	DescribeTable("Retrieving a MongoDB Operator Operand",
		func(requests []operatorv1alpha1.Request, expected *operatorv1alpha1.Operand) {
			opReq.Spec.Requests = requests
			actual := getMongoDBOperandFromOpReq(opReq)
			if expected == nil {
				Expect(actual).To(BeNil())
			} else {
				Expect(*actual).To(Equal(*expected))
			}
		},
		Entry("When Requests common-service registry contains earlier MongoDB Operator Operand",
			[]operatorv1alpha1.Request{{
				Operands: []operatorv1alpha1.Operand{{Name: "ibm-mongodb-operator"}},
				Registry: "common-service",
			}}, &earlierMongoDBOperand),
		Entry("When Requests with common-service registry contains newer MongoDB Operator Operand",
			[]operatorv1alpha1.Request{{
				Operands: []operatorv1alpha1.Operand{{Name: "ibm-im-mongodb-operator"}},
				Registry: "common-service",
			}}, &newerMongoDBOperand),
		Entry("When Requests common-service registry contains earlier MongoDB Operator Operand",
			[]operatorv1alpha1.Request{{
				Operands: []operatorv1alpha1.Operand{
					{Name: "ibm-mongodb-operator"},
					{Name: "ibm-im-mongodb-operator"},
					{Name: "ibm-im-mongodb-operator"},
				},
				Registry: "common-service",
			}}, &earlierMongoDBOperand),
		Entry("When Requests common-service registry contains earlier MongoDB Operator Operand",
			[]operatorv1alpha1.Request{{
				Operands: []operatorv1alpha1.Operand{
					{Name: "ibm-im-mongodb-operator"},
					{Name: "ibm-mongodb-operator"},
					{Name: "ibm-im-mongodb-operator"},
				},
				Registry: "common-service",
			}}, &newerMongoDBOperand),
		Entry("When Requests without registry contains earlier MongoDB Operator Operand",
			[]operatorv1alpha1.Request{{
				Operands: []operatorv1alpha1.Operand{{Name: "ibm-mongodb-operator"}},
			}}, nil),
		Entry("When Requests without registry contains newer MongoDB Operator Operand",
			[]operatorv1alpha1.Request{{
				Operands: []operatorv1alpha1.Operand{{Name: "ibm-im-mongodb-operator"}},
			}}, nil),
		Entry("When no Requests are set", nil, nil),
		Entry("When empty Requests are set", []operatorv1alpha1.Request{}, nil),
	)

})
