package operator

import (
	"context"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	//"testing"
)

//func TestOperandsAreEqual(t *testing.T) {
//	type test struct {
//		operandsA []operatorv1alpha1.Operand
//		operandsB []operatorv1alpha1.Operand
//		expected  bool
//	}
//
//	tests := []test{
//		{
//			operandsA: []operatorv1alpha1.Operand{},
//			operandsB: []operatorv1alpha1.Operand{},
//			expected:  true,
//		},
//		{
//			operandsA: []operatorv1alpha1.Operand{
//				{Name: "example-operator-one"},
//			},
//			operandsB: []operatorv1alpha1.Operand{
//				{Name: "example-operator-two"},
//			},
//			expected: false,
//		},
//		{
//			operandsA: []operatorv1alpha1.Operand{
//				{Name: "example-operator-one"},
//				{Name: "example-operator-two"},
//			},
//			operandsB: []operatorv1alpha1.Operand{
//				{Name: "example-operator-one"},
//				{Name: "example-operator-two"},
//			},
//			expected: true,
//		},
//		{
//			operandsA: []operatorv1alpha1.Operand{
//				{Name: "example-operator-one"},
//				{Name: "example-operator-two"},
//			},
//			operandsB: []operatorv1alpha1.Operand{
//				{Name: "example-operator-one"},
//				{Name: "example-operator-two"},
//				{Name: "example-operator-three"},
//			},
//			expected: false,
//		},
//		{
//			operandsA: []operatorv1alpha1.Operand{
//				{Name: "example-operator-one"},
//				{Name: "example-operator-two"},
//				{Name: "example-operator-three"},
//			},
//			operandsB: []operatorv1alpha1.Operand{
//				{Name: "example-operator-one"},
//				{Name: "example-operator-two"},
//			},
//			expected: false,
//		},
//	}
//
//	for _, tc := range tests {
//		result := operandsAreEqual(tc.operandsA, tc.operandsB)
//		if result != tc.expected {
//			t.Errorf("Expected %v, got %v", tc.expected, result)
//		}
//	}
//}

//func TestIsIBMMongoDBOperator(t *testing.T) {
//	type test struct {
//		name     string
//		expected bool
//	}
//
//	tests := []test{
//		{name: "ibm-mongodb-operator", expected: true},
//		{name: "ibm-im-mongodb-operator", expected: true},
//		{name: "ibm-operator", expected: false},
//		{name: "im-mongodb-operator", expected: false},
//		{name: "ibm-im-mongodb", expected: false},
//	}
//
//	for _, tc := range tests {
//		result := isIBMMongoDBOperator(tc.name)
//		if result != tc.expected {
//			t.Errorf("Expected %v, got %v", tc.expected, result)
//		}
//	}
//}

// Internal constant from fake library
const trackerAddResourceVersion = "999"

type fakeTimeoutClient struct {
	client.Client
	goodCalls int
}

func (f *fakeTimeoutClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if f.goodCalls > 0 {
		f.goodCalls--
		return f.Client.Get(ctx, key, obj, opts...)
	}
	return k8sErrors.NewTimeoutError("dummy error", 500)
}

func (f *fakeTimeoutClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if f.goodCalls > 0 {
		f.goodCalls--
		return f.Client.Update(ctx, obj, opts...)
	}
	return k8sErrors.NewTimeoutError("dummy error", 500)
}

func (f *fakeTimeoutClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if f.goodCalls > 0 {
		f.goodCalls--
		return f.Client.Create(ctx, obj, opts...)
	}
	return k8sErrors.NewTimeoutError("dummy error", 500)
}

func (f *fakeTimeoutClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if f.goodCalls > 0 {
		f.goodCalls--
		return f.Client.Delete(ctx, obj, opts...)
	}
	return k8sErrors.NewTimeoutError("dummy error", 500)
}

var _ client.Client = &fakeTimeoutClient{}

var _ = Describe("OperandRequest handling", func() {

	Describe("addEmbeddedEDBIfNeeded", func() {
		var r *AuthenticationReconciler
		var authCR *operatorv1alpha1.Authentication
		var cb fakeclient.ClientBuilder
		var cl client.WithWatch
		var operands *[]operatorv1alpha1.Operand
		Context("When determining external or embedded EDB", func() {
			BeforeEach(func() {
				operands = &[]operatorv1alpha1.Operand{}
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
				scheme := runtime.NewScheme()
				Expect(corev1.AddToScheme(scheme)).To(Succeed())
				Expect(operatorv1alpha1.AddToScheme(scheme)).To(Succeed())
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
					Client: &fakeTimeoutClient{
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
})
