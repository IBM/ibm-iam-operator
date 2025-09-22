/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"time"

	regen "github.com/zach-klippenstein/goregen"

	. "github.com/onsi/ginkgo/v2" //nolint:golint,revive
	. "github.com/onsi/gomega"    //nolint:golint,revive
	"github.com/opdev/subreconciler"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	prometheusOperatorVersion = "v0.77.1"
	prometheusOperatorURL     = "https://github.com/prometheus-operator/prometheus-operator/" +
		"releases/download/%s/bundle.yaml"

	certmanagerVersion = "v1.16.3"
	certmanagerURLTmpl = "https://github.com/cert-manager/cert-manager/releases/download/%s/cert-manager.yaml"
)

func warnError(err error) {
	_, _ = fmt.Fprintf(GinkgoWriter, "warning: %v\n", err)
}

// Run executes the provided command within this context
func Run(cmd *exec.Cmd) (string, error) {
	dir, _ := GetProjectDir()
	cmd.Dir = dir

	if err := os.Chdir(cmd.Dir); err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "chdir dir: %s\n", err)
	}

	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	command := strings.Join(cmd.Args, " ")
	_, _ = fmt.Fprintf(GinkgoWriter, "running: %s\n", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s failed with error: (%v) %s", command, err, string(output))
	}

	return string(output), nil
}

// InstallPrometheusOperator installs the prometheus Operator to be used to export the enabled metrics.
func InstallPrometheusOperator() error {
	url := fmt.Sprintf(prometheusOperatorURL, prometheusOperatorVersion)
	cmd := exec.Command("kubectl", "create", "-f", url)
	_, err := Run(cmd)
	return err
}

// UninstallPrometheusOperator uninstalls the prometheus
func UninstallPrometheusOperator() {
	url := fmt.Sprintf(prometheusOperatorURL, prometheusOperatorVersion)
	cmd := exec.Command("kubectl", "delete", "-f", url)
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}
}

// IsPrometheusCRDsInstalled checks if any Prometheus CRDs are installed
// by verifying the existence of key CRDs related to Prometheus.
func IsPrometheusCRDsInstalled() bool {
	// List of common Prometheus CRDs
	prometheusCRDs := []string{
		"prometheuses.monitoring.coreos.com",
		"prometheusrules.monitoring.coreos.com",
		"prometheusagents.monitoring.coreos.com",
	}

	cmd := exec.Command("kubectl", "get", "crds", "-o", "custom-columns=NAME:.metadata.name")
	output, err := Run(cmd)
	if err != nil {
		return false
	}
	crdList := GetNonEmptyLines(output)
	for _, crd := range prometheusCRDs {
		for _, line := range crdList {
			if strings.Contains(line, crd) {
				return true
			}
		}
	}

	return false
}

// UninstallCertManager uninstalls the cert manager
func UninstallCertManager() {
	url := fmt.Sprintf(certmanagerURLTmpl, certmanagerVersion)
	cmd := exec.Command("kubectl", "delete", "-f", url)
	if _, err := Run(cmd); err != nil {
		warnError(err)
	}
}

// InstallCertManager installs the cert manager bundle.
func InstallCertManager() error {
	url := fmt.Sprintf(certmanagerURLTmpl, certmanagerVersion)
	cmd := exec.Command("kubectl", "apply", "-f", url)
	if _, err := Run(cmd); err != nil {
		return err
	}
	// Wait for cert-manager-webhook to be ready, which can take time if cert-manager
	// was re-installed after uninstalling on a cluster.
	cmd = exec.Command("kubectl", "wait", "deployment.apps/cert-manager-webhook",
		"--for", "condition=Available",
		"--namespace", "cert-manager",
		"--timeout", "5m",
	)

	_, err := Run(cmd)
	return err
}

// IsCertManagerCRDsInstalled checks if any Cert Manager CRDs are installed
// by verifying the existence of key CRDs related to Cert Manager.
func IsCertManagerCRDsInstalled() bool {
	// List of common Cert Manager CRDs
	certManagerCRDs := []string{
		"certificates.cert-manager.io",
		"issuers.cert-manager.io",
		"clusterissuers.cert-manager.io",
		"certificaterequests.cert-manager.io",
		"orders.acme.cert-manager.io",
		"challenges.acme.cert-manager.io",
	}

	// Execute the kubectl command to get all CRDs
	cmd := exec.Command("kubectl", "get", "crds")
	output, err := Run(cmd)
	if err != nil {
		return false
	}

	// Check if any of the Cert Manager CRDs are present
	crdList := GetNonEmptyLines(output)
	for _, crd := range certManagerCRDs {
		for _, line := range crdList {
			if strings.Contains(line, crd) {
				return true
			}
		}
	}

	return false
}

// LoadImageToKindClusterWithName loads a local docker image to the kind cluster
func LoadImageToKindClusterWithName(name string) error {
	cluster := "kind"
	if v, ok := os.LookupEnv("KIND_CLUSTER"); ok {
		cluster = v
	}
	kindOptions := []string{"load", "docker-image", name, "--name", cluster}
	cmd := exec.Command("kind", kindOptions...)
	_, err := Run(cmd)
	return err
}

// GetNonEmptyLines converts given command output string into individual objects
// according to line breakers, and ignores the empty elements in it.
func GetNonEmptyLines(output string) []string {
	var res []string
	elements := strings.Split(output, "\n")
	for _, element := range elements {
		if element != "" {
			res = append(res, element)
		}
	}

	return res
}

// GetProjectDir will return the directory where the project is
func GetProjectDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return wd, err
	}
	wd = strings.Replace(wd, "/test/e2e", "", -1)
	return wd, nil
}

// UncommentCode searches for target in the file and remove the comment prefix
// of the target content. The target content may span multiple lines.
func UncommentCode(filename, target, prefix string) error {
	// false positive
	// nolint:gosec
	content, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	strContent := string(content)

	idx := strings.Index(strContent, target)
	if idx < 0 {
		return fmt.Errorf("unable to find the code %s to be uncomment", target)
	}

	out := new(bytes.Buffer)
	_, err = out.Write(content[:idx])
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(bytes.NewBufferString(target))
	if !scanner.Scan() {
		return nil
	}
	for {
		_, err := out.WriteString(strings.TrimPrefix(scanner.Text(), prefix))
		if err != nil {
			return err
		}
		// Avoid writing a newline in case the previous line was the last in target.
		if !scanner.Scan() {
			break
		}
		if _, err := out.WriteString("\n"); err != nil {
			return err
		}
	}

	_, err = out.Write(content[idx+len(target):])
	if err != nil {
		return err
	}
	// false positive
	// nolint:gosec
	return os.WriteFile(filename, out.Bytes(), 0644)
}

func ConfirmThatItRequeuesWithError(result *ctrl.Result, err error) {
	Expect(result).ToNot(BeNil())
	Expect(result.Requeue).To(BeTrue())
	Expect(result.RequeueAfter).To(BeZero())
	Expect(err).To(HaveOccurred())
	Expect(subreconciler.ShouldContinue(result, err)).To(BeFalse())
	Expect(subreconciler.ShouldRequeue(result, err)).To(BeTrue())
	Expect(subreconciler.ShouldHaltOrRequeue(result, err)).To(BeTrue())
}

func ConfirmThatItRequeuesWithDelay(result *ctrl.Result, err error, expectedDelay time.Duration) {
	Expect(err).ToNot(HaveOccurred())
	Expect(result).ToNot(BeNil())
	Expect(result.Requeue).To(BeTrue())
	Expect(result.RequeueAfter).To(Equal(expectedDelay))
	Expect(subreconciler.ShouldContinue(result, err)).To(BeFalse())
	Expect(subreconciler.ShouldRequeue(result, err)).To(BeTrue())
	Expect(subreconciler.ShouldHaltOrRequeue(result, err)).To(BeTrue())
}

func ConfirmThatItContinuesReconciling(result *ctrl.Result, err error) {
	Expect(result).To(BeNil())
	Expect(err).ToNot(HaveOccurred())
	Expect(subreconciler.ShouldContinue(result, err)).To(BeTrue())
	Expect(subreconciler.ShouldRequeue(result, err)).To(BeFalse())
	Expect(subreconciler.ShouldHaltOrRequeue(result, err)).To(BeFalse())
}

type fakeErrorClient interface {
	client.Client
	Error() error
}

type FakeErrorClient struct {
	client.Client
	ErrFunc       func() error
	GetAllowed    bool
	UpdateAllowed bool
	CreateAllowed bool
	DeleteAllowed bool
}

var _ fakeErrorClient = &FakeErrorClient{}

func (f *FakeErrorClient) Error() error {
	return f.ErrFunc()
}

func (f *FakeErrorClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if f.GetAllowed {
		return f.Client.Get(ctx, key, obj, opts...)
	}
	return f.Error()
}

func (f *FakeErrorClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if f.UpdateAllowed {
		return f.Client.Update(ctx, obj, opts...)
	}
	return f.Error()
}

func (f *FakeErrorClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if f.CreateAllowed {
		return f.Client.Create(ctx, obj, opts...)
	}
	return f.Error()
}

func (f *FakeErrorClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if f.DeleteAllowed {
		return f.Client.Delete(ctx, obj, opts...)
	}
	return f.Error()
}

func NewFakeTimeoutClient(cl client.Client) *FakeErrorClient {
	return &FakeErrorClient{
		Client: cl,
		ErrFunc: func() error {
			return k8sErrors.NewTimeoutError("dummy error", 500)
		},
	}
}

type FakeTimeoutClient struct {
	client.Client
	goodCalls int
}

func (f *FakeTimeoutClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if f.goodCalls > 0 {
		f.goodCalls--
		return f.Client.Get(ctx, key, obj, opts...)
	}
	return k8sErrors.NewTimeoutError("dummy error", 500)
}

func (f *FakeTimeoutClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if f.goodCalls > 0 {
		f.goodCalls--
		return f.Client.Update(ctx, obj, opts...)
	}
	return k8sErrors.NewTimeoutError("dummy error", 500)
}

func (f *FakeTimeoutClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if f.goodCalls > 0 {
		f.goodCalls--
		return f.Client.Create(ctx, obj, opts...)
	}
	return k8sErrors.NewTimeoutError("dummy error", 500)
}

func (f *FakeTimeoutClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if f.goodCalls > 0 {
		f.goodCalls--
		return f.Client.Delete(ctx, obj, opts...)
	}
	return k8sErrors.NewTimeoutError("dummy error", 500)
}

var _ client.Client = &FakeTimeoutClient{}

func GetRandomizedNamespace(base string) string {
	length := 253 - len(base) - 1
	rule := fmt.Sprintf(`^([a-z0-9]-.){%d,}([a-z0-9])$`, length-1)
	generator, _ := regen.NewGenerator(rule, &regen.GeneratorArgs{
		RngSource:               rand.NewSource(time.Now().UnixNano()),
		MaxUnboundedRepeatCount: 1})
	randomString := generator.Generate()
	return fmt.Sprintf("%s-%s", base, randomString)
}
