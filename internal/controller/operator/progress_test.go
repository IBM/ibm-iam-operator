/*
Copyright 2026 IBM Corporation.

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

package operator

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
)

var _ = Describe("SetProgress", func() {
	var authCR *operatorv1alpha1.Authentication

	BeforeEach(func() {
		authCR = &operatorv1alpha1.Authentication{}
	})

	Describe("parseProgress", func() {
		DescribeTable("parses percentage strings",
			func(s string, expectedVal int, expectedOK bool) {
				v, ok := parseProgress(s)
				Expect(ok).To(Equal(expectedOK))
				if expectedOK {
					Expect(v).To(Equal(expectedVal))
				}
			},
			Entry("normal", "42%", 42, true),
			Entry("zero", "0%", 0, true),
			Entry("hundred", "100%", 100, true),
			Entry("empty string", "", 0, false),
			Entry("no percent sign", "55", 55, true),
			Entry("garbage", "abc%", 0, false),
			Entry("whitespace", "  30%  ", 30, true),
		)
	})

	Describe("fresh start (no existing progress)", func() {
		It("writes 0% and returns true when incoming is 0 and status is blank", func() {
			changed := SetProgress(authCR, progressCheckpoints.Start)
			Expect(changed).To(BeTrue())
			Expect(authCR.Status.Progress).To(Equal("0%"))
			Expect(authCR.Status.ProgressMessage).To(Equal(progressCheckpoints.Start.msg))
		})

		It("returns false and leaves status blank when a non-zero checkpoint arrives before reset", func() {
			// Blank status is treated as a reset condition; only 0% is accepted.
			changed := SetProgress(authCR, progressCheckpoints.RBACDone)
			Expect(changed).To(BeFalse())
			Expect(authCR.Status.Progress).To(BeEmpty())
		})
	})

	Describe("advancing progress", func() {
		It("advances and returns true when incoming > current", func() {
			authCR.Status.Progress = "10%"
			changed := SetProgress(authCR, progressCheckpoints.DBRequested) // 20%
			Expect(changed).To(BeTrue())
			Expect(authCR.Status.Progress).To(Equal("20%"))
			Expect(authCR.Status.ProgressMessage).To(Equal(progressCheckpoints.DBRequested.msg))
		})

		It("accepts equal percentage and returns true (idempotent re-apply)", func() {
			authCR.Status.Progress = "20%"
			changed := SetProgress(authCR, progressCheckpoints.DBRequested) // 20%
			Expect(changed).To(BeTrue())
			Expect(authCR.Status.Progress).To(Equal("20%"))
		})

		It("returns false and does not go backwards", func() {
			authCR.Status.Progress = "55%"
			changed := SetProgress(authCR, progressCheckpoints.RBACDone) // 10%
			Expect(changed).To(BeFalse())
			Expect(authCR.Status.Progress).To(Equal("55%"))
		})

		It("advances all the way to 100% and returns true", func() {
			authCR.Status.Progress = "95%"
			changed := SetProgress(authCR, progressCheckpoints.Complete) // 100%
			Expect(changed).To(BeTrue())
			Expect(authCR.Status.Progress).To(Equal("100%"))
			Expect(authCR.Status.ProgressMessage).To(Equal(progressCompleteMessage))
		})
	})

	Describe("reset after completion", func() {
		It("resets to 0% and returns true when current is 100%", func() {
			authCR.Status.Progress = "100%"
			changed := SetProgress(authCR, progressCheckpoints.Start) // incoming 0
			Expect(changed).To(BeTrue())
			Expect(authCR.Status.Progress).To(Equal("0%"))
			Expect(authCR.Status.ProgressMessage).To(Equal(progressCheckpoints.Start.msg))
		})

		It("returns false and does not advance to non-zero when current is 100%", func() {
			authCR.Status.Progress = "100%"
			changed := SetProgress(authCR, progressCheckpoints.RBACDone) // 10%
			Expect(changed).To(BeFalse())
			Expect(authCR.Status.Progress).To(Equal("100%"))
		})
	})
})

var _ = Describe("AppendReconcileHistory", func() {
	var authCR *operatorv1alpha1.Authentication

	BeforeEach(func() {
		authCR = &operatorv1alpha1.Authentication{}
	})

	It("prepends an entry with a timestamp prefix", func() {
		before := time.Now().UTC()
		AppendReconcileHistory(authCR, "something went wrong")
		after := time.Now().UTC()

		Expect(authCR.Status.ReconcileHistory).To(HaveLen(1))
		entry := authCR.Status.ReconcileHistory[0]
		Expect(entry).To(ContainSubstring("something went wrong"))

		// Parse the timestamp prefix
		parts := strings.SplitN(entry, " ", 2)
		Expect(parts).To(HaveLen(2))
		ts, err := time.Parse("2006-01-02T15:04:05Z", parts[0])
		Expect(err).NotTo(HaveOccurred())
		Expect(ts).To(BeTemporally(">=", before.Truncate(time.Second)))
		Expect(ts).To(BeTemporally("<=", after.Add(time.Second)))
	})

	It("most recent entry is first", func() {
		AppendReconcileHistory(authCR, "first")
		AppendReconcileHistory(authCR, "second")
		AppendReconcileHistory(authCR, "third")

		Expect(authCR.Status.ReconcileHistory[0]).To(ContainSubstring("third"))
		Expect(authCR.Status.ReconcileHistory[1]).To(ContainSubstring("second"))
		Expect(authCR.Status.ReconcileHistory[2]).To(ContainSubstring("first"))
	})

	It("caps at maxReconcileHistoryEntries (3) and drops the oldest", func() {
		for i := 1; i <= 4; i++ {
			AppendReconcileHistory(authCR, fmt.Sprintf("msg %d", i))
		}
		Expect(authCR.Status.ReconcileHistory).To(HaveLen(maxReconcileHistoryEntries))
		// Most recent (msg 4) must be first; msg 1 (oldest) must be dropped
		Expect(authCR.Status.ReconcileHistory[0]).To(ContainSubstring("msg 4"))
		Expect(authCR.Status.ReconcileHistory).NotTo(ContainElement(ContainSubstring("msg 1")))
	})
})

var _ = Describe("MarkReconcileSuccess", func() {
	var authCR *operatorv1alpha1.Authentication

	BeforeEach(func() {
		authCR = &operatorv1alpha1.Authentication{}
	})

	It("prepends a success message", func() {
		MarkReconcileSuccess(authCR)
		Expect(authCR.Status.ReconcileHistory).To(HaveLen(1))
		Expect(authCR.Status.ReconcileHistory[0]).To(ContainSubstring("completed successfully"))
	})

	It("leaves previous failure entries below the success entry", func() {
		AppendReconcileHistory(authCR, "something failed")
		MarkReconcileSuccess(authCR)

		Expect(authCR.Status.ReconcileHistory).To(HaveLen(2))
		Expect(authCR.Status.ReconcileHistory[0]).To(ContainSubstring("completed successfully"))
		Expect(authCR.Status.ReconcileHistory[1]).To(ContainSubstring("something failed"))
	})

	It("obeys the 3-entry cap", func() {
		AppendReconcileHistory(authCR, "err 1")
		AppendReconcileHistory(authCR, "err 2")
		AppendReconcileHistory(authCR, "err 3")
		MarkReconcileSuccess(authCR)

		Expect(authCR.Status.ReconcileHistory).To(HaveLen(maxReconcileHistoryEntries))
		Expect(authCR.Status.ReconcileHistory[0]).To(ContainSubstring("completed successfully"))
	})
})

var _ = Describe("DeepCopy for progress fields", func() {
	It("copies ReconcileHistory without aliasing", func() {
		status := operatorv1alpha1.AuthenticationStatus{
			Progress:        "55%",
			ProgressMessage: "Finished Core Resources",
			ReconcileHistory: []string{
				"2026-09-02T10:00:00Z something failed",
			},
		}
		copied := status.DeepCopy()
		Expect(copied.Progress).To(Equal("55%"))
		Expect(copied.ProgressMessage).To(Equal("Finished Core Resources"))
		Expect(copied.ReconcileHistory).To(HaveLen(1))

		// Mutate original — copy must be unaffected.
		status.ReconcileHistory[0] = "mutated"
		Expect(copied.ReconcileHistory[0]).To(Equal("2026-09-02T10:00:00Z something failed"))
	})
})
