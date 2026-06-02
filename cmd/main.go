/*
Copyright 2023.

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

package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	sscsidriverv1 "sigs.k8s.io/secrets-store-csi-driver/apis/v1"

	oidcsecurityv1 "github.com/IBM/ibm-iam-operator/api/oidc.security/v1"
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/api/operator/v1alpha1"
	certmgrv1 "github.com/IBM/ibm-iam-operator/internal/api/certmanager/v1"
	zenv1 "github.com/IBM/ibm-iam-operator/internal/api/zen.cpd.ibm.com/v1"
	bootstrapcontrollers "github.com/IBM/ibm-iam-operator/internal/controller/bootstrap"
	"github.com/IBM/ibm-iam-operator/internal/controller/common"
	controllercommon "github.com/IBM/ibm-iam-operator/internal/controller/common"
	oidcsecuritycontrollers "github.com/IBM/ibm-iam-operator/internal/controller/oidc.security"
	operatorcontrollers "github.com/IBM/ibm-iam-operator/internal/controller/operator"
	routev1 "github.com/openshift/api/route/v1"
	discovery "k8s.io/client-go/discovery"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(oidcsecurityv1.AddToScheme(scheme))
	utilruntime.Must(certmgrv1.AddToScheme(scheme))
	utilruntime.Must(zenv1.AddToScheme(scheme))

	// Get config and create clients for SSAR checks
	cfg, err := config.GetConfig()
	if err != nil {
		return
	}

	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return
	}

	// Create a temporary client for SSAR checks during init
	tempClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		setupLog.Error(err, "Failed to create temporary client for SSAR checks")
		return
	}

	ctx := context.Background()

	// Check OperandRequest permissions
	operandRequestVerbs := []string{"create", "get", "list", "patch", "watch", "update", "delete"}
	if controllercommon.ClusterHasOperandRequestAPIResource(dc) {
		hasOperandRequestAccess, err := hasNamespacedAPIAccess(ctx, tempClient, "", "operator.ibm.com", "operandrequests", operandRequestVerbs)
		if err != nil {
			setupLog.Error(err, "Failed to check OperandRequest permissions")
		} else if hasOperandRequestAccess {
			setupLog.V(1).Info("OperandRequest API present with required permissions; adding ODLM-enabled operator.ibm.com scheme")
			utilruntime.Must(operatorv1alpha1.AddODLMEnabledToScheme(scheme))
		} else {
			setupLog.Info("OperandRequest API present but missing required permissions; adding base operator.ibm.com scheme")
			utilruntime.Must(operatorv1alpha1.AddToScheme(scheme))
		}
	} else {
		setupLog.V(1).Info("OperandRequest API not present; adding base operator.ibm.com scheme")
		utilruntime.Must(operatorv1alpha1.AddToScheme(scheme))
	}

	// Check Route permissions (including routes/custom-host subresource)
	routeVerbs := []string{"get", "list", "watch", "create", "delete", "update", "patch"}
	if controllercommon.ClusterHasRouteGroupVersion(dc) {
		hasRouteAccess, err := hasNamespacedAPIAccess(ctx, tempClient, "", "route.openshift.io", "routes", routeVerbs)
		if err != nil {
			setupLog.Error(err, "Failed to check Route permissions")
		} else if !hasRouteAccess {
			setupLog.Info("Route API present but missing required permissions; skipping Routes scheme")
		} else {
			// Also check routes/custom-host subresource permission
			hasCustomHostAccess, err := hasNamespacedAPIAccess(ctx, tempClient, "", "route.openshift.io", "routes/custom-host", []string{"create"})
			if err != nil {
				setupLog.Error(err, "Failed to check routes/custom-host permissions")
			} else if hasCustomHostAccess {
				setupLog.V(1).Info("Route API present with all required permissions including routes/custom-host; adding Routes to scheme")
				utilruntime.Must(routev1.AddToScheme(scheme))
			} else {
				setupLog.Info("Route API present but missing routes/custom-host create permission; skipping Routes scheme")
			}
		}
	}

	// Check SecretProviderClass permissions
	spcVerbs := []string{"get", "list", "watch"}
	if controllercommon.ClusterHasCSIGroupVersion(dc) {
		hasSPCAccess, err := hasNamespacedAPIAccess(ctx, tempClient, "", "secrets-store.csi.x-k8s.io", "secretproviderclasses", spcVerbs)
		if err != nil {
			setupLog.Error(err, "Failed to check SecretProviderClass permissions")
		} else if hasSPCAccess {
			setupLog.V(1).Info("SSCSI API present with required permissions; adding SSCSI driver to scheme")
			utilruntime.Must(sscsidriverv1.AddToScheme(scheme))
		} else {
			setupLog.Info("SSCSI API present but missing required permissions; skipping SSCSI driver scheme")
		}
	}
	//+kubebuilder:scaffold:scheme
}

// hasNamespacedAPIAccess uses SelfSubjectAccessReviews to check if the operator has all required permissions
// for a given namespaced resource. Empty namespace means check without namespace scope.
func hasNamespacedAPIAccess(ctx context.Context, c client.Client, namespace string, group string, resource string, verbs []string) (bool, error) {
	for _, verb := range verbs {
		ssar := &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: namespace,
					Verb:      verb,
					Group:     group,
					Resource:  resource,
				},
			},
		}
		if err := c.Create(ctx, ssar); err != nil {
			return false, fmt.Errorf("failed to create SSAR for %s.%s verb %s: %w", resource, group, verb, err)
		}
		if !ssar.Status.Allowed {
			return false, nil
		}
	}
	return true, nil
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrlLog := zap.New(zap.UseFlagOptions(&opts))
	ctrl.SetLogger(ctrlLog)

	watchNamespace, err := controllercommon.GetWatchNamespace()
	if err != nil {
		setupLog.Error(err, "Failed to get watch namespace")
		os.Exit(1)
	}

	mgrOptions := ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "b3c05180.ibm.com",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	}

	// If one or more namespaces are to be watched, the cache.Config for each of those namespaces must be
	// initialized; otherwise, as long as the Cache remains unset, the manager should watch all namespaces:
	// https://github.com/kubernetes-sigs/controller-runtime/blob/v0.17.0/pkg/cluster/cluster.go#L106-L107
	if watchNamespace != "" {
		defaultNamespaces := make(map[string]cache.Config)

		for _, namespace := range strings.Split(watchNamespace, ",") {
			defaultNamespaces[namespace] = cache.Config{}
		}

		cacheOptions := cache.Options{
			DefaultNamespaces:    defaultNamespaces,
			DefaultLabelSelector: labels.Everything(),
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Secret{}: {
					Label: labels.SelectorFromSet(map[string]string{
						"app.kubernetes.io/part-of": "im",
					}),
				},
			},
		}

		mgrOptions.Cache = cacheOptions
	} else {
		cacheOptions := cache.Options{
			DefaultLabelSelector: labels.Everything(),
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Secret{}: {
					Label: labels.SelectorFromSet(map[string]string{
						"app.kubernetes.io/part-of": "im",
					}),
				},
			},
		}

		mgrOptions.Cache = cacheOptions
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), mgrOptions)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	var dc *discovery.DiscoveryClient
	dc, err = discovery.NewDiscoveryClientForConfig(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "failed to get discovery client", "controller", "Authentication")
		os.Exit(1)
	}

	if err = (&bootstrapcontrollers.BootstrapReconciler{
		Client: &controllercommon.FallbackClient{
			Client: mgr.GetClient(),
			Reader: mgr.GetAPIReader(),
		},
		DiscoveryClient: dc,
	}).SetupWithManager(mgr, ctrlLog); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Authentication")
		os.Exit(1)
	}

	const clientControllerName = "controller_oidc_client"

	clientReconciler := &oidcsecuritycontrollers.ClientReconciler{
		Client: &controllercommon.FallbackClient{
			Client: mgr.GetClient(),
			Reader: mgr.GetAPIReader(),
		},
		Reader:        mgr.GetAPIReader(),
		Scheme:        mgr.GetScheme(),
		Recorder:      mgr.GetEventRecorderFor(clientControllerName),
		ByteGenerator: &common.RandomByteGenerator{},
	}
	if os.Getenv(common.ForceRunModeEnv) == string(common.LocalRunMode) {
		clientReconciler.RunMode = common.LocalRunMode
	} else {
		clientReconciler.RunMode = common.ClusterRunMode
	}
	if err = (clientReconciler).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Client")
		os.Exit(1)
	}
	if err = (&operatorcontrollers.AuthenticationReconciler{
		Client: &controllercommon.FallbackClient{
			Client: mgr.GetClient(),
			Reader: mgr.GetAPIReader(),
		},
		DiscoveryClient: *dc,
		Scheme:          mgr.GetScheme(),
		ByteGenerator:   &common.RandomByteGenerator{},
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Authentication")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	readyzLog := ctrl.Log.WithName("probe_readyz").V(1)
	healthzLog := ctrl.Log.WithName("probe_healthz").V(1)
	// Readiness check - verifies operator is ready to process requests
	readyzCheck := func(req *http.Request) error {
		ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
		defer cancel()

		// Primary check: ensure all Informers have synced
		if !mgr.GetCache().WaitForCacheSync(ctx) {
			readyzLog.Info("Readiness check failed; cache failed to sync")
			return fmt.Errorf("cache not synced - Informers not ready")
		} else {
			readyzLog.Info("Ready!")
		}

		return nil
	}

	// Liveness check - verifies operator is alive and can communicate with API server
	healthzCheck := func(req *http.Request) error {
		ctx, cancel := context.WithTimeout(req.Context(), 5*time.Second)
		defer cancel()

		// Verify we can still communicate with the API server
		// Use a lightweight operation to avoid impacting performance
		var authList operatorv1alpha1.AuthenticationList
		if err := mgr.GetClient().List(ctx, &authList, client.Limit(1)); err != nil {
			healthzLog.Info("Health check failed; API server connectivity could not be established", "reason", err.Error())
			return fmt.Errorf("API server connectivity check failed: %w", err)
		} else {
			healthzLog.Info("Healthy!")
		}

		return nil
	}

	if err := mgr.AddHealthzCheck("healthz", healthzCheck); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", readyzCheck); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
