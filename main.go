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
	"flag"
	"os"
	"strings"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	oidcsecurityv1 "github.com/IBM/ibm-iam-operator/apis/oidc.security/v1"
	operatorv1alpha1 "github.com/IBM/ibm-iam-operator/apis/operator/v1alpha1"
	zenv1 "github.com/IBM/ibm-iam-operator/apis/zen.cpd.ibm.com/v1"
	controllercommon "github.com/IBM/ibm-iam-operator/controllers/common"
	oidcsecuritycontrollers "github.com/IBM/ibm-iam-operator/controllers/oidc.security"
	operatorcontrollers "github.com/IBM/ibm-iam-operator/controllers/operator"
	certmgrv1 "github.com/ibm/ibm-cert-manager-operator/apis/cert-manager/v1"
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
	utilruntime.Must(operatorv1alpha1.AddToScheme(scheme))
	utilruntime.Must(certmgrv1.AddToScheme(scheme))
	utilruntime.Must(zenv1.AddToScheme(scheme))
	// Add the Route scheme if found on the cluster
	cfg, err := config.GetConfig()
	if err != nil {
		return
	}

	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return
	}
	if controllercommon.ClusterHasRouteGroupVersion(dc) {
		utilruntime.Must(routev1.AddToScheme(scheme))
	}
	//+kubebuilder:scaffold:scheme
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

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

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
			DefaultNamespaces: defaultNamespaces,
		}

		mgrOptions.Cache = cacheOptions
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), mgrOptions)
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}
	const clientControllerName = "controller_oidc_client"

	clientReconciler := &oidcsecuritycontrollers.ClientReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor(clientControllerName),
	}
	if err = (clientReconciler).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Client")
		os.Exit(1)
	}
	var dc *discovery.DiscoveryClient
	dc, err = discovery.NewDiscoveryClientForConfig(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "failed to get discovery client", "controller", "Authentication")
		os.Exit(1)
	}

	if err = (&operatorcontrollers.AuthenticationReconciler{
		Client:          mgr.GetClient(),
		DiscoveryClient: *dc,
		Scheme:          mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Authentication")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
