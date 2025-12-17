package main

import (
	"flag"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	piiv1alpha1 "github.com/bunseokbot/pii-redactor/api/v1alpha1"
	"github.com/bunseokbot/pii-redactor/internal/audit"
	"github.com/bunseokbot/pii-redactor/internal/controller"
	"github.com/bunseokbot/pii-redactor/internal/detector"
	"github.com/bunseokbot/pii-redactor/internal/notifier"
	"github.com/bunseokbot/pii-redactor/internal/policy"
	"github.com/bunseokbot/pii-redactor/internal/source"
	"github.com/bunseokbot/pii-redactor/internal/subscription"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(piiv1alpha1.AddToScheme(scheme))
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

	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "pii-redactor.namjun.kim",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Create shared components
	engine := detector.NewEngine()
	notifierManager := notifier.NewManager()
	auditLogger := audit.NewControllerRuntimeLogger()
	sourceCache := source.NewCache()

	// Create policy components
	policyMatcher := policy.NewMatcher(mgr.GetClient())
	policyAggregator := policy.NewAggregator(mgr.GetClient(), engine)

	// Create subscription components
	subscriptionManager := subscription.NewManager(sourceCache, engine)
	subscriptionUpdater := subscription.NewUpdater(sourceCache, subscriptionManager)

	// Setup PIIPattern controller
	if err = (&controller.PIIPatternReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Engine: engine,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PIIPattern")
		os.Exit(1)
	}

	// Setup PIIAlertChannel controller
	if err = (&controller.PIIAlertChannelReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		NotifierManager: notifierManager,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PIIAlertChannel")
		os.Exit(1)
	}

	// Setup PIIPolicy controller
	if err = (&controller.PIIPolicyReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		Engine:          engine,
		NotifierManager: notifierManager,
		AuditLogger:     auditLogger,
		Matcher:         policyMatcher,
		Aggregator:      policyAggregator,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PIIPolicy")
		os.Exit(1)
	}

	// Setup PIICommunitySource controller
	if err = (&controller.PIICommunitySourceReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Cache:  sourceCache,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PIICommunitySource")
		os.Exit(1)
	}

	// Setup PIIRuleSubscription controller
	if err = (&controller.PIIRuleSubscriptionReconciler{
		Client:              mgr.GetClient(),
		Scheme:              mgr.GetScheme(),
		Engine:              engine,
		Cache:               sourceCache,
		SubscriptionManager: subscriptionManager,
		Updater:             subscriptionUpdater,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PIIRuleSubscription")
		os.Exit(1)
	}

	// Add health check endpoints
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
