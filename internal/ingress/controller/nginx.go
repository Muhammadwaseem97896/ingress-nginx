/*
Copyright 2015 The Kubernetes Authors.

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

package controller

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	proxyproto "github.com/armon/go-proxyproto"
	"github.com/eapache/channels"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	apiv1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/ingress-nginx/pkg/tcpproxy"

	adm_controller "k8s.io/ingress-nginx/internal/admission/controller"
	"k8s.io/ingress-nginx/internal/ingress/controller/config"
	ngx_config "k8s.io/ingress-nginx/internal/ingress/controller/config"
	"k8s.io/ingress-nginx/internal/ingress/controller/process"
	"k8s.io/ingress-nginx/internal/ingress/controller/store"
	ngx_template "k8s.io/ingress-nginx/internal/ingress/controller/template"
	"k8s.io/ingress-nginx/internal/ingress/metric"
	"k8s.io/ingress-nginx/internal/ingress/status"
	ing_net "k8s.io/ingress-nginx/internal/net"
	"k8s.io/ingress-nginx/internal/net/dns"
	"k8s.io/ingress-nginx/internal/net/ssl"
	"k8s.io/ingress-nginx/internal/nginx"
	"k8s.io/ingress-nginx/internal/task"
	"k8s.io/ingress-nginx/pkg/apis/ingress"

	"k8s.io/ingress-nginx/pkg/util/file"
	utilingress "k8s.io/ingress-nginx/pkg/util/ingress"
	"k8s.io/ingress-nginx/pkg/util/maxmind"
	ingressruntime "k8s.io/ingress-nginx/pkg/util/runtime"

	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"

	klog "k8s.io/klog/v2"

	pubsub "github.com/moby/pubsub"
)

const (
	tempNginxPattern = "nginx-cfg"
)

// Subscribers represents a list of clients that subscribed to gRPC updates
type Subscribers struct {
	Lock    sync.RWMutex
	Clients map[string]chan int
}

// NewNGINXController creates a new NGINX Ingress controller.
func NewNGINXController(config *Configuration, mc metric.Collector) *NGINXController {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(klog.Infof)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{
		Interface: config.Client.CoreV1().Events(config.Namespace),
	})

	h, err := dns.GetSystemNameServers()
	if err != nil {
		klog.Warningf("Error reading system nameservers: %v", err)
	}

	n := &NGINXController{
		isIPV6Enabled: ing_net.IsIPv6Enabled(),

		resolver:        h,
		cfg:             config,
		syncRateLimiter: flowcontrol.NewTokenBucketRateLimiter(config.SyncRateLimit, 1),

		recorder: eventBroadcaster.NewRecorder(scheme.Scheme, apiv1.EventSource{
			Component: "nginx-ingress-controller",
		}),

		stopCh:   make(chan struct{}),
		updateCh: channels.NewRingChannel(1024),

		ngxErrCh: make(chan error),

		stopLock: &sync.Mutex{},

		runningConfig:  new(ingress.Configuration),
		templateConfig: new(ngx_config.TemplateConfig),

		Proxy: &tcpproxy.TCPProxy{},

		GRPCSubscribers: pubsub.NewPublisher(10*time.Second, 1024),

		metricCollector: mc,

		command: NewNginxCommand(),
	}

	if n.cfg.ValidationWebhook != "" {
		n.validationWebhookServer = &http.Server{
			Addr: config.ValidationWebhook,
			//G112 (CWE-400): Potential Slowloris Attack
			ReadHeaderTimeout: 10 * time.Second,
			Handler:           adm_controller.NewAdmissionControllerServer(&adm_controller.IngressAdmission{Checker: n}),
			TLSConfig:         ssl.NewTLSListener(n.cfg.ValidationWebhookCertPath, n.cfg.ValidationWebhookKeyPath).TLSConfig(),
			// disable http/2
			// https://github.com/kubernetes/kubernetes/issues/80313
			// https://github.com/kubernetes/ingress-nginx/issues/6323#issuecomment-737239159
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}
	}

	n.store = store.New(
		config.Namespace,
		config.WatchNamespaceSelector,
		config.ConfigMapName,
		config.TCPConfigMapName,
		config.UDPConfigMapName,
		config.DefaultSSLCertificate,
		config.ResyncPeriod,
		config.Client,
		n.updateCh,
		config.DisableCatchAll,
		config.DeepInspector,
		config.IngressClassConfiguration)

	n.syncQueue = task.NewTaskQueue(n.syncIngress)

	if config.UpdateStatus {
		n.syncStatus = status.NewStatusSyncer(status.Config{
			Client:                 config.Client,
			PublishService:         config.PublishService,
			PublishStatusAddress:   config.PublishStatusAddress,
			IngressLister:          n.store,
			UpdateStatusOnShutdown: config.UpdateStatusOnShutdown,
			UseNodeInternalIP:      config.UseNodeInternalIP,
		})
	} else {
		klog.Warning("Update of Ingress status is disabled (flag --update-status)")
	}

	onTemplateChange := func() {
		template, err := ngx_template.NewTemplate(nginx.TemplatePath)
		if err != nil {
			// this error is different from the rest because it must be clear why nginx is not working
			klog.ErrorS(err, "Error loading new template")
			return
		}

		n.t = template
		klog.InfoS("New NGINX configuration template loaded")
		n.syncQueue.EnqueueTask(task.GetDummyObject("template-change"))
	}

	ngxTpl, err := ngx_template.NewTemplate(nginx.TemplatePath)
	if err != nil {
		klog.Fatalf("Invalid NGINX configuration template: %v", err)
	}

	n.t = ngxTpl

	if config.ListenPorts.GRPCPort != -1 {
		n.gRPCServer = grpc.NewServer(config.GRPCOpts...)
	}
	_, err = file.NewFileWatcher(nginx.TemplatePath, onTemplateChange)
	if err != nil {
		klog.Fatalf("Error creating file watcher for %v: %v", nginx.TemplatePath, err)
	}

	filesToWatch := []string{}
	err = filepath.Walk("/etc/nginx/geoip/", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		filesToWatch = append(filesToWatch, path)
		return nil
	})

	if err != nil {
		klog.Fatalf("Error creating file watchers: %v", err)
	}

	for _, f := range filesToWatch {
		_, err = file.NewFileWatcher(f, func() {
			klog.InfoS("File changed detected. Reloading NGINX", "path", f)
			n.syncQueue.EnqueueTask(task.GetDummyObject("file-change"))
		})
		if err != nil {
			klog.Fatalf("Error creating file watcher for %v: %v", f, err)
		}
	}

	return n
}

// NGINXController describes a NGINX Ingress controller.
type NGINXController struct {
	cfg *Configuration

	recorder record.EventRecorder

	syncQueue *task.Queue

	syncStatus status.Syncer

	syncRateLimiter flowcontrol.RateLimiter

	// stopLock is used to enforce that only a single call to Stop send at
	// a given time. We allow stopping through an HTTP endpoint and
	// allowing concurrent stoppers leads to stack traces.
	stopLock *sync.Mutex

	stopCh   chan struct{}
	updateCh *channels.RingChannel

	// Subscribers are the subscribers of gRPC Endpoint
	GRPCSubscribers *pubsub.Publisher

	// ngxErrCh is used to detect errors with the NGINX processes
	ngxErrCh chan error

	// runningConfig contains the running configuration in the Backend
	runningConfig *ingress.Configuration

	// templateConfig contains the running template
	templateConfig *ngx_config.TemplateConfig

	t ngx_template.Writer

	resolver []net.IP

	isIPV6Enabled bool

	isShuttingDown bool

	Proxy *tcpproxy.TCPProxy

	store store.Storer

	metricCollector    metric.Collector
	admissionCollector metric.Collector

	validationWebhookServer *http.Server

	gRPCServer *grpc.Server

	command NginxExecTester
}

// Start starts a new NGINX master process running in the foreground.
func (n *NGINXController) Start() {
	klog.InfoS("Starting NGINX Ingress controller")

	n.store.Run(n.stopCh)

	// we need to use the defined ingress class to allow multiple leaders
	// in order to update information about ingress status
	// TODO: For now, as the the IngressClass logics has changed, is up to the
	// cluster admin to create different Leader Election IDs.
	// Should revisit this in a future
	electionID := n.cfg.ElectionID

	setupLeaderElection(&leaderElectionConfig{
		Client:     n.cfg.Client,
		ElectionID: electionID,
		OnStartedLeading: func(stopCh chan struct{}) {
			if n.syncStatus != nil {
				go n.syncStatus.Run(stopCh)
			}

			n.metricCollector.OnStartedLeading(electionID)
			// manually update SSL expiration metrics
			// (to not wait for a reload)
			n.metricCollector.SetSSLExpireTime(n.runningConfig.Servers)
			n.metricCollector.SetSSLInfo(n.runningConfig.Servers)
		},
		OnStoppedLeading: func() {
			n.metricCollector.OnStoppedLeading(electionID)
		},
	})

	/*if n.cfg.EnableSSLPassthrough {
		n.setupSSLProxy()
	}*/

	if n.gRPCServer == nil {
		klog.InfoS("Starting NGINX process")
		cmd := n.command.ExecCommand()

		// put NGINX in another process group to prevent it
		// to receive signals meant for the controller
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true,
			Pgid:    0,
		}
		n.start(cmd)
	}

	go n.syncQueue.Run(time.Second, n.stopCh)
	// force initial sync
	n.syncQueue.EnqueueTask(task.GetDummyObject("initial-sync"))

	// In case of error the temporal configuration file will
	// be available up to five minutes after the error
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			err := cleanTempNginxCfg()
			if err != nil {
				klog.ErrorS(err, "Unexpected error removing temporal configuration files")
			}
		}
	}()

	if n.validationWebhookServer != nil {
		klog.InfoS("Starting validation webhook", "address", n.validationWebhookServer.Addr,
			"certPath", n.cfg.ValidationWebhookCertPath, "keyPath", n.cfg.ValidationWebhookKeyPath)
		go func() {
			klog.ErrorS(n.validationWebhookServer.ListenAndServeTLS("", ""), "Error listening for TLS connections")
		}()
	}

	var healthcheck *health.Server
	if n.gRPCServer != nil {
		klog.InfoS("Starting grpc server", "port", n.cfg.ListenPorts.GRPCPort)
		healthcheck = health.NewServer()
		healthgrpc.RegisterHealthServer(n.gRPCServer, healthcheck)
		ingress.RegisterEventServiceServer(n.gRPCServer, &EventServer{
			n: n,
		})
		ingress.RegisterConfigurationServer(n.gRPCServer, &ConfigurationServer{
			n: n,
		})

		lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", n.cfg.ListenPorts.GRPCPort))
		if err != nil {
			klog.Fatalf("failed to listen: %v", err)
		}
		go func() {
			klog.ErrorS(n.gRPCServer.Serve(lis), "failed to start gRPC Server")
		}()
	}
	if healthcheck != nil {
		healthcheck.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)
	}

	for {
		select {
		case err := <-n.ngxErrCh:
			if n.isShuttingDown {
				if healthcheck != nil {
					healthcheck.SetServingStatus("", healthgrpc.HealthCheckResponse_NOT_SERVING)
				}
				return
			}

			// if the nginx master process dies, the workers continue to process requests
			// until the failure of the configured livenessProbe and restart of the pod.
			if process.IsRespawnIfRequired(err) {
				return
			}

		case event := <-n.updateCh.Out():
			if n.isShuttingDown {
				if healthcheck != nil {
					healthcheck.SetServingStatus("", healthgrpc.HealthCheckResponse_NOT_SERVING)
				}
				break
			}

			if evt, ok := event.(store.Event); ok {
				klog.V(3).InfoS("Event received", "type", evt.Type, "object", evt.Obj)
				if evt.Type == store.ConfigurationEvent {
					// TODO: is this necessary? Consider removing this special case
					n.syncQueue.EnqueueTask(task.GetDummyObject("configmap-change"))
					continue
				}

				n.syncQueue.EnqueueSkippableTask(evt.Obj)
			} else {
				klog.Warningf("Unexpected event type received %T", event)
			}
		case <-n.stopCh:
			if healthcheck != nil {
				healthcheck.SetServingStatus("", healthgrpc.HealthCheckResponse_NOT_SERVING)
			}
			return
		}
	}
}

// Stop gracefully stops the NGINX master process.
func (n *NGINXController) Stop() error {
	n.isShuttingDown = true

	n.stopLock.Lock()
	defer n.stopLock.Unlock()

	if n.syncQueue.IsShuttingDown() {
		return fmt.Errorf("shutdown already in progress")
	}

	time.Sleep(time.Duration(n.cfg.ShutdownGracePeriod) * time.Second)

	klog.InfoS("Shutting down controller queues")
	close(n.stopCh)
	go n.syncQueue.Shutdown()
	if n.syncStatus != nil {
		n.syncStatus.Shutdown()
	}

	if n.validationWebhookServer != nil {
		klog.InfoS("Stopping admission controller")
		err := n.validationWebhookServer.Close()
		if err != nil {
			return err
		}
	}

	if n.gRPCServer == nil {
		// send stop signal to NGINX
		klog.InfoS("Stopping NGINX process")
		cmd := n.command.ExecCommand("-s", "quit")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		if err != nil {
			return err
		}

		// wait for the NGINX process to terminate
		timer := time.NewTicker(time.Second * 1)
		for range timer.C {
			if !nginx.IsRunning() {
				klog.InfoS("NGINX process has stopped")
				timer.Stop()
				break
			}
		}
	}

	return nil
}

func (n *NGINXController) start(cmd *exec.Cmd) {
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		klog.Fatalf("NGINX error: %v", err)
		n.ngxErrCh <- err
		return
	}

	go func() {
		n.ngxErrCh <- cmd.Wait()
	}()
}

// DefaultEndpoint returns the default endpoint to be use as default server that returns 404.
func (n *NGINXController) DefaultEndpoint() ingress.Endpoint {
	return ingress.Endpoint{
		Address: "127.0.0.1",
		Port:    fmt.Sprintf("%v", n.cfg.ListenPorts.Default),
		Target:  &apiv1.ObjectReference{},
	}
}

// renderTemplate renders a new template. It can be used by template generation or gRPC Server
func (n *NGINXController) renderTemplate(cfg ngx_config.Configuration, ingressCfg ingress.Configuration) (config.TemplateConfig, error) {

	if n.cfg.EnableSSLPassthrough {
		servers := []*tcpproxy.TCPServer{}
		for _, pb := range ingressCfg.PassthroughBackends {
			svc := pb.Service
			if svc == nil {
				klog.Warningf("Missing Service for SSL Passthrough backend %q", pb.Backend)
				continue
			}
			port, err := strconv.Atoi(pb.Port.String()) // #nosec
			if err != nil {
				for _, sp := range svc.Spec.Ports {
					if sp.Name == pb.Port.String() {
						port = int(sp.Port)
						break
					}
				}
			} else {
				for _, sp := range svc.Spec.Ports {
					if sp.Port == int32(port) {
						port = int(sp.Port)
						break
					}
				}
			}

			// TODO: Allow PassthroughBackends to specify they support proxy-protocol
			servers = append(servers, &tcpproxy.TCPServer{
				Hostname:      pb.Hostname,
				IP:            svc.Spec.ClusterIP,
				Port:          port,
				ProxyProtocol: false,
			})
		}

		n.Proxy.ServerList = servers
	}

	// NGINX cannot resize the hash tables used to store server names. For
	// this reason we check if the current size is correct for the host
	// names defined in the Ingress rules and adjust the value if
	// necessary.
	// https://trac.nginx.org/nginx/ticket/352
	// https://trac.nginx.org/nginx/ticket/631
	var longestName int
	var serverNameBytes int

	for _, srv := range ingressCfg.Servers {
		hostnameLength := len(srv.Hostname)
		if srv.RedirectFromToWWW {
			hostnameLength += 4
		}
		if longestName < hostnameLength {
			longestName = hostnameLength
		}

		for _, alias := range srv.Aliases {
			if longestName < len(alias) {
				longestName = len(alias)
			}
		}

		serverNameBytes += hostnameLength
	}

	nameHashBucketSize := nginxHashBucketSize(longestName)
	if cfg.ServerNameHashBucketSize < nameHashBucketSize {
		klog.V(3).InfoS("Adjusting ServerNameHashBucketSize variable", "value", nameHashBucketSize)
		cfg.ServerNameHashBucketSize = nameHashBucketSize
	}

	serverNameHashMaxSize := nextPowerOf2(serverNameBytes)
	if cfg.ServerNameHashMaxSize < serverNameHashMaxSize {
		klog.V(3).InfoS("Adjusting ServerNameHashMaxSize variable", "value", serverNameHashMaxSize)
		cfg.ServerNameHashMaxSize = serverNameHashMaxSize
	}

	if cfg.MaxWorkerOpenFiles == 0 {
		// the limit of open files is per worker process
		// and we leave some room to avoid consuming all the FDs available
		maxOpenFiles := ingressruntime.RlimitMaxNumFiles() - 1024
		klog.V(3).InfoS("Maximum number of open file descriptors", "value", maxOpenFiles)
		if maxOpenFiles < 1024 {
			// this means the value of RLIMIT_NOFILE is too low.
			maxOpenFiles = 1024
		}
		klog.V(3).InfoS("Adjusting MaxWorkerOpenFiles variable", "value", maxOpenFiles)
		cfg.MaxWorkerOpenFiles = maxOpenFiles
	}

	if cfg.MaxWorkerConnections == 0 {
		maxWorkerConnections := int(float64(cfg.MaxWorkerOpenFiles * 3.0 / 4))
		klog.V(3).InfoS("Adjusting MaxWorkerConnections variable", "value", maxWorkerConnections)
		cfg.MaxWorkerConnections = maxWorkerConnections
	}

	setHeaders := map[string]string{}
	if cfg.ProxySetHeaders != "" {
		cmap, err := n.store.GetConfigMap(cfg.ProxySetHeaders)
		if err != nil {
			klog.Warningf("Error reading ConfigMap %q from local store: %v", cfg.ProxySetHeaders, err)
		} else {
			setHeaders = cmap.Data
		}
	}

	addHeaders := map[string]string{}
	if cfg.AddHeaders != "" {
		cmap, err := n.store.GetConfigMap(cfg.AddHeaders)
		if err != nil {
			klog.Warningf("Error reading ConfigMap %q from local store: %v", cfg.AddHeaders, err)
		} else {
			addHeaders = cmap.Data
		}
	}

	if n.cfg.IsChroot {
		if cfg.AccessLogPath == "/var/log/nginx/access.log" {
			cfg.AccessLogPath = fmt.Sprintf("syslog:server=%s", n.cfg.InternalLoggerAddress)
		}
		if cfg.ErrorLogPath == "/var/log/nginx/error.log" {
			cfg.ErrorLogPath = fmt.Sprintf("syslog:server=%s", n.cfg.InternalLoggerAddress)
		}
	}

	tc := ngx_config.TemplateConfig{
		Checksum:                 ingressCfg.ConfigurationChecksum,
		DefaultSSLCertificate:    n.getDefaultSSLCertificate(),
		ProxySetHeaders:          setHeaders,
		AddHeaders:               addHeaders,
		BacklogSize:              ingressruntime.SysctlSomaxconn(), // TODO: must be calculated in dataplane. Keeping for compatibility right now
		Backends:                 ingressCfg.Backends,
		PassthroughBackends:      ingressCfg.PassthroughBackends,
		Servers:                  ingressCfg.Servers,
		TCPBackends:              ingressCfg.TCPEndpoints,
		UDPBackends:              ingressCfg.UDPEndpoints,
		Cfg:                      cfg,
		IsIPV6Enabled:            n.isIPV6Enabled && !cfg.DisableIpv6,
		NginxStatusIpv4Whitelist: cfg.NginxStatusIpv4Whitelist,
		NginxStatusIpv6Whitelist: cfg.NginxStatusIpv6Whitelist,
		RedirectServers:          utilingress.BuildRedirects(ingressCfg.Servers),
		IsSSLPassthroughEnabled:  n.cfg.EnableSSLPassthrough,
		ListenPorts:              n.cfg.ListenPorts,
		EnableMetrics:            n.cfg.EnableMetrics,
		HealthzURI:               nginx.HealthPath,
		MonitorMaxBatchSize:      n.cfg.MonitorMaxBatchSize,
		PID:                      nginx.PID,
		StatusPath:               nginx.StatusPath,
		StatusPort:               nginx.StatusPort,
		StreamPort:               nginx.StreamPort,
		StreamSnippets:           append(ingressCfg.StreamSnippets, cfg.StreamSnippet),
	}

	if cfg.SSLDHParam != "" {
		dhfile, dhcontent := n.getDHParam(cfg)
		if dhfile != "" && dhcontent != nil {
			tc.DHParamFile = dhfile
			tc.DHParamContent = dhcontent
		}
	}

	if cfg.UseGeoIP2 {
		if files, exists := maxmind.GeoLite2DBExists(n.cfg.MaxMindEditionIDs); exists {
			tc.MaxmindEditionFiles = files
		}
	}

	return tc, nil

}

func (n *NGINXController) getDHParam(cfg ngx_config.Configuration) (string, []byte) {
	secretName := cfg.SSLDHParam
	nsSecName := strings.Replace(secretName, "/", "-", -1)

	var dh []byte
	var ok bool
	secret, err := n.store.GetSecret(secretName)
	if err != nil {
		klog.Warningf("Error reading Secret %q from local store: %v", secretName, err)
		return "", nil
	}

	dh, ok = secret.Data["dhparam.pem"]
	if !ok {
		klog.Warning("error geting the value")
		return "", nil

	}

	pemName := fmt.Sprintf("%s/%v.pem", file.DefaultSSLDirectory, nsSecName)
	return pemName, dh
}

// generateTemplate returns the nginx configuration file content
func (n *NGINXController) generateTemplate(cfg ngx_config.Configuration, ingressCfg ingress.Configuration) ([]byte, error) {

	// TODO: BEFORE MERGE! This shouln't be here!
	// This function should only get/generate the struct, but AddOrUpdateDHParam also writes a file.
	sslDHParamFile := ""
	if cfg.SSLDHParam != "" {
		sslDHParamFile, dh := n.getDHParam(cfg)
		if sslDHParamFile != "" && dh != nil {
			cfg.SSLDHParam = sslDHParamFile
		}

		err := ssl.AddOrUpdateDHParam(sslDHParamFile, dh)
		if err != nil {
			klog.Warningf("Error adding or updating dhparam file %v: %v", sslDHParamFile, err)
		}
	}

	cfg.SSLDHParam = sslDHParamFile

	tc, err := n.renderTemplate(cfg, ingressCfg)
	if err != nil {
		return nil, fmt.Errorf("error rendering template: %s", err)
	}

	return n.t.Write(tc)
}

// testTemplate checks if the NGINX configuration inside the byte array is valid
// running the command "nginx -t" using a temporal file.
func (n *NGINXController) testTemplate(cfg []byte) error {
	if len(cfg) == 0 {
		return fmt.Errorf("invalid NGINX configuration (empty)")
	}
	tmpDir := os.TempDir() + "/nginx"
	tmpfile, err := os.CreateTemp(tmpDir, tempNginxPattern)
	if err != nil {
		return err
	}
	defer tmpfile.Close()
	err = os.WriteFile(tmpfile.Name(), cfg, file.ReadWriteByUser)
	if err != nil {
		return err
	}
	out, err := n.command.Test(tmpfile.Name())
	if err != nil {
		// this error is different from the rest because it must be clear why nginx is not working
		oe := fmt.Sprintf(`
-------------------------------------------------------------------------------
Error: %v
%v
-------------------------------------------------------------------------------
`, err, string(out))

		return errors.New(oe)
	}

	os.Remove(tmpfile.Name())
	return nil
}

// OnUpdate is called by the synchronization loop whenever configuration
// changes were detected. The received backend Configuration is merged with the
// configuration ConfigMap before generating the final configuration file.
// Returns nil in case the backend was successfully reloaded.
func (n *NGINXController) OnUpdate(ingressCfg ingress.Configuration) error {
	cfg := n.store.GetBackendConfiguration()
	cfg.Resolver = n.resolver

	content, err := n.generateTemplate(cfg, ingressCfg)
	if err != nil {
		return err
	}

	err = createOpentracingCfg(cfg)
	if err != nil {
		return err
	}

	err = n.testTemplate(content)
	if err != nil {
		return err
	}

	if klog.V(2).Enabled() {
		src, _ := os.ReadFile(cfgPath)
		if !bytes.Equal(src, content) {
			tmpfile, err := os.CreateTemp("", "new-nginx-cfg")
			if err != nil {
				return err
			}
			defer tmpfile.Close()
			err = os.WriteFile(tmpfile.Name(), content, file.ReadWriteByUser)
			if err != nil {
				return err
			}

			diffOutput, err := exec.Command("diff", "-I", "'# Configuration.*'", "-u", cfgPath, tmpfile.Name()).CombinedOutput()
			if err != nil {
				if exitError, ok := err.(*exec.ExitError); ok {
					ws := exitError.Sys().(syscall.WaitStatus)
					if ws.ExitStatus() == 2 {
						klog.Warningf("Failed to executing diff command: %v", err)
					}
				}
			}

			klog.InfoS("NGINX configuration change", "diff", string(diffOutput))

			// we do not defer the deletion of temp files in order
			// to keep them around for inspection in case of error
			os.Remove(tmpfile.Name())
		}
	}

	err = os.WriteFile(cfgPath, content, file.ReadWriteByUser)
	if err != nil {
		return err
	}

	if n.gRPCServer == nil {
		o, err := n.command.ExecCommand("-s", "reload").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v\n%v", err, string(o))
		}
	}

	return nil
}

// nginxHashBucketSize computes the correct NGINX hash_bucket_size for a hash
// with the given longest key.
func nginxHashBucketSize(longestString int) int {
	// see https://github.com/kubernetes/ingress-nginxs/issues/623 for an explanation
	wordSize := 8 // Assume 64 bit CPU
	n := longestString + 2
	aligned := (n + wordSize - 1) & ^(wordSize - 1)
	rawSize := wordSize + wordSize + aligned
	return nextPowerOf2(rawSize)
}

// http://graphics.stanford.edu/~seander/bithacks.html#RoundUpPowerOf2
// https://play.golang.org/p/TVSyCcdxUh
func nextPowerOf2(v int) int {
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v++

	return v
}

func (n *NGINXController) setupSSLProxy() {
	cfg := n.store.GetBackendConfiguration()
	sslPort := n.cfg.ListenPorts.HTTPS
	proxyPort := n.cfg.ListenPorts.SSLProxy

	klog.InfoS("Starting TLS proxy for SSL Passthrough")
	n.Proxy = &tcpproxy.TCPProxy{
		Default: &tcpproxy.TCPServer{
			Hostname:      "localhost",
			IP:            "127.0.0.1",
			Port:          proxyPort,
			ProxyProtocol: true,
		},
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%v", sslPort))
	if err != nil {
		klog.Fatalf("%v", err)
	}

	proxyList := &proxyproto.Listener{Listener: listener, ProxyHeaderTimeout: cfg.ProxyProtocolHeaderTimeout}

	// accept TCP connections on the configured HTTPS port
	go func() {
		for {
			var conn net.Conn
			var err error

			if n.store.GetBackendConfiguration().UseProxyProtocol {
				// wrap the listener in order to decode Proxy
				// Protocol before handling the connection
				conn, err = proxyList.Accept()
			} else {
				conn, err = listener.Accept()
			}

			if err != nil {
				klog.Warningf("Error accepting TCP connection: %v", err)
				continue
			}

			klog.V(3).InfoS("Handling TCP connection", "remote", conn.RemoteAddr(), "local", conn.LocalAddr())
			go n.Proxy.Handle(conn)
		}
	}()
}

// Helper function to clear Certificates from the ingress configuration since they should be ignored when
// checking if the new configuration changes can be applied dynamically if dynamic certificates is on
func clearCertificates(config *ingress.Configuration) {
	var clearedServers []*ingress.Server
	for _, server := range config.Servers {
		copyOfServer := *server
		copyOfServer.SSLCert = nil
		clearedServers = append(clearedServers, &copyOfServer)
	}
	config.Servers = clearedServers
}

// Helper function to clear endpoints from the ingress configuration since they should be ignored when
// checking if the new configuration changes can be applied dynamically.
func clearL4serviceEndpoints(config *ingress.Configuration) {
	var clearedTCPL4Services []ingress.L4Service
	var clearedUDPL4Services []ingress.L4Service
	for _, service := range config.TCPEndpoints {
		copyofService := ingress.L4Service{
			Port:      service.Port,
			Backend:   service.Backend,
			Endpoints: []ingress.Endpoint{},
			Service:   nil,
		}
		clearedTCPL4Services = append(clearedTCPL4Services, copyofService)
	}
	for _, service := range config.UDPEndpoints {
		copyofService := ingress.L4Service{
			Port:      service.Port,
			Backend:   service.Backend,
			Endpoints: []ingress.Endpoint{},
			Service:   nil,
		}
		clearedUDPL4Services = append(clearedUDPL4Services, copyofService)
	}
	config.TCPEndpoints = clearedTCPL4Services
	config.UDPEndpoints = clearedUDPL4Services
}

const zipkinTmpl = `{
  "service_name": "{{ .ZipkinServiceName }}",
  "collector_host": "{{ .ZipkinCollectorHost }}",
  "collector_port": {{ .ZipkinCollectorPort }},
  "sample_rate": {{ .ZipkinSampleRate }}
}`

const jaegerTmpl = `{
  "service_name": "{{ .JaegerServiceName }}",
  "propagation_format": "{{ .JaegerPropagationFormat }}",
  "sampler": {
	"type": "{{ .JaegerSamplerType }}",
	"param": {{ .JaegerSamplerParam }},
	"samplingServerURL": "{{ .JaegerSamplerHost }}:{{ .JaegerSamplerPort }}/sampling"
  },
  "reporter": {
	"endpoint": "{{ .JaegerEndpoint }}",
	"localAgentHostPort": "{{ .JaegerCollectorHost }}:{{ .JaegerCollectorPort }}"
  },
  "headers": {
	"TraceContextHeaderName": "{{ .JaegerTraceContextHeaderName }}",
	"jaegerDebugHeader": "{{ .JaegerDebugHeader }}",
	"jaegerBaggageHeader": "{{ .JaegerBaggageHeader }}",
	"traceBaggageHeaderPrefix": "{{ .JaegerTraceBaggageHeaderPrefix }}"
  }
}`

const datadogTmpl = `{
  "service": "{{ .DatadogServiceName }}",
  "agent_host": "{{ .DatadogCollectorHost }}",
  "agent_port": {{ .DatadogCollectorPort }},
  "environment": "{{ .DatadogEnvironment }}",
  "operation_name_override": "{{ .DatadogOperationNameOverride }}",
  "sample_rate": {{ .DatadogSampleRate }},
  "dd.priority.sampling": {{ .DatadogPrioritySampling }}
}`

func createOpentracingCfg(cfg ngx_config.Configuration) error {
	var tmpl *template.Template
	var err error

	if cfg.ZipkinCollectorHost != "" {
		tmpl, err = template.New("zipkin").Parse(zipkinTmpl)
		if err != nil {
			return err
		}
	} else if cfg.JaegerCollectorHost != "" || cfg.JaegerEndpoint != "" {
		tmpl, err = template.New("jaeger").Parse(jaegerTmpl)
		if err != nil {
			return err
		}
	} else if cfg.DatadogCollectorHost != "" {
		tmpl, err = template.New("datadog").Parse(datadogTmpl)
		if err != nil {
			return err
		}
	} else {
		tmpl, _ = template.New("empty").Parse("{}")
	}

	tmplBuf := bytes.NewBuffer(make([]byte, 0))
	err = tmpl.Execute(tmplBuf, cfg)
	if err != nil {
		return err
	}

	// Expand possible environment variables before writing the configuration to file.
	expanded := os.ExpandEnv(tmplBuf.String())

	return os.WriteFile("/etc/nginx/opentracing.json", []byte(expanded), file.ReadWriteByUser)
}

func cleanTempNginxCfg() error {
	var files []string

	err := filepath.Walk(os.TempDir(), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && os.TempDir() != path {
			return filepath.SkipDir
		}

		dur, _ := time.ParseDuration("-5m")
		fiveMinutesAgo := time.Now().Add(dur)
		if strings.HasPrefix(info.Name(), tempNginxPattern) && info.ModTime().Before(fiveMinutesAgo) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return err
	}

	for _, file := range files {
		err := os.Remove(file)
		if err != nil {
			return err
		}
	}

	return nil
}
