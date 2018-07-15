/*
Copyright 2017 The Kubernetes Authors.

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
	"fmt"
	"os"
	"runtime"

	"github.com/golang/glog"
	"github.com/spf13/pflag"

	apiv1 "k8s.io/api/core/v1"

	"k8s.io/ingress-nginx/internal/ingress/annotations/class"
	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	"k8s.io/ingress-nginx/internal/ingress/controller"
	ngx_config "k8s.io/ingress-nginx/internal/ingress/controller/config"
	ing_net "k8s.io/ingress-nginx/internal/net"
	"net"
	"strings"
)

func parseFlags() (bool, *controller.Configuration, error) {
	var (
		flags = pflag.NewFlagSet("", pflag.ExitOnError)

		apiserverHost = flags.String("apiserver-host", "",
			`Address of the Kubernetes API server.
Takes the form "protocol://address:port". If not specified, it is assumed the
program runs inside a Kubernetes cluster and local discovery is attempted.`)

		kubeConfigFile = flags.String("kubeconfig", "",
			`Path to a kubeconfig file containing authorization and API server information.`)

		defaultSvc = flags.String("default-backend-service", "",
			`Service used to serve HTTP requests not matching any known server name (catch-all).
Takes the form "namespace/name". The controller configures NGINX to forward
requests to the first port of this Service.`)

		ingressClass = flags.String("ingress-class", "",
			`Name of the ingress class this controller satisfies.
The class of an Ingress object is set using the annotation "kubernetes.io/ingress.class".
All ingress classes are satisfied if this parameter is left empty.`)

		configMap = flags.String("configmap", "",
			`Name of the ConfigMap containing custom global configurations for the controller.`)

		publishSvc = flags.String("publish-service", "",
			`Service fronting the Ingress controller.
Takes the form "namespace/name". When used together with update-status, the
controller mirrors the address of this service's endpoints to the load-balancer
status of all Ingress objects it satisfies.`)

		tcpConfigMapName = flags.String("tcp-services-configmap", "",
			`Name of the ConfigMap containing the definition of the TCP services to expose.
The key in the map indicates the external port to be used. The value is a
reference to a Service in the form "namespace/name:port", where "port" can
either be a port number or name. TCP ports 80 and 443 are reserved by the
controller for servicing HTTP traffic.`)

		udpConfigMapName = flags.String("udp-services-configmap", "",
			`Name of the ConfigMap containing the definition of the UDP services to expose.
The key in the map indicates the external port to be used. The value is a
reference to a Service in the form "namespace/name:port", where "port" can
either be a port name or number.`)

		resyncPeriod = flags.Duration("sync-period", 0,
			`Period at which the controller forces the repopulation of its local object stores. Disabled by default.`)

		watchNamespace = flags.String("watch-namespace", apiv1.NamespaceAll,
			`Namespace the controller watches for updates to Kubernetes objects.
This includes Ingresses, Services and all configuration resources. All
namespaces are watched if this parameter is left empty.`)

		profiling = flags.Bool("profiling", true,
			`Enable profiling via web interface host:port/debug/pprof/`)

		defSSLCertificate = flags.String("default-ssl-certificate", "",
			`Secret containing a SSL certificate to be used by the default HTTPS server (catch-all).
Takes the form "namespace/name".`)

		defHealthzURL = flags.String("health-check-path", "/healthz",
			`URL path of the health check endpoint.
Configured inside the NGINX status server. All requests received on the port
defined by the healthz-port parameter are forwarded internally to this path.`)

		updateStatus = flags.Bool("update-status", true,
			`Update the load-balancer status of Ingress objects this controller satisfies.
Requires setting the publish-service parameter to a valid Service reference.`)

		electionID = flags.String("election-id", "ingress-controller-leader",
			`Election id to use for Ingress status updates.`)

		forceIsolation = flags.Bool("force-namespace-isolation", false,
			`Force namespace isolation.
Prevents Ingress objects from referencing Secrets and ConfigMaps located in a
different namespace than their own. May be used together with watch-namespace.`)

		updateStatusOnShutdown = flags.Bool("update-status-on-shutdown", true,
			`Update the load-balancer status of Ingress objects when the controller shuts down.
Requires the update-status parameter.`)

		sortBackends = flags.Bool("sort-backends", false,
			`Sort servers inside NGINX upstreams.`)

		useNodeInternalIP = flags.Bool("report-node-internal-ip-address", false,
			`Set the load-balancer status of Ingress objects to internal Node addresses instead of external.
Requires the update-status parameter.`)

		showVersion = flags.Bool("version", false,
			`Show release information about the NGINX Ingress controller and exit.`)

		enableSSLPassthrough = flags.Bool("enable-ssl-passthrough", false,
			`Enable SSL Passthrough.`)

		annotationsPrefix = flags.String("annotations-prefix", "nginx.ingress.kubernetes.io",
			`Prefix of the Ingress annotations specific to the NGINX controller.`)

		enableSSLChainCompletion = flags.Bool("enable-ssl-chain-completion", true,
			`Autocomplete SSL certificate chains with missing intermediate CA certificates.
A valid certificate chain is required to enable OCSP stapling. Certificates
uploaded to Kubernetes must have the "Authority Information Access" X.509 v3
extension for this to succeed.`)

		syncRateLimit = flags.Float32("sync-rate-limit", 0.3,
			`Define the sync frequency upper limit`)

		publishStatusAddress = flags.String("publish-status-address", "",
			`Customized address to set as the load-balancer status of Ingress objects this controller satisfies.
Requires the update-status parameter.`)

		dynamicConfigurationEnabled = flags.Bool("enable-dynamic-configuration", false,
			`Dynamically refresh backends on topology changes instead of reloading NGINX.
Feature backed by OpenResty Lua libraries.`)

		bindAddresses = flags.String("bind-addresses", "0.0.0.0,[::]",
			`Comma separated list of IPv4/IPv6 address to bind to. Default 0.0.0.0,[::]`)
		httpPort      = flags.Int("http-port", 80, `Port to use for servicing HTTP traffic.`)
		httpsPort     = flags.Int("https-port", 443, `Port to use for servicing HTTPS traffic.`)
		statusPort    = flags.Int("status-port", 18080, `Port to use for exposing NGINX status pages.`)
		sslProxyPort  = flags.Int("ssl-passthrough-proxy-port", 442, `Port to use internally for SSL Passthrough.`)
		defServerPort = flags.Int("default-server-port", 8181, `Port to use for exposing the default server (catch-all).`)
		healthzPort   = flags.Int("healthz-port", 10254, "Port to use for the healthz endpoint.")
	)

	flag.Set("logtostderr", "true")

	flags.AddGoFlagSet(flag.CommandLine)
	flags.Parse(os.Args)

	// Workaround for this issue:
	// https://github.com/kubernetes/kubernetes/issues/17162
	flag.CommandLine.Parse([]string{})

	pflag.VisitAll(func(flag *pflag.Flag) {
		glog.V(2).Infof("FLAG: --%s=%q", flag.Name, flag.Value)
	})

	if *showVersion {
		return true, nil, nil
	}

	if *defaultSvc == "" {
		return false, nil, fmt.Errorf("Please specify --default-backend-service")
	}

	if *ingressClass != "" {
		glog.Infof("Watching for Ingress class: %s", *ingressClass)

		if *ingressClass != class.DefaultClass {
			glog.Warningf("Only Ingresses with class %q will be processed by this Ingress controller", *ingressClass)
		}

		class.IngressClass = *ingressClass
	}

	parser.AnnotationsPrefix = *annotationsPrefix

	bindIpAddresses := make([]string, 0)
	for _, ipAddressStr := range strings.Split(*bindAddresses, ",") {
		ipAddressSanitized := strings.Replace(strings.Replace(ipAddressStr, "]", "", -1),
			"[", "", -1)

		ip := net.ParseIP(ipAddressSanitized)
		if ip == nil {
			return false, nil, fmt.Errorf("string %v is not an ip address", ipAddressStr)
		}
		if !ing_net.IsIPv6Enabled() && ing_net.IsIPV6(ip) {
			glog.Warningf("IPv6 is disabled, skipping IPv6 address: %s", ipAddressStr)
		} else {
			bindIpAddresses = append(bindIpAddresses, ipAddressStr)
		}
	}
	// check port collisions
	for _, ipAddress := range bindIpAddresses {
		if !ing_net.IsPortAvailable(ipAddress, *httpPort) {
			return false, nil, fmt.Errorf("port %v:%v is already in use. Please check the flag --http-port",
				ipAddress, *httpPort)
		}

		if !ing_net.IsPortAvailable(ipAddress, *httpsPort) {
			return false, nil, fmt.Errorf("port %v:%v is already in use. Please check the flag --https-port",
				ipAddress, *httpsPort)
		}

		if !ing_net.IsPortAvailable(ipAddress, *statusPort) {
			return false, nil, fmt.Errorf("port %v:%v is already in use. Please check the flag --status-port",
				ipAddress, *statusPort)
		}

		if !ing_net.IsPortAvailable(ipAddress, *defServerPort) {
			return false, nil, fmt.Errorf("port %v:%v is already in use. Please check the flag --default-server-port",
				ipAddress, *defServerPort)
		}

		if *enableSSLPassthrough && !ing_net.IsPortAvailable(ipAddress, *sslProxyPort) {
			return false, nil, fmt.Errorf("port %v:%v is already in use. Please check the flag --ssl-passtrough-proxy-port",
				ipAddress, *sslProxyPort)
		}
	}

	if !*enableSSLChainCompletion {
		glog.Warningf("SSL certificate chain completion is disabled (--enable-ssl-chain-completion=false)")
	}

	// LuaJIT is not available on arch s390x and ppc64le
	disableLua := false
	if runtime.GOARCH == "s390x" || runtime.GOARCH == "ppc64le" {
		disableLua = true
		if *dynamicConfigurationEnabled {
			*dynamicConfigurationEnabled = false
			glog.Warningf("LuaJIT is not available on s390x and ppc64le architectures: disabling dynamic configuration feature.")
		}
	}

	config := &controller.Configuration{
		APIServerHost:               *apiserverHost,
		KubeConfigFile:              *kubeConfigFile,
		UpdateStatus:                *updateStatus,
		ElectionID:                  *electionID,
		EnableProfiling:             *profiling,
		EnableSSLPassthrough:        *enableSSLPassthrough,
		EnableSSLChainCompletion:    *enableSSLChainCompletion,
		ResyncPeriod:                *resyncPeriod,
		DefaultService:              *defaultSvc,
		Namespace:                   *watchNamespace,
		ConfigMapName:               *configMap,
		TCPConfigMapName:            *tcpConfigMapName,
		UDPConfigMapName:            *udpConfigMapName,
		DefaultSSLCertificate:       *defSSLCertificate,
		DefaultHealthzURL:           *defHealthzURL,
		PublishService:              *publishSvc,
		PublishStatusAddress:        *publishStatusAddress,
		ForceNamespaceIsolation:     *forceIsolation,
		UpdateStatusOnShutdown:      *updateStatusOnShutdown,
		SortBackends:                *sortBackends,
		UseNodeInternalIP:           *useNodeInternalIP,
		SyncRateLimit:               *syncRateLimit,
		DynamicConfigurationEnabled: *dynamicConfigurationEnabled,
		DisableLua:                  disableLua,
		ListenPorts: &ngx_config.ListenPorts{
			Addresses: bindIpAddresses,
			Default:   *defServerPort,
			HTTP:      *httpPort,
			HTTPS:     *httpsPort,
			Health:    *healthzPort,
			SSLProxy:  *sslProxyPort,
			Status:    *statusPort,
		},
	}

	return false, config, nil
}
