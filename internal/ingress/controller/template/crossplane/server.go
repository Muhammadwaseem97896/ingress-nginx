/*
Copyright 2024 The Kubernetes Authors.

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

package crossplane

import (
	"strings"

	ngx_crossplane "github.com/nginxinc/nginx-go-crossplane"
	"k8s.io/ingress-nginx/pkg/apis/ingress"
)

func (c *Template) buildServerDirective(server *ingress.Server) *ngx_crossplane.Directive {
	cfg := c.tplConfig.Cfg
	serverName := buildServerName(server.Hostname)
	serverBlock := ngx_crossplane.Directives{
		buildDirective("server_name", serverName, server.Aliases),
		buildDirective("http2", cfg.UseHTTP2),
		buildDirective("set", "$proxy_upstream_name", "-"),
		buildDirective("ssl_certificate_by_lua_file", "/etc/nginx/lua/nginx/ngx_conf_certificate.lua"),
	}
	serverBlock = append(serverBlock, buildListener(*c.tplConfig, server.Hostname)...)

	if len(cfg.BlockUserAgents) > 0 {
		uaDirectives := buildBlockDirective("if", []string{"$block_ua"}, ngx_crossplane.Directives{
			buildDirective("return", "403"),
		})
		serverBlock = append(serverBlock, uaDirectives)
	}

	if len(cfg.BlockReferers) > 0 {
		refDirectives := buildBlockDirective("if", []string{"$block_ref"}, ngx_crossplane.Directives{
			buildDirective("return", "403"),
		})
		serverBlock = append(serverBlock, refDirectives)
	}

	if server.Hostname == "_" {
		serverBlock = append(serverBlock, buildDirective("ssl_reject_handshake", cfg.SSLRejectHandshake))
	}

	if server.CertificateAuth.MatchCN != "" {
		matchCNBlock := buildBlockDirective("if",
			[]string{"$ssl_client_s_dn", "!~", server.CertificateAuth.MatchCN},
			ngx_crossplane.Directives{
				buildDirective("return", "403", "client certificate unauthorized"),
			})
		serverBlock = append(serverBlock, matchCNBlock)
	}
	// TODO: This part should be reserved to SSL Configurations

	/* MISSING (I don't know where this if ends...)
	   {{ if not (empty $server.AuthTLSError) }}
	   # {{ $server.AuthTLSError }}
	   return 403;
	   {{ else }}
	*/
	serverBlock = append(serverBlock, c.buildCertificateDirectives(server)...)
	// END

	serverBlock = append(serverBlock, buildCustomErrorLocationsPerServer(server, c.tplConfig.EnableMetrics)...)

	serverBlock = append(serverBlock, buildMirrorLocationDirective(server.Locations)...)

	// DO NOT MOVE! THIS IS THE END DIRECTIVE OF SERVERS
	serverBlock = append(serverBlock, buildCustomErrorLocation("upstream-default-backend", cfg.CustomHTTPErrors, c.tplConfig.EnableMetrics)...)

	return &ngx_crossplane.Directive{
		Directive: "server",
		Block:     serverBlock, // TODO: Fix
	}
}

func (c *Template) buildCertificateDirectives(server *ingress.Server) ngx_crossplane.Directives {
	certDirectives := make(ngx_crossplane.Directives, 0)

	if server.CertificateAuth.CAFileName != "" {
		certAuth := server.CertificateAuth
		certDirectives = append(certDirectives, buildDirective("ssl_client_certificate", certAuth.CAFileName))
		certDirectives = append(certDirectives, buildDirective("ssl_verify_client", certAuth.VerifyClient))
		certDirectives = append(certDirectives, buildDirective("ssl_verify_depth", certAuth.ValidationDepth))
		if certAuth.CRLFileName != "" {
			certDirectives = append(certDirectives, buildDirective("ssl_crl", certAuth.CRLFileName))
		}
		if certAuth.ErrorPage != "" {
			certDirectives = append(certDirectives, buildDirective("error_page", "495", "496", "=", certAuth.ErrorPage))
		}
	}

	prxSSL := server.ProxySSL
	if prxSSL.CAFileName != "" {
		certDirectives = append(certDirectives, buildDirective("proxy_ssl_trusted_certificate", prxSSL.CAFileName))
		certDirectives = append(certDirectives, buildDirective("proxy_ssl_ciphers", prxSSL.Ciphers))
		certDirectives = append(certDirectives, buildDirective("proxy_ssl_protocols", strings.Split(prxSSL.Protocols, " ")))
		certDirectives = append(certDirectives, buildDirective("proxy_ssl_verify", prxSSL.Verify))
		certDirectives = append(certDirectives, buildDirective("proxy_ssl_verify_depth", prxSSL.VerifyDepth))
		if prxSSL.ProxySSLName != "" {
			certDirectives = append(certDirectives, buildDirective("proxy_ssl_name", prxSSL.ProxySSLName))
			certDirectives = append(certDirectives, buildDirective("proxy_ssl_server_name", prxSSL.ProxySSLServerName))
		}
	}
	if prxSSL.PemFileName != "" {
		certDirectives = append(certDirectives, buildDirective("proxy_ssl_certificate", prxSSL.PemFileName))
		certDirectives = append(certDirectives, buildDirective("proxy_ssl_certificate_key", prxSSL.PemFileName))
	}
	if server.SSLCiphers != "" {
		certDirectives = append(certDirectives, buildDirective("ssl_ciphers", server.SSLCiphers))
	}

	if server.SSLPreferServerCiphers != "" {
		certDirectives = append(certDirectives, buildDirective("ssl_prefer_server_ciphers", server.SSLPreferServerCiphers))
	}

	return certDirectives

}
