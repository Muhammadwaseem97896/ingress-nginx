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
	"fmt"
	"sort"

	ngx_crossplane "github.com/nginxinc/nginx-go-crossplane"
	"k8s.io/apimachinery/pkg/util/sets"

	"k8s.io/ingress-nginx/pkg/apis/ingress"
)

func buildMirrorLocationDirective(locs []*ingress.Location) ngx_crossplane.Directives {
	mirrorDirectives := make(ngx_crossplane.Directives, 0)

	mapped := sets.Set[string]{}

	for _, loc := range locs {
		if loc.Mirror.Source == "" || loc.Mirror.Target == "" || loc.Mirror.Host == "" {
			continue
		}

		if mapped.Has(loc.Mirror.Source) {
			continue
		}

		mapped.Insert(loc.Mirror.Source)
		mirrorDirectives = append(mirrorDirectives, buildBlockDirective("location",
			[]string{"=", loc.Mirror.Source},
			ngx_crossplane.Directives{
				buildDirective("internal"),
				buildDirective("proxy_set_header", "Host", loc.Mirror.Host),
				buildDirective("proxy_pass", loc.Mirror.Target),
			}))
	}
	return mirrorDirectives
}

// buildCustomErrorLocationsPerServer is a utility function which will collect all
// custom error codes for all locations of a server block, deduplicates them,
// and returns a set which is unique by default-upstream and error code. It returns an array
// of errorLocations, each of which contain the upstream name and a list of
// error codes for that given upstream, so that sufficiently unique
// @custom error location blocks can be created in the template
func buildCustomErrorLocationsPerServer(server *ingress.Server, enableMetrics bool) ngx_crossplane.Directives {
	type errorLocation struct {
		UpstreamName string
		Codes        []int
	}

	codesMap := make(map[string]map[int]bool)
	for _, loc := range server.Locations {
		backendUpstream := loc.DefaultBackendUpstreamName

		var dedupedCodes map[int]bool
		if existingMap, ok := codesMap[backendUpstream]; ok {
			dedupedCodes = existingMap
		} else {
			dedupedCodes = make(map[int]bool)
		}

		for _, code := range loc.CustomHTTPErrors {
			dedupedCodes[code] = true
		}
		codesMap[backendUpstream] = dedupedCodes
	}

	errorLocations := []errorLocation{}

	for upstream, dedupedCodes := range codesMap {
		codesForUpstream := []int{}
		for code := range dedupedCodes {
			codesForUpstream = append(codesForUpstream, code)
		}
		sort.Ints(codesForUpstream)
		errorLocations = append(errorLocations, errorLocation{
			UpstreamName: upstream,
			Codes:        codesForUpstream,
		})
	}

	sort.Slice(errorLocations, func(i, j int) bool {
		return errorLocations[i].UpstreamName < errorLocations[j].UpstreamName
	})

	errorLocationsDirectives := make(ngx_crossplane.Directives, 0)
	for i := range errorLocations {
		errorLocationsDirectives = append(errorLocationsDirectives, buildCustomErrorLocation(errorLocations[i].UpstreamName, errorLocations[i].Codes, enableMetrics)...)
	}
	return errorLocationsDirectives

}

func buildCustomErrorLocation(upstreamName string, errorCodes []int, enableMetrics bool) ngx_crossplane.Directives {
	directives := make(ngx_crossplane.Directives, len(errorCodes))
	for i := range errorCodes {
		locationDirectives := ngx_crossplane.Directives{
			buildDirective("internal"),
			buildDirective("proxy_intercept_errors", "off"),
			buildDirective("proxy_set_header", "X-Code", errorCodes[i]),
			buildDirective("proxy_set_header", "X-Format", "$http_accept"),
			buildDirective("proxy_set_header", "X-Original-URI", "$request_uri"),
			buildDirective("proxy_set_header", "X-Namespace", "$namespace"),
			buildDirective("proxy_set_header", "X-Ingress-Name", "$ingress_name"),
			buildDirective("proxy_set_header", "X-Service-Name", "$service_name"),
			buildDirective("proxy_set_header", "X-Service-Port", "$service_port"),
			buildDirective("proxy_set_header", "X-Request-ID", "$req_id"),
			buildDirective("proxy_set_header", "X-Forwarded-For", "$remote_addr"),
			buildDirective("proxy_set_header", "Host", "$best_http_host"),
			buildDirective("set", "$proxy_upstream_name", upstreamName),
			buildDirective("rewrite", "(.*)", "/", "break"),
			buildDirective("proxy_pass", "http://upstream_balancer"),
		}

		if enableMetrics {
			locationDirectives = append(locationDirectives, buildDirective("log_by_lua_file", "/etc/nginx/lua/nginx/ngx_conf_log.lua"))
		}
		locationName := fmt.Sprintf("@custom_%s_%d", upstreamName, errorCodes[i])
		directives[i] = buildBlockDirective("location", []string{locationName}, locationDirectives)
	}

	return directives
}

func (c *Template) buildServerLocations(server *ingress.Server, locations []*ingress.Location) ngx_crossplane.Directives {
	serverLocations := make(ngx_crossplane.Directives, 0)

	cfg := c.tplConfig.Cfg
	enforceRegexModifier := false
	needsRewrite := func(loc *ingress.Location) bool {
		return loc.Rewrite.Target != "" &&
			loc.Rewrite.Target != loc.Path
	}

	for _, location := range locations {
		if needsRewrite(location) || location.Rewrite.UseRegex {
			enforceRegexModifier = true
			break
		}
	}

	for _, location := range locations {
		locationPath := buildLocation(location, enforceRegexModifier)
		proxySetHeader := getProxySetHeader(location)
		authPath := buildAuthLocation(location, cfg.GlobalExternalAuth.URL)
		applyGlobalAuth := shouldApplyGlobalAuth(location, cfg.GlobalExternalAuth.URL)
		applyAuthUpstream := shouldApplyAuthUpstream(location, cfg)
		externalAuth := location.ExternalAuth
		if applyGlobalAuth {
			externalAuth = cfg.GlobalExternalAuth
		}

		if location.Rewrite.AppRoot != "" {
			serverLocations = append(serverLocations,
				buildBlockDirective("if", []string{"$uri = /"},
					ngx_crossplane.Directives{
						buildDirective("return", "302", fmt.Sprintf("$scheme://$http_host%s", location.Rewrite.AppRoot)),
					}))
		}

		if authPath != "" {

		}

	}

	return serverLocations
}

type externalAuth struct {
	AuthCacheKey      string   `json:"authCacheKey"`
	AuthCacheDuration []string `json:"authCacheDuration"`
}

func (c *Template) buildAuthLocation(server *ingress.Server, location *ingress.Location, authPath string, externalA *externalAuth) *ngx_crossplane.Directive {
	locationDirectives := ngx_crossplane.Directives{
		buildDirective("internal"),
	}

	if c.tplConfig.Cfg.EnableOpentelemetry || location.Opentelemetry.Enabled {
		locationDirectives = append(locationDirectives,
			buildDirective("opentelemetry", "on"),
			buildDirective("opentelemetry_propagate"),
		)
	}

	if !c.tplConfig.Cfg.EnableAuthAccessLog {
		locationDirectives = append(locationDirectives, buildDirective("access_log", "off"))
	}

	if externalA.AuthCacheKey != "" {
		locationDirectives = append(locationDirectives,
			buildDirective("$tmp_cache_key", fmt.Sprintf("%s%s%s", server.Hostname, authPath, externalA.AuthCacheKey)),
			buildDirective("$cache_key", ""),
			buildDirective("rewrite_by_lua_file", "/etc/nginx/lua/nginx/ngx_conf_rewrite_auth.lua"),
			buildDirective("proxy_cache", "auth_cache"),
			buildDirective("proxy_cache_key", "$cache_key"),
		)
		for i := range externalA.AuthCacheDuration {
			locationDirectives = append(locationDirectives,
				buildDirective("proxy_cache_valid", externalA.AuthCacheDuration[i]),
			)
		}
	}

	/*
		ngx_auth_request module overrides variables in the parent request,
		therefore we have to explicitly set this variable again so that when the parent request
		resumes it has the correct value set for this variable so that Lua can pick backend correctly
	*/
	locationDirectives = append(locationDirectives,
		buildDirective("set", "$proxy_upstream_name", location.Backend),
	)
	//// I HAVE STOPPED HERE

	return buildBlockDirective("location",
		[]string{"=", authPath}, locationDirectives)
}
