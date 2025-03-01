package filter

import (
	"log"
	"net/http"
	"strings"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-keyauth/auth"
)

// ClusterConfig holds configuration specific to a cluster
type ClusterConfig struct {
	Exclude bool
	ExcludePaths []string
}

// Config holds the filter configuration
type Config struct {
	APIKeyHeader   string
	UsernameHeader string
	ExcludePaths   []string
	KeySource      auth.KeySource
	ClusterConfigs map[string]*ClusterConfig
}

// Filter is the main HTTP filter that performs API key authentication
type Filter struct {
	api.PassThroughStreamFilter

	Callbacks api.FilterCallbackHandler
	Config    *Config
}

// DecodeHeaders is called when request headers are received
func (f *Filter) DecodeHeaders(header api.RequestHeaderMap, endStream bool) api.StatusType {
	// Get the request path
	path := header.Path()

	// Get the target cluster for this request from StreamInfo
	streamInfo := f.Callbacks.StreamInfo()
	clusterName, exists := streamInfo.UpstreamClusterName()
	if !exists {
		// If we can't determine the cluster, just use an empty string
		clusterName = ""
		log.Printf("Could not determine upstream cluster name for request to path: %s", path)
	}
	log.Print("Request to path: ", path, " cluster: ", clusterName)

	// Check if this path should be excluded from authentication
	if f.shouldSkipAuth(path, clusterName) {
		return api.Continue
	}

	// Extract API key from header
	apiKey, exists := header.Get(f.Config.APIKeyHeader)
	if !exists || apiKey == "" {
		return f.rejectWithUnauthorized("Missing API key")
	}

	// Validate the API key and get username
	username, err := f.Config.KeySource.GetUsername(apiKey)
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		return f.rejectWithUnauthorized("Invalid API key '" + apiKey + "'")
	}

	// Add username to headers for downstream services
	header.Set(f.Config.UsernameHeader, username)

	// Authentication successful, continue the filter chain
	return api.Continue
}

// shouldSkipAuth determines if authentication should be skipped for a path
// considering both global and cluster-specific exclude paths
func (f *Filter) shouldSkipAuth(path string, clusterName string) bool {
	// Check global exclude paths first
	for _, excludePath := range f.Config.ExcludePaths {
		if strings.HasPrefix(path, excludePath) {
			log.Printf("Skipping auth for path %s due to global exclude", path)
			return true
		}
	}

	// If we have a cluster name and cluster-specific config, check those exclude paths
	if clusterName != "" {
		if clusterConfig, exists := f.Config.ClusterConfigs[clusterName]; exists {
			for _, excludePath := range clusterConfig.ExcludePaths {
				if strings.HasPrefix(path, excludePath) {
					log.Printf("Skipping auth for path %s due to cluster-specific exclude for cluster %s",
						path, clusterName)
					return true
				}
			}
		}
	}

	return false
}

// rejectWithUnauthorized responds with a 401 Unauthorized
func (f *Filter) rejectWithUnauthorized(message string) api.StatusType {
	headers := make(map[string][]string)
	headers["content-type"] = []string{"text/plain"}
	headers["www-authenticate"] = []string{"API-Key"}

	f.Callbacks.DecoderFilterCallbacks().SendLocalReply(
		http.StatusUnauthorized,
		message,
		headers,
		-1, // No grpc status
		"auth_failure",
	)

	return api.LocalReply
}
