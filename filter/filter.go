package filter

import (
	"log"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-keyauth/auth"
)

// Filter is the main HTTP filter that performs API key authentication
type Filter struct {
	api.PassThroughStreamFilter

	callbacks    api.FilterCallbackHandler
	config       *Config
	authService  auth.AuthService
	cookieHelper CookieHelper
	apiKey       string
}



// NewFilter creates a new filter instance
func NewFilter(config *Config, callbacks api.FilterCallbackHandler) *Filter {
	authConfig := auth.AuthConfig{
		AuthPriority:     config.AuthPriority,
		ExcludePaths:     config.ExcludePaths,
		ClusterConfigs:   config.ClusterConfigs,
	}
	return &Filter{
		callbacks:    callbacks,
		config:       config,
		authService:  auth.NewAuthService(&authConfig, config.KeySource),
		cookieHelper: NewCookieHelper(config.CookieSettings),
	}
}

// DecodeHeaders is called when request headers are received
func (f *Filter) DecodeHeaders(header api.RequestHeaderMap, endStream bool) api.StatusType {
	// Get the request path and determine target cluster
	path := header.Path()
	clusterName := getClusterName(f.callbacks)

	// Log basic request information
	log.Printf("Request to path: %s, cluster: %s", path, clusterName)

	// Check if authentication should be skipped for this path/cluster
	if f.authService.ShouldSkipAuth(path, clusterName) {
		log.Printf("Skipping auth for path %s", path)
		return api.Continue
	}
	request := filterRequestFactory{
		config:    f.config,
		callbacks: f.callbacks,
		header:    header,
	}
	// Authenticate the request
	authResult := f.authService.Authenticate(&request)

	// Handle authentication result
	if !authResult.Success {
		return f.handleAuthFailure(authResult)
	}

	// Authentication successful - add username to headers
	return f.handleAuthSuccess(header, authResult.Username, authResult.AuthKey)
}

// EncodeHeaders is called when response headers are being sent
// This can be used to add cookies to responses after successful auth
func (f *Filter) EncodeHeaders(header api.ResponseHeaderMap, endStream bool) api.StatusType {

 	if f.config.APIKeyCookie != "" && f.config.CookieSettings.SaveToCookie {
  	f.cookieHelper.SetCookie(header, f.config.APIKeyCookie, f.apiKey )
  }
	return api.Continue
}

// getClusterName extracts the target cluster name from stream info
func getClusterName(callbacks api.FilterCallbackHandler) string {
	streamInfo := callbacks.StreamInfo()
	clusterName, exists := streamInfo.UpstreamClusterName()
	if !exists {
		return ""
	}
	return clusterName
}

// handleAuthFailure creates appropriate response for authentication failures
func (f *Filter) handleAuthFailure(result auth.AuthResult) api.StatusType {
	headers := createAuthErrorHeaders()

	f.callbacks.DecoderFilterCallbacks().SendLocalReply(
		result.StatusCode,
		result.ErrorMessage,
		headers,
		-1, // No grpc status
		"auth_failure",
	)

	return api.LocalReply
}

// handleAuthSuccess processes a successful authentication
func (f *Filter) handleAuthSuccess(header api.RequestHeaderMap, username,key string) api.StatusType {
	// Add username to headers for downstream services
	header.Set(f.config.UsernameHeader, username)
	f.apiKey = key

	// Authentication successful, continue the filter chain
	return api.Continue
}

// createAuthErrorHeaders creates standard headers for authentication errors
func createAuthErrorHeaders() map[string][]string {
	headers := make(map[string][]string)
	headers["content-type"] = []string{"text/plain"}
	headers["www-authenticate"] = []string{"API-Key"}
	return headers
}

// FilterFactory creates a new Filter instance
func FilterFactory(c interface{}, callbacks api.FilterCallbackHandler) api.StreamFilter {
	conf, ok := c.(*Config)
	if !ok {
		panic("unexpected config type")
	}
	return NewFilter(conf, callbacks)
}
