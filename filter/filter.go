package filter

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
)

// Filter is the main HTTP filter that performs API key authentication
type Filter struct {
	api.PassThroughStreamFilter

	Callbacks api.FilterCallbackHandler
	Config    *Config
	apiKey 	string
}

// AuthSource represents where the API key was found
type AuthSource string

const (
	AuthSourceHeader AuthSource = "header"
	AuthSourceQuery  AuthSource = "query"
	AuthSourceCookie AuthSource = "cookie"
	AuthSourceNone   AuthSource = "none"
)

// DecodeHeaders is called when request headers are received
func (f *Filter) DecodeHeaders(header api.RequestHeaderMap, endStream bool) api.StatusType {
	// Get the request path and determine if auth should be skipped
	path := header.Path()
	clusterName := getClusterName(f.Callbacks)

	// Log basic request information
	log.Print("Request to path: ", path, " cluster: ", clusterName)

	// Check if this path should be excluded from authentication
	if shouldSkipAuth(f.Config, path, clusterName) {
		return api.Continue
	}

	// Extract and validate API key based on configured priority
	apiKey, authSource := f.extractAPIKeyByPriority(header)
	if apiKey == "" {
		return rejectMissingAPIKey(f.Config, f.Callbacks)
	}

	// Log which authentication source was used
	log.Printf("Using API key from %s", authSource)

	// Authenticate the request
	status := authenticateRequest(f.Config, f.Callbacks, header, apiKey)
	if status == api.Continue {
		f.apiKey = apiKey
	}
	return status
}

func (f *Filter) EncodeHeaders(header api.ResponseHeaderMap, endStream bool) api.StatusType {
	SaveAPIKeyToCookie(f.Config, f.Callbacks.EncoderFilterCallbacks(), header, f.apiKey, AuthSourceHeader)

	return api.Continue
}

// extractAPIKeyByPriority gets the API key according to the configured priority order
func (f *Filter) extractAPIKeyByPriority(header api.RequestHeaderMap) (string, AuthSource) {
	for _, source := range f.Config.AuthPriority {
		switch source {
		case "header":
			if apiKey, exists := getHeaderAPIKey(f.Config, header); exists {
				return apiKey, AuthSourceHeader
			}
		case "query":
			if apiKey, exists := getQueryAPIKey(f.Config, header); exists {
				return apiKey, AuthSourceQuery
			}
		case "cookie":
			if apiKey, exists := getCookieAPIKey(f.Config, header); exists {
				return apiKey, AuthSourceCookie
			}
		}
	}

	return "", AuthSourceNone
}

// getHeaderAPIKey extracts the API key from the request header
func getHeaderAPIKey(config *Config, header api.RequestHeaderMap) (string, bool) {
	// Skip if header auth is disabled
	if config.APIKeyHeader == "" {
		return "", false
	}

	headerKey, headerExists := header.Get(config.APIKeyHeader)
	return headerKey, headerExists && headerKey != ""
}

// getQueryAPIKey extracts the API key from query parameters
func getQueryAPIKey(config *Config, header api.RequestHeaderMap) (string, bool) {
	// Skip if query param auth is disabled
	if config.APIKeyQueryParam == "" {
		return "", false
	}

	fullPath := header.Path()
	queryParams := ExtractQueryParams(fullPath)
	queryValue, queryExists := queryParams[config.APIKeyQueryParam]
	return queryValue, queryExists && queryValue != ""
}

// getCookieAPIKey extracts the API key from cookies
func getCookieAPIKey(config *Config, header api.RequestHeaderMap) (string, bool) {
	// Skip if cookie auth is disabled
	if config.APIKeyCookie == "" {
		return "", false
	}

	// Get Cookie header
	cookieHeader, exists := header.Get("Cookie")
	if !exists || cookieHeader == "" {
		return "", false
	}

	// Parse cookies
	cookies := parseCookies(cookieHeader)
	value, exists := cookies[config.APIKeyCookie]
	return value, exists && value != ""
}

// getClusterName extracts the target cluster name from stream info
func getClusterName(callbacks api.FilterCallbackHandler) string {
	streamInfo := callbacks.StreamInfo()
	clusterName, exists := streamInfo.UpstreamClusterName()
	if !exists {
		// If we can't determine the cluster, just use an empty string
		log.Printf("Could not determine upstream cluster name for request")
		return ""
	}
	return clusterName
}

// rejectMissingAPIKey creates an appropriate error message for missing API key
func rejectMissingAPIKey(config *Config, callbacks api.FilterCallbackHandler) api.StatusType {
	message := buildMissingAPIKeyMessage(config)
	return rejectWithUnauthorized(callbacks, message)
}

// buildMissingAPIKeyMessage constructs an informative error message for missing API key
func buildMissingAPIKeyMessage(config *Config) string {
	return "Forbidden"
}

// authenticateRequest validates the API key and adds the username to the request
func authenticateRequest(config *Config, callbacks api.FilterCallbackHandler, header api.RequestHeaderMap, apiKey string) api.StatusType {
	// Validate the API key and get username
	username, err := config.KeySource.GetUsername(apiKey)
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		return rejectWithUnauthorized(callbacks, "Invalid API key")
	}

	// Add username to headers for downstream services
	header.Set(config.UsernameHeader, username)

	// Authentication successful, continue the filter chain
	return api.Continue
}

// shouldSkipAuth determines if authentication should be skipped for a path
// considering both global and cluster-specific exclude paths
func shouldSkipAuth(config *Config, path string, clusterName string) bool {
	// Extract the path without query parameters
	pathOnly := getPathWithoutQuery(path)

	// Check if path is in global exclude list
	if isPathExcludedGlobally(config, pathOnly) {
		return true
	}

	// Check if path is excluded for the specific cluster
	if isPathExcludedForCluster(config, pathOnly, clusterName) {
		return true
	}

	return false
}

// getPathWithoutQuery removes query parameters from a path
func getPathWithoutQuery(path string) string {
	pathOnly := path
	if queryPos := strings.Index(path, "?"); queryPos != -1 {
		pathOnly = path[:queryPos]
	}
	return pathOnly
}

// isPathExcludedGlobally checks if a path is in the global exclude list
func isPathExcludedGlobally(config *Config, pathOnly string) bool {
	return isPathInExcludeList(pathOnly, config.ExcludePaths, "global exclude")
}

// isPathExcludedForCluster checks if a path is excluded for a specific cluster
func isPathExcludedForCluster(config *Config, pathOnly string, clusterName string) bool {
	if clusterName == "" {
		return false
	}

	clusterConfig, exists := config.ClusterConfigs[clusterName]
	if !exists {
		return false
	}

	logMsg := fmt.Sprintf("cluster-specific exclude for cluster %s", clusterName)
	return isPathInExcludeList(pathOnly, clusterConfig.ExcludePaths, logMsg)
}

// isPathInExcludeList is a helper function to check if a path is in an exclude list
func isPathInExcludeList(path string, excludePaths []string, logReason string) bool {
	for _, excludePath := range excludePaths {
		if strings.HasPrefix(path, excludePath) {
			log.Printf("Skipping auth for path %s due to %s", path, logReason)
			return true
		}
	}
	return false
}

// ExtractQueryParams parses query parameters from a URL path
func ExtractQueryParams(path string) map[string]string {
	result := make(map[string]string)

	// Extract the query string portion
	queryString := getQueryStringFromPath(path)
	if queryString == "" {
		return result // No query parameters
	}

	// Parse the query string into a map
	return parseQueryString(queryString)
}

// getQueryStringFromPath extracts just the query string portion from a path
func getQueryStringFromPath(path string) string {
	// Find the position of the query string marker
	queryPos := strings.Index(path, "?")
	if queryPos == -1 {
		return "" // No query parameters
	}

	// Extract the query string without the leading '?'
	return path[queryPos+1:]
}

// parseQueryString converts a query string into a map of parameter names to values
func parseQueryString(queryString string) map[string]string {
	result := make(map[string]string)

	// Split the query string by '&' to get individual parameters
	params := strings.Split(queryString, "&")
	for _, param := range params {
		parseQueryParameter(param, result)
	}

	return result
}

// parseQueryParameter parses a single query parameter and adds it to the result map
func parseQueryParameter(param string, result map[string]string) {
	// Skip empty parameters
	if param == "" {
		return
	}

	// Split each parameter by '=' to get key-value pairs
	keyValue := strings.SplitN(param, "=", 2)
	if len(keyValue) == 2 {
		result[keyValue[0]] = keyValue[1]
	} else if len(keyValue) == 1 {
		// Handle parameters without values
		result[keyValue[0]] = ""
	}
}

// rejectWithUnauthorized responds with a 401 Unauthorized
func rejectWithUnauthorized(callbacks api.FilterCallbackHandler, message string) api.StatusType {
	headers := createAuthErrorHeaders()

	callbacks.DecoderFilterCallbacks().SendLocalReply(
		http.StatusUnauthorized,
		message,
		headers,
		-1, // No grpc status
		"auth_failure",
	)

	return api.LocalReply
}

// createAuthErrorHeaders creates standard headers for authentication errors
func createAuthErrorHeaders() map[string][]string {
	headers := make(map[string][]string)
	headers["content-type"] = []string{"text/plain"}
	headers["www-authenticate"] = []string{"X-API-Key"}
	return headers
}
