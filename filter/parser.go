package filter

import (
	"fmt"
	"log"
	"time"

	xds "github.com/cncf/xds/go/xds/type/v3"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/rashpile/go-envoy-keyauth/auth"
	"google.golang.org/protobuf/types/known/anypb"
	"slices"
)

// Default configuration values
const (
	DefaultAPIKeyHeader   = "X-API-Key"
	DefaultUsernameHeader = "X-User-ID"
	DefaultKeysFile       = "/etc/envoy/api-keys.txt"
	DefaultCheckInterval  = 60 // seconds
)

// Parser parses the filter configuration
type Parser struct {
}

// FilterFactory creates a new Filter instance
func FilterFactory(c interface{}, callbacks api.FilterCallbackHandler) api.StreamFilter {
	conf, ok := c.(*Config)
	if !ok {
		panic("unexpected config type")
	}
	return &Filter{
		Callbacks: callbacks,
		Config:    conf,
	}
}

// Parse parses the filter configuration from Envoy
func (p *Parser) Parse(any *anypb.Any, callbacks api.ConfigCallbackHandler) (interface{}, error) {
	configStruct := &xds.TypedStruct{}
	if err := any.UnmarshalTo(configStruct); err != nil {
		return nil, err
	}

	v := configStruct.Value
	conf := &Config{
		APIKeyHeader:   DefaultAPIKeyHeader,
		UsernameHeader: DefaultUsernameHeader,
		ExcludePaths:   []string{},
		ClusterConfigs: make(map[string]*ClusterConfig),
	}

	// Parse API key header name
	if header, ok := v.AsMap()["api_key_header"].(string); ok && header != "" {
		conf.APIKeyHeader = header
	}

	// Parse username header name
	if header, ok := v.AsMap()["username_header"].(string); ok && header != "" {
		conf.UsernameHeader = header
	}

	// Parse exclude paths
	if excludes, ok := v.AsMap()["exclude_paths"].([]interface{}); ok {
		for _, exclude := range excludes {
			if path, ok := exclude.(string); ok {
				conf.ExcludePaths = append(conf.ExcludePaths, path)
			}
		}
	}
// Parse cluster-specific configurations
	if clusters, ok := v.AsMap()["clusters"].(map[string]interface{}); ok {
		for clusterName, clusterConfig := range clusters {
			if config, ok := clusterConfig.(map[string]interface{}); ok {
				clusterConf := &ClusterConfig{
					ExcludePaths: []string{},
					Exclude: false,
				}

				// Parse cluster-specific exclude paths
				if excludes, ok := config["exclude_paths"].([]interface{}); ok {
					for _, exclude := range excludes {
						if path, ok := exclude.(string); ok {
							clusterConf.ExcludePaths = append(clusterConf.ExcludePaths, path)
						}
					}
				}

				conf.ClusterConfigs[clusterName] = clusterConf
			}
		}
	}
	// Parse keys file path
	keysFile := DefaultKeysFile
	if file, ok := v.AsMap()["keys_file"].(string); ok && file != "" {
		keysFile = file
	}

	// Parse check interval
	checkInterval := DefaultCheckInterval
	if interval, ok := v.AsMap()["check_interval"].(float64); ok && interval >= 0 {
		checkInterval = int(interval)
	}

	// Create the key source
	keySource, err := auth.NewFileKeySource(keysFile, time.Duration(checkInterval)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to create key source: %w", err)
	}
	conf.KeySource = keySource

	log.Printf("Parsed config: API key header=%s, Username header=%s, Keys file=%s, Excluded paths=%v",
		conf.APIKeyHeader, conf.UsernameHeader, keysFile, conf.ExcludePaths)

	return conf, nil
}

// Merge merges parent and child configurations
func (p *Parser) Merge(parent interface{}, child interface{}) interface{} {
	parentConfig := parent.(*Config)
	childConfig := child.(*Config)

	// Create a new config to avoid modifying the parent
	newConfig := &Config{
		APIKeyHeader:   parentConfig.APIKeyHeader,
		UsernameHeader: parentConfig.UsernameHeader,
		KeySource:      parentConfig.KeySource,
		ExcludePaths:   slices.Clone(parentConfig.ExcludePaths),
		ClusterConfigs: make(map[string]*ClusterConfig),

	}

	// Override with child values if specified
	if childConfig.APIKeyHeader != "" {
		newConfig.APIKeyHeader = childConfig.APIKeyHeader
	}

	if childConfig.UsernameHeader != "" {
		newConfig.UsernameHeader = childConfig.UsernameHeader
	}

	if childConfig.KeySource != nil {
		newConfig.KeySource = childConfig.KeySource
	}

	if len(childConfig.ExcludePaths) > 0 {
		newConfig.ExcludePaths = append(newConfig.ExcludePaths, childConfig.ExcludePaths...)
	}
	// Merge child cluster configs
	for clusterName, childClusterConfig := range childConfig.ClusterConfigs {
		if parentClusterConfig, exists := newConfig.ClusterConfigs[clusterName]; exists {
			// Merge with existing cluster config
			parentClusterConfig.ExcludePaths = append(parentClusterConfig.ExcludePaths, childClusterConfig.ExcludePaths...)
		} else {
			// Add new cluster config
			newClusterConfig := &ClusterConfig{
				ExcludePaths: append([]string{}, childClusterConfig.ExcludePaths...),
			}
			newConfig.ClusterConfigs[clusterName] = newClusterConfig
		}
	}
	return newConfig
}
