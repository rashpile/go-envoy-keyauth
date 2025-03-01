package filter

import (
	"fmt"
	"log"
	"strings"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
)

// CookieSettings represents the settings for cookies
type CookieSettings struct {
	Enabled      bool
	MaxAge       int    // in seconds
	Domain       string // optional domain
	Path         string // default "/"
	Secure       bool   // secure flag
	HttpOnly     bool   // HttpOnly flag
	SameSite     string // None, Lax, Strict
	SaveToCookie bool   // Whether to save API key to cookie after successful auth
}

// DefaultCookieSettings provides reasonable defaults
func DefaultCookieSettings() CookieSettings {
	return CookieSettings{
		Enabled:      true,
		MaxAge:       86400 * 30, // 30 days
		Path:         "/",
		Secure:       true,
		HttpOnly:     true,
		SameSite:     "Lax",
		SaveToCookie: true,
	}
}

// SetCookie adds or updates a cookie in the response headers
func SetCookie(encoderCallbacks api.EncoderFilterCallbacks, header api.ResponseHeaderMap, name, value string, settings CookieSettings) {
	if !settings.Enabled {
		return
	}

	// Build cookie string
	cookieValue := fmt.Sprintf("%s=%s; Max-Age=%d; Path=%s",
		name, value, settings.MaxAge, settings.Path)

	// Add domain if specified
	if settings.Domain != "" {
		cookieValue += fmt.Sprintf("; Domain=%s", settings.Domain)
	}

	// Add secure flag if enabled
	if settings.Secure {
		cookieValue += "; Secure"
	}

	// Add HttpOnly flag if enabled
	if settings.HttpOnly {
		cookieValue += "; HttpOnly"
	}

	// Add SameSite if specified
	if settings.SameSite != "" {
		cookieValue += fmt.Sprintf("; SameSite=%s", settings.SameSite)
	}

	// Add the cookie to the response headers
	log.Printf("Setting cookie: %s", name)
	header.Add("Set-Cookie", cookieValue)
}

// parseCookieSettings parses cookie settings from configuration
func parseCookieSettings(configMap map[string]interface{}) CookieSettings {
	settings := DefaultCookieSettings()

	// Parse values from config if they exist
	if cookieConfig, ok := configMap["cookie_settings"].(map[string]interface{}); ok {
		// Parse enabled flag
		if enabled, ok := cookieConfig["enabled"].(bool); ok {
			settings.Enabled = enabled
		}

		// Parse max age
		if maxAge, ok := cookieConfig["max_age"].(float64); ok {
			settings.MaxAge = int(maxAge)
		}

		// Parse domain
		if domain, ok := cookieConfig["domain"].(string); ok {
			settings.Domain = domain
		}

		// Parse path
		if path, ok := cookieConfig["path"].(string); ok {
			settings.Path = path
		}

		// Parse secure flag
		if secure, ok := cookieConfig["secure"].(bool); ok {
			settings.Secure = secure
		}

		// Parse http_only flag
		if httpOnly, ok := cookieConfig["http_only"].(bool); ok {
			settings.HttpOnly = httpOnly
		}

		// Parse SameSite
		if sameSite, ok := cookieConfig["same_site"].(string); ok {
			settings.SameSite = sameSite
		}

		// Parse save to cookie flag
		if saveToCookie, ok := cookieConfig["save_to_cookie"].(bool); ok {
			settings.SaveToCookie = saveToCookie
		}
	}

	return settings
}

// SaveAPIKeyToCookie saves the API key to a cookie if enabled in config
func SaveAPIKeyToCookie(config *Config, encoderCallbacks api.EncoderFilterCallbacks, header api.ResponseHeaderMap, apiKey string, authSource AuthSource) {
	// Skip if cookie is disabled or the cookie name is not set
	if !config.CookieSettings.Enabled || config.APIKeyCookie == "" {
		return
	}

	// Skip if SaveToCookie is disabled
	if !config.CookieSettings.SaveToCookie {
		return
	}

	// Skip if the API key already came from a cookie
	if authSource == AuthSourceCookie {
		return
	}

	// Save the API key to a cookie
	SetCookie(encoderCallbacks, header, config.APIKeyCookie, apiKey, config.CookieSettings)
}


// parseCookies parses a Cookie header into a map of cookie names to values
func parseCookies(cookieHeader string) map[string]string {
	cookies := make(map[string]string)

	// Split by semicolon and process each cookie
	parts := strings.Split(cookieHeader, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Split by = to get key and value
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			cookies[kv[0]] = kv[1]
		}
	}

	return cookies
}
