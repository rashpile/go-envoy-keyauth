package main

import (
	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/http"
	"github.com/rashpile/go-envoy-keyauth/filter"
)

const Name = "go-envoy-keyauth"

func init() {
	http.RegisterHttpFilterFactoryAndConfigParser(Name, filter.FilterFactory, &filter.Parser{})
}

func main() {}
