package filter

import (
	"log"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
)


type Filter struct {
	api.PassThroughStreamFilter

	Callbacks api.FilterCallbackHandler
	Config    *Config
	path      string
}

func (f *Filter) DecodeHeaders(header api.RequestHeaderMap, endStream bool) api.StatusType {
	go func() {
				defer f.Callbacks.DecoderFilterCallbacks().RecoverPanic()
				// do time-consuming jobs
				log.Printf("path: %s", header.Path())
				// resume the filter
				f.Callbacks.DecoderFilterCallbacks().Continue(api.Continue)
			}()

			// suspend the filter
			return api.Running
}
