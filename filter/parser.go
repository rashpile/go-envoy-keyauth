package filter

import (
	"errors"
	"fmt"
	"log"

	xds "github.com/cncf/xds/go/xds/type/v3"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"google.golang.org/protobuf/types/known/anypb"
)

type Config struct {
	echoBody string
}
type Parser struct {
}

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
func (p *Parser) Parse(any *anypb.Any, callbacks api.ConfigCallbackHandler) (interface{}, error) {
	configStruct := &xds.TypedStruct{}
	if err := any.UnmarshalTo(configStruct); err != nil {
		return nil, err
	}

	v := configStruct.Value
	conf := &Config{}
	prefix, ok := v.AsMap()["echo_server_addr"]
	if !ok {
		return nil, errors.New("missing prefix_localreply_body")
	}
	if str, ok := prefix.(string); ok {
		conf.echoBody = str
	} else {
		return nil, fmt.Errorf("prefix_localreply_body: expect string while got %T", prefix)
	}
	log.Printf("parsed config: %v", conf)
	return conf, nil
}


// Merge configuration from the inherited parent configuration
func (p *Parser) Merge(parent interface{}, child interface{}) interface{} {
	parentConfig := parent.(*Config)
	childConfig := child.(*Config)

	// copy one, do not update parentConfig directly.
	newConfig := *parentConfig
	if childConfig.echoBody != "" {
		newConfig.echoBody = childConfig.echoBody
	}
	return &newConfig
}
