package agent

import "context"

// 实现接口
type Authentication struct {
	Token string
}

func (a *Authentication) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authentication": a.Token}, nil // 将设定的token传入metadata
}

func (a *Authentication) RequireTransportSecurity() bool {
	return false
}
