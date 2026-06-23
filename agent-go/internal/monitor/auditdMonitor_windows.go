package monitor

import (
	"context"
	"systemwire/agent/internal/models"
	pb "systemwire/agent/proto"
)

type AuditdMonitor struct {
}

// AddPaths implements Monitor.
func (a *AuditdMonitor) AddPaths(paths []string) error {
	panic("unimplemented")
}

// GetPath implements Monitor.
func (a *AuditdMonitor) GetPath() []string {
	panic("unimplemented")
}

// HandleEvent implements Monitor.
func (a *AuditdMonitor) HandleEvent(ctx context.Context, events []*models.MonitorEvent) error {
	panic("unimplemented")
}

// RemovePath implements Monitor.
func (a *AuditdMonitor) RemovePath(paths []string) error {
	panic("unimplemented")
}

// Restart implements Monitor.
func (a *AuditdMonitor) Restart(ctx context.Context) error {
	panic("unimplemented")
}

// Start implements Monitor.
func (a *AuditdMonitor) Start(ctx context.Context) error {
	panic("unimplemented")
}

// Stop implements Monitor.
func (a *AuditdMonitor) Stop() error {
	panic("unimplemented")
}

func NewAuditdMonitor(client pb.AgentServiceClient) *AuditdMonitor {
	return nil
}

func (m *AuditdMonitor) SetRPCClient(client pb.AgentServiceClient) {

}
