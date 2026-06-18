package graphactions

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/writer/cerebro/internal/deviceauth"
)

const cerebroDeviceRevokeExternalPrefix = "cerebro-device:revoke:"

type CerebroDeviceService interface {
	LookupDevice(context.Context, string) (deviceauth.DeviceRecord, error)
	Revoke(context.Context, string, string) error
}

type CerebroDeviceProvider struct {
	Service CerebroDeviceService
	Now     func() time.Time
}

func (p CerebroDeviceProvider) ExecuteGraphAction(ctx context.Context, spec ActionSpec, request ProviderActionRequest) (*GraphAction, error) {
	if p.Service == nil {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(spec.ProviderAction) != CerebroDeviceActionRevoke {
		return nil, fmt.Errorf("%w: unsupported cerebro device action %q", ErrInvalidRequest, spec.ProviderAction)
	}
	target, err := NormalizeDeviceTarget(request.Target)
	if err != nil {
		return nil, err
	}
	device, err := p.lookupTenantDevice(ctx, target, request.TenantID)
	if err != nil {
		return nil, err
	}
	if err := p.Service.Revoke(ctx, target, request.Reason); err != nil {
		if errors.Is(err, deviceauth.ErrDeviceNotFound) {
			return nil, fmt.Errorf("%w: target device was not found", ErrInvalidRequest)
		}
		return nil, fmt.Errorf("%w: revoke device: %w", ErrRemote, err)
	}
	device.Status = "revoked"
	device.RevokedAt = p.now()
	return GraphActionFromCerebroDevice(spec.ID, device, request, "succeeded", "revoked", ""), nil
}

func (p CerebroDeviceProvider) GetGraphAction(ctx context.Context, externalID string) (*GraphAction, error) {
	if p.Service == nil {
		return nil, ErrNotConfigured
	}
	target, ok := CerebroDeviceTargetFromExternalID(externalID)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported cerebro device action id %q", ErrInvalidRequest, externalID)
	}
	device, err := p.Service.LookupDevice(ctx, target)
	if err != nil {
		if errors.Is(err, deviceauth.ErrDeviceNotFound) {
			return nil, fmt.Errorf("%w: target device was not found", ErrInvalidRequest)
		}
		return nil, fmt.Errorf("%w: lookup device: %w", ErrRemote, err)
	}
	status := "needs_attention"
	reason := "device is not revoked"
	if strings.EqualFold(strings.TrimSpace(device.Status), "revoked") {
		status = "succeeded"
		reason = ""
	}
	return GraphActionFromCerebroDevice(ActionEndpointCerebroRevokeDevice, device, ProviderActionRequest{}, status, device.Status, reason), nil
}

func (p CerebroDeviceProvider) lookupTenantDevice(ctx context.Context, deviceID string, tenantID string) (deviceauth.DeviceRecord, error) {
	device, err := p.Service.LookupDevice(ctx, deviceID)
	if err != nil {
		if errors.Is(err, deviceauth.ErrDeviceNotFound) {
			return deviceauth.DeviceRecord{}, fmt.Errorf("%w: target device was not found", ErrInvalidRequest)
		}
		return deviceauth.DeviceRecord{}, fmt.Errorf("%w: lookup device: %w", ErrRemote, err)
	}
	if tenantID = strings.TrimSpace(tenantID); tenantID != "" && strings.TrimSpace(device.TenantID) != tenantID {
		return deviceauth.DeviceRecord{}, fmt.Errorf("%w: target device does not belong to finding tenant", ErrInvalidRequest)
	}
	return device, nil
}

func (p CerebroDeviceProvider) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}

func CerebroDeviceExternalID(deviceID string) string {
	return cerebroDeviceRevokeExternalPrefix + strings.TrimSpace(deviceID)
}

func CerebroDeviceTargetFromExternalID(externalID string) (string, bool) {
	externalID = strings.TrimSpace(externalID)
	if !strings.HasPrefix(externalID, cerebroDeviceRevokeExternalPrefix) {
		return "", false
	}
	target, err := NormalizeDeviceTarget(strings.TrimPrefix(externalID, cerebroDeviceRevokeExternalPrefix))
	if err != nil {
		return "", false
	}
	return target, true
}

func GraphActionFromCerebroDevice(action string, device deviceauth.DeviceRecord, request ProviderActionRequest, status string, externalStatus string, statusReason string) *GraphAction {
	target := strings.TrimSpace(device.DeviceID)
	now := time.Now().UTC()
	if !device.RevokedAt.IsZero() {
		now = device.RevokedAt.UTC()
	}
	metadata := map[string]string{
		"device_id": target,
	}
	for key, value := range map[string]string{
		"tenant_id":       firstNonEmptyString(device.TenantID, request.TenantID),
		"finding_id":      request.FindingID,
		"finding_rule_id": request.FindingRuleID,
		"resource_urn":    request.ResourceURN,
		"subject_urn":     request.SubjectURN,
		"hostname":        device.Hostname,
		"hardware_uuid":   device.HardwareUUID,
		"serial_number":   device.SerialNumber,
	} {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			metadata[key] = trimmed
		}
	}
	externalID := CerebroDeviceExternalID(target)
	return &GraphAction{
		ID:                   externalID,
		Action:               strings.TrimSpace(action),
		Provider:             ProviderCerebroDeviceAuth,
		Status:               strings.TrimSpace(status),
		Target:               target,
		ExternalID:           externalID,
		ExternalStatus:       strings.TrimSpace(externalStatus),
		ExternalStatusReason: strings.TrimSpace(statusReason),
		Reason:               strings.TrimSpace(request.Reason),
		Source:               strings.TrimSpace(request.Source),
		TicketURL:            strings.TrimSpace(request.TicketURL),
		IdempotencyKey:       strings.TrimSpace(request.IdempotencyKey),
		CreatedAtUnix:        now.Unix(),
		UpdatedAtUnix:        now.Unix(),
		CompletedAtUnix:      now.Unix(),
		LastError:            strings.TrimSpace(statusReason),
		Metadata:             metadata,
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
