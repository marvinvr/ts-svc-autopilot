package tailscale

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"

	apptypes "github.com/marvinvr/docktail/types"
)

// Client handles Tailscale CLI interactions
type Client struct {
	socketPath string
}

// NewClient creates a new Tailscale client
func NewClient(socketPath string) *Client {
	return &Client{
		socketPath: socketPath,
	}
}

// ServiceEndpoint represents a single endpoint for comparison
type ServiceEndpoint struct {
	ServiceName string // e.g., "svc:web"
	Port        string // e.g., "443"
	Protocol    string // e.g., "http", "https", "tcp"
	Destination string // e.g., "http://localhost:9080"
}

// TailscaleStatus represents the structure of 'tailscale serve status --json'
type TailscaleStatus struct {
	Services map[string]TailscaleService `json:"Services"`
}

type TailscaleService struct {
	TCP map[string]TailscaleTCPConfig `json:"TCP"`
	Web map[string]TailscaleWebConfig `json:"Web"`
}

type TailscaleTCPConfig struct {
	HTTP  bool `json:"HTTP"`
	HTTPS bool `json:"HTTPS"`
}

type TailscaleWebConfig struct {
	Handlers map[string]TailscaleHandler `json:"Handlers"`
}

type TailscaleHandler struct {
	Proxy string `json:"Proxy"`
}

// GetCurrentServices retrieves the current Tailscale service status using CLI
func (c *Client) GetCurrentServices(ctx context.Context) (map[string]ServiceEndpoint, error) {
	cmd := exec.CommandContext(ctx, "tailscale", "serve", "status", "--json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		stderr := string(output)
		// Empty config is not an error
		if strings.Contains(stderr, "no services") ||
			strings.Contains(stderr, "not found") ||
			strings.Contains(stderr, "nothing to show") {
			log.Debug().Msg("No existing Tailscale services found")
			return make(map[string]ServiceEndpoint), nil
		}
		return nil, fmt.Errorf("failed to get tailscale status: %w (output: %s)", err, stderr)
	}

	// Strip any warning messages from the output (they appear before the JSON)
	// Example: "Warning: client version "X" != tailscaled server version "Y"\n"
	outputStr := string(output)
	jsonStart := strings.Index(outputStr, "{")
	if jsonStart > 0 {
		outputStr = outputStr[jsonStart:]
		log.Debug().
			Int("stripped_bytes", jsonStart).
			Msg("Stripped warning message from tailscale output")
	}

	// Parse the status JSON
	var status TailscaleStatus
	if err := json.Unmarshal([]byte(outputStr), &status); err != nil {
		// If we can't parse JSON, assume no services
		log.Warn().
			Err(err).
			Str("output", outputStr).
			Msg("Could not parse status JSON, assuming no services")
		return make(map[string]ServiceEndpoint), nil
	}

	log.Debug().
		Int("total_services_in_status", len(status.Services)).
		Msg("Parsed Tailscale status JSON")

	services := make(map[string]ServiceEndpoint)

	// Parse each service
	for serviceName, svcConfig := range status.Services {
		// Only process services we manage (with svc: prefix)
		if !strings.HasPrefix(serviceName, "svc:") {
			continue
		}

		// Parse TCP config to get port and protocol
		for port, tcpConfig := range svcConfig.TCP {
			var protocol string
			if tcpConfig.HTTPS {
				protocol = "https"
			} else if tcpConfig.HTTP {
				protocol = "http"
			} else {
				protocol = "tcp"
			}

			// Get destination from Web config
			var destination string
			for webKey, webConfig := range svcConfig.Web {
				// Find the matching port in the web key
				if strings.Contains(webKey, ":"+port) {
					for _, handler := range webConfig.Handlers {
						if handler.Proxy != "" {
							destination = handler.Proxy
							break
						}
					}
					break
				}
			}

			// Create a unique key for this service+port combination
			key := fmt.Sprintf("%s:%s", serviceName, port)

			services[key] = ServiceEndpoint{
				ServiceName: serviceName,
				Port:        port,
				Protocol:    protocol,
				Destination: destination,
			}

			log.Debug().
				Str("service", serviceName).
				Str("port", port).
				Str("protocol", protocol).
				Str("destination", destination).
				Msg("Parsed existing service")
		}
	}

	log.Info().
		Int("service_count", len(services)).
		Msg("Retrieved current Tailscale services")

	return services, nil
}

// ReconcileServices compares desired services with current services and makes necessary changes
func (c *Client) ReconcileServices(ctx context.Context, desiredServices []*apptypes.ContainerService) error {
	log.Info().
		Int("desired_count", len(desiredServices)).
		Msg("Starting service reconciliation using CLI commands")

	// Build map of desired services for easy lookup
	desiredMap := make(map[string]*apptypes.ContainerService)
	for _, svc := range desiredServices {
		key := fmt.Sprintf("svc:%s:%s", svc.ServiceName, svc.Port)
		desiredMap[key] = svc
	}

	// Get current services
	currentServices, err := c.GetCurrentServices(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get current services, will apply all desired services")
		currentServices = make(map[string]ServiceEndpoint)
	}

	log.Info().
		Int("current_service_count", len(currentServices)).
		Msg("Retrieved current service state from Tailscale")

	// Track what we need to add and remove
	toAdd := make(map[string]*apptypes.ContainerService)
	toRemove := make(map[string]ServiceEndpoint)

	// Find services to add (in desired but not in current, or changed)
	for key, desired := range desiredMap {
		if current, exists := currentServices[key]; !exists {
			// Service doesn't exist - add it
			toAdd[key] = desired
			log.Debug().
				Str("key", key).
				Str("service", desired.ServiceName).
				Msg("Service not found in current state, will add")
		} else {
			// Service exists - check if configuration changed
			expectedDest := c.buildDestination(desired)
			if current.Destination != expectedDest || current.Protocol != desired.ServiceProtocol {
				toAdd[key] = desired
				log.Info().
					Str("key", key).
					Str("service", desired.ServiceName).
					Str("current_dest", current.Destination).
					Str("expected_dest", expectedDest).
					Str("current_protocol", current.Protocol).
					Str("expected_protocol", desired.ServiceProtocol).
					Msg("Service configuration changed, will update")
			} else {
				// Service exists and matches - no action needed
				log.Debug().
					Str("key", key).
					Str("service", desired.ServiceName).
					Str("protocol", current.Protocol).
					Str("destination", current.Destination).
					Msg("Service already exists with correct configuration, skipping")
			}
		}
	}

	// Find services to remove (in current but not in desired)
	for key, current := range currentServices {
		if _, exists := desiredMap[key]; !exists {
			toRemove[key] = current
		}
	}

	log.Info().
		Int("to_add", len(toAdd)).
		Int("to_remove", len(toRemove)).
		Msg("Calculated reconciliation actions")

	// Remove old services first
	for key, svc := range toRemove {
		log.Info().
			Str("service", svc.ServiceName).
			Str("port", svc.Port).
			Msg("Removing service")

		if err := c.removeService(ctx, svc.ServiceName); err != nil {
			log.Error().
				Err(err).
				Str("service", svc.ServiceName).
				Msg("Failed to remove service")
			// Continue with other services
		} else {
			log.Info().
				Str("key", key).
				Str("service", svc.ServiceName).
				Msg("Successfully removed service")
		}
	}

	// Add new services
	successCount := 0
	failCount := 0

	for key, svc := range toAdd {
		log.Info().
			Str("container", svc.ContainerName).
			Str("service", svc.ServiceName).
			Str("service_port", svc.Port).
			Str("service_protocol", svc.ServiceProtocol).
			Str("backend_protocol", svc.Protocol).
			Str("backend_port", svc.TargetPort).
			Msg("Adding service")

		if err := c.addService(ctx, svc); err != nil {
			failCount++
			log.Error().
				Err(err).
				Str("service", svc.ServiceName).
				Str("container", svc.ContainerName).
				Msg("Failed to add service")
			// Continue with other services
		} else {
			successCount++
			log.Info().
				Str("key", key).
				Str("service", svc.ServiceName).
				Str("container", svc.ContainerName).
				Msg("Successfully added service")
		}
	}

	log.Info().
		Int("added", successCount).
		Int("failed", failCount).
		Int("removed", len(toRemove)).
		Msg("Service reconciliation completed")

	if failCount > 0 {
		return fmt.Errorf("failed to add %d services", failCount)
	}

	return nil
}

// addService adds a single service using Tailscale CLI
// NOTE: This does NOT drain by default - draining only happens when needed
// If adding fails due to config conflict, it clears (with drain) and retries
func (c *Client) addService(ctx context.Context, svc *apptypes.ContainerService) error {
	serviceName := fmt.Sprintf("svc:%s", svc.ServiceName)
	destination := c.buildDestination(svc)

	// Map service protocol to CLI flag (this is what Tailscale exposes)
	var protocolFlag string
	switch svc.ServiceProtocol {
	case "http":
		protocolFlag = "--http"
	case "https":
		protocolFlag = "--https"
	case "tcp", "tls-terminated-tcp":
		protocolFlag = "--tcp"
	default:
		return fmt.Errorf("unsupported service protocol: %s", svc.ServiceProtocol)
	}

	// Build the command: tailscale serve --service=svc:<name> --<protocol>=<port> <destination>
	portArg := fmt.Sprintf("%s=%s", protocolFlag, svc.Port)
	serviceArg := fmt.Sprintf("--service=%s", serviceName)

	cmd := exec.CommandContext(ctx, "tailscale", "serve", serviceArg, portArg, destination)

	log.Debug().
		Str("command", cmd.String()).
		Str("service", serviceName).
		Str("service_protocol", svc.ServiceProtocol).
		Str("service_port", svc.Port).
		Str("backend_protocol", svc.Protocol).
		Str("destination", destination).
		Msg("Executing tailscale serve command")

	output, err := cmd.CombinedOutput()
	if err != nil {
		stderr := string(output)

		// Check if error is due to config conflict (e.g., protocol change)
		if strings.Contains(stderr, "already serving") ||
		   strings.Contains(stderr, "want to serve") ||
		   strings.Contains(stderr, "port is already serving") {
			log.Warn().
				Str("service", serviceName).
				Str("error", stderr).
				Msg("Service config conflict detected, clearing old config and retrying")

			// Clear the old service (this will drain connections gracefully)
			if clearErr := c.clearServiceOnly(ctx, serviceName); clearErr != nil {
				return fmt.Errorf("failed to clear conflicting service: %w", clearErr)
			}

			// Retry the add
			log.Info().
				Str("service", serviceName).
				Msg("Retrying add after clearing conflicting config")

			retryCmd := exec.CommandContext(ctx, "tailscale", "serve", serviceArg, portArg, destination)
			retryOutput, retryErr := retryCmd.CombinedOutput()
			if retryErr != nil {
				return fmt.Errorf("failed to add service after clearing: %w\nOutput: %s", retryErr, string(retryOutput))
			}

			log.Info().
				Str("service", serviceName).
				Msg("Service added successfully after resolving conflict")
			return nil
		}

		return fmt.Errorf("failed to add service: %w\nOutput: %s", err, stderr)
	}

	log.Debug().
		Str("output", string(output)).
		Str("service", serviceName).
		Msg("Service added successfully")

	return nil
}

// clearServiceOnly clears a service configuration without draining
// Used when updating service config (protocol change, etc) where service continues running
func (c *Client) clearServiceOnly(ctx context.Context, serviceName string) error {
	log.Info().
		Str("service", serviceName).
		Msg("Clearing service configuration (no drain - service will be reconfigured)")

	cmd := exec.CommandContext(ctx, "tailscale", "serve", "clear", serviceName)

	log.Debug().
		Str("command", cmd.String()).
		Str("service", serviceName).
		Msg("Executing tailscale serve clear command")

	output, err := cmd.CombinedOutput()
	if err != nil {
		stderr := string(output)
		// Ignore errors if service doesn't exist
		if strings.Contains(stderr, "not found") || strings.Contains(stderr, "does not exist") {
			log.Debug().
				Str("service", serviceName).
				Msg("Service doesn't exist, nothing to clear")
			return nil
		}
		return fmt.Errorf("failed to clear service: %w\nOutput: %s", err, stderr)
	}

	log.Info().
		Str("service", serviceName).
		Msg("Service configuration cleared successfully")

	return nil
}

// removeService gracefully removes a service using Tailscale CLI
// It first drains the service (allows existing connections to complete),
// then clears it (removes the configuration)
// SAFETY: Only removes services with "svc:" prefix to avoid touching manually created services
// NOTE: This is used when containers STOP - for config changes, use clearServiceOnly instead
func (c *Client) removeService(ctx context.Context, serviceName string) error {
	// Safety check: only remove services we manage (those with svc: prefix)
	if !strings.HasPrefix(serviceName, "svc:") {
		log.Warn().
			Str("service", serviceName).
			Msg("Refusing to remove service without 'svc:' prefix - not managed by DockTail")
		return fmt.Errorf("refusing to remove service '%s': not managed by DockTail (missing 'svc:' prefix)", serviceName)
	}

	log.Info().
		Str("service", serviceName).
		Msg("Gracefully removing service: draining then clearing")

	// Step 1: Drain the service to gracefully close existing connections
	// This is important for security - prevents stale services from staying accessible
	drainCmd := exec.CommandContext(ctx, "tailscale", "serve", "drain", serviceName)

	log.Debug().
		Str("command", drainCmd.String()).
		Str("service", serviceName).
		Msg("Draining service to close existing connections")

	drainOutput, drainErr := drainCmd.CombinedOutput()
	if drainErr != nil {
		stderr := string(drainOutput)
		// Only warn if drain fails - we'll still try to clear
		if !strings.Contains(stderr, "not found") && !strings.Contains(stderr, "does not exist") {
			log.Warn().
				Err(drainErr).
				Str("service", serviceName).
				Str("output", stderr).
				Msg("Failed to drain service, will attempt to clear anyway")
		} else {
			log.Debug().
				Str("service", serviceName).
				Msg("Service doesn't exist for draining, will skip to clear")
		}
	} else {
		log.Info().
			Str("service", serviceName).
			Msg("Service drained successfully")
	}

	// Step 2: Clear the service configuration
	clearCmd := exec.CommandContext(ctx, "tailscale", "serve", "clear", serviceName)

	log.Debug().
		Str("command", clearCmd.String()).
		Str("service", serviceName).
		Msg("Clearing service configuration")

	clearOutput, clearErr := clearCmd.CombinedOutput()
	if clearErr != nil {
		stderr := string(clearOutput)
		// Ignore errors if service doesn't exist
		if strings.Contains(stderr, "not found") || strings.Contains(stderr, "does not exist") {
			log.Debug().
				Str("service", serviceName).
				Msg("Service already removed or doesn't exist")
			return nil
		}
		return fmt.Errorf("failed to clear service: %w\nOutput: %s", clearErr, stderr)
	}

	log.Info().
		Str("service", serviceName).
		Msg("Service removed successfully (drained and cleared)")

	return nil
}

// buildDestination constructs the destination URL for a service
func (c *Client) buildDestination(svc *apptypes.ContainerService) string {
	// Use the service protocol directly in the destination URL
	// The protocol flag and destination protocol should match the service configuration
	return fmt.Sprintf("%s://%s:%s", svc.Protocol, svc.IPAddress, svc.TargetPort)
}

// CleanupAllServices removes all services managed by DockTail
// This is called on shutdown to ensure no orphaned services remain advertised
func (c *Client) CleanupAllServices(ctx context.Context) error {
	log.Info().Msg("Starting cleanup: removing all managed Tailscale services")

	// Get all current services
	currentServices, err := c.GetCurrentServices(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get current services for cleanup")
		return err
	}

	if len(currentServices) == 0 {
		log.Info().Msg("No services to clean up")
		return nil
	}

	log.Info().
		Int("service_count", len(currentServices)).
		Msg("Found services to clean up")

	// Remove each service (drain + clear)
	successCount := 0
	failCount := 0

	for _, svc := range currentServices {
		log.Info().
			Str("service", svc.ServiceName).
			Str("port", svc.Port).
			Str("protocol", svc.Protocol).
			Msg("Cleaning up service")

		if err := c.removeService(ctx, svc.ServiceName); err != nil {
			failCount++
			log.Error().
				Err(err).
				Str("service", svc.ServiceName).
				Msg("Failed to clean up service")
			// Continue with other services
		} else {
			successCount++
		}
	}

	log.Info().
		Int("total", len(currentServices)).
		Int("success", successCount).
		Int("failed", failCount).
		Msg("Cleanup completed")

	if failCount > 0 {
		return fmt.Errorf("failed to clean up %d services", failCount)
	}

	return nil
}

// DrainService gracefully drains a service
func (c *Client) DrainService(ctx context.Context, serviceName string) error {
	fullName := fmt.Sprintf("svc:%s", serviceName)
	cmd := exec.CommandContext(ctx, "tailscale", "serve", "drain", fullName)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to drain service %s: %w\nOutput: %s", fullName, err, string(output))
	}
	log.Info().Str("service", fullName).Msg("Drained service")
	return nil
}
