package docker

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/rs/zerolog/log"

	apptypes "github.com/marvinvr/docktail/types"
)

// Client wraps the Docker client with our business logic
type Client struct {
	cli *client.Client
}

// NewClient creates a new Docker client
func NewClient() (*Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	return &Client{cli: cli}, nil
}

// Close closes the Docker client
func (c *Client) Close() error {
	return c.cli.Close()
}

// WatchEvents streams Docker container events
func (c *Client) WatchEvents(ctx context.Context) (<-chan events.Message, <-chan error) {
	eventsChan, errChan := c.cli.Events(ctx, events.ListOptions{
		Filters: filters.NewArgs(
			filters.Arg("type", "container"),
			filters.Arg("event", "start"),
			filters.Arg("event", "stop"),
			filters.Arg("event", "die"),
			filters.Arg("event", "restart"),
		),
	})

	return eventsChan, errChan
}

// GetEnabledContainers returns all running containers with docktail.service.enable=true
func (c *Client) GetEnabledContainers(ctx context.Context) ([]*apptypes.ContainerService, error) {
	containers, err := c.cli.ContainerList(ctx, container.ListOptions{
		Filters: filters.NewArgs(
			filters.Arg("label", apptypes.LabelEnable+"=true"),
		),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var services []*apptypes.ContainerService
	for _, cont := range containers {
		service, err := c.parseContainer(ctx, cont.ID, cont.Labels)
		if err != nil {
			log.Warn().
				Err(err).
				Str("container_id", cont.ID[:12]).
				Str("container_name", strings.TrimPrefix(cont.Names[0], "/")).
				Msg("Failed to parse container, skipping")
			continue
		}
		if service != nil {
			services = append(services, service)
		}
	}

	return services, nil
}

// parseContainer extracts service configuration from container labels
func (c *Client) parseContainer(ctx context.Context, containerID string, labels map[string]string) (*apptypes.ContainerService, error) {
	// Check if autopilot is enabled
	if labels[apptypes.LabelEnable] != "true" {
		return nil, nil
	}

	// Validate required labels
	serviceName := labels[apptypes.LabelService]
	if serviceName == "" {
		return nil, fmt.Errorf("missing required label: %s", apptypes.LabelService)
	}

	targetPort := labels[apptypes.LabelTarget]
	if targetPort == "" {
		return nil, fmt.Errorf("missing required label: %s", apptypes.LabelTarget)
	}

	// Optional labels with defaults
	port := labels[apptypes.LabelPort]
	if port == "" {
		port = "80"
	}

	protocol := labels[apptypes.LabelTargetProtocol]
	if protocol == "" {
		protocol = "http"
	}

	// Validate protocol
	validProtocols := map[string]bool{
		"http":                true,
		"https":               true,
		"tcp":                 true,
		"tls-terminated-tcp":  true,
	}
	if !validProtocols[protocol] {
		return nil, fmt.Errorf("invalid protocol: %s (must be http, https, tcp, or tls-terminated-tcp)", protocol)
	}

	// Get container details for port bindings
	inspect, err := c.cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	containerName := strings.TrimPrefix(inspect.Name, "/")

	// Tailscale serve only supports localhost/127.0.0.1 proxies
	// We need to find the published host port that maps to the target port
	var hostPort string
	targetPortKey := nat.Port(fmt.Sprintf("%s/tcp", targetPort))

	log.Debug().
		Str("container", containerName).
		Str("looking_for_port", string(targetPortKey)).
		Msg("Looking for published port binding")

	if inspect.HostConfig != nil && inspect.HostConfig.PortBindings != nil {
		if bindings, ok := inspect.HostConfig.PortBindings[targetPortKey]; ok && len(bindings) > 0 {
			// Use the first host port binding
			hostPort = bindings[0].HostPort
			log.Debug().
				Str("container", containerName).
				Str("target_port", targetPort).
				Str("host_port", hostPort).
				Msg("Detected published port binding")
		}
	}

	// If no port binding found, check NetworkSettings.Ports as fallback
	if hostPort == "" && inspect.NetworkSettings != nil && inspect.NetworkSettings.Ports != nil {
		if bindings, ok := inspect.NetworkSettings.Ports[targetPortKey]; ok && len(bindings) > 0 {
			hostPort = bindings[0].HostPort
			log.Debug().
				Str("container", containerName).
				Str("target_port", targetPort).
				Str("host_port", hostPort).
				Msg("Detected published port from NetworkSettings")
		}
	}

	if hostPort == "" {
		// Debug: Show what ports ARE available
		var availablePorts []string
		if inspect.HostConfig != nil && inspect.HostConfig.PortBindings != nil {
			for port := range inspect.HostConfig.PortBindings {
				availablePorts = append(availablePorts, string(port))
			}
		}

		log.Warn().
			Str("container", containerName).
			Str("needed_port", string(targetPortKey)).
			Strs("available_ports", availablePorts).
			Msg("Port not found in bindings")

		return nil, fmt.Errorf(
			"container port %s is NOT published to host. "+
				"Tailscale serve requires localhost proxies. "+
				"Fix: Add 'ports: [\"%s:%s\"]' to container '%s' in docker-compose.yaml. "+
				"Format is HOST:CONTAINER where %s is the CONTAINER port (docktail.service.port=%s). "+
				"Available published ports: %v",
			targetPort, targetPort, targetPort, containerName, targetPort, targetPort, availablePorts,
		)
	}

	log.Info().
		Str("container", containerName).
		Str("container_port", targetPort).
		Str("host_port", hostPort).
		Str("will_proxy_to", fmt.Sprintf("localhost:%s", hostPort)).
		Msg("Detected port binding for Tailscale proxy")

	return &apptypes.ContainerService{
		ContainerID:   containerID[:12],
		ContainerName: containerName,
		ServiceName:   serviceName,
		Port:          port,
		TargetPort:    hostPort, // Use the published host port
		Protocol:      protocol,
		IPAddress:     "localhost", // Tailscale serve requires localhost
		Network:       "host",      // Using host-published ports
	}, nil
}
