package types

// ContainerService represents a parsed container with its Tailscale service configuration
type ContainerService struct {
	ContainerID     string
	ContainerName   string
	ServiceName     string
	Port            string // Tailscale service port (e.g., "443")
	TargetPort      string // Container/host port to proxy to (e.g., "9080")
	ServiceProtocol string // Protocol Tailscale uses (e.g., "https", "http", "tcp")
	Protocol        string // Protocol the container speaks (e.g., "http", "https", "tcp")
	IPAddress       string
	Network         string // optional: specific network to use
}

// TailscaleServiceConfig represents the JSON structure for Tailscale service configuration
type TailscaleServiceConfig struct {
	Version  string                        `json:"version"`
	Services map[string]ServiceDefinition  `json:"services"`
}

// ServiceDefinition defines a single Tailscale service
type ServiceDefinition struct {
	Endpoints map[string]string `json:"endpoints"`
}

// Labels for container discovery
const (
	LabelEnable         = "docktail.service.enable"
	LabelService        = "docktail.service.name"
	LabelPort           = "docktail.service.service-port"
	LabelServiceProtocol = "docktail.service.service-protocol"
	LabelTarget         = "docktail.service.port"
	LabelTargetProtocol = "docktail.service.protocol"
	LabelNetwork        = "docktail.service.network"
)
