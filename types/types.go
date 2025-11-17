package types

// ContainerService represents a parsed container with its Tailscale service configuration
type ContainerService struct {
	ContainerID   string
	ContainerName string
	ServiceName   string
	Port          string
	TargetPort    string
	Protocol      string
	IPAddress     string
	Network       string // optional: specific network to use
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
	LabelTarget         = "docktail.service.port"
	LabelTargetProtocol = "docktail.service.protocol"
	LabelNetwork        = "docktail.service.network"
)
