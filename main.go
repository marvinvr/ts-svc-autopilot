package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/marvinvr/docktail/docker"
	"github.com/marvinvr/docktail/reconciler"
	"github.com/marvinvr/docktail/tailscale"
)

func main() {
	// Setup logging
	setupLogging()

	log.Info().Msg("Starting DockTail")

	// Get configuration from environment
	reconcileInterval := getEnvDuration("RECONCILE_INTERVAL", 60*time.Second)
	tailscaleSocket := getEnv("TAILSCALE_SOCKET", "/var/run/tailscale/tailscaled.sock")

	log.Info().
		Dur("reconcile_interval", reconcileInterval).
		Str("tailscale_socket", tailscaleSocket).
		Msg("Configuration loaded")

	// Create Docker client
	dockerClient, err := docker.NewClient()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create Docker client")
	}
	defer dockerClient.Close()

	log.Info().Msg("Docker client initialized")

	// Create Tailscale client
	tailscaleClient := tailscale.NewClient(tailscaleSocket)

	log.Info().Msg("Tailscale client initialized")

	// Create reconciler
	rec := reconciler.NewReconciler(dockerClient, tailscaleClient, reconcileInterval)

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Info().Str("signal", sig.String()).Msg("Received shutdown signal")
		cancel()
	}()

	// Run reconciler
	log.Info().Msg("Starting reconciliation loop")
	if err := rec.Run(ctx); err != nil && err != context.Canceled {
		log.Fatal().Err(err).Msg("Reconciler failed")
	}

	log.Info().Msg("DockTail stopped")
}

func setupLogging() {
	// Configure zerolog
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
	})

	// Set log level from environment
	logLevel := getEnv("LOG_LEVEL", "info")
	switch logLevel {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	log.Debug().Str("level", logLevel).Msg("Log level set")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
		log.Warn().
			Str("key", key).
			Str("value", value).
			Dur("default", defaultValue).
			Msg("Failed to parse duration, using default")
	}
	return defaultValue
}
