package telemetry

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/smallbiznis/railzway-auth/internal/config"
)

// Provider wires OpenTelemetry tracing with lifecycle support.
type Provider struct {
	tracerProvider *sdktrace.TracerProvider
	shutdown       func(ctx context.Context) error
}

// Tracer exposes the configured tracer provider, falling back to noop if disabled.
func (p *Provider) Tracer() trace.Tracer {
	if p == nil || p.tracerProvider == nil {
		return otel.Tracer("github.com/smallbiznis/railzway-auth")
	}
	return p.tracerProvider.Tracer("github.com/smallbiznis/railzway-auth")
}

// Shutdown flushes exporters.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || p.shutdown == nil {
		return nil
	}
	return p.shutdown(ctx)
}

// New configures OpenTelemetry tracing. When endpoint is empty it installs a noop provider.
func New(ctx context.Context, cfg config.Config, logger *zap.Logger) (*Provider, error) {
	if cfg.TelemetryEndpoint == "" {
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
		otel.SetTextMapPropagator(propagation.TraceContext{})
		return &Provider{
			tracerProvider: nil,
			shutdown: func(context.Context) error {
				return nil
			},
		}, nil
	}

	clientOpts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(cfg.TelemetryEndpoint),
	}
	if cfg.TelemetryInsecure {
		clientOpts = append(clientOpts, otlptracehttp.WithInsecure())
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	exp, err := otlptracehttp.New(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("create otlp exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithProcess(),
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("build telemetry resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exp),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if logger != nil {
		logger.Info("telemetry enabled", zap.String("endpoint", cfg.TelemetryEndpoint))
	}

	return &Provider{
		tracerProvider: tp,
		shutdown:       tp.Shutdown,
	}, nil
}
