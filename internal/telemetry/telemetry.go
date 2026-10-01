// Package telemetry is the service's OpenTelemetry (spec 005): set up from the standard environment
// (OTEL_EXPORTER_OTLP_*, OTEL_SERVICE_NAME, OTEL_RESOURCE_ATTRIBUTES, OTEL_SDK_DISABLED), nothing exported
// unless an endpoint is set. Traces only continue a caller's: the sampler follows the parent and never samples
// a root. Metrics are the service's own; logs carry the audit. Nothing secret is ever an attribute.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Name is the instrumentation scope of every tracer, meter and logger here.
const Name = "github.com/hugr-lab/tresor-server"

// Options are what the configuration decides; the rest is the environment's.
type Options struct {
	Version string
	// Traces: spans under a caller's trace. false: none, the audit's trace id only.
	Traces bool
}

// Setup sets the global providers from the environment, for the signals that have an endpoint. It returns what
// flushes them at the end. The W3C trace context is the one propagator (the protocol defines no other header).
func Setup(ctx context.Context, opts Options) (shutdown func(context.Context) error, err error) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	noop := func(context.Context) error { return nil }
	if strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true") {
		return noop, nil
	}
	traces, metrics, logs := endpoint("TRACES"), endpoint("METRICS"), endpoint("LOGS")
	if !traces && !metrics && !logs {
		return noop, nil
	}
	for _, signal := range []string{"", "TRACES_", "METRICS_", "LOGS_"} {
		if p := os.Getenv("OTEL_EXPORTER_OTLP_" + signal + "PROTOCOL"); p != "" && p != "http/protobuf" {
			return nil, fmt.Errorf("OTEL_EXPORTER_OTLP_%sPROTOCOL is %s: this build exports http/protobuf only", signal, p)
		}
	}
	if os.Getenv("OTEL_SERVICE_NAME") == "" {
		os.Setenv("OTEL_SERVICE_NAME", "tresor-server") // the resource reads it
	}
	res, err := resource.New(ctx, resource.WithFromEnv(), resource.WithTelemetrySDK(),
		resource.WithAttributes(semconv.ServiceVersion(opts.Version)))
	if err != nil {
		return nil, fmt.Errorf("telemetry: the resource: %w", err)
	}
	var stops []func(context.Context) error
	if traces && opts.Traces {
		exp, err := otlptracehttp.New(ctx)
		if err != nil {
			return nil, fmt.Errorf("telemetry: traces: %w", err)
		}
		tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(exp),
			// only under a caller's sampled trace: tresor's (spec 005); never a root of the service's own
			sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.NeverSample())))
		otel.SetTracerProvider(tp)
		stops = append(stops, tp.Shutdown)
	}
	if metrics {
		exp, err := otlpmetrichttp.New(ctx)
		if err != nil {
			return nil, fmt.Errorf("telemetry: metrics: %w", err)
		}
		mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res),
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp, sdkmetric.WithInterval(30*time.Second))))
		otel.SetMeterProvider(mp)
		stops = append(stops, mp.Shutdown)
	}
	if logs {
		exp, err := otlploghttp.New(ctx)
		if err != nil {
			return nil, fmt.Errorf("telemetry: logs: %w", err)
		}
		lp := sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)))
		global.SetLoggerProvider(lp)
		stops = append(stops, lp.Shutdown)
	}
	return func(ctx context.Context) error {
		var errs []error
		for _, stop := range stops {
			errs = append(errs, stop(ctx))
		}
		return errors.Join(errs...)
	}, nil
}

// endpoint: an OTLP endpoint is set for the signal, or for all.
func endpoint(signal string) bool {
	return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" || os.Getenv("OTEL_EXPORTER_OTLP_"+signal+"_ENDPOINT") != ""
}
