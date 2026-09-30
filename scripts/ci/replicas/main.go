// replicas runs a service's replicas behind a round-robin proxy, as one foreground process: tresor's
// test_keycloak.sh takes one command that is the server (TRESOR_SERVER_CMD, run with exec), and this is that
// command for a run with several replicas (spec 002). Not shipped.
//
//	replicas -n 2 -config <file> <tresor-server>
//
// The proxy listens where the configuration's listen says; each replica on a free port of its own, given as
// TRESOR_LISTEN (the environment over the file), with the configuration's public_url - the proxy's. The
// replicas' logs pass through, so request lines can still be read from this process's output. SIGTERM stops
// the replicas; a replica that exits stops everything.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hugr-lab/tresor-server/internal/config"
)

func main() {
	n := flag.Int("n", 2, "how many replicas")
	configPath := flag.String("config", "", "the configuration file")
	flag.Parse()
	if flag.NArg() != 1 || *n < 1 {
		log.Fatal("usage: replicas -n 2 -config <file> <tresor-server>")
	}
	if err := run(flag.Arg(0), *configPath, *n); err != nil {
		log.Fatalf("replicas: %v", err)
	}
}

func freePort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}

func run(server, configPath string, n int) error {
	cfg, _, err := config.Load(configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var targets []*url.URL
	exited := make(chan error, n)
	var children []*exec.Cmd
	defer func() {
		for _, c := range children {
			_ = c.Process.Signal(syscall.SIGTERM)
		}
		for _, c := range children {
			_ = c.Wait()
		}
	}()
	for i := range n {
		addr, err := freePort()
		if err != nil {
			return err
		}
		cmd := exec.Command(server, "-config", configPath)
		cmd.Env = append(os.Environ(), "TRESOR_LISTEN="+addr)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Start(); err != nil {
			return err
		}
		children = append(children, cmd)
		go func() { exited <- fmt.Errorf("replica %d exited: %v", i+1, cmd.Wait()) }()
		targets = append(targets, &url.URL{Scheme: "http", Host: addr})
	}
	// the proxy opens once every replica answers: whoever waits on it waits on them all
	for _, t := range targets {
		if err := waitFor(ctx, t.String()+"/healthz", exited); err != nil {
			return err
		}
	}
	var next atomic.Uint64
	proxy := &httputil.ReverseProxy{Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(targets[next.Add(1)%uint64(len(targets))])
		r.Out.Host = r.In.Host
	}}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: proxy, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(listener) }()
	log.Printf("replicas: %d behind %s", n, cfg.Listen)
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		return nil
	case err := <-exited:
		_ = srv.Close()
		return err
	}
}

// waitFor polls url until it answers, a replica exits, or 60 s pass.
func waitFor(ctx context.Context, target string, exited <-chan error) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-exited:
			return err
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if res, err := http.Get(target); err == nil {
			res.Body.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("%s did not answer", target)
}
