package dnsconfig_test

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"github.com/DefinedNet/dnsconfig"
)

// This example assumes the resolver is already serving and the application
// owns the existing myvpn0 adapter's DNS settings. It runs until interrupted.
func ExampleManager_Set_splitDNS() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	m, err := dnsconfig.New(ctx, dnsconfig.Options{
		Identity:        "myapp",
		Logger:          slog.New(slog.NewTextHandler(os.Stderr, nil)),
		InterfaceName:   "myvpn0",
		ShutdownTimeout: 10 * time.Second,
	})
	if err != nil {
		log.Print(err)
		return
	}
	defer func() {
		if err := m.Close(); err != nil {
			log.Printf("DNS cleanup incomplete; recover with Clear under this identity: %v", err)
		}
	}()

	cfg := dnsconfig.Config{
		Nameservers:   []netip.Addr{netip.MustParseAddr("192.0.2.53")},
		MatchDomains:  []string{"corp.example"},
		SearchDomains: []string{"corp.example"},
	}
	// Set records the goal; the Manager applies, retries, and repairs it in
	// the background. Status reports progress.
	if err := m.Set(cfg); err != nil {
		log.Print(err)
		return
	}

	// Keep the resolver and its network path available through DNS cleanup.
	<-ctx.Done()
}

// A recovery process uses the predecessor's identity. Windows discovers the
// adapter from recovery records, so InterfaceName is unnecessary here.
func ExampleManager_Clear_recovery() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	m, err := dnsconfig.New(ctx, dnsconfig.Options{
		Identity:        "myapp",
		ShutdownTimeout: 10 * time.Second,
	})
	if err != nil {
		log.Print(err)
		return
	}
	defer func() {
		if err := m.Close(); err != nil {
			log.Printf("DNS cleanup remains incomplete: %v", err)
		}
	}()

	if err := m.Clear(); err != nil {
		log.Print(err)
		return
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		s := m.Status()
		switch {
		case s.Converged && s.LastChangedAt.IsZero():
			log.Print("no DNS configuration attributable to myapp was found")
			return
		case s.Converged:
			log.Print("managed DNS configuration removed")
			return
		case errors.Is(s.LastError, dnsconfig.ErrManagerAlreadyRunning):
			log.Print("myapp is still running; leave its DNS configuration in place")
			return
		}
		select {
		case <-ctx.Done():
			log.Printf("DNS recovery incomplete; keep the resolver available and retry: %v", s.LastError)
			return
		case <-ticker.C:
		}
	}
}

// Set returns only failures that retrying cannot fix. Everything the host
// decides, such as another identity holding the namespace, appears in Status
// and is retried. In an application, retain the Manager for its lifetime.
func ExampleManager_Status() {
	ctx := context.Background()
	m, err := dnsconfig.New(ctx, dnsconfig.Options{
		Identity:        "myapp",
		InterfaceName:   "myvpn0",
		ShutdownTimeout: 10 * time.Second,
	})
	if err != nil {
		log.Print(err)
		return
	}
	defer m.Close()

	cfg := dnsconfig.Config{
		Nameservers:  []netip.Addr{netip.MustParseAddr("192.0.2.53")},
		MatchDomains: []string{"corp.example"},
	}
	if err := m.Set(cfg); err != nil {
		log.Printf("DNS configuration refused: %v", err)
		return
	}

	time.Sleep(5 * time.Second)
	s := m.Status()
	var conflict *dnsconfig.ConflictError
	switch {
	case s.Converged:
		log.Print("DNS configuration installed")
	case errors.As(s.LastError, &conflict):
		log.Printf("%s is held by %s; retrying until it leaves", conflict.Domain, conflict.Holder)
	case s.LastError != nil:
		log.Printf("attempt failed, possibly after partial changes; retrying: %v", s.LastError)
	default:
		log.Print("first attempt still running")
	}
}
