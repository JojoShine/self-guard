package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const probeVersion = "0.1.6"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	versionFlag := flag.Bool("version", false, "show independent probe version")
	reviewObserver := flag.Bool("review-observer", false, "print the approved BPF attachment program without attaching")
	installConfig := flag.String("install-config", "", "install this approved source as separate continuous services")
	opensslConfig := flag.String("openssl-capture-config", "", "reviewed external OpenSSL observation configuration")
	captureConfig := flag.String("capture-config", "", "root-owned continuous capture configuration")
	inspectPID := flag.Int("inspect-process", 0, "inspect one approved process and OpenSSL library")
	libraryPath := flag.String("library", "", "approved mapped OpenSSL library")
	configPath := flag.String("config", "", "private probe configuration")
	inputPath := flag.String("pcap", "-", "authorized PCAP pipe or replay file")
	queueBudget := flag.Int64("queue-limit", 1<<30, "offline purge queue byte budget")
	expirePath := flag.String("expire-queue", "", "purge expired offline payloads without platform access")
	once := flag.Bool("once", false, "finish after replay and durable delivery")
	flag.Parse()
	if *versionFlag {
		fmt.Println(probeVersion)
		return nil
	}
	if *installConfig != "" {
		return runProbeInstallation(*installConfig)
	}
	if *opensslConfig != "" {
		return runOpenSSLCapture(*opensslConfig, *reviewObserver)
	}
	if *captureConfig != "" {
		return runPacketCapture(*captureConfig)
	}
	if *inspectPID > 0 {
		profile, err := inspectOpenSSLProcess(*inspectPID, *libraryPath)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(profile)
	}
	if *expirePath != "" {
		q, err := openQueue(*expirePath, *queueBudget)
		if err != nil {
			return err
		}
		unlock, err := lockQueue(*expirePath)
		if errors.Is(err, errQueueOwned) {
			return nil
		}
		if err != nil {
			return err
		}
		defer unlock()
		if _, err = q.recoverUncommitted(); err != nil {
			return err
		}
		return q.expire(time.Now())
	}
	if os.Geteuid() == 0 {
		return errors.New("run the decoder as a dedicated unprivileged probe user, separate from packet capture")
	}
	info, err := os.Lstat(*configPath)
	if err != nil || !info.Mode().IsRegular() || (info.Mode().Perm()&0077 != 0 && !(info.Mode().Perm() == 0440 && info.Sys().(*syscall.Stat_t).Uid == 0)) || info.Size() > 65536 {
		return errors.New("probe configuration must be a private regular file")
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		return errors.New("probe configuration unavailable")
	}
	var local ProbeLocalConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&local); err != nil || local.StateDir == "" || local.SourceID == "" || len(local.Token) < 24 {
		return errors.New("probe configuration invalid")
	}
	client, err := newProbeClient(local)
	if err != nil {
		return err
	}
	var source ProbeConfiguration
	if err = client.request("/configuration", nil, &source); err != nil {
		return err
	}
	if source.ID != local.SourceID || !source.Enabled || !installationSnapshotMatches(local, source) {
		return errors.New("probe source not authorized")
	}
	if source.Mode != "NETWORK" && source.Mode != "PLAINTEXT_EVENTS" {
		return errors.New("capture adapter not supported")
	}
	if source.Mode == "PLAINTEXT_EVENTS" && local.PlaintextSocket == "" {
		return errors.New("approved plaintext observer socket required")
	}
	queue, err := openQueue(local.StateDir, source.MaxQueueBytes)
	if err != nil {
		return err
	}
	lock, err := lockQueue(local.StateDir)
	if err != nil {
		return err
	}
	defer lock()
	recovered, recoveryErr := queue.recoverUncommitted()
	if recoveryErr != nil {
		return recoveryErr
	}
	if err = queue.expire(time.Now()); err != nil {
		return err
	}
	input := os.Stdin
	if source.Mode == "NETWORK" && *inputPath != "-" {
		input, err = os.Open(*inputPath)
		if err != nil {
			return errors.New("authorized capture input unavailable")
		}
		defer input.Close()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var capturedPackets atomic.Int64
	source.onPacket = func() { capturedPackets.Add(1) }
	var mu sync.Mutex
	gap, state := "NONE", "RUNNING"
	if recovered > 0 {
		gap = "DISCONNECTED"
		state = "DEGRADED"
	}
	setGap := func(code string) { mu.Lock(); gap = code; state = "DEGRADED"; mu.Unlock() }
	source.onPlaintext = func(dropped uint64) {
		mu.Lock()
		if gap == "NONE" {
			state = "RUNNING"
		}
		mu.Unlock()
	}
	if source.Mode == "PLAINTEXT_EVENTS" {
		state = "STARTING"
	}
	if local.CaptureStatsPath != "" {
		state = "STARTING"
	}
	captureStarted := time.Now()
	var observedDrops atomic.Uint64
	report := func() {
		var loss *uint64
		if local.CaptureStatsPath != "" {
			raw, e := os.ReadFile(local.CaptureStatsPath)
			var stats CaptureStatistics
			if e == nil {
				e = json.Unmarshal(raw, &stats)
			}
			if e != nil || time.Since(stats.UpdatedAt) > 5*time.Second {
				if time.Since(captureStarted) > 5*time.Second {
					setGap("PROBE_STOPPED")
				}
			} else {
				mu.Lock()
				if gap == "NONE" {
					state = "RUNNING"
				}
				mu.Unlock()
				loss = &stats.Dropped
				observedDrops.Store(stats.Dropped)
				if stats.Dropped > 0 {
					setGap("CAPTURE_LOSS")
				}
			}
		}

		mu.Lock()
		health := map[string]any{"state": state, "gap": gap, "version": probeVersion, "capturedPackets": capturedPackets.Load(), "droppedPackets": loss, "configurationVersion": source.Version}
		mu.Unlock()
		usage, err := queue.usage()
		if err != nil {
			setGap("QUEUE_FULL")
			return
		}
		pending, err := queue.pending()
		if err != nil {
			setGap("PARSE_ERROR")
			return
		}
		health["queueBytes"] = usage
		health["pendingEvents"] = len(pending)
		rejected, err := queue.rejectedCount()
		if err != nil {
			setGap("PARSE_ERROR")
			return
		}
		health["rejectedEvents"] = rejected
		if rejected > 0 {
			health["state"] = "DEGRADED"
			health["gap"] = "PARSE_ERROR"
		}
		if err = client.request("/health", health, nil); err != nil {
			fmt.Fprintln(os.Stderr, "probe health report unavailable")
		}
	}
	var workers sync.WaitGroup
	if !*once {
		workers.Add(1)
		go func() {
			defer workers.Done()
			tick := time.NewTicker(5 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					if err := queue.expire(time.Now()); err != nil {
						setGap("PARSE_ERROR")
					}
					var current ProbeConfiguration
					configurationErr := client.request("/configuration", nil, &current)
					if configurationErr != nil {
						var failure *probeHTTPError
						if errors.As(configurationErr, &failure) && (failure.status == 401 || failure.status == 403) {
							setGap("PROBE_STOPPED")
							input.Close()
							stop()
							return
						}
						fmt.Fprintln(os.Stderr, "probe platform temporarily unavailable; independent encrypted queue retained")
						continue
					}
					if !current.Enabled || current.ID != source.ID {
						setGap("PROBE_STOPPED")
						input.Close()
						stop()
						return
					}
					if err := deliverPending(client, queue); err != nil {
						fmt.Fprintln(os.Stderr, "probe evidence delivery deferred; encrypted queue retained")
					}
					report()
				}
			}
		}()
	}
	report()
	captureDone := make(chan error, 1)
	go func() {
		commit := func(e *Exchange) error {
			if observedDrops.Load() > 0 {
				e.gap("CAPTURE_LOSS")
			}
			if len(e.Gaps) > 0 {
				setGap(e.Gaps[0])
			}
			if err := queue.commit(e); err != nil {
				setGap("QUEUE_FULL")
				return err
			}
			return nil
		}
		if source.Mode == "PLAINTEXT_EVENTS" {
			captureDone <- observeOpenSSL(ctx, local.PlaintextSocket, source, queue.newEvent, commit, setGap, *once)
		} else {
			captureDone <- observePCAP(input, source, queue.newEvent, commit, setGap)
		}
	}()
	select {
	case err = <-captureDone:
	case <-ctx.Done():
		input.Close()
		err = <-captureDone
	}
	stop()
	workers.Wait()
	if err != nil {
		var failure *observationError
		if errors.As(err, &failure) {
			setGap(failure.gap)
		} else {
			setGap("PARSE_ERROR")
		}
		// Commit valid completed exchanges even when a later capture is incomplete.
		if deliveryErr := deliverPending(client, queue); deliveryErr != nil {
			report()
			return errors.Join(errors.New("probe capture incomplete"), deliveryErr)
		}
		report()
		return errors.New("probe capture incomplete; inspect platform coverage and retained encrypted queue")
	}
	if err = deliverPending(client, queue); err != nil {
		report()
		return err
	}
	mu.Lock()
	state = "STOPPED"
	mu.Unlock()
	report()
	return nil
}
