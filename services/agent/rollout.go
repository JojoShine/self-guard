package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Set at release build time: go build -ldflags '-X main.agentVersion=0.2.0'.
var agentVersion = "0.1.0"
var processInstance = time.Now().UTC().Format(time.RFC3339Nano)
var errUpgradeRestart = errors.New("upgrade staged: supervisor restart required")

type RolloutOffer struct {
	ID            string             `json:"id"`
	ArtifactURL   string             `json:"artifactUrl"`
	ManifestBytes string             `json:"manifestBytes"`
	Signature     string             `json:"signature"`
	Authorization *TaskAuthorization `json:"authorization,omitempty"`
	DownloadGrant *TaskAuthorization `json:"downloadGrant,omitempty"`
}
type rolloutReceipt struct {
	ExecutorResult *Result      `json:"executorResult,omitempty"`
	Offer          RolloutOffer `json:"offer"`
	Status         string       `json:"status"`
	StagedBy       string       `json:"stagedBy"`
}

func trustedArtifact(c Config, value string) error {
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "https" && !(c.AllowHTTP && u.Scheme == "http")) || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("artifact requires an explicitly trusted transport and origin")
	}
	for _, origin := range c.UpgradeOrigins {
		o, e := url.Parse(origin)
		if e == nil && o.Scheme == u.Scheme && o.Host == u.Host && o.User == nil && validPlatformPath(o) && (u.Path == strings.TrimSuffix(o.Path, "/") || strings.HasPrefix(u.Path, strings.TrimSuffix(o.Path, "/")+"/")) {
			return nil
		}
	}
	return errors.New("artifact origin not configured")
}
func (a *Agent) stageRemote(offer RolloutOffer) error {
	if a.Config.ExecutorSocket != "" {
		return errors.New("privilege-separated collector requires separate administrator updater")
	}
	if a.Config.UpgradeInstallRoot == "" {
		return errors.New("remote upgrades disabled")
	}
	if err := trustedArtifact(a.Config, offer.ArtifactURL); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(offer.ManifestBytes)
	if err != nil || len(raw) > 64<<10 {
		return errors.New("invalid signed manifest")
	}
	key, err := base64.StdEncoding.DecodeString(a.Config.UpgradePublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("configured trust key required")
	}
	sig, err := base64.StdEncoding.DecodeString(offer.Signature)
	if err != nil || !ed25519.Verify(key, raw, sig) {
		return errors.New("invalid release signature")
	}
	var m UpgradeManifest
	if err = json.Unmarshal(raw, &m); err != nil || m.Size < 1 || m.Size > 64<<20 || !m.ExpiresAt.After(time.Now()) {
		return errors.New("invalid manifest bounds or expiry")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, offer.ArtifactURL, nil)
	if err != nil {
		return err
	}
	if offer.DownloadGrant != nil {
		artifact, _ := url.Parse(offer.ArtifactURL)
		platform, e := url.Parse(a.Config.Server)
		if e != nil || (platform.Scheme != "https" && !(a.Config.AllowHTTP && platform.Scheme == "http")) || artifact.Scheme != platform.Scheme || artifact.Host != platform.Host || artifact.Path != strings.TrimSuffix(platform.Path, "/")+"/api/agent/rollout/"+offer.ID+"/artifact" || artifact.RawQuery != "" {
			return errors.New("managed download grant requires its bound platform and route")
		}
		grant, e := json.Marshal(offer.DownloadGrant)
		if e != nil {
			return e
		}
		req.Header.Set("Authorization", "SelfGuardDownload "+base64.StdEncoding.EncodeToString(grant))
	}
	// Forward only a target-bound download grant to the exact platform route.
	// Never forward collector identity credentials or follow redirects.
	client := *a.Client
	client.Timeout = 2 * time.Minute
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil {
		return errors.New("artifact download failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return errors.New("artifact response rejected")
	}
	if res.ContentLength > m.Size {
		return errors.New("artifact too large")
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, m.Size+1))
	if err != nil || int64(len(b)) != m.Size {
		return errors.New("artifact size mismatch")
	}
	c := a.Config
	c.remoteUpgrade = true
	return stageUpgrade(c, SignedUpgrade{Manifest: raw, Signature: offer.Signature}, b, candidateHealth)
}
func (a *Agent) rolloutCycle() error {
	if a.Config.UpgradeInstallRoot == "" || a.Config.UpgradePublicKey == "" || len(a.Config.UpgradeOrigins) == 0 {
		return nil
	}
	receiptPath := filepath.Join(a.Config.StateDir, "rollout.json")
	var receipt rolloutReceipt
	if err := read(receiptPath, &receipt); err != nil {
		return err
	}
	if receipt.Offer.ID != "" {
		status := receipt.Status
		if status == "STAGED" {
			var m UpgradeManifest
			raw, _ := base64.StdEncoding.DecodeString(receipt.Offer.ManifestBytes)
			json.Unmarshal(raw, &m)
			// Only a process running the requested release can acknowledge activation.
			if receipt.StagedBy == processInstance || agentVersion != m.Version {
				stagedBody := map[string]any{"status": "STAGED", "version": m.Version}
				if receipt.ExecutorResult != nil {
					stagedBody["executorResult"] = receipt.ExecutorResult
				}
				if err := a.request("POST", "/agent/rollout/"+receipt.Offer.ID+"/result", a.Identity.Token, stagedBody, nil); err != nil {
					return err
				}
				return errUpgradeRestart
			}
			status = "RUNNING"
		}
		body := map[string]any{"status": status, "version": agentVersion}
		if a.Config.ExecutorSocket != "" && status == "RUNNING" {
			result := a.delegatedUpgrade(receipt.Offer)
			if !result.Success || result.Details["executorVersion"] != agentVersion || result.Details["executorProcess"] == result.Details["stageProcess"] {
				return errors.New("waiting for privileged executor release activation")
			}
			body["executorResult"] = result
		}
		if err := a.request("POST", "/agent/rollout/"+receipt.Offer.ID+"/result", a.Identity.Token, body, nil); err != nil {
			return err
		}
		if status == "RUNNING" {
			if a.Config.ExecutorSocket == "" {
				if err := writeUpgradeStatus(filepath.Join(a.Config.UpgradeInstallRoot, "upgrade-status.json"), map[string]any{"status": "ACTIVE", "version": agentVersion, "at": time.Now().UTC()}); err != nil {
					return err
				}
			}
			if _, err := os.Stat(filepath.Join(a.Config.StateDir, "rollout-restarting")); err == nil {
				if err := removeDurable(filepath.Join(a.Config.StateDir, "rollout-restarting")); err != nil {
					return err
				}
			}
		}
		if err := removeDurable(receiptPath); err != nil {
			return err
		}
	}
	var response struct {
		Item *RolloutOffer `json:"item"`
	}
	if err := a.request("GET", "/agent/rollout", a.Identity.Token, nil, &response); err != nil {
		return err
	}
	if response.Item == nil {
		return nil
	}
	// A durable intent prevents an interrupted installation from being silently retried.
	receipt = rolloutReceipt{Offer: *response.Item, Status: "FAILED"}
	if err := writePrivate(receiptPath, receipt); err != nil {
		return err
	}
	var executorResult *Result
	var stageErr error
	if a.Config.ExecutorSocket != "" {
		result := a.delegatedUpgrade(*response.Item)
		executorResult = &result
		if !result.Success {
			stageErr = errors.New(result.Evidence)
		}
	} else {
		stageErr = a.stageRemote(*response.Item)
	}
	if err := stageErr; err != nil {
		if reportErr := a.request("POST", "/agent/rollout/"+receipt.Offer.ID+"/result", a.Identity.Token, map[string]string{"status": "FAILED", "version": agentVersion}, nil); reportErr != nil {
			return reportErr
		}
		removeDurable(receiptPath)
		return err
	}
	receipt.Status = "STAGED"
	receipt.ExecutorResult = executorResult
	receipt.StagedBy = processInstance
	if err := writePrivate(receiptPath, receipt); err != nil {
		return err
	}
	body := map[string]any{"status": "STAGED", "version": agentVersion}
	if executorResult != nil {
		body["executorResult"] = executorResult
	}
	if err := a.request("POST", "/agent/rollout/"+receipt.Offer.ID+"/result", a.Identity.Token, body, nil); err != nil {
		return err
	}
	return errUpgradeRestart
}

// Retain operator recovery controls. Rollback uses a private backup, never remote bytes.
func (a *Agent) ensureRunningRelease() error {
	if a.Config.UpgradeInstallRoot == "" {
		return nil
	}
	var receipt rolloutReceipt
	if err := read(filepath.Join(a.Config.StateDir, "rollout.json"), &receipt); err != nil {
		return err
	}
	if receipt.Status != "STAGED" {
		return nil
	}
	var m UpgradeManifest
	raw, err := base64.StdEncoding.DecodeString(receipt.Offer.ManifestBytes)
	if err != nil || json.Unmarshal(raw, &m) != nil {
		return errors.New("invalid local rollout receipt")
	}
	if receipt.StagedBy == processInstance || agentVersion == m.Version {
		return nil
	}
	if a.Config.ExecutorSocket != "" {
		receipt.Status = "FAILED"
		if err := writePrivate(filepath.Join(a.Config.StateDir, "rollout.json"), receipt); err != nil {
			return err
		}
		return errUpgradeRestart
	}
	c := a.Config
	c.remoteUpgrade = true
	if err = rollbackUpgrade(c); err != nil {
		return err
	}
	receipt.Status = "FAILED"
	if err = writePrivate(filepath.Join(a.Config.StateDir, "rollout.json"), receipt); err != nil {
		return err
	}
	removeDurable(filepath.Join(a.Config.StateDir, "rollout-restarting"))
	return errUpgradeRestart
}
