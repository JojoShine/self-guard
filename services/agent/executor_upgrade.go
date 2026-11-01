package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"

	"path/filepath"
	"time"
)

type upgradeCommand struct {
	ArtifactURL   string             `json:"artifactUrl"`
	ManifestBytes string             `json:"manifestBytes"`
	Signature     string             `json:"signature"`
	DownloadGrant *TaskAuthorization `json:"downloadGrant,omitempty"`
}

func (a *Agent) delegatedUpgrade(offer RolloutOffer) Result {
	if offer.Authorization == nil {
		return Result{Evidence: "signed privileged upgrade authorization required"}
	}
	raw, err := base64.StdEncoding.DecodeString(offer.Authorization.Payload)
	var command executorPayload
	if err != nil || json.Unmarshal(raw, &command) != nil || command.ID != offer.ID || command.AssetID != a.Identity.AssetID || command.Template != "UPGRADE" || !command.ExpiresAt.After(time.Now()) {
		return Result{Evidence: "upgrade authorization binding invalid"}
	}
	var params upgradeCommand
	if decodeExecutorParameters(command.Parameters, &params) != nil || !reflect.DeepEqual(params, upgradeCommand{offer.ArtifactURL, offer.ManifestBytes, offer.Signature, offer.DownloadGrant}) {
		return Result{Evidence: "upgrade parameters differ from signed authorization"}
	}
	return a.executorRequest(offer.Authorization, 3*time.Minute)
}
func (e *privilegedExecutor) stageExecutorUpgrade(payload executorPayload) Result {
	c := e.agent.Config
	if c.UpgradeInstallRoot == "" || !filepath.IsAbs(c.UpgradeInstallRoot) {
		return Result{Evidence: "root upgrade installation disabled"}
	}
	if err := executorTrustedDirectory(c.UpgradeInstallRoot, false); err != nil {
		return Result{Evidence: "upgrade root must be root-owned and protected"}
	}
	var command upgradeCommand
	if decodeExecutorParameters(payload.Parameters, &command) != nil {
		return Result{Evidence: "invalid signed upgrade parameters"}
	}
	offer := RolloutOffer{ID: payload.ID, ArtifactURL: command.ArtifactURL, ManifestBytes: command.ManifestBytes, Signature: command.Signature, DownloadGrant: command.DownloadGrant}
	e.agent.Config.upgradePublicExecutable = true
	defer func() { e.agent.Config.upgradePublicExecutable = false }()
	if err := e.agent.stageRemote(offer); err != nil {
		return Result{Evidence: err.Error()}
	}
	var manifest UpgradeManifest
	raw, _ := base64.StdEncoding.DecodeString(command.ManifestBytes)
	if json.Unmarshal(raw, &manifest) != nil {
		return Result{Evidence: "staged manifest unreadable", Details: map[string]string{"resultUnknown": "true"}}
	}
	return Result{Success: true, Evidence: "root executor verified and staged signed upgrade", Details: map[string]string{"upgradeStaged": "true", "upgradeVersion": manifest.Version, "stageProcess": processInstance}}
}
func (e *privilegedExecutor) recoverExecutorVersion() error {
	for id, receipt := range e.receipts {
		if receipt.Template == "UPGRADE" && receipt.Result.Details["resultUnknown"] == "true" {
			return errors.New("executor upgrade outcome unknown; operator reconciliation required")
		}
		if receipt.Result.Success && receipt.Result.Details["upgradeStaged"] == "true" && receipt.Result.Details["stageProcess"] != processInstance && receipt.Result.Details["upgradeVersion"] != agentVersion {
			// Only the highest staged installation is relevant after several historical upgrades.
			var installed UpgradeManifest
			if err := read(filepath.Join(e.agent.Config.UpgradeInstallRoot, "installed.json"), &installed); err != nil {
				return err
			}
			if installed.Version != receipt.Result.Details["upgradeVersion"] {
				continue
			}
			c := e.agent.Config
			c.remoteUpgrade = true
			if err := rollbackUpgrade(c); err != nil {
				return err
			}
			receipt.Result = Result{Evidence: "new executor version did not match staged release", Details: map[string]string{"upgradeStaged": "false"}}
			e.receipts[id] = receipt
			if err := writePrivate(filepath.Join(c.StateDir, "executor-receipts.json"), e.receipts); err != nil {
				return err
			}
			return errUpgradeRestart
		}
	}
	return nil
}
