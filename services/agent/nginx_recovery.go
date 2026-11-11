package main

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

// The immutable plan is persisted before bootstrap/container/config side effects.
// Recovery must not depend on the final success/failure report being written.
func rollbackBoundNginxState(state string, p HostWafPlan, run func(...string) error) (map[string]any, error) {
	if err := executorTrustedDirectory(state, true); err != nil {
		return nil, err
	}
	planPath := filepath.Join(state, "plan.json")
	if err := executorTrustedConfig(planPath); err != nil {
		return nil, err
	}
	raw, err := readBoundedFile(planPath, 16<<10)
	if err != nil {
		return nil, err
	}
	var saved HostWafPlan
	if err = decodeExecutorParameters(raw, &saved); err != nil {
		return nil, err
	}
	if saved != p {
		return nil, errors.New("rollback plan differs from immutable installed binding")
	}
	transaction := filepath.Join(state, "nginx")
	journal := filepath.Join(transaction, "journal.json")
	if _, err = os.Lstat(journal); err == nil {
		if err = executorTrustedDirectory(transaction, true); err != nil {
			return nil, err
		}
		if err = executorTrustedConfig(journal); err != nil {
			return nil, err
		}
		var tx nginxTransaction
		if err = read(journal, &tx); err != nil {
			return nil, err
		}
		if tx.Path != p.NginxConfig || p.ExpectedPlannedConfigSHA256 != "" && tx.AfterSHA256 != p.ExpectedPlannedConfigSHA256 {
			return nil, errors.New("nginx transaction differs from bound plan")
		}
		if err = rollbackNginxTransaction(transaction, run); err != nil {
			return nil, err
		}
	} else if os.IsNotExist(err) {
		// Bootstrap may fail before any transaction exists. Only acknowledge a no-op
		// when the original reviewed path is still unchanged; never remove a new file.
		if p.BusinessMode == "NEW" {
			if _, e := os.Lstat(p.NginxConfig); !os.IsNotExist(e) {
				return nil, errors.New("new nginx path changed without a recovery journal")
			}
		} else {
			if err = executorTrustedConfig(p.NginxConfig); err != nil {
				return nil, err
			}
			body, e := readBoundedFile(p.NginxConfig, 256<<10)
			if e != nil {
				return nil, e
			}
			if p.ExpectedConfigSHA256 == "" || contentDigest(body) != p.ExpectedConfigSHA256 {
				return nil, errors.New("nginx source changed without a recovery journal")
			}
		}
	} else {
		return nil, err
	}
	report := map[string]any{"schema": p.Schema, "siteId": p.SiteID, "mode": p.Mode, "status": "ROLLED_BACK", "updatedAt": time.Now().UTC().Format(time.RFC3339Nano), "transactionDir": transaction, "message": "Original nginx configuration restored or unchanged before transaction; recovery verified"}
	if err = writePrivate(filepath.Join(state, "report.json"), report); err != nil {
		return nil, err
	}
	return report, nil
}
