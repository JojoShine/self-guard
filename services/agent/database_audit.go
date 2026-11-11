package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

type databaseObject struct {
	Database string   `json:"database"`
	Schema   string   `json:"schema,omitempty"`
	Table    string   `json:"table,omitempty"`
	Columns  []string `json:"columns,omitempty"`
}

func databaseEngine(value string) bool {
	return databaseIncludes([]string{"oracle", "mysql", "postgresql", "sqlserver", "dm", "kingbase", "mongodb", "redis", "vastbase"}, value)
}
func databaseIncludes(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func databaseAuditRows(rule PolicyRule, lines []string) ([]map[string]any, bool) {
	out := []map[string]any{}
	complete := true
	for _, line := range lines {
		if len(line) > 64<<10 {
			complete = false
			continue
		}
		var row struct {
			Objects           []databaseObject `json:"objects"`
			EventID           string           `json:"eventId"`
			Timestamp         string           `json:"timestamp"`
			Service           string           `json:"service"`
			Database          string           `json:"database"`
			Schema            string           `json:"schema"`
			Table             string           `json:"table"`
			Columns           []string         `json:"columns"`
			User              string           `json:"user"`
            UserKnown         *bool            `json:"userKnown"`
			SourceIP          string           `json:"sourceIp"`
			SourceHost        string           `json:"sourceHost"`
			PermissionGranted *bool            `json:"permissionGranted"`
			Operation         string           `json:"operation"`
			SessionID         string           `json:"sessionId"`
			Application       string           `json:"application"`
			Succeeded         *bool            `json:"succeeded"`
			TLS               *bool            `json:"tls"`
			Rows              *int64           `json:"rows"`
			Outcome           string           `json:"outcome"`
			Execution         map[string]any   `json:"execution"`
		}
		input := line
		native := !databaseIncludes([]string{"audit-json", "mysql", "postgresql"}, rule.Config.Service)
		if native {
			value, ok, ordinary := databaseNative(line, rule.Config.Service)
			if ordinary {
				continue
			}
			if !ok {
				complete = false
				continue
			}
			raw, err := json.Marshal(value)
			if err != nil {
				complete = false
				continue
			}
			input = string(raw)
		}
		if rule.Config.Service == "audit-json" || native {
			if json.Unmarshal([]byte(input), &row) != nil {
				complete = false
				continue
			}
		} else {
			observation, ok := databaseLog(line, rule.Config.Service)
			if !ok {
				continue
			}
			row.Timestamp = observation.At.Format(time.RFC3339Nano)
			row.Service = observation.Service
			row.Database = observation.Database
			row.User = observation.User
			row.SourceIP = observation.SourceIP
			row.Outcome = observation.Outcome
		}
		if row.Operation == "" && row.Outcome == "AUTH_FAILURE" {
			row.Operation = "LOGIN"
			v := false
			row.Succeeded = &v
		}
		if row.Operation == "" && row.Outcome == "CONNECTED" {
			row.Operation = "LOGIN"
			v := true
			row.Succeeded = &v
		}
		row.EventID = strings.TrimSpace(row.EventID)
		row.SourceHost = strings.TrimSpace(row.SourceHost)
		row.User = strings.TrimSpace(row.User)
		row.Database = strings.TrimSpace(row.Database)
		row.Schema = strings.TrimSpace(row.Schema)
		row.Table = strings.TrimSpace(row.Table)
		if !databaseIncludes([]string{"oracle", "mysql", "postgresql", "sqlserver", "dm", "kingbase", "redis", "vastbase"}, row.Service) || !databaseIncludes([]string{"LOGIN", "LOGOUT", "SELECT", "INSERT", "UPDATE", "DELETE", "DDL", "GRANT", "REVOKE", "EXPORT", "AUDIT_DISABLE", "OTHER"}, row.Operation) || databaseTime(row.Timestamp).IsZero() || row.User == "" || len(row.User) > 128 || len(row.Database) > 128 || len(row.Schema) > 128 || len(row.Table) > 128 || len(row.Columns) > 128 || len(row.EventID) > 200 || len(row.SessionID) > 128 || len(row.Application) > 128 || len(row.SourceHost) > 253 {
			complete = false
			continue
		}
		if len(rule.Config.Engines) > 0 && !databaseIncludes(rule.Config.Engines, row.Service) {
			continue
		}
		if row.SourceIP != "" && net.ParseIP(row.SourceIP) == nil {
			complete = false
			continue
		}
		if row.Rows != nil && (*row.Rows < 0 || *row.Rows > 9007199254740991) {
			complete = false
			continue
		}
		if len(row.Objects) > 32 {
			complete = false
			continue
		}
		objectValid := true
		for i := range row.Objects {
			o := &row.Objects[i]
			o.Database = strings.TrimSpace(o.Database)
			o.Schema = strings.TrimSpace(o.Schema)
			o.Table = strings.TrimSpace(o.Table)
			if o.Database == "" || len(o.Database) > 128 || len(o.Schema) > 128 || len(o.Table) > 128 || len(o.Columns) > 128 {
				objectValid = false
			}
			for j := range o.Columns {
				o.Columns[j] = strings.TrimSpace(o.Columns[j])
				if o.Columns[j] == "" || len(o.Columns[j]) > 128 {
					objectValid = false
				}
			}
		}
		if !objectValid {
			complete = false
			continue
		}
		valid := true
		for i, column := range row.Columns {
			column = strings.TrimSpace(column)
			row.Columns[i] = column
			if len(column) == 0 || len(column) > 128 {
				valid = false
			}
		}
		if !valid {
			complete = false
			continue
		}
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(line)))
		if row.EventID == "" {
			row.EventID = digest
		}
		value := map[string]any{"eventId": row.EventID, "instanceId": rule.Config.InstanceID, "timestamp": databaseTime(row.Timestamp).UTC().Format(time.RFC3339Nano), "service": row.Service, "operation": row.Operation, "user": row.User, "sourceSha256": digest, "sourcePath": rule.Config.Path, "columns": []string{}}
		for k, v := range map[string]string{"database": row.Database, "schema": row.Schema, "table": row.Table, "sourceIp": row.SourceIP, "sessionId": row.SessionID, "application": row.Application, "sourceHost": row.SourceHost} {
			if v != "" {
				value[k] = v
			}
		}
		if len(row.Columns) > 0 {
			value["columns"] = row.Columns
		}
		if len(row.Objects) > 0 {
			value["objects"] = row.Objects
		}
		if row.PermissionGranted != nil {
			value["permissionGranted"] = *row.PermissionGranted
		}
		if row.Succeeded != nil {
			value["succeeded"] = *row.Succeeded
		}
		if row.TLS != nil {
			value["tls"] = *row.TLS
		}
		if row.Rows != nil {
			value["rows"] = *row.Rows
		}
		if row.UserKnown!=nil {value["userKnown"]=*row.UserKnown}
        if databaseStatementFormat(rule.Config.Service) && row.Execution != nil {checked,ok:=checkedDatabaseExecution(row.Execution);if !ok {complete=false;continue};value["execution"] = checked}
		out = append(out, value)
	}
	return out, complete
}
