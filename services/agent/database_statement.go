package main

import (
	"encoding/json"
	"math"
	"regexp"
)

func databaseStatementFormat(format string) bool {
	return databaseIncludes([]string{"postgresql-csv-sql", "audit-sql-json", "mysql-audit-sql-json", "oracle-traditional-sql-json", "oracle-unified-sql-json", "dm-audit-sql-json", "kingbase-audit-sql-json", "vastbase-audit-sql-json", "redis-command-json"}, format)
}

func checkedDatabaseExecution(raw any) (map[string]any, bool) {
	value, ok := raw.(map[string]any)
	if !ok {
		return nil, false
	}
	for key := range value {
		if !databaseIncludes([]string{"sql", "protocol", "sqlState", "durationMs", "portalLabelIncluded"}, key) {
			return nil, false
		}
	}
	protocol, ok := value["protocol"].(string)
	if !ok || !databaseIncludes([]string{"SIMPLE", "EXTENDED", "ERROR", "AUDIT", "COMMAND"}, protocol) {
		return nil, false
	}
	if text, exists := value["sql"]; exists {
		sql, valid := text.(string)
		if !valid || len(sql) == 0 || len(sql) > 32768 {
			return nil, false
		}
	}
	if state, exists := value["sqlState"]; exists {
		s, valid := state.(string)
		if !valid || !regexp.MustCompile(`^[0-9A-Z]{5}$`).MatchString(s) {
			return nil, false
		}
	} else if databaseIncludes([]string{"SIMPLE", "EXTENDED", "ERROR"}, protocol) {
		return nil, false
	}
	if duration, exists := value["durationMs"]; exists {
		n, valid := duration.(float64)
		if !valid || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 31536000000 {
			return nil, false
		}
	}
	if label, exists := value["portalLabelIncluded"]; exists {
		if _, valid := label.(bool); !valid {
			return nil, false
		}
	}
	return value, true
}

// Existing sources remain metadata-only; raw statements require a distinct source selection.
func databaseStatementNative(line, format string) (map[string]any, bool, bool) {
	if databaseIncludes([]string{"audit-sql-json", "kingbase-audit-sql-json", "vastbase-audit-sql-json", "redis-command-json"}, format) {
		var value map[string]any
		if json.Unmarshal([]byte(line), &value) != nil {
			return nil, false, false
		}
		expected := map[string]string{"kingbase-audit-sql-json": "kingbase", "vastbase-audit-sql-json": "vastbase", "redis-command-json": "redis"}[format]
		if expected != "" && value["service"] != expected {
			return nil, false, false
		}
		if execution, exists := value["execution"]; exists {
			checked, ok := checkedDatabaseExecution(execution)
			if !ok {
				return nil, false, false
			}
			value["execution"] = checked
		}
		return value, true, false
	}
	base := map[string]string{"mysql-audit-sql-json": "mysql-audit-json", "oracle-traditional-sql-json": "oracle-traditional-json", "oracle-unified-sql-json": "oracle-unified-json", "dm-audit-sql-json": "dm-audit-json"}[format]
	if base == "" {
		return nil, false, false
	}
	value, ok, ordinary := databaseNative(line, base)
	if !ok || ordinary {
		return value, ok, ordinary
	}
	if value["operation"] == "LOGIN" || value["operation"] == "LOGOUT" {
		return value, true, false
	}
	var raw map[string]any
	if json.Unmarshal([]byte(line), &raw) != nil {
		return nil, false, false
	}
	var sql string
	if base == "mysql-audit-json" {
		if general, valid := raw["general_data"].(map[string]any); valid {
			sql, _ = general["query"].(string)
		}
	} else {
		sql, _ = raw["SQL_TEXT"].(string)
	}
	if sql == "" {
		return value, true, false
	}
	execution, valid := checkedDatabaseExecution(map[string]any{"sql": sql, "protocol": "AUDIT"})
	if !valid {
		return nil, false, false
	}
	value["execution"] = execution
	return value, true, false
}
