package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func databaseFormat(format string) bool {
 if databaseStatementFormat(format) {return true}
	return databaseIncludes([]string{"audit-json", "mysql", "postgresql", "postgresql-stderr", "postgresql-csv", "postgresql-csv-sql", "postgresql-audit-json", "mysql-audit-json", "oracle-traditional-json", "oracle-unified-json", "sqlserver-audit-json", "dm-audit-json"}, format)
}
func databaseCommand(command string) string {
	value := strings.ToUpper(strings.TrimSpace(command))
	if strings.HasPrefix(value, "CREATE ") || strings.HasPrefix(value, "ALTER ") || strings.HasPrefix(value, "DROP ") || strings.HasPrefix(value, "TRUNCATE ") {
		return "DDL"
	}
	switch value {
	case "NOAUDIT":
		return "AUDIT_DISABLE"
	case "SELECT", "READ":
		return "SELECT"
	case "INSERT", "UPDATE", "DELETE", "GRANT", "REVOKE":
		return value
	case "LOGON", "LOGIN", "CONNECT":
		return "LOGIN"
	case "CREATE TABLE", "ALTER TABLE", "DROP TABLE", "CREATE INDEX", "ALTER INDEX", "DROP INDEX", "TRUNCATE TABLE", "CREATE USER", "ALTER USER", "DROP USER", "CREATE ROLE", "ALTER ROLE", "DROP ROLE", "CREATE VIEW", "ALTER VIEW", "DROP VIEW", "CREATE FUNCTION", "ALTER FUNCTION", "DROP FUNCTION":
		return "DDL"
	}
	return "OTHER"
}
func databaseNative(line, format string) (map[string]any, bool, bool) {
 if databaseStatementFormat(format)&&format!="postgresql-csv-sql" {return databaseStatementNative(line,format)}
	value := map[string]any{}
	switch format {
	case "postgresql-stderr":
		return postgresStderr(line)
	case "postgresql-csv", "postgresql-csv-sql", "postgresql-audit-json":
		var at, user, database, host, session, number, state, message, application, tag string
		var csvFields []string
		if format == "postgresql-csv" || format == "postgresql-csv-sql" {
			csvLine:=line
			if format=="postgresql-csv-sql" {csvLine=postgresSQLCSV(line)}
			reader := csv.NewReader(strings.NewReader(csvLine))
			reader.FieldsPerRecord = -1
			fields, err := reader.Read()
			if err != nil || len(fields) < 23 {
				return nil, false, false
			}
			at, user, database, host, session, number, state, message, application = fields[0], fields[1], fields[2], fields[4], fields[5], fields[6], fields[12], fields[13], fields[22]
			tag = fields[7]
			csvFields = fields
		} else {
			var row struct {
				Timestamp   string          `json:"timestamp"`
				User        string          `json:"user"`
				Database    string          `json:"dbname"`
				Host        string          `json:"remote_host"`
				Session     string          `json:"session_id"`
				Number      json.RawMessage `json:"line_num"`
				State       string          `json:"state_code"`
				Message     string          `json:"message"`
				Application string          `json:"application_name"`
				CommandTag  string          `json:"command_tag"`
			}
			if json.Unmarshal([]byte(line), &row) != nil {
				return nil, false, false
			}
			at, user, database, host, session, number, state, message, application = row.Timestamp, row.User, row.Database, row.Host, row.Session, string(row.Number), row.State, row.Message, row.Application
			tag = row.CommandTag
		}
		if databaseTime(at).IsZero() {
			return nil, false, false
		}
		value = map[string]any{"timestamp": databaseTime(at).UTC().Format(time.RFC3339Nano), "service": "postgresql", "user": user, "database": database, "sessionId": session, "application": application}
		if session != "" && number != "" {
			value["eventId"] = session + ":" + number
		}
		if address, _, err := net.SplitHostPort(host); err == nil {
			host = address
		}
		if net.ParseIP(host) != nil {
			value["sourceIp"] = host
		} else if host != "" {
			value["sourceHost"] = host
		}
		if postgresConnection(value, message, state, tag) {
			return value, true, false
		}
		if format == "postgresql-csv-sql" { return postgresSQL(value,csvFields) }
		if strings.HasPrefix(message, "disconnection: session time: ") { return nil, false, false }
		if !strings.HasPrefix(message, "AUDIT: ") {
			return nil, true, true
		}
		reader := csv.NewReader(strings.NewReader(strings.TrimPrefix(message, "AUDIT: ")))
		reader.FieldsPerRecord = -1
		fields, err := reader.Read()
		if err != nil || len(fields) < 7 {
			return nil, false, false
		}
		operation := databaseCommand(fields[4])
		if operation == "" {
			return nil, false, false
		}
		value["operation"] = operation
		if fields[6] != "" && databaseIncludes([]string{"TABLE", "VIEW", "MATERIALIZED VIEW", "FOREIGN TABLE"}, fields[5]) {
			parts := strings.Split(fields[6], ".")
			if len(parts) == 2 && !strings.ContainsAny(fields[6], "\" ") {
				value["schema"] = parts[0]
				value["table"] = parts[1]
			}
		}
		// pgAudit logs attempts; a log entry alone does not prove statement success.
		return value, true, false
	case "oracle-traditional-json", "oracle-unified-json":
		var row struct {
			EventID           string `json:"EVENT_ID"`
			UserHost          string `json:"USERHOST"`
			SessionID         string `json:"SESSION_ID"`
			At                string `json:"EVENT_TIMESTAMP"`
			TraditionalAt     string `json:"TIMESTAMP"`
			User              string `json:"DBUSERNAME"`
			TraditionalUser   string `json:"USERNAME"`
			Database          string `json:"DBNAME"`
			Action            string `json:"ACTION_NAME"`
			Return            *int   `json:"RETURN_CODE"`
			TraditionalReturn *int   `json:"RETURNCODE"`
			Schema            string `json:"OBJECT_SCHEMA"`
			Owner             string `json:"OWNER"`
			Table             string `json:"OBJECT_NAME"`
			Object            string `json:"OBJ_NAME"`
			Source            string `json:"CLIENT_IP"`
		}
		if json.Unmarshal([]byte(line), &row) != nil {
			return nil, false, false
		}
		if format == "oracle-traditional-json" {
			row.At = row.TraditionalAt
			row.User = row.TraditionalUser
			row.Return = row.TraditionalReturn
			row.Schema = row.Owner
			row.Table = row.Object
		}
		operation := databaseCommand(row.Action)
		if operation == "" || databaseTime(row.At).IsZero() {
			return nil, false, false
		}
		value = map[string]any{"timestamp": row.At, "service": "oracle", "user": row.User, "operation": operation}
		if row.EventID != "" {
			value["eventId"] = row.EventID
		}
		if row.SessionID != "" {
			value["sessionId"] = row.SessionID
		}
		if row.Source == "" {
			row.Source = row.UserHost
		}
		if row.Source != "" && net.ParseIP(row.Source) == nil {
			value["sourceHost"] = row.Source
			row.Source = ""
		}
		for key, v := range map[string]string{"database": row.Database, "schema": row.Schema, "table": row.Table, "sourceIp": row.Source} {
			if v != "" {
				value[key] = v
			}
		}
		if row.Return != nil {
			if *row.Return == 1031 {
				value["permissionGranted"] = false
			}
			value["succeeded"] = *row.Return == 0
		}
		return value, true, false
	case "mysql-audit-json":
		var row struct {
			At         string          `json:"timestamp"`
			ID         json.RawMessage `json:"id"`
			Class      string          `json:"class"`
			Event      string          `json:"event"`
			Connection json.RawMessage `json:"connection_id"`
			Account    struct {
				User string `json:"user"`
			} `json:"account"`
			Login struct {
				IP string `json:"ip"`
			} `json:"login"`
			General struct {
				Command string `json:"sql_command"`
				Status  *int   `json:"status"`
			} `json:"general_data"`
			Table struct {
				Database string `json:"db"`
				Name     string `json:"table"`
				Command  string `json:"sql_command"`
			} `json:"table_access_data"`
			Connect struct {
				Database string `json:"db"`
				Status   *int   `json:"status"`
				Type     string `json:"connection_type"`
			} `json:"connection_data"`
		}
		if json.Unmarshal([]byte(line), &row) != nil {
			return nil, false, false
		}
		at, err := time.ParseInLocation("2006-01-02 15:04:05", row.At, time.UTC)
		if err != nil {
			at = databaseTime(row.At)
		}
		if at.IsZero() {
			return nil, false, false
		}
		value = map[string]any{"timestamp": at.UTC().Format(time.RFC3339Nano), "service": "mysql", "user": row.Account.User}
		if len(row.ID) > 0 {
			value["eventId"] = row.At + ":" + string(row.ID)
		}
		if len(row.Connection) > 0 {
			value["sessionId"] = string(row.Connection)
		}
		if row.Login.IP != "" {
			value["sourceIp"] = row.Login.IP
		}
		switch row.Class {
		case "connection":
			if row.Event != "connect" && row.Event != "change_user" {
				return nil, true, true
			}
			value["operation"] = "LOGIN"
			if row.Connect.Database != "" {
				value["database"] = row.Connect.Database
			}
			if row.Connect.Status != nil {
				value["succeeded"] = *row.Connect.Status == 0
			}
			if row.Connect.Type == "ssl" {
				value["tls"] = true
			} else if row.Connect.Type == "tcp/ip" {
				value["tls"] = false
			}
		case "general":
			value["operation"] = databaseCommand(row.General.Command)
			if row.General.Status != nil {
				value["succeeded"] = *row.General.Status == 0
			}
		case "table_access":
			value["operation"] = databaseCommand(row.Table.Command)
			value["database"] = row.Table.Database
			value["table"] = row.Table.Name
		default:
			return nil, true, true
		}
		if value["operation"] == "" {
			return nil, false, false
		}
		return value, true, false
	case "dm-audit-json":
		var row struct {
			ID       string `json:"EVENT_ID"`
			At       string `json:"EVENT_TIMESTAMP"`
			User     string `json:"USERNAME"`
			Database string `json:"DBNAME"`
			Schema   string `json:"SCHNAME"`
			Object   string `json:"OBJNAME"`
			Action   string `json:"OPERATION"`
			Success  string `json:"SUCC_FLAG"`
			IP       string `json:"IP"`
		}
		if json.Unmarshal([]byte(line), &row) != nil || row.ID == "" || databaseTime(row.At).IsZero() {
			return nil, false, false
		}
		value = map[string]any{"eventId": row.ID, "timestamp": row.At, "service": "dm", "user": row.User, "operation": databaseCommand(row.Action)}
		for key, v := range map[string]string{"database": row.Database, "schema": row.Schema, "table": row.Object} {
			if v != "" {
				value[key] = v
			}
		}
		if row.IP != "" {
			if net.ParseIP(row.IP) != nil {
				value["sourceIp"] = row.IP
			} else {
				value["sourceHost"] = row.IP
			}
		}
		if row.Success == "Y" {
			value["succeeded"] = true
		} else if row.Success == "N" {
			value["succeeded"] = false
		}
		return value, true, false
	case "sqlserver-audit-json":
		var row struct {
			At        string          `json:"event_time"`
			Action    string          `json:"action_id"`
			User      string          `json:"server_principal_name"`
			Database  string          `json:"database_name"`
			Schema    string          `json:"schema_name"`
			Object    string          `json:"object_name"`
			IP        string          `json:"client_ip"`
			Session   json.RawMessage `json:"session_id"`
			Succeeded *bool           `json:"succeeded"`
			Sequence  json.RawMessage `json:"sequence_number"`
			Group     string          `json:"sequence_group_id"`
		}
		if json.Unmarshal([]byte(line), &row) != nil {
			return nil, false, false
		}
		operation := map[string]string{"SL": "SELECT", "IN": "INSERT", "UP": "UPDATE", "DL": "DELETE", "CR": "DDL", "AL": "DDL", "DR": "DDL", "G": "GRANT", "R": "REVOKE", "LGIS": "LOGIN", "LGIF": "LOGIN"}[strings.TrimSpace(row.Action)]
		if operation == "" {
			operation = "OTHER"
		}
		if operation == "" || databaseTime(row.At).IsZero() {
			return nil, false, false
		}
		value = map[string]any{"timestamp": row.At, "service": "sqlserver", "user": row.User, "operation": operation}
		for key, v := range map[string]string{"database": row.Database, "schema": row.Schema, "table": row.Object, "sourceIp": row.IP} {
			if v != "" {
				value[key] = v
			}
		}
		if len(row.Session) > 0 {
			value["sessionId"] = string(row.Session)
		}
		if row.Group != "" {
			value["eventId"] = row.Group + ":" + string(row.Sequence)
		}
		if row.Succeeded != nil && operation != "LOGIN" {
			value["permissionGranted"] = *row.Succeeded
		}
		if row.IP != "" && net.ParseIP(row.IP) == nil {
			delete(value, "sourceIp")
			value["sourceHost"] = row.IP
		}
		if operation == "LOGIN" {
			value["succeeded"] = strings.TrimSpace(row.Action) == "LGIS"
		}
		return value, true, false
	}
	return nil, false, false
}

func databaseFixture(input string) (string, error) {
	var request struct {
		Format     string   `json:"format"`
		InstanceID string   `json:"instanceId"`
		Lines      []string `json:"lines"`
		Raw        string   `json:"raw"`
	}
	if err := json.Unmarshal([]byte(input), &request); err != nil {
		return "", err
	}
	if len(request.Lines) > 1000 {
		return "", fmt.Errorf("too many fixture rows")
	}
	frameComplete := true
	if request.Raw != "" {
		body := request.Raw
		for {
			record, rest, ok := databaseRecord(body, request.Format)
			if !ok {
				if strings.TrimSpace(strings.Trim(rest, "[], \r\n\t")) != "" {
					frameComplete = false
				}
				break
			}
			request.Lines = append(request.Lines, record)
			body = rest
			if len(request.Lines) > 1000 {
				return "", fmt.Errorf("too many fixture rows")
			}
		}
	}
	rows, complete := databaseAuditRows(PolicyRule{Config: PolicyConfig{Path: "/authorized/fixture", Service: request.Format, InstanceID: request.InstanceID}}, request.Lines)
	raw, err := json.Marshal(map[string]any{"events": rows, "complete": complete && frameComplete, "count": strconv.Itoa(len(rows))})
	return string(raw), err
}
