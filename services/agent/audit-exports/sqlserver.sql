-- Configure a locally authorized audit file pattern before execution.
-- SQL Server 2022 needs VIEW SERVER SECURITY AUDIT to read server audit files.
-- Emit one JSON object per row: top-level FOR JSON may split one array into
-- several result rows, which a command-line client can otherwise corrupt.
SET NOCOUNT ON;
DECLARE @audit_files nvarchar(260) = N'C:\SelfGuardAudit\*.sqlaudit';
SELECT (SELECT CONVERT(varchar(33),event_time,126)+'Z' AS event_time,
 action_id,server_principal_name,database_name,schema_name,object_name,
 client_ip,session_id,succeeded,sequence_number,
 CONVERT(varchar(130),sequence_group_id,2) AS sequence_group_id
 FOR JSON PATH,WITHOUT_ARRAY_WRAPPER)
FROM sys.fn_get_audit_file(@audit_files,DEFAULT,DEFAULT)
ORDER BY event_time,sequence_number;
-- Event identity is sequence_group_id + sequence_number. File offsets alone
-- identify a block and may be shared by different audit events.
-- Statements and parameters are not exported.
-- Non-login succeeded represents permission-check outcome, not execution success.
