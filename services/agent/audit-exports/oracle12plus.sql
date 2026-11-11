SET SERVEROUTPUT ON SIZE UNLIMITED
SET ECHO OFF VERIFY OFF
WHENEVER SQLERROR EXIT SQL.SQLCODE
SET FEEDBACK OFF HEADING OFF PAGESIZE 0 LINESIZE 32767 TRIMSPOOL ON
ALTER SESSION SET TIME_ZONE='+00:00';
DECLARE
  n PLS_INTEGER:=0;
  source_timezone VARCHAR2(64):='UTC'; -- Set to the actual audit timestamp source time zone.
  timezone_confirmed BOOLEAN:=FALSE; -- Set TRUE only after verifying the source time zone.
  FUNCTION q(v VARCHAR2) RETURN VARCHAR2 IS
    result VARCHAR2(32767) := '"'; c VARCHAR2(4);
  BEGIN
    IF v IS NULL THEN RETURN 'null'; END IF;
    FOR i IN 1..LENGTH(v) LOOP
      c := SUBSTR(v,i,1);
      IF c='"' THEN result:=result||'\"';
      ELSIF c='\' THEN result:=result||'\\';
      ELSIF ASCII(c)<32 THEN result:=result||'\u00'||RAWTOHEX(UTL_RAW.CAST_TO_RAW(c));
      ELSE result:=result||c; END IF;
    END LOOP;
    RETURN result||'"';
  END;
BEGIN
  IF NOT timezone_confirmed THEN RAISE_APPLICATION_ERROR(-20001,'Verify source_timezone before exporting audit timestamps'); END IF;
  -- Connect to each intended PDB separately; this is not a CDB-wide view export.
  FOR r IN (SELECT event_timestamp,dbusername,action_name,return_code,object_schema,object_name,userhost,sessionid,entry_id,statement_id,dbid,instance_id FROM unified_audit_trail WHERE FROM_TZ(CAST(event_timestamp AS TIMESTAMP),source_timezone)>=SYSTIMESTAMP-INTERVAL '15' MINUTE ORDER BY event_timestamp,sessionid,entry_id) LOOP
    n:=n+1;
    IF n>5000 THEN DBMS_OUTPUT.PUT_LINE('{"coverageIncomplete":true,"reason":"export_limit_5000"}'); EXIT; END IF;
    DBMS_OUTPUT.PUT_LINE('{"EVENT_TIMESTAMP":'||q(TO_CHAR(FROM_TZ(CAST(r.event_timestamp AS TIMESTAMP),source_timezone) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.FF6"Z"'))||
      ',"DBNAME":'||q(SYS_CONTEXT('USERENV','DB_NAME')||':'||SYS_CONTEXT('USERENV','CON_NAME'))||
      ',"EVENT_ID":'||q(r.dbid||':'||r.instance_id||':'||SYS_CONTEXT('USERENV','CON_NAME')||':'||r.sessionid||':'||r.entry_id||':'||r.statement_id)||
      ',"SESSION_ID":'||q(TO_CHAR(r.sessionid))||',"DBUSERNAME":'||q(r.dbusername)||',"ACTION_NAME":'||q(r.action_name)||',"RETURN_CODE":'||NVL(TO_CHAR(r.return_code),'null')||
      ',"OBJECT_SCHEMA":'||q(r.object_schema)||',"OBJECT_NAME":'||q(r.object_name)||',"USERHOST":'||q(r.userhost)||'}');
  END LOOP;
END;
/
