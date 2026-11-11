-- Explicit protected SQL_TEXT export. Write to a private temporary file; append only after successful exit.
SET SERVEROUTPUT ON SIZE UNLIMITED
SET ECHO OFF VERIFY OFF
WHENEVER SQLERROR EXIT SQL.SQLCODE
SET FEEDBACK OFF HEADING OFF PAGESIZE 0 LINESIZE 32767 TRIMSPOOL ON
ALTER SESSION SET TIME_ZONE='+00:00';
DECLARE
  n PLS_INTEGER:=0;
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
  FOR r IN (SELECT sql_text,extended_timestamp,username,action_name,returncode,owner,obj_name,userhost,sessionid,entryid,statementid,dbid,instance_number FROM dba_audit_trail WHERE extended_timestamp>=SYSTIMESTAMP-INTERVAL '15' MINUTE ORDER BY extended_timestamp,sessionid,entryid) LOOP
    n:=n+1;
    IF n>5000 THEN DBMS_OUTPUT.PUT_LINE('{"coverageIncomplete":true,"reason":"export_limit_5000"}'); EXIT; END IF;
    DBMS_OUTPUT.PUT_LINE('{"TIMESTAMP":'||q(TO_CHAR(r.extended_timestamp AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.FF6"Z"'))||
      ',"DBNAME":'||q(SYS_CONTEXT('USERENV','DB_NAME'))||
      ',"EVENT_ID":'||q(r.dbid||':'||r.instance_number||':'||r.sessionid||':'||r.entryid||':'||r.statementid)||
      ',"SESSION_ID":'||q(TO_CHAR(r.sessionid))||',"USERNAME":'||q(r.username)||',"ACTION_NAME":'||q(r.action_name)||',"RETURNCODE":'||NVL(TO_CHAR(r.returncode),'null')||
      ',"SQL_TEXT":'||q(r.sql_text)||',"OWNER":'||q(r.owner)||',"OBJ_NAME":'||q(r.obj_name)||',"USERHOST":'||q(r.userhost)||'}');
  END LOOP;
END;
/
