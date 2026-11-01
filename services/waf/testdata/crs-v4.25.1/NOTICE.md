# Frozen upstream samples

Source: OWASP Core Rule Set v4.25.1, rules 941100 and 942100.

- https://github.com/coreruleset/coreruleset/blob/v4.25.1/tests/regression/tests/REQUEST-941-APPLICATION-ATTACK-XSS/941100.yaml
- https://github.com/coreruleset/coreruleset/blob/v4.25.1/tests/regression/tests/REQUEST-942-APPLICATION-ATTACK-SQLI/942100.yaml

The upstream LICENSE is retained. JSON files are lossless YAML-to-JSON
transcriptions used only as test data. Original author attribution remains in
both formats. The tests exercise the core operators and the request selectors;
they do not by themselves establish complete CRS policy compatibility.

Self Guard implements its own bounded SQL token and HTML attribute inspection.
No ModSecurity, Coraza, libinjection, or other detection engine is linked or
invoked. The compatibility gate remains closed until the complete selected
profile, reference corpus, normal traffic, rollout and capacity checks pass.
