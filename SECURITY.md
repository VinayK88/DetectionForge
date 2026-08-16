# Security and responsible use

DetectionForge is a defensive detection-engineering lab. Checked-in telemetry is synthetic and uses reserved/example values. The project does not execute malware, exploit systems, collect credentials, or automatically deploy rules into a production SIEM.

Before adapting it to real environments:

- use only authorized telemetry;
- review privacy and retention requirements;
- validate every query against the target schema;
- require human review before production rule deployment;
- test false-positive impact against representative benign traffic;
- preserve rollback and version history.
