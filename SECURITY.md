# Security

DoxShield is a hackathon prototype. Do not use it as a production security boundary or a legal compliance assessment.

Never post credentials, OTPs, scan reports, browser databases or personal device information in public issues. Report suspected vulnerabilities privately to the repository owner through a verified private channel; use GitHub private vulnerability reporting if the owner enables it.

If a credential is exposed, revoke/rotate it with its provider, inspect provider activity and delivery logs, update local deployment configuration, and then remove it from every published reachable ref. Deleting a file or rewriting history does not revoke a key or erase clones/caches. Avoid publishing backup refs or archives containing the old history.

See SECURITY_REMEDIATION.md for the November 2026 local audit, configuration behavior changes and unresolved risks. Enable GitHub secret scanning, push protection, dependency alerts and private vulnerability reporting where available. These settings have not been changed by this cleanup.
