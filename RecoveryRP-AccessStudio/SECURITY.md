# Security design and known boundaries

This is a development preview with **known unverified Windows runtime behavior**. The agent is assumed to be reachable only on an isolated VPN. VPN membership does not grant application permissions.

1. Deny by default. The agent requires bearer sessions for privileged operations, authenticates every request and authorizes by server-owned role.
2. Account identity is a Windows SID persisted with a managed identity record. An existing local account is never automatically adopted. Stale SID records fail closed.
3. Workspaces are created only below a fixed controlled root. An unregistered folder, symlink, junction, reparse point or unexpected volume is rejected.
4. Account passwords are derived using PBKDF2-HMAC-SHA256 at 600,000 iterations with distinct salts; password hashes cannot be decrypted.
5. TOTP secrets are encrypted using Windows DPAPI LocalMachine scope and stored under a private ProgramData directory ACL. A local Administrator/SYSTEM compromise can defeat this boundary.
6. Sessions use 32 random bytes, never stored or logged in plaintext server side; the stored hash is SHA-256. Session creation and credential rotation are serialized, and rotation revokes all sessions.
7. No arbitrary shell or PowerShell commands from the client; Windows PowerShell scripts are fixed, JSON is received through stdin, and the agent authorizes operation and arguments before invoking scripts.
8. Server credentials and TLS certificate private keys must be protected; backups and recovery need manual approval.
9. NVIDIA AI runs in the **desktop client only**, uses per-user Windows DPAPI for API key storage, never receives administrator password, TOTP, token, or server configuration.
10. Fail closed on unrecognized accounts, expired sessions, failed cert checks, unsupported request variants or unsupported filesystem locations.
11. NTFS Modify permits deletion. "None" only removes Access Studio's explicit grant and does NOT guarantee denial if other group/inherited permissions grant access. The UI must disclose this.
12. Logging avoids credentials and tokens. Audit logs in this preview are local and not tamper-evident; production needs protected central/event log.
13. Production releases MUST be Authenticode signed; development builds should never be deployed as trusted production artifacts. A signature check inside a hostile client is defense in depth, not an authorization boundary.

Audit gates: run scripts `--init`, `--serve`, login, MFA, password rotation, SID mismatch, deny existing users, ACL inheritance, junction traversal, reparse and file-lock races on disposable Windows Server VMs.
