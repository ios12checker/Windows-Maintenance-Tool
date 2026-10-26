# Recovery RP Access Studio v7 — Development Branch

Standalone Windows desktop UI + private Windows Server agent. Built for simple local developer account and project permission management. No browser UI, public admin panel, or mandatory Microsoft 365 subscription.

**Status: SECURITY DEVELOPMENT PREVIEW — NOT PRODUCTION APPROVED.** This branch is intentionally isolated from the existing Windows Maintenance Tool main branch. The complete v6.2 source archive has not been automatically merged; this is a clean design targeting the lessons from the v6.2 audit. Windows builds and end-to-end tests have not been executed in this environment.

## Projects
- `src/AccessStudio.Contracts`: shared request and response DTOs.
- `src/AccessStudio.Agent`: Windows Server private HTTPS API, account registration, session handling, ACL operations.
- `src/AccessStudio.Client`: native WPF client with EasyEntra-like user-first workflow, server certificate pinning and optional NVIDIA assistant.
- `tests/AccessStudio.SecurityTests`: dependency-free security regression test harness.

## Prerequisites
- Windows Server 2022 or 2025 test VM (domain controller not supported by this local-accounts implementation).
- Windows 11 for the client.
- .NET 10 SDK for builds. Client and server publish as self-contained single-file executables.
- NetBird installed separately on both machines. Bind the agent to a **private NetBird IPv4** and firewall it to your administrator device.
- Server TLS certificate installed in LocalMachine/My with private key accessible to the service principal.
- Administrator elevation for setup of local Windows accounts and NTFS workspaces.

## First-time setup
1. Build: `dotnet publish src/AccessStudio.Agent -c Release -r win-x64 -p:PublishSingleFile=true --self-contained true`
2. Build: `dotnet publish src/AccessStudio.Client -c Release -r win-x64 -p:PublishSingleFile=true --self-contained true`
3. On the isolated test VPS, use an elevated terminal: `AccessStudio.Agent.exe --init`. Record the displayed TOTP enrollment secret securely and configure an authenticator.
4. Issue/import a TLS certificate to LocalMachine/My, and set `AS_TLS_THUMBPRINT` to its SHA-1 store thumbprint. The client independently pins the certificate's SHA-256 DER fingerprint. These identifiers are not interchangeable.
5. `AS_BIND` is a literal IP address (default 127.0.0.1); `AS_PORT` defaults to 7443. Do not bind the agent publicly.
6. For initial testing, start `AccessStudio.Agent.exe --serve` from elevated console. Production requires a carefully configured Windows service and security audit before deployment.
7. In client, enter `https://NETBIRD_PRIVATE_IP:7443`, the 64-hex SHA-256 DER fingerprint, username, password and TOTP.

## Security boundaries
All effective authorization is server-side. Client role claims are never trusted. The agent rejects existing unmanaged Windows accounts even if names start with `dev_`. Only workspaces created and registered by Access Studio may have their permissions modified. Session revocation is immediate on password rotation. Secrets are not sent to NVIDIA. The NVIDIA assistant is advisory only and cannot call privileged APIs.

## Critical release gate
Unsigned development artifacts and this GitHub Actions build must **never** be presented as production-signed binaries. Before production: independent Daybreak Blue review, Windows end-to-end verification, private code-signing workflow (Authenticode), package signature verification, manual key-rotation tests, RDP policy evaluation, effective ACL tests including inherited permissions and reparse points.

See `SECURITY.md` and `CODEX_TASKS.md`.
