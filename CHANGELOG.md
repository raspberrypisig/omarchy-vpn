# Changelog

## Unreleased

- Report why NetworkManager rejected an import instead of one generic message,
  naming the missing `networkmanager-openvpn` package when that is the cause and
  redacting certificate, key-sized, and credential values from diagnostics.
- Sweep archived certificate and key files that no import and no NetworkManager
  connection refers to, instead of leaving them on disk after a failed import.
  Imports do this automatically; `python3 scripts/vpn.py sweep` does it on
  demand without touching saved profiles.
- Rename the plugin to `mohankumargupta.vpn`, including its private data
  directory at `~/.local/share/mohankumargupta.vpn/`.
- Choose the `.ovpn` file with the panel's own Qt file dialog, dropping the
  `zenity` dependency.

## 1.3.0

Initial public release.

- Import OpenVPN configurations and archive referenced certificates and keys
  with owner-only permissions.
- Save readable profile names, rename profiles, and remove imported connections.
- Enable split tunneling by default, with a per-profile routing switch.
- Use Omarchy's native panel styling and hide the disconnected icon until hover.
- Install missing dependencies through an explicit terminal setup command.
- Cover profile storage, removal, routing, and setup with 34 automated tests.
