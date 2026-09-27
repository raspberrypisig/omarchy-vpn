# Changelog

## Unreleased

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
