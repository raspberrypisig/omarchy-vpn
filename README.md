# Omarchy VPN

An OpenVPN widget with dependency-aware installation, local `.ovpn` import,
saved profiles, and connect/disconnect controls. It requires an Omarchy version
with shell plugin support (tested on Omarchy 4.0.4). Split routing and public
internet access have been tested with a live OpenVPN connection.

- Import `.ovpn` files and save their certificates and keys privately.
- Give profiles readable names, rename them, and remove them.
- Keep normal internet access with per-profile split tunneling.
- Match Omarchy's theme and reveal the disconnected indicator on bar hover.

Plugin ID: `adarsh.vpn`. Maintained by
[TheComputeCenter](https://github.com/TheComputeCenter).

## Install

Run these commands in a terminal:

```bash
git clone https://github.com/TheComputeCenter/omarchy-vpn.git
cd omarchy-vpn
bash install.sh https://github.com/TheComputeCenter/omarchy-vpn.git
```

The installer checks dependencies, acknowledges packages already installed,
asks before installing missing packages, and opens Omarchy's normal plugin
installation flow. Select the **center** bar section to use the disconnected
icon's hover-reveal behavior. Administrator authentication may be required for
packages. The installation starts without discovering or importing any existing
VPN profiles; add your own `.ovpn` file from the panel.

If you installed using `omarchy plugin add` or the marketplace command, run the
dependency setup separately, then enable the plugin:

```bash
bash ~/.config/omarchy/plugins/adarsh.vpn/scripts/setup-dependencies.sh --install
omarchy plugin enable adarsh.vpn
```

Omarchy does not automatically execute dependency installation scripts. A
working NetworkManager service is required. The plugin does not start or
restart the system's network service.

## Update and remove

```bash
omarchy plugin update adarsh.vpn
```

Updates preserve saved profiles. After an update, rerun dependency setup if the
release adds a dependency. If the running shell still shows the old widget,
reload it with `omarchy restart shell`.

To remove only the widget:

```bash
omarchy plugin remove adarsh.vpn
```

To also delete the plugin's saved VPN profiles, run this **before** removing
the widget (it disconnects and deletes plugin-imported NetworkManager
connections and their saved configuration copies):

```bash
python3 ~/.config/omarchy/plugins/adarsh.vpn/scripts/vpn.py reset
omarchy plugin remove adarsh.vpn
```

Your original source `.ovpn` files and externally created NetworkManager
connections are not deleted. Dependency packages are left installed because
other applications may use them. Saved profiles otherwise remain under
`~/.local/share/adarsh.vpn/` and are reused if you reinstall; use the reset
command above when you want a fresh start.

## Import and save a VPN

1. Hover over the center of the bar to reveal the disconnected VPN icon, click
   it, then click **Add VPN**. Connected VPNs keep the icon visible.
2. Select your provider's `.ovpn` configuration in the file chooser.
3. Enter a readable name, such as **Office VPN**, and click **Save VPN**.
   The plugin saves a private local copy and imports a persistent connection
   into NetworkManager. Importing does not connect automatically.
4. Select a saved profile from the list and use the header switch to connect.

Use the pencil beside a profile to rename it. Names are local display labels,
between 1 and 64 characters. Use the trash icon to remove a profile, then confirm
**Remove VPN**. Removal deletes the plugin-imported NetworkManager connection
and its private saved files, disconnecting it if active. Your original source
file is kept. Previously migrated external profiles are only forgotten by the
plugin; their system connections are not deleted.

The selected profile is remembered across shell restarts. Import more files to
add more profiles. Selecting another profile does not disconnect an active VPN;
select the connected profile and turn its switch off when needed.

## Split tunneling

**Split tunneling** is enabled by default on import. This keeps the default
internet route on the normal connection while retaining the VPN's specific
routes. The import form shows the choice, and the selected profile's switch can
be changed while disconnected. Disable it to allow the VPN configuration/server
to provide the default internet route. Changing it takes effect on next connect.

The implementation sets `ipv4.never-default` and `ipv6.never-default` in the
NetworkManager profile. It leaves specific routes and DNS supplied by the VPN
intact. A server that supplies broad explicit routes or catch-all DNS domains
may need additional provider-specific settings. This is route-based splitting,
not an application bypass list. Public traffic outside the VPN's routes is not
protected by that VPN when split tunneling is enabled.

If route setup fails after import, the profile is retained for recovery and
connecting is blocked until its split-tunneling setting is successfully saved.

Files are kept in `$XDG_DATA_HOME/adarsh.vpn`, normally
`~/.local/share/adarsh.vpn/`, outside the plugin source directory. Directories
have owner-only permissions (`700`) and files have owner-only read/write
permissions (`600`). This includes the original `.ovpn`, a working copy,
referenced certificate/key files, and the remembered profile selection. No
configuration is uploaded to a website. These files are not encrypted at rest.

Inline certificates/keys and common external file options (`ca`, `cert`, `key`,
`pkcs12`, `tls-auth`, `tls-crypt`, `tls-crypt-v2`, `secret`, `extra-certs`,
`crl-verify`, `auth-user-pass`, `askpass`, and `dh`) are archived. Relative paths
are resolved against the selected configuration's folder. Included configs,
`cd`, certificate directories, and CRL directories are rejected with a message;
use one configuration with inline data or explicit file references instead.
Each source/asset file is limited to 16 MiB. NetworkManager determines which
OpenVPN options are supported.

VPNs requiring usernames, passwords, MFA, or encrypted-key passphrases may need
configuration through NetworkManager and a desktop secret agent. Importing a
file does not guarantee its authentication details are complete. The plugin
does not implement its own password manager.

Keep the saved profile files while their NetworkManager connections exist.
Routine plugin code updates/removal do not delete saved files or connections.
A requested fresh setup can clear all tracked profiles using
`python3 scripts/vpn.py reset`; it never discovers or migrates existing system
VPNs. This reset removes plugin-imported connections and saved copies. Failed
or timed-out NetworkManager imports retain their archived files for recovery,
because the connection may have been created before the response was lost.

## Dependencies

| Package | Purpose |
| --- | --- |
| `networkmanager` | NetworkManager and `nmcli` |
| `openvpn` | OpenVPN client |
| `networkmanager-openvpn` | OpenVPN support in NetworkManager |
| `coreutils` | Installer utilities |
| `python` | Import, private storage, and profile selection |

Check without installing anything:

```bash
bash scripts/setup-dependencies.sh --check
```

Exit codes: `0` means ready, `1` means missing/broken dependencies, cancellation,
or installation failure, and `2` means invalid arguments or an unsupported
setup environment. If package installation fails, resolve the displayed error
and rerun setup. No package database refresh or system upgrade is run by these
scripts.

## Validation

```bash
python3 -m unittest discover -s tests -v
bash -n install.sh scripts/setup-dependencies.sh
omarchy plugin validate .
```

The tests use fake package commands and mocked NetworkManager calls. They cover
missing dependencies, private file permissions, certificate copying, persistence,
profile selection, cancellation, and import failures. They never install packages
or change network settings. The running panel and a live split-tunnel VPN
connection were also checked on Omarchy 4.0.4; other providers may require
additional authentication or DNS setup.

## License

[MIT](LICENSE). The widget uses Omarchy's shared UI components and requires
Omarchy, Quickshell, and the system dependencies above.

Reference: [Omarchy plugin installation](https://github.com/basecamp/omarchy/blob/quattro/shell/README.md#installing-a-third-party-plugin).
