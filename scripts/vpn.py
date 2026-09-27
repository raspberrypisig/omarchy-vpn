#!/usr/bin/env python3
"""Private OpenVPN imports and persistent profile selection for the widget."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata


UUID = re.compile(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b")
FILE_OPTIONS = {
    'ca', 'cert', 'key', 'pkcs12', 'tls-auth', 'tls-crypt', 'tls-crypt-v2',
    'secret', 'extra-certs', 'crl-verify', 'auth-user-pass', 'askpass', 'dh',
}
INLINE_OPTIONS = FILE_OPTIONS | {'auth-gen-token-secret'}
MAX_FILE_BYTES = 16 * 1024 * 1024
GENERIC_FAILURE = 'NetworkManager could not complete the request. Check the VPN file, permissions, and any required login credentials.'
MISSING_OPENVPN = re.compile(r'unknown VPN plugin "org\.freedesktop\.NetworkManager\.openvpn"')
MISSING_SECRETS = re.compile(r'No valid secrets')
ANSI = re.compile(r'\x1b\[[0-9;?]*[a-zA-Z]')
PEM_BLOCK = re.compile(r'-{4,}.*?-{4,}')
# Only an explicit separator marks a value, so prose like "password for
# 'vpn.secrets.password' not given" keeps its words instead of being eaten.
SECRET_ASSIGNMENT = re.compile(r'(?i)\b(pass(?:word|phrase)?|secret|token|pin|credential)s?\b\s*[:=]\s*"?([^\s"]+)"?')
OPAQUE_TOKEN = re.compile(r'[A-Za-z0-9+/=_-]{24,}')
MAX_DETAIL = 160
NMCLI = 'nmcli'


class VpnError(Exception):
    def __init__(self, message, needs_secrets=False):
        super().__init__(message)
        self.needs_secrets = needs_secrets


def data_root():
    base = Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local/share'))
    if not base.is_absolute():
        base = Path.home() / '.local/share'
    return base / 'mohankumargupta.vpn'


def private_dir(path):
    if path.is_symlink():
        raise VpnError('The VPN storage directory must not be a symbolic link.')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)


def read_file(path):
    if not path.is_file():
        raise VpnError('The configuration or a referenced certificate/key file is missing.')
    with path.open('rb') as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise VpnError('The configuration or a referenced file exceeds the 16 MiB limit.')
    return data


def write_private(path, data):
    # Exclusive creation prevents overwriting or following existing links.
    with path.open('xb') as stream:
        os.chmod(path, 0o600)
        stream.write(data)


def load_state(root):
    path = root / 'state.json'
    if not path.exists():
        return {'selected': '', 'profiles': []}
    try:
        state = json.loads(path.read_text())
        assert isinstance(state['selected'], str)
        assert isinstance(state['profiles'], list)
        for profile in state['profiles']:
            assert UUID.fullmatch(profile['uuid'])
            assert isinstance(profile['name'], str)
        return state
    except (ValueError, KeyError, TypeError, AssertionError):
        raise VpnError('Saved VPN settings are invalid. Restore state.json from a backup.') from None


def save_state(root, state):
    fd, filename = tempfile.mkstemp(prefix='.state-', dir=root)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(state, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(filename, root / 'state.json')
    finally:
        Path(filename).unlink(missing_ok=True)


def nm_failure(output):
    # nmcli can quote the parsed configuration or a credential back at us, so
    # only the reason survives and every opaque run is redacted. Output read
    # from a pty also carries terminal escapes and a preamble.
    text = ANSI.sub('', output or '')
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return GENERIC_FAILURE
    if MISSING_OPENVPN.search(text):
        return 'NetworkManager has no OpenVPN support installed. On Arch install networkmanager-openvpn, then try again.'
    # A pty leaves the prompt and the error on one line, so take the reason
    # from wherever the Error: marker appears rather than the whole line.
    reason = next((line[line.index('Error:'):] for line in lines if 'Error:' in line), lines[0])
    detail = PEM_BLOCK.sub('[redacted]', reason)
    detail = SECRET_ASSIGNMENT.sub(lambda match: match.group(1) + '=[redacted]', detail)
    detail = OPAQUE_TOKEN.sub('[redacted]', detail)
    detail = detail.removeprefix('**nmcli**').removeprefix('Error:').strip()
    if len(detail) > MAX_DETAIL:
        detail = detail[:MAX_DETAIL].rstrip() + '…'
    if not detail:
        return GENERIC_FAILURE
    if MISSING_SECRETS.search(text):
        # nmcli cannot prompt without a terminal, so the widget collects the
        # secrets itself and answers --ask over a pty.
        return f'{detail.rstrip(".")}. Enter your VPN login to continue.'
    return f'NetworkManager rejected this request: {detail}'


def nmcli(*args, timeout=40):
    try:
        result = subprocess.run(
            [NMCLI, '--wait', '30', *args], capture_output=True,
            text=True, timeout=timeout, env=dict(os.environ, LC_ALL='C'),
        )
    except FileNotFoundError:
        raise VpnError('nmcli is missing. Run the plugin dependency setup first.') from None
    except subprocess.TimeoutExpired:
        raise VpnError('NetworkManager timed out. Check its connection list before trying again.') from None
    if result.returncode:
        message = nm_failure(result.stderr or result.stdout)
        raise VpnError(message, needs_secrets=bool(MISSING_SECRETS.search(result.stderr or '')))
    return result.stdout


def nmcli_ask(args, answers, timeout=90):
    # nmcli only prompts for secrets with --ask on a terminal, and it refuses
    # to store them any other way, so answer its own prompts over a pty. The
    # secrets reach nmcli through this pipe and never appear in argv.
    controller, terminal = os.openpty()
    try:
        try:
            process = subprocess.Popen(
                [NMCLI, '--ask', '--wait', '30', *args], stdin=terminal,
                stdout=terminal, stderr=terminal, close_fds=True,
                env=dict(os.environ, LC_ALL='C'),
            )
        except FileNotFoundError:
            raise VpnError('nmcli is missing. Run the plugin dependency setup first.') from None
        finally:
            os.close(terminal)
        collected = []
        pending = dict(answers)
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait(timeout=5)
                raise VpnError('NetworkManager timed out while asking for your VPN login.')
            if not select.select([controller], [], [], min(remaining, 0.5))[0]:
                continue
            try:
                chunk = os.read(controller, 4096)
            except OSError:
                break
            if not chunk:
                break
            text = chunk.decode('utf-8', 'replace')
            collected.append(text)
            for name in [key for key in pending if key in text]:
                os.write(controller, pending.pop(name).encode() + b'\n')
        for name in pending:
            # A secret left blank is a legitimate answer for an unused field.
            try:
                os.write(controller, b'\n')
            except OSError:
                break
        while select.select([controller], [], [], 0.5)[0]:
            try:
                chunk = os.read(controller, 4096)
            except OSError:
                break
            if not chunk:
                break
            collected.append(chunk.decode('utf-8', 'replace'))
        return process.wait(timeout=5), ''.join(collected)
    finally:
        os.close(controller)


def archive_config(source, destination):
    original = read_file(source)
    try:
        content = original.decode('utf-8-sig')
    except UnicodeError:
        raise VpnError('Select a UTF-8 OpenVPN configuration file.') from None
    write_private(destination / 'source.ovpn', original)
    lines = []
    inline = None
    for line in content.splitlines():
        stripped = line.strip()
        if inline:
            lines.append(line)
            if stripped == '</' + inline + '>':
                inline = None
            continue
        if stripped.startswith('<') and stripped.endswith('>') and stripped[1:-1] in INLINE_OPTIONS:
            inline = stripped[1:-1]
            lines.append(line)
            continue
        try:
            tokens = shlex.split(line, comments=True)
        except ValueError:
            raise VpnError('The OpenVPN configuration contains an invalid quoted option.') from None
        if not tokens or tokens[0].startswith(';'):
            lines.append(line)
            continue
        option = tokens[0].removeprefix('--')
        if option in {'config', 'cd', 'capath'}:
            raise VpnError('Use one .ovpn file with inline certificates or explicit certificate/key files; included configs and certificate directories are not supported.')
        if option in FILE_OPTIONS and len(tokens) > 1 and tokens[1] not in {'[inline]', 'none'}:
            if option == 'crl-verify' and len(tokens) > 2 and tokens[2] == 'dir':
                raise VpnError('CRL directories are not supported; use a CRL file.')
            asset = Path(tokens[1])
            if not asset.is_absolute():
                asset = source.parent / asset
            saved = destination / ('asset-' + str(len(lines)) + '.dat')
            write_private(saved, read_file(asset))
            # OpenVPN accepts double-quoted paths with escaped quotes/backslashes.
            quoted = '"' + str(saved).replace('\\', '\\\\').replace('"', '\\"') + '"'
            suffix = ''.join(' ' + shlex.quote(value) for value in tokens[2:])
            lines.append(tokens[0] + ' ' + quoted + suffix)
        else:
            lines.append(line)
    if inline:
        raise VpnError('The OpenVPN configuration has an unclosed inline certificate/key block.')
    prepared = destination / ('vpn-' + source.name)
    write_private(prepared, ('\n'.join(lines) + '\n').encode())
    return prepared


def prune_orphans(root, state):
    # An import can succeed even when its response is lost, so a directory that
    # NetworkManager still points at is kept. Anything else is key material
    # nothing refers to any more.
    profiles_dir = root / 'profiles'
    if profiles_dir.is_symlink() or not profiles_dir.is_dir():
        return []
    known = {Path(profile['directory']) for profile in state['profiles'] if profile.get('directory')}
    stale = [entry for entry in profiles_dir.iterdir()
             if entry.name.startswith('profile-') and not entry.is_symlink() and entry not in known]
    if not stale:
        return []
    try:
        registered = nmcli('connection', 'show')
    except VpnError:
        return []
    removed = []
    for entry in stale:
        if str(entry) not in registered:
            shutil.rmtree(entry, ignore_errors=True)
            removed.append(entry.name)
    return removed


def read_secrets():
    # Two lines on stdin: the VPN password, then the optional passphrase for
    # the certificate or pkcs12 file.
    password = sys.stdin.readline()
    if not password:
        raise VpnError('Enter your VPN password to continue.')
    return password.rstrip('\n'), sys.stdin.readline().rstrip('\n')


def connect_profile(root, answers=None):
    state = load_state(root)
    if not state['selected']:
        raise VpnError('Import a VPN profile first.')
    if any(item['uuid'] == state['selected'] and item.get('routingPending', False) for item in state['profiles']):
        raise VpnError('Set the split-tunneling option before connecting this imported profile.')
    command = ('connection', 'up', 'uuid', state['selected'])
    if answers is None:
        nmcli(*command)
        return
    code, output = nmcli_ask(command, answers)
    if code:
        raise VpnError(nm_failure(output), needs_secrets=bool(MISSING_SECRETS.search(output)))


def disconnect_profile(root):
    state = load_state(root)
    if not state['selected']:
        raise VpnError('Import a VPN profile first.')
    nmcli('connection', 'down', 'uuid', state['selected'])


def profile_name(name):
    name = (name or '').strip()
    if not name or len(name) > 64 or any(unicodedata.category(char).startswith('C') for char in name):
        raise VpnError('Enter a name between 1 and 64 characters, without control characters.')
    return name


def import_profile(root, source, name=None, split_tunnel=True):
    source = Path(source).expanduser().resolve()
    if source.suffix.lower() != '.ovpn':
        raise VpnError('Please choose a file ending in .ovpn.')
    label = profile_name(name if name is not None else source.stem[:64])
    state = load_state(root)
    profiles_dir = root / 'profiles'
    private_dir(profiles_dir)
    prune_orphans(root, state)
    destination = Path(tempfile.mkdtemp(prefix='profile-', dir=profiles_dir))
    try:
        prepared = archive_config(source, destination)
    except Exception:
        shutil.rmtree(destination)
        raise
    try:
        output = nmcli('connection', 'import', 'type', 'openvpn', 'file', str(prepared))
        matches = UUID.findall(output)
        if not matches:
            raise VpnError('NetworkManager did not return the imported profile ID. The file is saved; check NetworkManager before importing again.')
        profile = {'uuid': matches[-1].lower(), 'name': label, 'directory': str(destination), 'routingPending': True}
        state['profiles'].append(profile)
        state['selected'] = profile['uuid']
        save_state(root, state)
    except Exception:
        prune_orphans(root, state)
        raise
    # Record the imported profile before setting routing so failures leave it
    # recoverable. It cannot connect until routing configuration succeeds.
    configure_split(root, profile['uuid'], split_tunnel, newly_imported=True)
    profile['routingPending'] = False
    return profile


def configure_split(root, selected, enabled, newly_imported=False):
    state = load_state(root)
    profile = next((item for item in state['profiles'] if item['uuid'] == selected), None)
    if profile is None:
        raise VpnError('Choose one of the saved VPN profiles.')
    if not newly_imported:
        active = nmcli('-t', '-f', 'UUID', 'connection', 'show', '--active').splitlines()
        if selected in active:
            raise VpnError('Disconnect this VPN before changing split tunneling.')
    flag = 'yes' if enabled else 'no'
    nmcli('connection', 'modify', 'uuid', selected,
          'ipv4.never-default', flag, 'ipv6.never-default', flag)
    profile['routingPending'] = False
    save_state(root, state)


def select_profile(root, selected):
    state = load_state(root)
    if not any(profile['uuid'] == selected for profile in state['profiles']):
        raise VpnError('Choose one of the saved VPN profiles.')
    state['selected'] = selected
    save_state(root, state)


def rename_profile(root, selected, name):
    label = profile_name(name)
    state = load_state(root)
    for profile in state['profiles']:
        if profile['uuid'] == selected:
            profile['name'] = label
            save_state(root, state)
            return
    raise VpnError('Choose one of the saved VPN profiles.')


def remove_profile(root, selected):
    state = load_state(root)
    profile = next((item for item in state['profiles'] if item['uuid'] == selected), None)
    if profile is None:
        raise VpnError('Choose one of the saved VPN profiles.')
    directory = None
    if profile.get('directory'):
        directory = Path(profile['directory'])
        expected = root / 'profiles'
        if directory.parent != expected or not directory.name.startswith('profile-') or directory.is_symlink() or expected.is_symlink():
            raise VpnError('The saved profile directory is invalid; no files were removed.')
        # A migrated, externally managed connection has no directory and is
        # only forgotten. Imported profiles belong to this plugin.
        registered = nmcli('-t', '-f', 'UUID', 'connection', 'show').splitlines()
        if selected in registered:
            nmcli('connection', 'delete', 'uuid', selected)
        # Keep metadata until cleanup succeeds so deletion can be retried.
        if directory.exists():
            shutil.rmtree(directory)
    state['profiles'] = [item for item in state['profiles'] if item['uuid'] != selected]
    if state['selected'] == selected:
        state['selected'] = state['profiles'][0]['uuid'] if state['profiles'] else ''
    save_state(root, state)


def sweep_profiles(root):
    return prune_orphans(root, load_state(root))


def reset_profiles(root):
    # Save progress after each removal; a failed deletion is safely retryable.
    for profile in list(load_state(root)['profiles']):
        remove_profile(root, profile['uuid'])
    state = {'selected': '', 'profiles': []}
    prune_orphans(root, state)
    save_state(root, state)


def status(root):
    state = load_state(root)
    split_tunnel = None
    routing_pending = any(profile['uuid'] == state['selected'] and profile.get('routingPending', False) for profile in state['profiles'])
    try:
        all_active = nmcli('-t', '-f', 'UUID', 'connection', 'show', '--active', timeout=8).splitlines()
        saved = {profile['uuid'] for profile in state['profiles']}
        active = [uuid for uuid in all_active if uuid in saved]
        if state['selected']:
            flags = nmcli('-g', 'ipv4.never-default,ipv6.never-default',
                          'connection', 'show', 'uuid', state['selected'], timeout=8).strip().splitlines()
            if len(flags) == 2 and all(flag in {'yes', 'no'} for flag in flags):
                split_tunnel = flags == ['yes', 'yes']
        known = True
        error = ''
    except VpnError as exc:
        active, known, error = [], False, str(exc)
    return dict(state, connected=state['selected'] in active, splitTunnel=split_tunnel, routingPending=routing_pending,
                active=active, stateKnown=known, error=error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['status', 'import', 'select', 'rename', 'remove', 'reset', 'sweep', 'set-split', 'connect', 'connect-ask', 'disconnect'])
    parser.add_argument('value', nargs='?')
    parser.add_argument('--name')
    parser.add_argument('--full-tunnel', action='store_true', help='Allow the VPN to supply the default internet route')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        root = data_root()
        private_dir(root)
        removed = []
        with (root / '.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if args.action == 'import':
                if not args.value:
                    raise VpnError('Choose a .ovpn file to import.')
                import_profile(root, args.value, args.name, not args.full_tunnel)
            elif args.action == 'select':
                select_profile(root, args.value)
            elif args.action == 'rename':
                rename_profile(root, args.value, args.name)
            elif args.action == 'remove':
                remove_profile(root, args.value)
            elif args.action == 'reset':
                reset_profiles(root)
            elif args.action == 'sweep':
                removed = sweep_profiles(root)
            elif args.action == 'set-split':
                configure_split(root, args.value, not args.full_tunnel)
            elif args.action == 'connect':
                connect_profile(root)
            elif args.action == 'connect-ask':
                password, certificate = read_secrets()
                connect_profile(root, {'vpn.secrets.password': password, 'vpn.secrets.cert-pass': certificate})
            elif args.action == 'disconnect':
                disconnect_profile(root)
            result = status(root)
            if removed:
                result['swept'] = removed
        print(json.dumps(result))
        return 0
    except (VpnError, OSError) as exc:
        message = str(exc) if isinstance(exc, VpnError) else 'Unable to read or save VPN files. Check file access and available disk space.'
        print(json.dumps({'error': message, 'needsSecrets': isinstance(exc, VpnError) and exc.needs_secrets}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
