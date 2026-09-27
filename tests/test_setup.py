import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ['networkmanager', 'openvpn', 'networkmanager-openvpn', 'coreutils', 'python']
FAKE = '''#!/usr/bin/python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['FAKE_ROOT'])
command = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
state = root / 'packages.json'
packages = json.loads(state.read_text())
if command == 'pacman':
    assert len(args) == 2 and args[0] == '-Q', args
    sys.exit(0 if args[1] in packages else 1)
with (root / 'calls.jsonl').open('a') as out:
    out.write(json.dumps([command] + args) + '\\n')
if command == 'omarchy' and args[:2] == ['pkg', 'add']:
    if os.environ.get('FAIL_INSTALL') == '1':
        sys.exit(1)
    if os.environ.get('FALSE_SUCCESS') != '1':
        state.write_text(json.dumps(packages + args[2:]))
if command == 'omarchy-git-url-check' and args[0].startswith('-'):
    sys.exit(1)
'''


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.bin = self.path / 'bin'
        self.bin.mkdir()
        for command in ('pacman', 'omarchy', 'omarchy-git-url-check',
                        'nmcli', 'openvpn', 'timeout', 'python3'):
            target = self.bin / command
            target.write_text(FAKE)
            target.chmod(0o755)
        for command in ('bash', 'dirname'):
            (self.bin / command).symlink_to('/usr/bin/' + command)
        self.env = dict(os.environ, PATH=str(self.bin), FAKE_ROOT=str(self.path))
        self.set_packages(PACKAGES)

    def set_packages(self, packages):
        (self.path / 'packages.json').write_text(json.dumps(packages))

    def calls(self):
        log = self.path / 'calls.jsonl'
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def run_script(self, *args, installer=False, answer=''):
        script = ROOT / ('install.sh' if installer else 'scripts/setup-dependencies.sh')
        return subprocess.run(['/usr/bin/bash', str(script), *args],
                              env=self.env, input=answer, text=True,
                              capture_output=True, timeout=10)

    def test_existing_packages_skip_without_privilege_or_prompt(self):
        result = self.run_script('--install')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('SKIP:'), len(PACKAGES))
        self.assertEqual(self.calls(), [])

    def test_check_missing_is_read_only(self):
        self.set_packages(['networkmanager', 'coreutils', 'python'])
        result = self.run_script('--check')
        self.assertEqual(result.returncode, 1)
        self.assertIn('MISSING: openvpn', result.stdout)
        self.assertEqual(self.calls(), [])

    def test_install_only_missing_and_repeat_skips(self):
        self.set_packages(['networkmanager', 'coreutils', 'python'])
        result = self.run_script('--install', answer='y\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [['omarchy', 'pkg', 'add', 'openvpn', 'networkmanager-openvpn']])
        result = self.run_script('--install')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('SKIP:'), len(PACKAGES))
        self.assertEqual(len(self.calls()), 1)

    def test_cancel_and_closed_input_do_not_install(self):
        self.set_packages([])
        for answer in ('n\n', ''):
            result = self.run_script('--install', answer=answer)
            self.assertEqual(result.returncode, 1)
            self.assertIn('Cancelled', result.stdout)
        self.assertEqual(self.calls(), [])

    def test_failed_install_prevents_plugin_add(self):
        self.set_packages([])
        self.env['FAIL_INSTALL'] = '1'
        result = self.run_script('https://example.com/vpn.git', installer=True, answer='yes\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn('installation failed', result.stderr)
        self.assertFalse(any(call[1:3] == ['plugin', 'add'] for call in self.calls()))

    def test_false_package_success_is_detected(self):
        self.set_packages([])
        self.env['FALSE_SUCCESS'] = '1'
        result = self.run_script('--install', answer='y\n')
        self.assertEqual(result.returncode, 1)
        self.assertIn('still missing', result.stderr)

    def test_installer_installs_dependencies_before_plugin(self):
        self.set_packages(['networkmanager', 'coreutils', 'python'])
        url = 'https://example.com/vpn.git'
        result = self.run_script(url, installer=True, answer='y\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [
            ['omarchy-git-url-check', url],
            ['omarchy', 'pkg', 'add', 'openvpn', 'networkmanager-openvpn'],
            ['omarchy', 'plugin', 'add', url, '--enable'],
        ])

    def test_invalid_url_rejected_before_package_changes(self):
        self.set_packages([])
        result = self.run_script('--bad-option', installer=True, answer='y\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [['omarchy-git-url-check', '--bad-option']])

    def test_missing_executable_despite_installed_package(self):
        (self.bin / 'nmcli').unlink()
        result = self.run_script('--check')
        self.assertEqual(result.returncode, 1)
        self.assertIn('nmcli is not on PATH', result.stderr)
        self.assertEqual(self.calls(), [])

    def test_unsupported_system_and_invalid_arguments(self):
        (self.bin / 'pacman').unlink()
        result = self.run_script('--check')
        self.assertEqual(result.returncode, 2)
        self.assertIn('requires Omarchy', result.stderr)
        result = self.run_script('--unknown')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.calls(), [])


if __name__ == '__main__':
    unittest.main()
