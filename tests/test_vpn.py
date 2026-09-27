import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch


MODULE = Path(__file__).resolve().parents[1] / 'scripts/vpn.py'
spec = importlib.util.spec_from_file_location('vpn', MODULE)
vpn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vpn)
MISSING_SECRETS = vpn.MISSING_SECRETS
UUID1 = '11111111-1111-4111-8111-111111111111'
UUID2 = '22222222-2222-4222-8222-222222222222'
ASK_STUB = '''#!/usr/bin/python3
import sys
for name in ('vpn.secrets.password', 'vpn.secrets.cert-pass'):
    sys.stdout.write(name + ': ')
    sys.stdout.flush()
    sys.stdout.write('<' + sys.stdin.readline().rstrip('\\n') + '>\\n')
    sys.stdout.flush()
sys.stdout.write('Error: stub finished\\n')
sys.exit(4)
'''


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'data'
        vpn.private_dir(self.root)
        self.source = self.base / 'Office VPN.ovpn'
        self.source.write_text('client\nremote vpn.example.test 1194\n<ca>\nTEST CERT\n</ca>\n')

    def import_sample(self, uuid=UUID1):
        with patch.object(vpn, 'nmcli', return_value=f"Connection 'VPN' ({uuid}) successfully added.") as command:
            profile = vpn.import_profile(self.root, self.source)
        self.assertEqual(command.call_args_list[0].args[:5], ('connection', 'import', 'type', 'openvpn', 'file'))
        return profile

    def test_import_archives_privately_and_persists_selection(self):
        profile = self.import_sample()
        self.assertEqual(vpn.load_state(self.root)['selected'], UUID1)
        self.assertEqual(profile['name'], 'Office VPN')
        directory = Path(profile['directory'])
        self.assertEqual((directory / 'source.ovpn').read_bytes(), self.source.read_bytes())
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for path in directory.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.root / 'state.json').stat().st_mode), 0o600)
        # Removing the downloaded source must not remove the saved copy.
        self.source.unlink()
        self.assertTrue((directory / 'source.ovpn').is_file())

    def test_external_keys_copied_and_rewritten_with_spaces(self):
        certificate = self.base / 'client certificate.pem'
        certificate.write_text('PRIVATE TEST DATA')
        self.source.write_text('client\nremote vpn.example.test\ncert "client certificate.pem"\ntls-auth "client certificate.pem" 1\n')
        profile = self.import_sample()
        directory = Path(profile['directory'])
        archived = list(directory.glob('asset-*.dat'))
        self.assertEqual(len(archived), 2)
        content = (directory / ('vpn-' + self.source.name)).read_text()
        for asset in archived:
            self.assertIn(str(asset), content)
            self.assertEqual(asset.read_text(), 'PRIVATE TEST DATA')
            self.assertEqual(stat.S_IMODE(asset.stat().st_mode), 0o600)
        self.assertTrue(content.rstrip().endswith('" 1'))

    def test_inline_content_is_preserved_without_parsing_secrets(self):
        self.source.write_text('client\n<key>\nnot "balanced \' text\n</key>\n')
        profile = self.import_sample()
        self.assertEqual((Path(profile['directory']) / ('vpn-' + self.source.name)).read_text(), self.source.read_text())

    def test_missing_asset_and_bad_extension_do_not_call_nm(self):
        self.source.write_text('cert missing.pem\n')
        with patch.object(vpn, 'nmcli') as command:
            with self.assertRaises(vpn.VpnError):
                vpn.import_profile(self.root, self.source)
            with self.assertRaises(vpn.VpnError):
                vpn.import_profile(self.root, self.base / 'file.txt')
            command.assert_not_called()
        self.assertEqual(list((self.root / 'profiles').iterdir()), [])

    def test_rejects_include_and_unclosed_inline_data(self):
        for content in ('config other.ovpn\n', 'capath certs\n', '<key>\nabc\n'):
            self.source.write_text(content)
            with patch.object(vpn, 'nmcli') as command:
                with self.assertRaises(vpn.VpnError):
                    vpn.import_profile(self.root, self.source)
                command.assert_not_called()

    def test_failure_retains_existing_selection_and_recovery_files(self):
        self.import_sample()
        original = vpn.load_state(self.root)
        with patch.object(vpn, 'nmcli', side_effect=vpn.VpnError('Import failed')):
            with self.assertRaises(vpn.VpnError):
                vpn.import_profile(self.root, self.source)
        self.assertEqual(vpn.load_state(self.root), original)
        self.assertEqual(len(list((self.root / 'profiles').iterdir())), 2)

    def test_failed_import_removes_key_material_nothing_references(self):
        with patch.object(vpn, 'nmcli', side_effect=[vpn.VpnError('Import failed'), '']):
            with self.assertRaises(vpn.VpnError):
                vpn.import_profile(self.root, self.source)
        self.assertEqual(list((self.root / 'profiles').iterdir()), [])
        self.assertEqual(vpn.load_state(self.root), {'selected': '', 'profiles': []})

    def test_failed_import_keeps_files_a_lost_response_may_have_registered(self):
        def command(*args, **kwargs):
            if args[0:2] == ('connection', 'show'):
                return ''.join(str(path) + '\n' for path in (self.root / 'profiles').iterdir())
            raise vpn.VpnError('NetworkManager timed out.')

        with patch.object(vpn, 'nmcli', side_effect=command):
            with self.assertRaises(vpn.VpnError):
                vpn.import_profile(self.root, self.source)
        self.assertEqual(len(list((self.root / 'profiles').iterdir())), 1)

    def test_later_import_sweeps_directories_earlier_failures_left_behind(self):
        stale = self.root / 'profiles' / 'profile-abandoned'
        stale.mkdir(parents=True)
        (stale / 'asset-0.dat').write_text('PRIVATE TEST DATA')
        with patch.object(vpn, 'nmcli', return_value=f'Connection ({UUID1})') as command:
            vpn.import_profile(self.root, self.source)
        self.assertEqual(command.call_args_list[0].args, ('connection', 'show'))
        self.assertFalse(stale.exists())
        self.assertTrue(Path(vpn.load_state(self.root)['profiles'][0]['directory']).is_dir())

    def test_sweep_removes_saved_directories_and_ignores_unrelated_entries(self):
        self.import_sample()
        other = self.root / 'profiles' / 'notes.txt'
        other.write_text('not a profile')
        with patch.object(vpn, 'nmcli', return_value='') as command:
            vpn.reset_profiles(self.root)
        self.assertTrue(other.exists())
        self.assertEqual([entry.name for entry in (self.root / 'profiles').iterdir()], ['notes.txt'])

    def test_sweep_keeps_the_tracked_profile_and_reports_what_it_removed(self):
        profile = self.import_sample()
        stale = self.root / 'profiles' / 'profile-abandoned'
        stale.mkdir(parents=True)
        (stale / 'asset-0.dat').write_text('PRIVATE TEST DATA')
        with patch.object(vpn, 'nmcli', return_value='') as command:
            self.assertEqual(vpn.sweep_profiles(self.root), ['profile-abandoned'])
        self.assertFalse(stale.exists())
        self.assertTrue(Path(profile['directory']).is_dir())
        self.assertEqual(vpn.load_state(self.root)['selected'], UUID1)

    def test_sweep_action_leaves_saved_profiles_in_the_reported_status(self):
        profile = self.import_sample()
        stale = self.root / 'profiles' / 'profile-abandoned'
        stale.mkdir(parents=True)
        with patch.object(vpn, 'data_root', return_value=self.root), \
                patch('sys.argv', ['vpn.py', 'sweep']), \
                patch.object(vpn, 'nmcli', return_value=''), \
                io.StringIO() as output, contextlib.redirect_stdout(output):
            code = vpn.main()
            printed = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(printed['swept'], ['profile-abandoned'])
        self.assertEqual(printed['profiles'][0]['uuid'], UUID1)
        self.assertTrue(Path(profile['directory']).is_dir())
        self.assertFalse(stale.exists())

    def test_multi_profile_selection_and_active_filtering(self):
        self.import_sample()
        self.import_sample(UUID2)
        vpn.select_profile(self.root, UUID1)
        with patch.object(vpn, 'nmcli', return_value=UUID1 + '\nwifi-profile\n'):
            result = vpn.status(self.root)
        self.assertTrue(result['connected'])
        self.assertEqual(result['active'], [UUID1])
        vpn.select_profile(self.root, UUID2)
        with patch.object(vpn, 'nmcli', return_value=UUID1 + '\n'):
            self.assertFalse(vpn.status(self.root)['connected'])
        with self.assertRaises(vpn.VpnError):
            vpn.select_profile(self.root, 'not-a-profile')

    def test_helper_offers_no_file_picker_action(self):
        with patch('sys.argv', ['vpn.py', 'pick-file']):
            with self.assertRaises(SystemExit):
                vpn.main()

    def test_import_without_a_path_is_rejected_before_nm(self):
        with patch.dict(os.environ, {'XDG_DATA_HOME': str(self.base)}), \
                patch('sys.argv', ['vpn.py', 'import']), \
                patch.object(vpn, 'nmcli') as command, \
                io.StringIO() as output, contextlib.redirect_stdout(output):
            code = vpn.main()
            printed = output.getvalue()
        self.assertEqual(code, 1)
        self.assertIn('Choose a .ovpn file', printed)
        command.assert_not_called()

    def test_nm_error_does_not_expose_secrets(self):
        response = subprocess.CompletedProcess([], 1, '', 'password: private-secret')
        with patch.object(vpn.subprocess, 'run', return_value=response):
            with self.assertRaises(vpn.VpnError) as error:
                vpn.nmcli('connection', 'import')
        self.assertNotIn('private-secret', str(error.exception))

    def test_nm_failure_keeps_the_words_after_a_secret_name(self):
        detail = vpn.nm_failure("Warning: password for 'vpn.secrets.password' not given in 'passwd-file' and nmcli cannot ask without '--ask' option.")
        self.assertIn("password for 'vpn.secrets.password' not given", detail)

    def test_missing_secrets_asks_for_a_login_and_is_flagged(self):
        response = subprocess.CompletedProcess([], 4, '', 'Error: Connection activation failed: No valid secrets')
        with patch.object(vpn.subprocess, 'run', return_value=response):
            with self.assertRaises(vpn.VpnError) as error:
                vpn.nmcli('connection', 'up', 'uuid', UUID1)
        self.assertTrue(error.exception.needs_secrets)
        self.assertIn('Enter your VPN login', str(error.exception))

    def test_other_failures_are_not_flagged_as_missing_secrets(self):
        response = subprocess.CompletedProcess([], 4, '', 'Error: Connection activation failed: No valid secrets')
        message = vpn.nm_failure('Error: Connection activation failed: Unknown reason')
        self.assertNotIn('Enter your VPN login', message)
        self.assertFalse(MISSING_SECRETS.search('Error: Connection activation failed: Unknown reason'))
        self.assertTrue(MISSING_SECRETS.search(response.stderr))

    def test_pty_reason_is_read_past_the_prompt_it_follows(self):
        output = ('You need to authenticate to access the Virtual Private Network “probe”.\n'
                  '\x1b[?2004hCertificate password (vpn.secrets.cert-pass): \x1b[?2004l\r'
                  'Error: Connection activation failed: Unknown reason\n')
        message = vpn.nm_failure(output)
        self.assertIn('Connection activation failed: Unknown reason', message)
        self.assertNotIn('vpn.secrets.cert-pass', message)
        self.assertNotIn('\x1b', message)

    def test_nm_failure_reports_the_actual_reason(self):
        response = subprocess.CompletedProcess([], 1, '', 'Error: <ca>:error:0480006A:asn1 encoding routines::CMS decryption failed')
        with patch.object(vpn.subprocess, 'run', return_value=response):
            with self.assertRaises(vpn.VpnError) as error:
                vpn.nmcli('connection', 'import', 'file', '/tmp/a.ovpn')
        self.assertIn('CMS decryption failed', str(error.exception))

    def test_missing_openvpn_support_names_the_package(self):
        response = subprocess.CompletedProcess([], 1, '', 'Error: failed to load VPN plugin: unknown VPN plugin "org.freedesktop.NetworkManager.openvpn".')
        with patch.object(vpn.subprocess, 'run', return_value=response):
            with self.assertRaises(vpn.VpnError) as error:
                vpn.nmcli('connection', 'import', 'file', '/tmp/a.ovpn')
        self.assertIn('networkmanager-openvpn', str(error.exception))

    def test_failure_without_diagnostics_keeps_generic_guidance(self):
        response = subprocess.CompletedProcess([], 1, '', '   \n')
        with patch.object(vpn.subprocess, 'run', return_value=response):
            with self.assertRaises(vpn.VpnError) as error:
                vpn.nmcli('connection', 'import')
        self.assertIn('Check the VPN file', str(error.exception))

    def test_certificate_material_in_diagnostics_is_redacted(self):
        payload = 'MIIDdzCCAl+gAwIBAgIEAAAABDAKBggqhkjOPQQDAjA='
        response = subprocess.CompletedProcess([], 1, '', f'Error: cannot parse -----BEGIN CERTIFICATE-----{payload}-----END CERTIFICATE-----')
        with patch.object(vpn.subprocess, 'run', return_value=response):
            with self.assertRaises(vpn.VpnError) as error:
                vpn.nmcli('connection', 'import')
        message = str(error.exception)
        self.assertNotIn(payload, message)
        self.assertNotIn('BEGIN CERTIFICATE', message)
        self.assertIn('cannot parse', message)

    def test_subprocess_arguments_are_not_shell_interpolated(self):
        response = subprocess.CompletedProcess([], 0, 'OK', '')
        with patch.object(vpn.subprocess, 'run', return_value=response) as command:
            vpn.nmcli('connection', 'import', 'file', '/tmp/a ; $file.ovpn')
        self.assertEqual(command.call_args.args[0][-1], '/tmp/a ; $file.ovpn')
        self.assertNotIn('shell', command.call_args.kwargs)

    def test_network_unavailable_keeps_saved_profiles(self):
        self.import_sample()
        with patch.object(vpn, 'nmcli', side_effect=vpn.VpnError('NetworkManager unavailable')):
            result = vpn.status(self.root)
        self.assertFalse(result['stateKnown'])
        self.assertEqual(len(result['profiles']), 1)

    def test_oversized_input_and_corrupt_state(self):
        with patch.object(vpn, 'MAX_FILE_BYTES', 1):
            with self.assertRaises(vpn.VpnError):
                vpn.import_profile(self.root, self.source)
        (self.root / 'state.json').write_text('{broken')
        with self.assertRaises(vpn.VpnError):
            vpn.load_state(self.root)

    def test_custom_name_on_import_and_rename_survives_reload(self):
        with patch.object(vpn, 'nmcli', return_value=f'Imported ({UUID1})'):
            vpn.import_profile(self.root, self.source, '  Office VPN  ')
        self.assertEqual(vpn.load_state(self.root)['profiles'][0]['name'], 'Office VPN')
        with patch.object(vpn, 'nmcli') as command:
            vpn.rename_profile(self.root, UUID1, 'Home · India')
            command.assert_not_called()
        self.assertEqual(vpn.load_state(self.root)['profiles'][0]['name'], 'Home · India')

    def test_bad_name_is_rejected_before_import(self):
        for name in ('', '   ', 'x' * 65, 'VPN\nname', 'bad\x00name'):
            with patch.object(vpn, 'nmcli') as command:
                with self.assertRaises(vpn.VpnError):
                    vpn.import_profile(self.root, self.source, name)
                command.assert_not_called()

    def test_remove_deletes_managed_connection_and_saved_files_only(self):
        profile = self.import_sample()
        with patch.object(vpn, 'nmcli', side_effect=[UUID1 + '\n', 'deleted']) as command:
            vpn.remove_profile(self.root, UUID1)
        self.assertEqual(command.call_args.args, ('connection', 'delete', 'uuid', UUID1))
        self.assertFalse(Path(profile['directory']).exists())
        self.assertTrue(self.source.exists())
        self.assertEqual(vpn.load_state(self.root), {'selected': '', 'profiles': []})

    def test_remove_failure_preserves_profile_and_files(self):
        profile = self.import_sample()
        with patch.object(vpn, 'nmcli', side_effect=[UUID1 + '\n', vpn.VpnError('denied')]):
            with self.assertRaises(vpn.VpnError):
                vpn.remove_profile(self.root, UUID1)
        self.assertTrue(Path(profile['directory']).exists())
        self.assertEqual(vpn.load_state(self.root)['selected'], UUID1)

    def test_remove_already_deleted_connection_cleans_saved_copy(self):
        profile = self.import_sample()
        with patch.object(vpn, 'nmcli', return_value='') as command:
            vpn.remove_profile(self.root, UUID1)
        self.assertEqual(command.call_count, 1)
        self.assertFalse(Path(profile['directory']).exists())

    def test_remove_refuses_directory_outside_storage(self):
        self.import_sample()
        state = vpn.load_state(self.root)
        state['profiles'][0]['directory'] = str(self.base)
        vpn.save_state(self.root, state)
        with patch.object(vpn, 'nmcli') as command:
            with self.assertRaises(vpn.VpnError):
                vpn.remove_profile(self.root, UUID1)
            command.assert_not_called()
        self.assertTrue(self.source.exists())

    def test_reset_forgets_legacy_and_removes_managed_profiles(self):
        managed = self.import_sample()
        state = vpn.load_state(self.root)
        state['profiles'].append({'uuid': UUID2, 'name': 'Existing VPN', 'existing': True})
        vpn.save_state(self.root, state)
        with patch.object(vpn, 'nmcli', side_effect=[UUID1 + '\n' + UUID2 + '\n', 'deleted']) as command:
            vpn.reset_profiles(self.root)
        self.assertEqual(command.call_count, 2)
        self.assertFalse(Path(managed['directory']).exists())
        self.assertEqual(vpn.load_state(self.root), {'selected': '', 'profiles': []})

    def test_import_defaults_to_split_tunneling_for_both_ip_versions(self):
        with patch.object(vpn, 'nmcli', return_value=f'Imported ({UUID1})') as command:
            vpn.import_profile(self.root, self.source)
        self.assertEqual(command.call_args.args, ('connection', 'modify', 'uuid', UUID1,
                         'ipv4.never-default', 'yes', 'ipv6.never-default', 'yes'))
        self.assertFalse(vpn.load_state(self.root)['profiles'][0]['routingPending'])

    def test_full_tunnel_can_be_selected_explicitly(self):
        with patch.object(vpn, 'nmcli', return_value=f'Imported ({UUID1})') as command:
            vpn.import_profile(self.root, self.source, split_tunnel=False)
        self.assertEqual(command.call_args.args, ('connection', 'modify', 'uuid', UUID1,
                         'ipv4.never-default', 'no', 'ipv6.never-default', 'no'))

    def test_failed_route_setup_keeps_profile_pending_and_recoverable(self):
        with patch.object(vpn, 'nmcli', side_effect=[f'Imported ({UUID1})', vpn.VpnError('denied')]):
            with self.assertRaises(vpn.VpnError):
                vpn.import_profile(self.root, self.source)
        profile = vpn.load_state(self.root)['profiles'][0]
        self.assertTrue(profile['routingPending'])
        self.assertTrue(Path(profile['directory']).exists())
        with patch.object(vpn, 'nmcli', side_effect=['', '']):
            vpn.configure_split(self.root, UUID1, True)
        self.assertFalse(vpn.load_state(self.root)['profiles'][0]['routingPending'])

    def test_routing_change_requires_disconnected_vpn(self):
        self.import_sample()
        with patch.object(vpn, 'nmcli', return_value=UUID1 + '\n') as command:
            with self.assertRaisesRegex(vpn.VpnError, 'Disconnect'):
                vpn.configure_split(self.root, UUID1, True)
        self.assertEqual(command.call_count, 1)

    def test_status_reads_real_networkmanager_split_setting(self):
        self.import_sample()
        with patch.object(vpn, 'nmcli', side_effect=[UUID1 + '\n', 'yes\nyes\n']):
            self.assertTrue(vpn.status(self.root)['splitTunnel'])
        with patch.object(vpn, 'nmcli', side_effect=['', 'no\nno\n']):
            self.assertFalse(vpn.status(self.root)['splitTunnel'])


class CredentialsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'data'
        vpn.private_dir(self.root)
        vpn.save_state(self.root, {'selected': UUID1, 'profiles': [{'uuid': UUID1, 'name': 'Office VPN'}]})

    def test_secrets_are_read_as_two_lines_and_never_arguments(self):
        answers = {'vpn.secrets.password': 'first', 'vpn.secrets.cert-pass': 'second'}
        with patch.object(vpn, 'nmcli_ask', return_value=(0, '')) as ask:
            vpn.connect_profile(self.root, answers)
        command = ask.call_args.args[0]
        self.assertEqual(command, ('connection', 'up', 'uuid', UUID1))
        self.assertEqual(ask.call_args.args[1], answers)
        self.assertNotIn('first', repr(ask.call_args))

    def test_read_secrets_takes_a_password_and_an_optional_passphrase(self):
        with patch('sys.stdin', io.StringIO('hunter2\n\n')):
            self.assertEqual(vpn.read_secrets(), ('hunter2', ''))
        with patch('sys.stdin', io.StringIO('hunter2\np12pass\n')):
            self.assertEqual(vpn.read_secrets(), ('hunter2', 'p12pass'))

    def test_empty_stdin_is_rejected_before_asking(self):
        with patch('sys.stdin', io.StringIO('')):
            with self.assertRaises(vpn.VpnError):
                vpn.read_secrets()

    def test_answered_prompts_reach_nmcli_in_order(self):
        stub = self.base / 'ask-stub'
        stub.write_text(ASK_STUB)
        stub.chmod(0o755)
        with patch.object(vpn, 'NMCLI', str(stub)):
            code, output = vpn.nmcli_ask(('connection', 'up', 'uuid', UUID1),
                                        {'vpn.secrets.password': 'first', 'vpn.secrets.cert-pass': 'second'})
        self.assertEqual(code, 4)
        self.assertIn('<first>', output)
        self.assertIn('<second>', output)
        self.assertLess(output.index('<first>'), output.index('<second>'))

    def test_unanswered_prompt_is_answered_with_a_blank_line(self):
        stub = self.base / 'ask-stub'
        stub.write_text(ASK_STUB)
        stub.chmod(0o755)
        with patch.object(vpn, 'NMCLI', str(stub)):
            code, output = vpn.nmcli_ask(('connection', 'up', 'uuid', UUID1), {'vpn.secrets.password': 'only'})
        self.assertEqual(code, 4)
        self.assertIn('<only>', output)
        self.assertIn('<>', output)

    def test_missing_secrets_after_answering_asks_for_the_login_again(self):
        with patch.object(vpn, 'nmcli_ask', return_value=(4, 'Error: Connection activation failed: No valid secrets')):
            with self.assertRaises(vpn.VpnError) as error:
                vpn.connect_profile(self.root, {'vpn.secrets.password': 'x', 'vpn.secrets.cert-pass': ''})
        self.assertTrue(error.exception.needs_secrets)

    def test_connect_action_reports_missing_secrets_to_the_widget(self):
        answers = {'vpn.secrets.password': 'x', 'vpn.secrets.cert-pass': ''}
        with patch.object(vpn, 'data_root', return_value=self.root), \
                patch('sys.stdin', io.StringIO('x\n\n')), \
                patch('sys.argv', ['vpn.py', 'connect-ask']), \
                patch.object(vpn, 'nmcli_ask', return_value=(4, 'Error: Connection activation failed: No valid secrets')), \
                io.StringIO() as output, contextlib.redirect_stdout(output):
            code = vpn.main()
            printed = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertTrue(printed['needsSecrets'])
        self.assertEqual(answers['vpn.secrets.cert-pass'], '')

    def test_connect_requires_a_profile_and_respects_pending_routing(self):
        vpn.save_state(self.root, {'selected': '', 'profiles': []})
        with patch.object(vpn, 'nmcli') as command:
            with self.assertRaises(vpn.VpnError):
                vpn.connect_profile(self.root)
        command.assert_not_called()
        vpn.save_state(self.root, {'selected': UUID1, 'profiles': [{'uuid': UUID1, 'name': 'x', 'routingPending': True}]})
        with patch.object(vpn, 'nmcli') as command:
            with self.assertRaises(vpn.VpnError):
                vpn.connect_profile(self.root)
        command.assert_not_called()


if __name__ == '__main__':
    unittest.main()
