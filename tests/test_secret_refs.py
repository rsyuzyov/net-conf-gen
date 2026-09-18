import subprocess
import unittest

from src.credentials import CredentialManager
from src.secret_refs import SecretResolutionError, SecretResolver


class FakeRunner:
    """Подмена subprocess.run для keepassxc-cli."""

    def __init__(self, stdout='', returncode=0, stderr=''):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr
        self.calls = []

    def __call__(self, cmd, input=None, **kwargs):
        self.calls.append({'cmd': cmd, 'input': input})
        return subprocess.CompletedProcess(cmd, self.returncode, stdout=self.stdout, stderr=self.stderr)


class SecretResolverTests(unittest.TestCase):
    def test_plain_string_is_returned_as_is(self):
        resolver = SecretResolver(environ={})
        self.assertEqual(resolver.resolve('secret'), 'secret')
        self.assertEqual(resolver.resolve(12345), '12345')
        self.assertIsNone(resolver.resolve(None))

    def test_plain_prefix_allows_literal_with_ref_prefix(self):
        resolver = SecretResolver(environ={})
        self.assertEqual(resolver.resolve('plain:env:NOT_A_REF'), 'env:NOT_A_REF')

    def test_env_reference(self):
        resolver = SecretResolver(environ={'NCG_PW': 'from-env\r\n'})
        self.assertEqual(resolver.resolve('env:NCG_PW'), 'from-env')

    def test_env_reference_missing_variable_fails_without_value(self):
        resolver = SecretResolver(environ={})
        with self.assertRaises(SecretResolutionError) as ctx:
            resolver.resolve('env:NCG_MISSING')
        self.assertIn('NCG_MISSING', str(ctx.exception))

    def test_kdbx_reference_uses_cli_with_master_on_stdin(self):
        runner = FakeRunner(stdout='vault-secret\r\n')
        resolver = SecretResolver(
            config={'secrets': {'kdbx': {'database': 'C:/vault/agent.kdbx', 'cli': 'keepassxc-cli'}}},
            environ={'NCG_KDBX_MASTER': 'master'},
            runner=runner,
        )
        self.assertEqual(resolver.resolve('kdbx:общие/agent-internal-domains'), 'vault-secret')
        # повторное обращение берётся из кэша
        self.assertEqual(resolver.resolve('kdbx:общие/agent-internal-domains'), 'vault-secret')
        self.assertEqual(len(runner.calls), 1)
        call = runner.calls[0]
        self.assertEqual(call['cmd'], ['keepassxc-cli', 'show', '-q', '-s', '-a', 'Password',
                                       'C:/vault/agent.kdbx', 'общие/agent-internal-domains'])
        self.assertEqual(call['input'], 'master\n')

    def test_kdbx_reference_with_attribute(self):
        runner = FakeRunner(stdout='login\n')
        resolver = SecretResolver(
            environ={'NCG_KDBX_MASTER': 'm', 'NCG_KDBX_DATABASE': 'db.kdbx', 'NCG_KEEPASSXC_CLI': 'cli'},
            runner=runner,
        )
        self.assertEqual(resolver.resolve('kdbx:root@host#UserName'), 'login')
        self.assertEqual(runner.calls[0]['cmd'][4:6], ['-a', 'UserName'])

    def test_kdbx_reference_error_is_reported(self):
        runner = FakeRunner(returncode=1, stderr='Could not find entry with path nope.')
        resolver = SecretResolver(
            environ={'NCG_KDBX_MASTER': 'm', 'NCG_KDBX_DATABASE': 'db.kdbx', 'NCG_KEEPASSXC_CLI': 'cli'},
            runner=runner,
        )
        with self.assertRaises(SecretResolutionError) as ctx:
            resolver.resolve('kdbx:nope')
        self.assertIn('nope', str(ctx.exception))

    def test_kdbx_reference_without_database_fails(self):
        resolver = SecretResolver(environ={'NCG_KDBX_MASTER': 'm'}, runner=FakeRunner(stdout='x'))
        with self.assertRaises(SecretResolutionError):
            resolver.resolve('kdbx:entry')

    def test_kdbx_reference_without_master_fails(self):
        resolver = SecretResolver(environ={'NCG_KDBX_DATABASE': 'db.kdbx', 'NCG_KEEPASSXC_CLI': 'cli'},
                                  runner=FakeRunner(stdout='x'))
        with self.assertRaises(SecretResolutionError):
            resolver.resolve('kdbx:entry')


class CredentialManagerSecretTests(unittest.TestCase):
    def test_references_are_resolved_and_plain_passwords_kept(self):
        resolver = SecretResolver(environ={'NCG_AGENT': 'agent-pw'})
        manager = CredentialManager([
            {'protocol': 'ssh', 'accounts': [
                {'user': 'root', 'password': 'legacy'},
                {'user': 'root', 'password': 'env:NCG_AGENT'},
                {'user': 'root', 'key_path': '/k'},
            ]},
            {'protocol': 'winrm', 'accounts': [{'user': 'dom\\agent', 'password': 'env:NCG_AGENT'}]},
        ], resolver=resolver)
        creds = {(c['type'], c['user']): c for c in manager}
        self.assertEqual(creds[('ssh', 'root')]['passwords'], ['legacy', 'agent-pw'])
        self.assertEqual(creds[('ssh', 'root')]['key_paths'], ['/k'])
        self.assertEqual(creds[('winrm', 'dom\\agent')]['passwords'], ['agent-pw'])


if __name__ == '__main__':
    unittest.main()
