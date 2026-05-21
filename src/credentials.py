class CredentialManager:
    def __init__(self, raw_credentials):
        self._credentials = self._normalize(raw_credentials)

    def _normalize(self, credentials):
        """Normalize credentials to internal flat format."""
        normalized = []
        
        # Check if we're using the new format (grouped by protocol)
        if credentials and isinstance(credentials[0], dict) and 'protocol' in credentials[0]:
            for group in credentials:
                proto = group.get('protocol')
                accounts = group.get('accounts', [])
                
                for account in accounts:
                    user = account.get('user')
                    password = account.get('password')
                    key_path = account.get('key_path')
                    use_ssh_config = proto == 'ssh' and user == 'ssh_config'

                    # Find existing entry for this user and protocol
                    existing = next((c for c in normalized
                                   if c['user'] == user and c['type'] == proto), None)


                    if not existing:
                        existing = {
                            'type': proto,
                            'user': user,
                            'passwords': [],
                            'key_paths': [],
                            'use_ssh_config': use_ssh_config,
                        }
                        normalized.append(existing)

                    if use_ssh_config:
                        existing['use_ssh_config'] = True

                    if password:
                        existing['passwords'].append(str(password))
                    if key_path:
                        existing['key_paths'].append(key_path)

        # ssh_config-credentials всегда пробуем первой попыткой
        normalized.sort(key=lambda c: 0 if c.get('use_ssh_config') else 1)
        return normalized

    def __iter__(self):
        return iter(self._credentials)

    def get_all(self):
        return self._credentials
