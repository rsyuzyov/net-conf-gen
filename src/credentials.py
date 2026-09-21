from src.secret_refs import get_default_resolver


def normalize_categories(value):
    """Список категорий хостов, на которых учётку разрешено пробовать.

    None/пусто — ограничения нет (учётка пробуется везде, как раньше).
    """
    if value is None:
        return None
    if isinstance(value, str):
        items = [part.strip() for part in value.replace(',', ' ').split()]
    else:
        items = [str(part).strip() for part in value]
    items = [item.lower() for item in items if item]
    if not items:
        return None
    return tuple(sorted(set(items)))


class CredentialManager:
    def __init__(self, raw_credentials, resolver=None):
        self._resolver = resolver or get_default_resolver()
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
                    categories = normalize_categories(account.get('categories'))
                    use_ssh_config = proto == 'ssh' and user == 'ssh_config'

                    # Find existing entry for this user, protocol and category filter
                    existing = next((c for c in normalized
                                   if c['user'] == user and c['type'] == proto
                                   and c.get('categories') == categories), None)


                    if not existing:
                        existing = {
                            'type': proto,
                            'user': user,
                            'passwords': [],
                            'key_paths': [],
                            'categories': categories,
                            'use_ssh_config': use_ssh_config,
                        }
                        normalized.append(existing)

                    if use_ssh_config:
                        existing['use_ssh_config'] = True

                    if password:
                        # env:/kdbx:-ссылка разрешается здесь; обычная строка — как есть
                        existing['passwords'].append(self._resolver.resolve(password))
                    if key_path:
                        existing['key_paths'].append(key_path)

        # ssh_config-credentials всегда пробуем первой попыткой
        normalized.sort(key=lambda c: 0 if c.get('use_ssh_config') else 1)
        return normalized

    def __iter__(self):
        return iter(self._credentials)

    def get_all(self):
        return self._credentials
