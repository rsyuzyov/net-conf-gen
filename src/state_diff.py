"""HTML diff между scan_state.json и история изменений конкретного хоста.

CLI:
    python -m src.state_diff diff <prev.json> <curr.json> [--out diff.html]
    python -m src.state_diff history <ip> [--out history.html] [--state-dir output/<domain>]

Также используется из ReportGenerator: генерирует scan_diff.html на основе
последнего бэкапа из output/<domain>/backups/.
"""
import argparse
import glob
import html as html_lib
import json
import os
import re
import sys
from datetime import datetime

# Поля, которые сравниваем напрямую (плоские значения)
SCALAR_FIELDS = (
    'hostname', 'category', 'type', 'os_type', 'os', 'vendor', 'model', 'mac',
    'scan_status', 'auth_method', 'user', 'kernel_version', 'distribution',
)

# Поля-коллекции — сравниваем по списку/набору с компактным выводом
LIST_FIELDS = ('open_ports', 'services', 'auth_methods', 'hostnames')

# Поля-словари — выводим как глубокий diff (added/removed/changed ports)
DICT_FIELDS = ('web_probes', 'service_details')

# Какие поля внутри web_probes/service_details показывать
WEB_PROBE_FIELDS = ('server', 'title', 'status_code', 'location', 'www_authenticate', 'auth_scheme', 'content_type', 'tls_subject', 'tls_issuer', 'device_vendor', 'device_model', 'device_family')
SERVICE_DETAIL_FIELDS = ('name', 'product', 'version', 'extrainfo')

BACKUP_NAME_RE = re.compile(r'scan_state_(\d{8})-(\d{6})\.json$')


def load_state(path):
    """Загружает scan_state.json (новый формат с meta+hosts или старый плоский)."""
    with open(path, 'r', encoding='utf-8') as f:
        raw = json.load(f)
    if isinstance(raw, dict) and 'hosts' in raw and 'meta' in raw:
        return raw.get('hosts') or {}, raw.get('meta') or {}
    if isinstance(raw, dict):
        return raw, {}
    return {}, {}


def _normalize_list(value):
    if not value:
        return []
    if isinstance(value, list):
        return sorted(str(v) for v in value if v not in (None, ''))
    return [str(value)]


def _dict_keys(value):
    if isinstance(value, dict):
        return sorted(str(k) for k in value.keys())
    return []


def _diff_inner_fields(old_dict, new_dict, fields):
    """Возвращает список (field, ov, nv) для непустых отличий между двумя dict."""
    result = []
    for f in fields:
        ov = old_dict.get(f) if isinstance(old_dict, dict) else None
        nv = new_dict.get(f) if isinstance(new_dict, dict) else None
        if (ov or '') != (nv or ''):
            result.append((f, ov or '', nv or ''))
    return result


def _summary_for_port(port_dict, fields):
    """Краткая сводка по записи (server + title) для added/removed строк."""
    if not isinstance(port_dict, dict):
        return ''
    parts = []
    for f in fields:
        v = port_dict.get(f)
        if v:
            parts.append(f'{f}={v}')
            if len(parts) >= 3:
                break
    return '; '.join(str(p) for p in parts)


def diff_dict_field(old_dict, new_dict, inner_fields):
    """Глубокий diff для словарей вроде web_probes/service_details.
    Возвращает list of (status, port_key, payload):
      - ('added', port, summary_str)
      - ('removed', port, summary_str)
      - ('changed', port, [(field, ov, nv), ...])
    """
    old_dict = old_dict or {}
    new_dict = new_dict or {}
    old_keys = {str(k) for k in old_dict.keys()}
    new_keys = {str(k) for k in new_dict.keys()}
    result = []
    for key in sorted(new_keys - old_keys, key=lambda x: (int(x) if str(x).isdigit() else 0, x)):
        result.append(('added', key, _summary_for_port(new_dict.get(key) or new_dict.get(int(key)) if str(key).isdigit() else new_dict.get(key), inner_fields)))
    for key in sorted(old_keys - new_keys, key=lambda x: (int(x) if str(x).isdigit() else 0, x)):
        result.append(('removed', key, _summary_for_port(old_dict.get(key) or old_dict.get(int(key)) if str(key).isdigit() else old_dict.get(key), inner_fields)))
    for key in sorted(old_keys & new_keys, key=lambda x: (int(x) if str(x).isdigit() else 0, x)):
        ov = old_dict.get(key) if key in old_dict else old_dict.get(int(key)) if str(key).isdigit() else None
        nv = new_dict.get(key) if key in new_dict else new_dict.get(int(key)) if str(key).isdigit() else None
        inner = _diff_inner_fields(ov, nv, inner_fields)
        if inner:
            result.append(('changed', key, inner))
    return result


def diff_auth_attempts(old_attempts, new_attempts):
    """Возвращает (old_count, new_count, [(idx, status, attempt)]) — новые/изменившиеся попытки."""
    old_attempts = old_attempts or []
    new_attempts = new_attempts or []
    return (len(old_attempts), len(new_attempts), list(new_attempts))


def diff_host(old, new):
    """Сравнивает два host-record. Возвращает dict со списками изменений по типам полей."""
    scalar = []
    for field in SCALAR_FIELDS:
        ov = old.get(field, '') or ''
        nv = new.get(field, '') or ''
        if ov != nv:
            scalar.append((field, ov, nv))

    lists = []
    for field in LIST_FIELDS:
        ov = _normalize_list(old.get(field))
        nv = _normalize_list(new.get(field))
        if ov != nv:
            lists.append((field, ', '.join(ov), ', '.join(nv)))

    web_probes_diff = diff_dict_field(old.get('web_probes'), new.get('web_probes'), WEB_PROBE_FIELDS)
    service_details_diff = diff_dict_field(old.get('service_details'), new.get('service_details'), SERVICE_DETAIL_FIELDS)

    old_attempts = old.get('auth_attempts') or []
    new_attempts = new.get('auth_attempts') or []
    attempts_changed = old_attempts != new_attempts

    has_any = bool(scalar or lists or web_probes_diff or service_details_diff or attempts_changed)
    return {
        'scalar': scalar,
        'lists': lists,
        'web_probes': web_probes_diff,
        'service_details': service_details_diff,
        'auth_attempts': (old_attempts, new_attempts) if attempts_changed else None,
        'has_any': has_any,
    }


def diff_states(old_hosts, new_hosts):
    """Возвращает {added: [ip], removed: [ip], changed: [(ip, hostname, host_diff)]}.
    host_diff — dict из diff_host."""
    old_ips = set(old_hosts.keys())
    new_ips = set(new_hosts.keys())
    added = sorted(new_ips - old_ips, key=_ip_sort_key)
    removed = sorted(old_ips - new_ips, key=_ip_sort_key)
    changed = []
    for ip in sorted(old_ips & new_ips, key=_ip_sort_key):
        host_diff = diff_host(old_hosts[ip], new_hosts[ip])
        if host_diff['has_any']:
            hostname = new_hosts[ip].get('hostname') or old_hosts[ip].get('hostname') or ''
            changed.append((ip, hostname, host_diff))
    return {'added': added, 'removed': removed, 'changed': changed}


def _ip_sort_key(ip):
    try:
        return tuple(int(part) for part in str(ip).split('.'))
    except (ValueError, AttributeError):
        return (0, 0, 0, 0)


def _esc(value):
    if value is None:
        return ''
    return html_lib.escape(str(value))


def _render_scalar_rows(changes):
    return ''.join(
        f'<tr><td>{_esc(f)}</td><td class="old">{_esc(ov)}</td><td class="new">{_esc(nv)}</td></tr>'
        for f, ov, nv in changes
    )


def _render_dict_diff(title, dict_diff):
    if not dict_diff:
        return ''
    rows = []
    for status, key, payload in dict_diff:
        if status == 'added':
            rows.append(
                f'<tr><td class="port added">+ {_esc(key)}</td>'
                f'<td colspan="2">{_esc(payload) or "<span class=muted>(пусто)</span>"}</td></tr>'
            )
        elif status == 'removed':
            rows.append(
                f'<tr><td class="port removed">− {_esc(key)}</td>'
                f'<td colspan="2">{_esc(payload) or "<span class=muted>(пусто)</span>"}</td></tr>'
            )
        else:  # changed
            inner = ''.join(
                f'<tr class="inner"><td>{_esc(f)}</td><td class="old">{_esc(ov)}</td><td class="new">{_esc(nv)}</td></tr>'
                for f, ov, nv in payload
            )
            rows.append(
                f'<tr><td class="port changed" rowspan="{len(payload) + 1}">~ {_esc(key)}</td>'
                f'<td colspan="2" class="muted">изменены поля:</td></tr>' + inner
            )
    return f'<tr class="section"><td colspan="3"><b>{_esc(title)}</b></td></tr>' + ''.join(rows)


def _render_auth_attempts(payload):
    if not payload:
        return ''
    old_attempts, new_attempts = payload
    new_rows = ''.join(
        f'<tr><td>{i + 1}</td><td>{_esc(a.get("method", ""))}</td>'
        f'<td>{_esc(a.get("user", ""))}</td><td>{_esc(a.get("status", ""))}</td>'
        f'<td class="error">{_esc((a.get("error", "") or "")[:200])}</td></tr>'
        for i, a in enumerate(new_attempts)
    )
    return (
        '<tr class="section"><td colspan="3"><b>auth_attempts</b> '
        f'<span class="muted">(было {len(old_attempts)}, стало {len(new_attempts)})</span></td></tr>'
        '<tr><td colspan="3"><table class="attempts"><thead>'
        '<tr><th>#</th><th>method</th><th>user</th><th>status</th><th>error</th></tr>'
        f'</thead><tbody>{new_rows}</tbody></table></td></tr>'
    )


def render_diff_html(diff, meta_old, meta_new, old_label='previous', new_label='current'):
    added, removed, changed = diff['added'], diff['removed'], diff['changed']
    transitions = {}
    for _, _, host_diff in changed:
        for field, ov, nv in host_diff['scalar']:
            if field in ('scan_status', 'category', 'type', 'os_type'):
                key = (field, ov or '∅', nv or '∅')
                transitions[key] = transitions.get(key, 0) + 1

    sum_rows = ''.join(
        f'<tr><td>{_esc(field)}</td><td>{_esc(ov)}</td><td>{_esc(nv)}</td><td class="num">{count}</td></tr>'
        for (field, ov, nv), count in sorted(transitions.items(), key=lambda x: (x[0][0], -x[1]))
    ) or '<tr><td colspan="4" class="muted">переходов нет</td></tr>'

    added_rows = ''.join(f'<tr><td>{_esc(ip)}</td></tr>' for ip in added)
    removed_rows = ''.join(f'<tr><td>{_esc(ip)}</td></tr>' for ip in removed)

    changed_blocks = []
    for ip, hostname, host_diff in changed:
        parts = []
        if host_diff['scalar']:
            parts.append(
                '<tr class="section"><td colspan="3"><b>основные поля</b></td></tr>'
                + _render_scalar_rows(host_diff['scalar'])
            )
        if host_diff['lists']:
            parts.append(
                '<tr class="section"><td colspan="3"><b>списки</b></td></tr>'
                + _render_scalar_rows(host_diff['lists'])
            )
        if host_diff['web_probes']:
            parts.append(_render_dict_diff('web_probes', host_diff['web_probes']))
        if host_diff['service_details']:
            parts.append(_render_dict_diff('service_details', host_diff['service_details']))
        if host_diff['auth_attempts']:
            parts.append(_render_auth_attempts(host_diff['auth_attempts']))

        change_count = (
            len(host_diff['scalar']) + len(host_diff['lists'])
            + len(host_diff['web_probes']) + len(host_diff['service_details'])
            + (1 if host_diff['auth_attempts'] else 0)
        )

        changed_blocks.append(
            f'<details class="host"><summary><span class="ip">{_esc(ip)}</span> '
            f'<span class="hostname">{_esc(hostname)}</span> '
            f'<span class="count">{change_count}</span></summary>'
            f'<table class="kv">{"".join(parts)}</table></details>'
        )

    return f"""<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="utf-8"><title>State diff</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 1200px; margin: 1rem auto; padding: 0 1rem; color: #222; }}
  h1, h2 {{ margin-top: 1.5rem; }}
  .meta {{ background: #f5f5f5; padding: .5rem 1rem; border-radius: 4px; font-size: .9rem; }}
  table {{ border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; }}
  th, td {{ padding: .25rem .5rem; text-align: left; border-bottom: 1px solid #eee; font-size: .9rem; vertical-align: top; }}
  th {{ background: #fafafa; }}
  .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  .muted {{ color: #888; }}
  details.host {{ margin: .25rem 0; padding: .25rem .5rem; background: #fafafa; border-radius: 4px; }}
  details.host[open] {{ background: #fff8e0; }}
  details.host summary {{ cursor: pointer; }}
  .ip {{ font-family: ui-monospace, Consolas, monospace; font-weight: 600; }}
  .hostname {{ color: #555; margin: 0 .5rem; }}
  .count {{ float: right; background: #ddd; padding: 0 .4rem; border-radius: 8px; font-size: .8rem; }}
  table.kv {{ margin-left: 1.5rem; max-width: 1000px; border: 1px solid #eee; }}
  table.kv td:first-child {{ font-family: ui-monospace, Consolas, monospace; color: #555; width: 14rem; }}
  table.kv tr.section td {{ background: #f0f0f0; padding-top: .5rem; }}
  table.kv tr.inner td:first-child {{ padding-left: 2rem; color: #777; }}
  td.old {{ background: #ffeaea; font-family: ui-monospace, Consolas, monospace; }}
  td.new {{ background: #eaffea; font-family: ui-monospace, Consolas, monospace; }}
  td.port {{ font-weight: 600; }}
  td.port.added {{ color: #1a7a1a; background: #eaffea; }}
  td.port.removed {{ color: #a02020; background: #ffeaea; }}
  td.port.changed {{ color: #8a6a00; background: #fff4d0; }}
  table.attempts {{ margin: 0; }}
  table.attempts td.error {{ color: #888; font-size: .85rem; }}
  .added {{ color: #2a7a2a; }}
  .removed {{ color: #a02020; }}
</style></head>
<body>
<h1>Сравнение состояний</h1>
<div class="meta">
  <div><b>{_esc(old_label)}</b>: last_scan = {_esc(meta_old.get('last_scan', '—'))}</div>
  <div><b>{_esc(new_label)}</b>: last_scan = {_esc(meta_new.get('last_scan', '—'))}</div>
  <div>добавлено <span class="added">{len(added)}</span>, удалено <span class="removed">{len(removed)}</span>, изменено {len(changed)}</div>
</div>

<h2>Сводка переходов (scan_status / category / type / os_type)</h2>
<table>
  <thead><tr><th>поле</th><th>было</th><th>стало</th><th class="num">кол-во</th></tr></thead>
  <tbody>{sum_rows}</tbody>
</table>

<h2>Добавлено хостов: {len(added)}</h2>
{('<table><thead><tr><th>IP</th></tr></thead><tbody>' + added_rows + '</tbody></table>') if added else '<p class="muted">нет</p>'}

<h2>Удалено хостов: {len(removed)}</h2>
{('<table><thead><tr><th>IP</th></tr></thead><tbody>' + removed_rows + '</tbody></table>') if removed else '<p class="muted">нет</p>'}

<h2>Изменено хостов: {len(changed)}</h2>
<p class="muted">Клик по строке раскрывает поля. Слева — старое значение, справа — новое. Для web_probes показан глубокий diff по портам.</p>
{''.join(changed_blocks) if changed_blocks else '<p class="muted">нет</p>'}

</body></html>"""


def render_history_html(ip, snapshots):
    """snapshots: список (label, host_dict). Сортированный по времени."""
    if not snapshots:
        return f'<html><body><p>No snapshots for {_esc(ip)}</p></body></html>'

    blocks = []
    prev = None
    for label, host in snapshots:
        rows = []
        for field in SCALAR_FIELDS + LIST_FIELDS:
            value = host.get(field) if isinstance(host, dict) else None
            if isinstance(value, list):
                display = ', '.join(_normalize_list(value)) or '—'
            else:
                display = str(value) if value not in (None, '') else '—'
            cell_class = ''
            if prev is not None:
                ov = prev.get(field)
                if isinstance(ov, list) or isinstance(value, list):
                    if _normalize_list(ov) != _normalize_list(value):
                        cell_class = ' class="diff"'
                elif (ov or '') != (value or ''):
                    cell_class = ' class="diff"'
            rows.append(f'<tr><td>{_esc(field)}</td><td{cell_class}>{_esc(display)}</td></tr>')

        # Сводка по web_probes
        wp_keys = _dict_keys(host.get('web_probes') if isinstance(host, dict) else None)
        rows.append(f'<tr><td>web_probes (порты)</td><td>{_esc(", ".join(wp_keys)) or "—"}</td></tr>')

        blocks.append(
            f'<details class="snapshot" open><summary><b>{_esc(label)}</b></summary>'
            f'<table class="kv">{"".join(rows)}</table></details>'
        )
        prev = host if isinstance(host, dict) else {}

    return f"""<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="utf-8"><title>История {_esc(ip)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 1000px; margin: 1rem auto; padding: 0 1rem; }}
  h1 {{ margin-top: 0; }}
  details.snapshot {{ margin: .5rem 0; padding: .25rem .5rem; background: #fafafa; border-radius: 4px; }}
  details.snapshot summary {{ cursor: pointer; padding: .25rem 0; }}
  table.kv {{ border-collapse: collapse; margin: .25rem 0 .5rem 1.5rem; }}
  table.kv td {{ padding: .15rem .5rem; border-bottom: 1px solid #eee; font-size: .9rem; }}
  table.kv td:first-child {{ font-family: ui-monospace, Consolas, monospace; color: #555; width: 14rem; }}
  td.diff {{ background: #fff4d0; }}
</style></head>
<body>
<h1>История хоста {_esc(ip)}</h1>
<p>Снимков: {len(snapshots)}. Жёлтым выделены поля, изменившиеся относительно предыдущего снимка.</p>
{''.join(blocks)}
</body></html>"""


def collect_snapshots_for_host(ip, state_dir):
    """Собирает все снимки хоста из backups/ + текущий scan_state.json. Сортирует по времени."""
    snapshots = []

    backup_dir = os.path.join(state_dir, 'backups')
    if os.path.isdir(backup_dir):
        for path in sorted(glob.glob(os.path.join(backup_dir, 'scan_state_*.json'))):
            hosts, _meta = load_state(path)
            host = hosts.get(ip)
            if host is None:
                continue
            label = _label_from_backup_name(os.path.basename(path))
            snapshots.append((label, host))

    current = os.path.join(state_dir, 'scan_state.json')
    if os.path.exists(current):
        hosts, meta = load_state(current)
        host = hosts.get(ip)
        if host is not None:
            label = f'current ({meta.get("last_scan", "—")})'
            snapshots.append((label, host))

    return snapshots


def _label_from_backup_name(filename):
    match = BACKUP_NAME_RE.search(filename)
    if not match:
        return filename
    date, time_ = match.groups()
    return f'{date[:4]}-{date[4:6]}-{date[6:8]} {time_[:2]}:{time_[2:4]}:{time_[4:6]}'


def generate_diff_html(prev_path, curr_path, out_path):
    old_hosts, old_meta = load_state(prev_path)
    new_hosts, new_meta = load_state(curr_path)
    diff = diff_states(old_hosts, new_hosts)
    html = render_diff_html(
        diff, old_meta, new_meta,
        old_label=os.path.basename(prev_path),
        new_label=os.path.basename(curr_path),
    )
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)
    return diff


def generate_history_html(ip, state_dir, out_path):
    snapshots = collect_snapshots_for_host(ip, state_dir)
    html = render_history_html(ip, snapshots)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)
    return snapshots


def find_latest_backup(state_dir):
    backup_dir = os.path.join(state_dir, 'backups')
    if not os.path.isdir(backup_dir):
        return None
    files = sorted(glob.glob(os.path.join(backup_dir, 'scan_state_*.json')))
    return files[-1] if files else None


def main(argv=None):
    parser = argparse.ArgumentParser(description='State diff and host history (HTML).')
    sub = parser.add_subparsers(dest='cmd', required=True)

    p_diff = sub.add_parser('diff', help='HTML diff между двумя scan_state.json')
    p_diff.add_argument('prev')
    p_diff.add_argument('curr')
    p_diff.add_argument('--out', default='scan_diff.html')

    p_hist = sub.add_parser('history', help='HTML история изменений хоста')
    p_hist.add_argument('ip')
    p_hist.add_argument('--state-dir', default='.', help='каталог с scan_state.json и backups/')
    p_hist.add_argument('--out', default=None)

    args = parser.parse_args(argv)

    if args.cmd == 'diff':
        diff = generate_diff_html(args.prev, args.curr, args.out)
        print(f'Diff: added={len(diff["added"])} removed={len(diff["removed"])} changed={len(diff["changed"])} -> {args.out}')
        return 0

    if args.cmd == 'history':
        out_path = args.out or f'history-{args.ip}.html'
        snapshots = generate_history_html(args.ip, args.state_dir, out_path)
        print(f'History for {args.ip}: {len(snapshots)} snapshots -> {out_path}')
        return 0


if __name__ == '__main__':
    sys.exit(main())
