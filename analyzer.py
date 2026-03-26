import json
import sys

with open('output/lion.local/scan_state.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

hosts = list(data.values())

with open('analyze_result.txt', 'w', encoding='utf-8') as out:
    out.write(f"Total hosts scanned: {len(hosts)}\n\n")

    unknown_os = []
    default_names = []
    enrichment_errors = []
    no_ports = []
    hostnames_dict = {}

    for h in hosts:
        ip = h.get('ip', 'Unknown')
        hostname = h.get('hostname') or ''
        os_type = h.get('os_type') or 'Unknown'
        vendor = h.get('vendor') or ''
        ports = h.get('open_ports') or []
        
        if os_type == 'Unknown' or not os_type:
            unknown_os.append((ip, vendor))
        
        if hostname.upper().startswith('WIN-') or hostname.upper().startswith('DESKTOP-') or hostname == '' or hostname == 'localhost' or hostname.upper().startswith('MININT-'):
            default_names.append((ip, hostname))
            
        if hostname:
            hostnames_dict.setdefault(hostname.lower(), []).append(ip)

        if not ports:
            no_ports.append(ip)
            
        errs = h.get('enrichment_errors', {})
        if errs:
            if isinstance(errs, dict):
                enrichment_errors.append((ip, list(errs.items())))
            elif isinstance(errs, list):
                enrichment_errors.append((ip, errs))

    out.write(f"--- АНАЛИЗ ОТЧЕТА ---\n")
    out.write(f"1. Хосты без определенной ОС: {len(unknown_os)} шт (примеры: {unknown_os[:5]})\n")
    out.write(f"2. Дефолтные или пустые имена (WIN-*, DESKTOP-*, localhost, пустые): {len(default_names)} шт (примеры: {default_names[:5]})\n")
    out.write(f"3. Хосты вообще без открытых портов (возможно заблокированы файрволом): {len(no_ports)} шт (примеры: {no_ports[:5]})\n")
    out.write(f"4. Хосты с ошибками Enrichment (WinRM/SMB/SSH и тд): {len(enrichment_errors)} шт\n")

    for ip, errs in enrichment_errors[:5]:
        out.write(f"   IP {ip}:\n")
        if not errs:
            continue
        if isinstance(errs[0], tuple) or isinstance(errs[0], list):
            for k, v in errs:
                out.write(f"     - [{k}] {v}\n")
        else:
            for item in errs:
                out.write(f"     - {item}\n")

    if len(enrichment_errors) > 5:
        out.write("   ... (показано 5 из {})\n".format(len(enrichment_errors)))
            
    # Дубликаты MAC
    macs = {}
    for h in hosts:
        mac = h.get('mac')
        if mac and mac != '00:00:00:00:00:00':
            macs.setdefault(mac, []).append(h.get('ip'))

    dup_macs = {m: ips for m, ips in macs.items() if len(ips) > 1}
    if dup_macs:
        out.write(f"\n5. ДУБЛИКАТЫ MAC: Найдено {len(dup_macs)} повторяющихся MAC-адресов.\n")
        for m, ips in list(dup_macs.items())[:5]:
            out.write(f"   MAC {m} используется на IP: {ips}\n")

    dup_names = {n: ips for n, ips in hostnames_dict.items() if len(ips) > 1}
    if dup_names:
        out.write(f"\n6. ДУБЛИКАТЫ ИМЕН: Найдено {len(dup_names)} повторяющихся хостнеймов.\n")
        for n, ips in list(dup_names.items())[:5]:
            out.write(f"   Имя {n} на IP: {ips}\n")

    # Хосты "server" без имен
    no_name_servers = [h.get('ip') for h in hosts if h.get('type') == 'server' and not h.get('hostname')]
    if no_name_servers:
        out.write(f"\n7. Серверы без имени (hostname пустое, но тип server): {len(no_name_servers)} шт (примеры: {no_name_servers[:5]})\n")
