#!/usr/bin/env python3
"""
FortiGate Policy Extractor
--------------------------
Estrae le firewall policy e i relativi oggetti (address, address-group,
service, service-group, schedule, ip-pool, vip) dal backup della configurazione
FortiGate (.conf).

Utilizzo:
    python fortigate_policy_extractor.py -f fortigate.conf
    python fortigate_policy_extractor.py -f fortigate.conf --srcintf VPN --dstintf lan
    python fortigate_policy_extractor.py -f fortigate.conf --srcintf VPN --dstintf lan --output policy_report.json
    python fortigate_policy_extractor.py -f fortigate.conf --all --output all_policies.json
"""

import re
import json
import argparse
import sys
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def parse_config_blocks(text: str, block_path: str) -> list[dict]:
    """
    Estrae blocchi 'config <block_path> ... edit N ... next ... end' dal file
    e li restituisce come lista di dizionari.
    """
    # Normalizza a line list
    lines = text.splitlines()
    results = []
    depth = 0
    in_target = False
    current_entry: Optional[dict] = None
    current_key = None
    nested_depth = 0  # per sub-blocchi config dentro una entry

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if not in_target:
            # Cerca inizio del blocco desiderato
            if re.match(rf'^config\s+{re.escape(block_path)}\s*$', line):
                in_target = True
                depth = 1
        else:
            if line.startswith('config ') and current_entry is not None:
                # sub-blocco dentro una entry: raccogliamo tutto
                nested_depth += 1
                sub_key = line[7:].strip()
                sub_lines = []
                i += 1
                nd = 1
                while i < len(lines) and nd > 0:
                    sl = lines[i].strip()
                    if sl.startswith('config ') or sl == 'end':
                        if sl == 'end':
                            nd -= 1
                        else:
                            nd += 1
                    if nd > 0:
                        sub_lines.append(sl)
                    i += 1
                if current_entry is not None:
                    current_entry[f'_sub_{sub_key}'] = sub_lines
                nested_depth -= 1
                continue

            elif line.startswith('edit '):
                entry_id = line[5:].strip().strip('"')
                current_entry = {'_id': entry_id}
                current_key = None

            elif line == 'next':
                if current_entry is not None:
                    results.append(current_entry)
                current_entry = None
                current_key = None

            elif line == 'end':
                depth -= 1
                if depth == 0:
                    in_target = False
                    if current_entry is not None:
                        results.append(current_entry)
                        current_entry = None

            elif line.startswith('set ') and current_entry is not None:
                parts = line[4:].split(None, 1)
                key = parts[0]
                value = parts[1] if len(parts) > 1 else ''
                # Rimuovi eventuali virgolette iniziali/finali
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                current_entry[key] = value
                current_key = key

            elif line.startswith('unset ') and current_entry is not None:
                key = line[6:].strip()
                current_entry[key] = None

        i += 1

    return results


def parse_firewall_policies(text: str) -> list[dict]:
    return parse_config_blocks(text, 'firewall policy')


def parse_address_objects(text: str) -> dict:
    blocks = parse_config_blocks(text, 'firewall address')
    return {b['_id']: b for b in blocks}


def parse_address_groups(text: str) -> dict:
    blocks = parse_config_blocks(text, 'firewall addrgrp')
    return {b['_id']: b for b in blocks}


def parse_service_objects(text: str) -> dict:
    blocks = parse_config_blocks(text, 'firewall service custom')
    return {b['_id']: b for b in blocks}


def parse_service_groups(text: str) -> dict:
    blocks = parse_config_blocks(text, 'firewall service group')
    return {b['_id']: b for b in blocks}


def parse_schedules(text: str) -> dict:
    recurring = parse_config_blocks(text, 'firewall schedule recurring')
    onetime = parse_config_blocks(text, 'firewall schedule onetime')
    result = {}
    for b in recurring:
        result[b['_id']] = {**b, '_type': 'recurring'}
    for b in onetime:
        result[b['_id']] = {**b, '_type': 'onetime'}
    return result


def parse_vips(text: str) -> dict:
    blocks = parse_config_blocks(text, 'firewall vip')
    return {b['_id']: b for b in blocks}


def parse_ip_pools(text: str) -> dict:
    blocks = parse_config_blocks(text, 'firewall ippool')
    return {b['_id']: b for b in blocks}


def parse_zones(text: str) -> dict:
    """Estrae le zone definite dall'utente e le interfacce che le compongono."""
    blocks = parse_config_blocks(text, 'system zone')
    result = {}
    for b in blocks:
        ifaces = b.get('interface', '').split()
        result[b['_id']] = {'interfaces': ifaces, **b}
    return result


def parse_user_groups(text: str) -> dict:
    """
    Estrae i gruppi utente (config user group).
    Ogni gruppo ha: member (utenti locali), match (remote groups/server LDAP/RADIUS/FSSO).
    """
    blocks = parse_config_blocks(text, 'user group')
    result = {}
    for b in blocks:
        members_raw = b.get('member', '')
        members = members_raw.split() if members_raw else []
        result[b['_id']] = {
            'name':    b['_id'],
            'type':    b.get('group-type', 'firewall'),
            'members': members,
            'comment': b.get('comment', ''),
        }
    return result


def parse_user_local(text: str) -> dict:
    """Estrae gli utenti locali (config user local)."""
    blocks = parse_config_blocks(text, 'user local')
    return {b['_id']: b for b in blocks}


# ---------------------------------------------------------------------------
# Object resolution
# ---------------------------------------------------------------------------

def resolve_address(name: str, addresses: dict, addrgrps: dict, depth: int = 0) -> dict:
    """Risolve ricorsivamente un indirizzo o gruppo."""
    if depth > 10:
        return {'name': name, 'error': 'max recursion depth'}

    if name in addresses:
        obj = addresses[name]
        return {
            'name': name,
            'type': obj.get('type', 'ipmask'),
            'subnet': obj.get('subnet', ''),
            'fqdn': obj.get('fqdn', ''),
            'wildcard-fqdn': obj.get('wildcard-fqdn', ''),
            'comment': obj.get('comment', ''),
        }
    elif name in addrgrps:
        grp = addrgrps[name]
        members_raw = grp.get('member', '')
        members = members_raw.split() if members_raw else []
        resolved_members = [resolve_address(m, addresses, addrgrps, depth + 1) for m in members]
        return {
            'name': name,
            'type': 'group',
            'members': resolved_members,
            'comment': grp.get('comment', ''),
        }
    else:
        # Built-in come "all"
        return {'name': name, 'type': 'builtin'}


def resolve_service(name: str, services: dict, svc_groups: dict, depth: int = 0) -> dict:
    if depth > 10:
        return {'name': name, 'error': 'max recursion depth'}

    if name in services:
        obj = services[name]
        return {
            'name': name,
            'protocol': obj.get('protocol', ''),
            'tcp-portrange': obj.get('tcp-portrange', ''),
            'udp-portrange': obj.get('udp-portrange', ''),
            'comment': obj.get('comment', ''),
        }
    elif name in svc_groups:
        grp = svc_groups[name]
        members_raw = grp.get('member', '')
        members = members_raw.split() if members_raw else []
        resolved = [resolve_service(m, services, svc_groups, depth + 1) for m in members]
        return {'name': name, 'type': 'group', 'members': resolved}
    else:
        return {'name': name, 'type': 'builtin'}


# ---------------------------------------------------------------------------
# Policy enrichment
# ---------------------------------------------------------------------------

def enrich_policy(policy: dict, addresses: dict, addrgrps: dict,
                  services: dict, svc_groups: dict, schedules: dict,
                  vips: dict, ip_pools: dict, user_groups: dict = None) -> dict:
    """Arricchisce una policy con gli oggetti risolti."""
    enriched = dict(policy)

    # Source addresses
    srcaddr_raw = policy.get('srcaddr', '')
    enriched['srcaddr_resolved'] = [
        resolve_address(a, addresses, addrgrps)
        for a in srcaddr_raw.split()
    ] if srcaddr_raw else []

    # Destination addresses
    dstaddr_raw = policy.get('dstaddr', '')
    enriched['dstaddr_resolved'] = [
        resolve_address(a, addresses, addrgrps)
        for a in dstaddr_raw.split()
    ] if dstaddr_raw else []

    # Services
    service_raw = policy.get('service', '')
    enriched['service_resolved'] = [
        resolve_service(s, services, svc_groups)
        for s in service_raw.split()
    ] if service_raw else []

    # Schedule
    sched_name = policy.get('schedule', 'always')
    enriched['schedule_resolved'] = schedules.get(sched_name, {'name': sched_name, 'type': 'builtin'})

    # NAT / IP Pool
    if policy.get('nat') == 'enable' and policy.get('ippool') == 'enable':
        poolname = policy.get('poolname', '')
        enriched['ippool_resolved'] = ip_pools.get(poolname, {'name': poolname})

    # VIP (destination NAT)
    dstaddr_raw2 = policy.get('dstaddr', '')
    vip_resolved = []
    for name in dstaddr_raw2.split():
        if name in vips:
            vip_resolved.append(vips[name])
    if vip_resolved:
        enriched['vip_resolved'] = vip_resolved

    # Internet Service (ISDB) — destinazione alternativa a dstaddr
    # I campi possibili sono: internet-service, internet-service-name, internet-service-src
    # Quando presente, dstaddr è vuoto o ignorato dal FW
    isvc_ids   = policy.get('internet-service', '')
    isvc_names = policy.get('internet-service-name', '')
    isvc_src   = policy.get('internet-service-src', '')
    isvc_src_names = policy.get('internet-service-src-name', '')

    if isvc_ids or isvc_names:
        enriched['internet_service_dst'] = {
            'ids':   isvc_ids.split()   if isvc_ids   else [],
            'names': isvc_names.split() if isvc_names else [],
        }
    if isvc_src or isvc_src_names:
        enriched['internet_service_src'] = {
            'ids':   isvc_src.split()       if isvc_src       else [],
            'names': isvc_src_names.split() if isvc_src_names else [],
        }
    # Flag: usa internet-service come destinazione (invece di dstaddr)
    enriched['uses_internet_service'] = bool(isvc_ids or isvc_names)

    # User groups / users / fsso-groups
    ug = user_groups or {}
    groups_raw  = policy.get('groups', '')
    users_raw   = policy.get('users', '')
    fsso_raw    = policy.get('fsso-groups', '')

    enriched['groups_resolved'] = [
        ug.get(g, {'name': g, 'type': 'unknown'}) for g in groups_raw.split()
    ] if groups_raw else []

    enriched['users_resolved'] = [
        {'name': u, 'type': 'local_user'} for u in users_raw.split()
    ] if users_raw else []

    enriched['fsso_groups_resolved'] = [
        ug.get(g, {'name': g, 'type': 'fsso'}) for g in fsso_raw.split()
    ] if fsso_raw else []

    # Flag: la policy richiede autenticazione utente
    enriched['requires_auth'] = bool(groups_raw or users_raw or fsso_raw)

    return enriched


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def get_zone_interfaces(zone_name: str, zones: dict) -> list[str]:
    """Restituisce le interfacce fisiche associate a una zona."""
    if zone_name in zones:
        return zones[zone_name].get('interfaces', [])
    return [zone_name]  # potrebbe essere già un'interfaccia


def filter_policies(policies: list[dict],
                    srcintf: Optional[str],
                    dstintf: Optional[str],
                    zones: dict) -> list[dict]:
    """
    Filtra le policy per coppia srcintf/dstintf.
    Supporta sia interfacce fisiche che zone.
    """
    if srcintf is None and dstintf is None:
        return policies

    # Espandi zone → set di interfacce
    src_ifaces = set(get_zone_interfaces(srcintf, zones)) | {srcintf} if srcintf else None
    dst_ifaces = set(get_zone_interfaces(dstintf, zones)) | {dstintf} if dstintf else None

    filtered = []
    for p in policies:
        p_src = set(p.get('srcintf', '').split())
        p_dst = set(p.get('dstintf', '').split())

        src_match = src_ifaces is None or bool(p_src & src_ifaces)
        dst_match = dst_ifaces is None or bool(p_dst & dst_ifaces)

        if src_match and dst_match:
            filtered.append(p)

    return filtered


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Estrae le policy FortiGate e i relativi oggetti dal file di backup.'
    )
    parser.add_argument('-f', '--file', required=True, help='Path al file di configurazione FortiGate (.conf)')
    parser.add_argument('--srcintf', help='Interfaccia/zona sorgente (es. VPN, ssl.root, wan1)')
    parser.add_argument('--dstintf', help='Interfaccia/zona destinazione (es. lan, internal)')
    parser.add_argument('--all', action='store_true', dest='extract_all',
                        help='Estrae tutte le policy (ignora srcintf/dstintf)')
    parser.add_argument('--output', '-o', help='File JSON di output (default: stdout)')
    parser.add_argument('--pretty', action='store_true', default=True,
                        help='Output JSON formattato (default: True)')
    parser.add_argument('--no-resolve', action='store_true',
                        help='Non risolvere gli oggetti referenziati dalle policy')
    args = parser.parse_args()

    conf_path = Path(args.file)
    if not conf_path.exists():
        print(f"[ERROR] File non trovato: {conf_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Lettura configurazione: {conf_path}", file=sys.stderr)
    text = conf_path.read_text(encoding='utf-8', errors='replace')

    print("[*] Parsing oggetti...", file=sys.stderr)
    addresses   = parse_address_objects(text)
    addrgrps    = parse_address_groups(text)
    services    = parse_service_objects(text)
    svc_groups  = parse_service_groups(text)
    schedules   = parse_schedules(text)
    vips        = parse_vips(text)
    ip_pools    = parse_ip_pools(text)
    zones       = parse_zones(text)
    user_groups = parse_user_groups(text)
    user_local  = parse_user_local(text)
    policies    = parse_firewall_policies(text)
    print(f"[*] User groups trovati: {len(user_groups)}, utenti locali: {len(user_local)}", file=sys.stderr)

    print(f"[*] Trovate {len(policies)} policy totali.", file=sys.stderr)
    print(f"[*] Zone definite: {list(zones.keys())}", file=sys.stderr)

    # Filtro
    if not args.extract_all:
        filtered = filter_policies(policies, args.srcintf, args.dstintf, zones)
        print(f"[*] Policy dopo filtro ({args.srcintf} → {args.dstintf}): {len(filtered)}", file=sys.stderr)
    else:
        filtered = policies
        print(f"[*] Estrazione di tutte le {len(filtered)} policy.", file=sys.stderr)

    # Enrichment
    if not args.no_resolve:
        print("[*] Risoluzione oggetti...", file=sys.stderr)
        filtered = [
            enrich_policy(p, addresses, addrgrps, services, svc_groups,
                          schedules, vips, ip_pools, user_groups)
            for p in filtered
        ]

    # Output
    report = {
        'meta': {
            'source_file': str(conf_path),
            'total_policies': len(policies),
            'filtered_policies': len(filtered),
            'filter': {
                'srcintf': args.srcintf,
                'dstintf': args.dstintf,
                'all': args.extract_all,
            },
            'zones': zones,
            'user_groups': user_groups,
        },
        'policies': filtered,
    }

    indent = 2 if args.pretty else None
    json_output = json.dumps(report, indent=indent, ensure_ascii=False)

    if args.output:
        Path(args.output).write_text(json_output, encoding='utf-8')
        print(f"[✓] Output salvato in: {args.output}", file=sys.stderr)
    else:
        print(json_output)


if __name__ == '__main__':
    main()
