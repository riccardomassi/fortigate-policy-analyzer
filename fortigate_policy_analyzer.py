#!/usr/bin/env python3
"""
FortiGate Policy Analyzer v2
-----------------------------
Analizza le policy estratte da fortigate_policy_extractor.py e produce
un report raggruppato per tipologia di problema.

Utilizzo:
    python fortigate_policy_analyzer.py -i policies.json --format html -o report.html
    python fortigate_policy_analyzer.py -i policies.json
    python fortigate_policy_analyzer.py --conf backup.conf --srcintf VPN --dstintf lan --format html -o report.html
    python fortigate_policy_analyzer.py --conf backup.conf --all --format html -o report.html

    # Override interfacce internet (se non usa nomi standard):
    python fortigate_policy_analyzer.py -i policies.json --internet-intf wan1,pppoe0 --format html -o report.html
"""

import re
import json
import argparse
import sys
import ipaddress
import subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict


# ---------------------------------------------------------------------------
# Costanti
# ---------------------------------------------------------------------------

CRITICAL = 'CRITICAL'
WARNING  = 'WARNING'
INFO     = 'INFO'
OK       = 'OK'

SEVERITY_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2, OK: 3}
SEVERITY_COLOR = {CRITICAL: '#c0392b', WARNING: '#e67e22', INFO: '#2980b9', OK: '#27ae60'}
SEVERITY_EMOJI = {CRITICAL: '🔴', WARNING: '🟡', INFO: '🔵', OK: '🟢'}
SEVERITY_BG    = {CRITICAL: '#fdf2f2', WARNING: '#fef9f0', INFO: '#f0f6fd', OK: '#f0fdf4'}

# Pattern interfacce internet — sovrascrivibile via CLI.
# Logica a due livelli:
#   1. Wildcard substring: qualsiasi interfaccia che contenga "wan" nel nome
#      (es. wan1, wanVodafone, _wan2, backup_wan, wan-fibra, ecc.)
#   2. Pattern exact per nomi comuni che NON contengono "wan"
INTERNET_INTF_CONTAINS = re.compile(r'wan', re.IGNORECASE)   # wildcard *wan*

INTERNET_INTF_RE = re.compile(
    r'^(internet|untrust|outside|external|public|'
    r'pppoe\d*|vdsl\d*|adsl\d*|lte\d*|4g\d*|5g\d*)$', re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Helper: porte
# ---------------------------------------------------------------------------

def parse_port_ranges(s: str) -> list[tuple[int, int]]:
    ranges = []
    for part in s.split():
        part = part.split(':')[0]
        if '-' in part:
            a, b = part.split('-', 1)
            try:
                ranges.append((int(a), int(b)))
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                ranges.append((p, p))
            except ValueError:
                pass
    return ranges


def covers_all_ports(ranges: list[tuple[int, int]]) -> bool:
    return any(a == 0 and b >= 65535 for a, b in ranges)


def is_wide_port_range(ranges: list[tuple[int, int]], threshold: int = 1000) -> bool:
    return any((b - a) >= threshold for a, b in ranges)


def port_ranges_overlap(r1: list[tuple[int, int]], r2: list[tuple[int, int]]) -> bool:
    for a1, b1 in r1:
        for a2, b2 in r2:
            if a1 <= b2 and a2 <= b1:
                return True
    return False


# ---------------------------------------------------------------------------
# Helper: subnet / indirizzi
# ---------------------------------------------------------------------------

def is_subnet_any(subnet_str: str) -> bool:
    s = subnet_str.strip()
    return s in ('0.0.0.0 0.0.0.0', '0.0.0.0/0', '0.0.0.0/0.0.0.0', '::/0')


def subnet_prefix_len(subnet_str: str) -> int:
    s = subnet_str.strip()
    parts = s.split()
    if len(parts) == 2:
        try:
            return ipaddress.IPv4Network(f"{parts[0]}/{parts[1]}", strict=False).prefixlen
        except ValueError:
            pass
    try:
        return ipaddress.ip_network(s, strict=False).prefixlen
    except ValueError:
        return -1


def subnet_to_network(subnet_str: str):
    s = subnet_str.strip()
    parts = s.split()
    try:
        if len(parts) == 2:
            return ipaddress.IPv4Network(f"{parts[0]}/{parts[1]}", strict=False)
        return ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None


def collect_flat_addresses(resolved_list: list) -> list[dict]:
    flat = []
    for addr in resolved_list:
        if addr.get('type') == 'group':
            flat.extend(collect_flat_addresses(addr.get('members', [])))
        else:
            flat.append(addr)
    return flat


def collect_flat_services(resolved_list: list) -> list[dict]:
    flat = []
    for svc in resolved_list:
        if svc.get('type') == 'group':
            flat.extend(collect_flat_services(svc.get('members', [])))
        else:
            flat.append(svc)
    return flat


def addr_is_any(resolved_list: list) -> bool:
    flat = collect_flat_addresses(resolved_list)
    return any(
        (a.get('type') == 'builtin' and a.get('name', '').lower() in ('all', 'any'))
        or is_subnet_any(a.get('subnet', ''))
        for a in flat
    )


def addr_min_prefix(resolved_list: list) -> int:
    flat = collect_flat_addresses(resolved_list)
    min_plen = 32
    for a in flat:
        if a.get('type') == 'builtin' and a.get('name', '').lower() in ('all', 'any'):
            return 0
        plen = subnet_prefix_len(a.get('subnet', ''))
        if plen >= 0:
            min_plen = min(min_plen, plen)
    return min_plen


def service_is_any(resolved_list: list) -> bool:
    flat = collect_flat_services(resolved_list)
    for s in flat:
        if s.get('name', '').upper() in ('ALL', 'ANY'):
            return True
        for pk in ('tcp-portrange', 'udp-portrange'):
            r = parse_port_ranges(s.get(pk, ''))
            if r and covers_all_ports(r):
                return True
    return False


# ---------------------------------------------------------------------------
# Helper: classificazione interfacce
# ---------------------------------------------------------------------------

def intf_is_internet(intf_str: str) -> bool:
    """
    True se almeno una delle interfacce nella stringa è considerata internet-facing.
    Criteri (OR):
    - Il nome contiene 'wan' (case-insensitive) — wildcard *wan*
    - Corrisponde a uno dei pattern noti (pppoe, vdsl, untrust, outside, ecc.)
    """
    for iface in intf_str.split():
        if INTERNET_INTF_CONTAINS.search(iface):
            return True
        if INTERNET_INTF_RE.match(iface):
            return True
    return False


def policy_goes_to_internet(policy: dict) -> bool:
    return intf_is_internet(policy.get('dstintf', ''))


def policy_comes_from_internet(policy: dict) -> bool:
    return intf_is_internet(policy.get('srcintf', ''))


# ---------------------------------------------------------------------------
# Helper: Internet Service (ISDB)
# ---------------------------------------------------------------------------

def policy_uses_internet_service_dst(policy: dict) -> bool:
    """True se la policy usa internet-service come destinazione (non dstaddr)."""
    return policy.get('uses_internet_service', False) or bool(
        policy.get('internet-service') or policy.get('internet-service-name')
    )


def policy_uses_internet_service_src(policy: dict) -> bool:
    """True se la policy usa internet-service-src come sorgente."""
    return bool(policy.get('internet-service-src') or policy.get('internet-service-src-name'))


def iservice_dst_key(policy: dict) -> frozenset:
    """Chiave canonica per gli internet-service di destinazione."""
    names = set()
    raw_ids   = policy.get('internet-service', '')
    raw_names = policy.get('internet-service-name', '')
    if raw_ids:   names.update(raw_ids.split())
    if raw_names: names.update(raw_names.split())
    return frozenset(names)


def iservice_src_key(policy: dict) -> frozenset:
    """Chiave canonica per gli internet-service sorgente."""
    names = set()
    raw_ids   = policy.get('internet-service-src', '')
    raw_names = policy.get('internet-service-src-name', '')
    if raw_ids:   names.update(raw_ids.split())
    if raw_names: names.update(raw_names.split())
    return frozenset(names)


def dst_key_compatible(p1: dict, p2: dict) -> bool:
    """
    True se le due policy usano lo stesso TIPO di destinazione e hanno destinazioni
    confrontabili. Policy con internet-service e policy con dstaddr usano
    meccanismi completamente diversi: non si ombrano mai.
    """
    p1_isvc = policy_uses_internet_service_dst(p1)
    p2_isvc = policy_uses_internet_service_dst(p2)
    # Tipi diversi → incomparabili
    if p1_isvc != p2_isvc:
        return False
    return True


# ---------------------------------------------------------------------------
# Helper: coverage (per shadowing)
# ---------------------------------------------------------------------------

def intfs_subset(narrow: str, broad: str) -> bool:
    """
    True se TUTTE le interfacce di 'narrow' sono contenute in 'broad'
    (o 'broad' contiene 'any').
    Usare subset e non overlap evita falsi positivi quando le intf sono diverse.
    """
    sn = set(narrow.split())
    sb = set(broad.split())
    if 'any' in sb:
        return True
    if 'any' in sn:
        return False
    return sn.issubset(sb)


def addr_names_set(resolved_list: list) -> set[str]:
    """Restituisce il set dei nomi foglia (non-gruppo) di una lista di indirizzi."""
    return {a['name'] for a in collect_flat_addresses(resolved_list) if 'name' in a}


def addresses_subset(list_small: list, list_large: list) -> bool:
    """
    True se ogni indirizzo di list_small è coperto da almeno una subnet di list_large.

    Strategia a due livelli:
    1. Se i nomi coincidono esattamente → coperto (evita falsi positivi da subnet overlap).
    2. Altrimenti verifica containment subnet con ipaddress.
    Se una subnet non è parsabile → NON assume copertura (falso negativo sicuro).
    """
    if addr_is_any(list_large):
        return True
    if addr_is_any(list_small):
        return False

    flat_large = collect_flat_addresses(list_large)
    flat_small = collect_flat_addresses(list_small)

    names_large = {a.get('name', '') for a in flat_large}
    nets_large  = [(a.get('name',''), subnet_to_network(a.get('subnet', '')))
                   for a in flat_large]
    nets_large  = [(name, net) for name, net in nets_large if net is not None]

    for a_small in flat_small:
        name_s = a_small.get('name', '')

        # livello 1: nome identico → coperto
        if name_s in names_large:
            continue

        # livello 2: containment subnet
        net_s = subnet_to_network(a_small.get('subnet', ''))
        if net_s is None:
            # Non riusciamo a parsare → assumiamo NON coperto (conservativo anti-falsi-positivi)
            return False

        if not any(net_s.subnet_of(nl) for _, nl in nets_large):
            return False

    return True


def services_subset(list_small: list, list_large: list) -> bool:
    """
    True se ogni servizio di list_small è coperto da list_large.
    Confronto per nome prima, poi per range porte.
    """
    if service_is_any(list_large):
        return True
    if service_is_any(list_small):
        return False

    flat_small = collect_flat_services(list_small)
    flat_large = collect_flat_services(list_large)
    names_large = {s.get('name', '') for s in flat_large}

    for ss in flat_small:
        # nome identico → coperto
        if ss.get('name', '') in names_large:
            continue

        covered = False
        for sl in flat_large:
            for pk in ('tcp-portrange', 'udp-portrange'):
                rs = parse_port_ranges(ss.get(pk, ''))
                rl = parse_port_ranges(sl.get(pk, ''))
                if rs and rl:
                    if all(any(a2 <= a1 and b1 <= b2 for a2, b2 in rl) for a1, b1 in rs):
                        covered = True
                        break
            if covered:
                break

        if not covered:
            return False

    return True


def groups_key(policy: dict) -> frozenset:
    """
    Chiave canonica per i gruppi/utenti di una policy.
    Combina groups, users e fsso-groups in un frozenset di nomi.
    Una policy senza vincoli di gruppo ha frozenset vuoto = nessuna restrizione utente.
    """
    names = set()
    for field in ('groups', 'users', 'fsso-groups'):
        raw = policy.get(field, '')
        if raw:
            names.update(raw.split())
    return frozenset(names)


def policies_same_auth(p1: dict, p2: dict) -> bool:
    """
    True se le due policy hanno gli stessi vincoli di autenticazione utente.
    Due policy con gruppi DIVERSI NON si ombrano mai: il FortiGate le valuta
    separatamente perché richiedono identità diverse.
    """
    return groups_key(p1) == groups_key(p2)


def policy_covers(p_broad: dict, p_narrow: dict) -> bool:
    """
    True se p_broad copre completamente p_narrow su tutti gli assi:
    - interfacce (subset)
    - destinazione: stesso tipo (internet-service vs dstaddr); se internet-service,
      stesso set di servizi; se dstaddr, containment subnet
    - sorgente: indirizzi (subset) o internet-service-src (stesso set)
    - servizi (subset)
    - stessi vincoli di gruppo utente

    Regole fondamentali:
    - Policy con internet-service e policy con dstaddr NON si ombrano mai
    - Policy con status=disable vengono escluse dal confronto di shadowing
      (una policy disabilitata non può ombrane un'altra)
    """
    # Una policy disabilitata non può ombrare nulla
    if p_broad.get('status', 'enable') == 'disable':
        return False

    # I vincoli di autenticazione devono essere identici
    if not policies_same_auth(p_broad, p_narrow):
        return False

    # Le intf di p_narrow devono essere tutte presenti in p_broad
    if not intfs_subset(p_narrow.get('srcintf', ''), p_broad.get('srcintf', '')):
        return False
    if not intfs_subset(p_narrow.get('dstintf', ''), p_broad.get('dstintf', '')):
        return False

    # ── Destinazione ──
    # Se usano tipi diversi (una dstaddr, l'altra internet-service) → incomparabili
    if not dst_key_compatible(p_broad, p_narrow):
        return False

    if policy_uses_internet_service_dst(p_narrow):
        # Entrambe usano internet-service: broad deve contenere tutti i servizi di narrow
        if not iservice_dst_key(p_narrow).issubset(iservice_dst_key(p_broad)):
            return False
    else:
        # Entrambe usano dstaddr: containment subnet classico
        if not addresses_subset(p_narrow.get('dstaddr_resolved', []), p_broad.get('dstaddr_resolved', [])):
            return False

    # ── Sorgente ──
    if policy_uses_internet_service_src(p_narrow) or policy_uses_internet_service_src(p_broad):
        # Se uno usa internet-service-src e l'altro no → incomparabili
        if policy_uses_internet_service_src(p_narrow) != policy_uses_internet_service_src(p_broad):
            return False
        if not iservice_src_key(p_narrow).issubset(iservice_src_key(p_broad)):
            return False
    else:
        if not addresses_subset(p_narrow.get('srcaddr_resolved', []), p_broad.get('srcaddr_resolved', [])):
            return False

    if not services_subset(p_narrow.get('service_resolved', []), p_broad.get('service_resolved', [])):
        return False

    return True


# ---------------------------------------------------------------------------
# Check per singola policy
# ---------------------------------------------------------------------------

def check_logging(p: dict) -> list[dict]:
    lt = p.get('logtraffic', 'utm')
    if lt == 'disable':
        return [{'cat': 'LOGGING_DISABLED', 'severity': WARNING,
                 'msg': 'Logging disabilitato: impossibile fare forensics o audit sul traffico.'}]
    if lt == 'all':
        return [{'cat': 'LOGGING_ALL', 'severity': INFO,
                 'msg': 'Logging su "all": può generare un volume molto elevato di log.'}]
    return []


def check_utm(p: dict) -> list[dict]:
    """Profili UTM richiesti SOLO se la policy va verso internet."""
    if p.get('action', 'deny') != 'accept':
        return []
    if not policy_goes_to_internet(p):
        return []
    utm = {
        'av-profile':        'Antivirus',
        'webfilter-profile': 'Web Filter',
        'ips-sensor':        'IPS',
        'application-list':  'Application Control',
        'ssl-ssh-profile':   'SSL/SSH Inspection',
        'dnsfilter-profile': 'DNS Filter',
    }
    missing = [label for key, label in utm.items() if not p.get(key)]
    issues = []
    if missing:
        sev = CRITICAL if len(missing) >= 4 else WARNING
        issues.append({'cat': 'MISSING_UTM', 'severity': sev,
                       'msg': f'Policy verso internet senza profili UTM: {", ".join(missing)}.'})
    if not p.get('ssl-ssh-profile'):
        issues.append({'cat': 'NO_SSL_INSPECTION', 'severity': WARNING,
                       'msg': 'Nessun profilo SSL/SSH inspection: il traffico cifrato verso internet non è ispezionato.'})
    return issues


def check_broad_inbound(p: dict) -> list[dict]:
    """Segnala quando da internet si raggiunge una LAN molto ampia."""
    if p.get('action', 'deny') != 'accept':
        return []
    if not policy_comes_from_internet(p):
        return []
    dst = p.get('dstaddr_resolved', [])
    if addr_is_any(dst):
        return [{'cat': 'BROAD_INBOUND', 'severity': CRITICAL,
                 'msg': 'Da internet verso destinazione "any": l\'intera rete è esposta a internet.'}]
    plen = addr_min_prefix(dst)
    if 0 <= plen <= 16:
        return [{'cat': 'BROAD_INBOUND', 'severity': WARNING,
                 'msg': f'Da internet verso subnet molto ampia (/{plen}): '
                        f'limitare agli host effettivamente da esporre.'}]
    return []


def check_service_any(p: dict) -> list[dict]:
    if p.get('action', 'deny') != 'accept':
        return []
    issues = []
    svc = p.get('service_resolved', [])
    if service_is_any(svc):
        return [{'cat': 'SERVICE_ANY', 'severity': CRITICAL,
                 'msg': 'Servizio ANY/ALL: la policy permette qualsiasi protocollo e porta.'}]
    for s in collect_flat_services(svc):
        for pk in ('tcp-portrange', 'udp-portrange'):
            r = parse_port_ranges(s.get(pk, ''))
            if r and is_wide_port_range(r, 1000):
                issues.append({'cat': 'WIDE_PORT_RANGE', 'severity': WARNING,
                               'msg': f'Servizio "{s.get("name","?")}" ha un range molto ampio '
                                      f'({s.get(pk,"")}): valutare restrizione.'})
    return issues


def check_src_dst_any(p: dict) -> list[dict]:
    if p.get('action', 'deny') != 'accept':
        return []
    issues = []
    if addr_is_any(p.get('srcaddr_resolved', [])):
        issues.append({'cat': 'SRC_ANY', 'severity': WARNING,
                       'msg': 'Sorgente "any/all": traffico accettato da qualsiasi IP sorgente.'})
    if addr_is_any(p.get('dstaddr_resolved', [])):
        issues.append({'cat': 'DST_ANY', 'severity': WARNING,
                       'msg': 'Destinazione "any/all": traffico permesso verso qualsiasi destinazione.'})
    return issues


def check_disabled(p: dict) -> list[dict]:
    if p.get('status', 'enable') == 'disable':
        return [{'cat': 'POLICY_DISABLED', 'severity': WARNING,
                 'msg': 'Policy disabilitata: se non più necessaria, rimuoverla per ridurre la complessità.'}]
    return []


def check_comment(p: dict) -> list[dict]:
    name = p.get('name', '').strip()
    if not name:
        return [{'cat': 'NO_NAME', 'severity': WARNING,
                 'msg': 'La policy non ha un nome: assegnare un nome descrittivo facilita la gestione e le revisioni.'}]
    return []


def check_nat_vpn(p: dict) -> list[dict]:
    if p.get('action', 'deny') != 'accept':
        return []
    src = p.get('srcintf', '')
    if p.get('nat') == 'enable' and any(k in src.lower() for k in ('vpn', 'ssl', 'ipsec', 'tunnel')):
        return [{'cat': 'NAT_ON_VPN', 'severity': INFO,
                 'msg': 'NAT abilitato su un\'interfaccia VPN/tunnel: verificare che non mascheri gli IP client reali.'}]
    return []


def check_user_groups(p: dict) -> list[dict]:
    """
    Segnala situazioni anomale legate ai gruppi utente nelle policy.
    """
    if p.get('action', 'deny') != 'accept':
        return []

    issues = []
    groups_raw    = p.get('groups', '')
    users_raw     = p.get('users', '')
    fsso_raw      = p.get('fsso-groups', '')
    has_auth      = bool(groups_raw or users_raw or fsso_raw)

    # Policy con autenticazione utente ma source addr = any:
    # il traffico senza autenticazione non matcherà mai questa policy
    # (a meno di FSSO passivo), ma è comunque inusuale
    if has_auth and addr_is_any(p.get('srcaddr_resolved', [])):
        auth_names = ' '.join(filter(None, [groups_raw, users_raw, fsso_raw]))
        issues.append({
            'cat': 'AUTH_WITH_SRC_ANY', 'severity': INFO,
            'msg': (f'Policy con autenticazione utente ({auth_names}) e sorgente "any": '
                    f'solo gli utenti autenticati nel gruppo matcheranno. '
                    f'Verificare che sia il comportamento atteso.')
        })

    # Policy con sia groups (autenticazione attiva) che fsso-groups:
    # combinazione insolita che può generare confusione
    if groups_raw and fsso_raw:
        issues.append({
            'cat': 'MIXED_AUTH_TYPES', 'severity': INFO,
            'msg': (f'Policy con sia groups (autenticazione attiva: {groups_raw}) '
                    f'che fsso-groups (FSSO passivo: {fsso_raw}): '
                    f'verificare che la combinazione sia intenzionale.')
        })

    return issues


def check_internet_service(p: dict) -> list[dict]:
    """
    Controlli specifici per policy che usano Internet Service (ISDB).
    """
    issues = []

    uses_isvc_dst = policy_uses_internet_service_dst(p)
    uses_isvc_src = policy_uses_internet_service_src(p)

    if not uses_isvc_dst and not uses_isvc_src:
        return []

    # Policy con internet-service come destinazione + dstaddr popolato:
    # i due campi sono mutualmente esclusivi nel FW, dstaddr viene ignorato
    if uses_isvc_dst and p.get('dstaddr', '').strip() not in ('', 'all'):
        issues.append({
            'cat': 'ISVC_WITH_DSTADDR', 'severity': INFO,
            'msg': (f'La policy usa Internet Service come destinazione '
                    f'({p.get("internet-service-name", p.get("internet-service",""))}) '
                    f'ma ha anche dstaddr="{p.get("dstaddr","")}" impostato: '
                    f'quando internet-service è attivo, dstaddr viene ignorato dal FortiGate.')
        })

    # Policy con internet-service e servizi custom: il campo "service" viene ignorato
    # quando si usa internet-service (il servizio è implicito nell'ISDB)
    if uses_isvc_dst and p.get('service', '').strip() not in ('', 'ALL', 'ANY'):
        issues.append({
            'cat': 'ISVC_WITH_SERVICE', 'severity': INFO,
            'msg': (f'La policy usa Internet Service come destinazione ma ha anche '
                    f'service="{p.get("service","")}" impostato: il campo service è '
                    f'ignorato quando si usa internet-service (il servizio è incluso nell\'ISDB).')
        })

    return issues


SINGLE_CHECKS = [
    check_disabled,
    check_logging,
    check_utm,
    check_broad_inbound,
    check_service_any,
    check_src_dst_any,
    check_nat_vpn,
    check_user_groups,
    check_internet_service,
    check_comment,
]


# ---------------------------------------------------------------------------
# Check cross-policy
# ---------------------------------------------------------------------------

def check_shadowing(policies: list[dict]) -> dict[str, list[dict]]:
    """
    NEVER_MATCHES : policy ACCEPT completamente ombrata da un ACCEPT precedente più ampio.
    USELESS_DENY  : policy DENY seguita da un ACCEPT più ampio che permette comunque quel traffico.
    """
    results: dict[str, list[dict]] = defaultdict(list)
    pos = {p['_id']: i for i, p in enumerate(policies)}

    accept_enabled = [p for p in policies
                      if p.get('action', 'deny') == 'accept' and p.get('status', 'enable') == 'enable']
    deny_enabled   = [p for p in policies
                      if p.get('action', 'deny') in ('deny', 'drop') and p.get('status', 'enable') == 'enable']

    # NEVER_MATCHES
    # Nota: policy_covers esclude già le policy disabled come "broader"
    for p in accept_enabled:
        pid   = p['_id']
        p_pos = pos.get(pid, 9999)
        for broader in accept_enabled:
            if broader['_id'] == pid:
                continue
            if pos.get(broader['_id'], 9999) >= p_pos:
                continue
            if policy_covers(broader, p):
                # Nota se la policy candidata ad ombrare usa internet-service
                isvc_note = ''
                if policy_uses_internet_service_dst(broader):
                    isvc_note = ' (usa Internet Service come destinazione)'
                results[pid].append({
                    'cat': 'NEVER_MATCHES', 'severity': WARNING,
                    'msg': (f'Non sarà mai raggiunta: la policy ID {broader["_id"]}'
                            f' ("{broader.get("name","")}")'
                            f'{isvc_note}'
                            f' la precede ed è più ampia, coprendo tutto il traffico che gestirebbe.')
                })
                break

    # USELESS_DENY
    # Un DENY ha senso se esiste un ACCEPT successivo più ampio che lo giustifica
    # (senza quel DENY il traffico passerebbe). Se NON esiste nessun ACCEPT successivo
    # ABILITATO che copra il traffico, il DENY è ridondante.
    # Nota: policy_covers esclude già i broader disabled.
    # Caso speciale: se il DENY usa internet-service, il confronto è possibile
    # solo con ACCEPT che usano lo stesso tipo di destinazione.
    for p in deny_enabled:
        pid   = p['_id']
        p_pos = pos.get(pid, 9999)

        # Cerca un ACCEPT successivo abilitato che copra questo traffico
        covering_accept = None
        for broader in accept_enabled:
            if pos.get(broader['_id'], 9999) > p_pos and policy_covers(broader, p):
                covering_accept = broader
                break

        isvc_note = ''
        if policy_uses_internet_service_dst(p):
            isvc_note = ' Questa policy usa Internet Service come destinazione.'

        disabled_note = ''
        if p.get('status', 'enable') == 'disable':
            disabled_note = ' La policy è anche disabilitata.'

        if not covering_accept:
            results[pid].append({
                'cat': 'USELESS_DENY', 'severity': WARNING,
                'msg': ('Regola DENY potenzialmente ridondante: non esiste nessuna policy ACCEPT '
                        'successiva più ampia (e abilitata) che copra questo traffico. '
                        'La default-deny lo bloccherebbe comunque; valutare se questa regola '
                        f'sia necessaria.{isvc_note}{disabled_note}')
            })

    return results


def _addr_key(resolved_list: list) -> frozenset[str]:
    """
    Chiave canonica per un insieme di indirizzi: frozenset dei nomi foglia.
    Insensibile all'ordine e alla struttura dei gruppi.
    """
    return frozenset(a.get('name', '') for a in collect_flat_addresses(resolved_list))


def _svc_key(resolved_list: list) -> frozenset[str]:
    """Chiave canonica per un insieme di servizi: frozenset dei nomi foglia."""
    return frozenset(s.get('name', '') for s in collect_flat_services(resolved_list))


def _dst_canonical_key(p: dict) -> tuple:
    """
    Chiave canonica per la destinazione, distinguendo dstaddr da internet-service.
    Restituisce una tupla (tipo, frozenset) così due policy con tipo diverso
    non avranno mai la stessa chiave.
    """
    if policy_uses_internet_service_dst(p):
        return ('isvc', iservice_dst_key(p))
    else:
        return ('addr', _addr_key(p.get('dstaddr_resolved', [])))


def _src_canonical_key(p: dict) -> tuple:
    """Chiave canonica per la sorgente, distinguendo srcaddr da internet-service-src."""
    if policy_uses_internet_service_src(p):
        return ('isvc', iservice_src_key(p))
    else:
        return ('addr', _addr_key(p.get('srcaddr_resolved', [])))


def check_duplicates(policies: list[dict]) -> list[dict]:
    """
    Individua gruppi di policy duplicate confrontando:
    - srcintf / dstintf (frozenset, insensibile all'ordine)
    - sorgente: srcaddr O internet-service-src (con tipo nella chiave)
    - destinazione: dstaddr O internet-service (con tipo nella chiave)
    - servizi (frozenset nomi foglia)
    - gruppi/utenti (groups + users + fsso-groups)
    - azione

    Restituisce una lista di gruppi, ciascuno contenente tutte le policy
    del gruppo con i relativi dettagli — per visualizzazione a coppie/gruppi.

    Regole:
    - Policy con internet-service e policy con dstaddr NON sono mai duplicate
    - I gruppi con almeno una policy disabilitata vengono marcati esplicitamente
    """
    policy_map = {p['_id']: p for p in policies}
    seen: dict[tuple, list] = defaultdict(list)

    for p in policies:
        key = (
            frozenset(p.get('srcintf', '').split()),
            frozenset(p.get('dstintf', '').split()),
            _src_canonical_key(p),
            _dst_canonical_key(p),
            _svc_key(p.get('service_resolved', [])),
            groups_key(p),
            p.get('action', ''),
        )
        seen[key].append(p['_id'])

    groups = []
    for key, ids in seen.items():
        if len(ids) < 2:
            continue

        disabled_ids = [i for i in ids if policy_map.get(i, {}).get('status', 'enable') == 'disable']

        members = []
        for pid in ids:
            p = policy_map.get(pid, {})
            isvc_dst = p.get('internet-service-name', p.get('internet-service', ''))
            dst_display = f'[ISVC] {isvc_dst}' if isvc_dst else p.get('dstaddr', '')

            auth_parts = []
            if p.get('groups'):      auth_parts.append('G:' + p['groups'])
            if p.get('users'):       auth_parts.append('U:' + p['users'])
            if p.get('fsso-groups'): auth_parts.append('FSSO:' + p['fsso-groups'])

            members.append({
                'policy_id':   pid,
                'policy_name': p.get('name', ''),
                'srcintf':     p.get('srcintf', ''),
                'dstintf':     p.get('dstintf', ''),
                'action':      p.get('action', ''),
                'status':      p.get('status', 'enable'),
                'srcaddr':     p.get('srcaddr', ''),
                'dstaddr':     dst_display,
                'service':     p.get('service', ''),
                'auth':        '  '.join(auth_parts),
            })

        disabled_note = ''
        if disabled_ids:
            disabled_note = (f' Le policy {disabled_ids} sono disabilitate: '
                             f'candidate immediate alla rimozione.')

        groups.append({
            'ids':          ids,
            'members':      members,
            'disabled_ids': disabled_ids,
            'msg':          f'Gruppo di {len(ids)} policy identiche (stesse intf/src/dst/service/gruppi/azione).{disabled_note} Valutare consolidamento.',
        })

    return groups


# ---------------------------------------------------------------------------
# Metadati categorie (label, severity, descrizione)
# ---------------------------------------------------------------------------

CATEGORY_META: dict[str, tuple[str, str, str]] = {
    'LOGGING_DISABLED':  ('Logging Disabilitato',                    WARNING,
                          'Le policy seguenti hanno il logging completamente disabilitato. '
                          'Qualsiasi analisi forense o di compliance diventa impossibile.'),
    'LOGGING_ALL':       ('Logging Totale (verbose)',                 INFO,
                          'Il logging è impostato su "all": genera log anche per il traffico normale, '
                          'causando volumi molto elevati.'),
    'MISSING_UTM':       ('Profili UTM Mancanti (→ Internet)',        CRITICAL,
                          'Queste policy verso internet mancano di profili di sicurezza UTM. '
                          'Il traffico transita senza ispezione antivirus, IPS, webfilter, ecc.'),
    'NO_SSL_INSPECTION': ('SSL/SSH Inspection Assente (→ Internet)',  WARNING,
                          'Traffico verso internet senza profilo di ispezione SSL: '
                          'il contenuto cifrato (HTTPS, ecc.) non è analizzato dal firewall.'),
    'BROAD_INBOUND':     ('Accesso Inbound Troppo Ampio da Internet', CRITICAL,
                          'Policy che permettono a traffico proveniente da internet di raggiungere '
                          'subnet molto grandi o "any". Elevato rischio di esposizione.'),
    'SERVICE_ANY':       ('Servizio ANY / ALL',                       CRITICAL,
                          'Policy che permettono qualsiasi protocollo e porta. '
                          'Il principio del minimo privilegio non è rispettato.'),
    'WIDE_PORT_RANGE':   ('Range di Porte Molto Ampio (> 1000)',      WARNING,
                          'Policy con range di porte eccessivamente ampi: '
                          'valutare la restrizione ai soli servizi effettivamente necessari.'),
    'SRC_ANY':           ('Sorgente ANY / All',                       WARNING,
                          'La sorgente è impostata su "any/all": preferibile limitare '
                          'agli IP sorgente effettivi per ridurre la superficie di attacco.'),
    'DST_ANY':           ('Destinazione ANY / All',                   WARNING,
                          'La destinazione è impostata su "any/all": preferibile limitare '
                          'agli IP destinazione effettivi.'),
    'POLICY_DISABLED':   ('Policy Disabilitate',                      WARNING,
                          'Queste policy sono disabilitate. Se non più necessarie andrebbero '
                          'rimosse per ridurre la complessità del ruleset e gli errori di manutenzione.'),
    'AUTH_WITH_SRC_ANY': ('Autenticazione + Sorgente ANY',              INFO,
                          'Policy con vincolo di gruppo utente ma sorgente "any": solo gli utenti '
                          'autenticati nel gruppo matcheranno. Il traffico non autenticato non passerà '
                          '(a meno di FSSO passivo). Verificare che sia il comportamento atteso.'),
    'MIXED_AUTH_TYPES':  ('Autenticazione Attiva e FSSO Insieme',        INFO,
                          'Policy che combinano groups (autenticazione attiva/captive portal) e '
                          'fsso-groups (FSSO passivo): combinazione insolita, verificare l\'intenzionalità.'),
    'ISVC_WITH_DSTADDR': ('Internet Service + dstaddr Ridondante',     INFO,
                          'Policy che usano Internet Service come destinazione ma hanno anche '
                          'dstaddr impostato: quando internet-service è attivo, dstaddr viene '
                          'completamente ignorato dal FortiGate. Il campo dstaddr è ridondante.'),
    'ISVC_WITH_SERVICE': ('Internet Service + service Field Ridondante', INFO,
                          'Policy che usano Internet Service come destinazione ma hanno anche '
                          'il campo service impostato: quando internet-service è attivo, il campo '
                          'service è ignorato (il servizio è già incluso nell\'ISDB).'),
    'NO_NAME':           ('Policy senza Nome',                        WARNING,
                          'Queste policy non hanno un nome assegnato. Un nome descrittivo '
                          'è essenziale per identificare rapidamente lo scopo della regola '
                          'durante revisioni, troubleshooting e audit.'),
    'NAT_ON_VPN':        ('NAT su Traffico VPN/Tunnel',               INFO,
                          'NAT abilitato su un\'interfaccia VPN o tunnel. '
                          'Verificare che sia intenzionale e non mascheri gli IP client reali.'),
    'NEVER_MATCHES':     ('Policy Mai Raggiunta (Shadowed)',           WARNING,
                          'Queste policy ACCEPT non saranno mai raggiunte perché una policy '
                          'precedente più ampia le copre completamente. Sono di fatto dead rules.'),
    'USELESS_DENY':      ('Regola DENY Potenzialmente Ridondante',     WARNING,
                          'Queste regole DENY non sono giustificate da nessuna policy ACCEPT successiva '
                          'più ampia. Senza un ACCEPT sottostante che copra quel traffico, la default-deny '
                          'lo bloccherebbe comunque: il DENY esplicito è probabilmente ridondante.'),
    'DUPLICATE_POLICY':  ('Policy Duplicate o Identiche',             WARNING,
                          'Policy con srcintf, dstintf, src, dst, servizi, gruppi utente e azione identici '
                          'ad altre. Nota: policy che usano Internet Service e policy con dstaddr normale '
                          'non vengono mai considerate duplicate (meccanismi diversi). '
                          'Se una delle duplicate è disabilitata, è candidata immediata alla rimozione.'),
}


# ---------------------------------------------------------------------------
# Analisi principale
# ---------------------------------------------------------------------------

def analyze_all(report: dict) -> dict:
    policies = report.get('policies', [])
    meta     = report.get('meta', {})

    # Garantisci _id su ogni policy
    for p in policies:
        if '_id' not in p:
            p['_id'] = str(p.get('policyid', p.get('id', '?')))

    # Check singola policy
    per_policy: dict[str, list[dict]] = defaultdict(list)
    for p in policies:
        for fn in SINGLE_CHECKS:
            per_policy[p['_id']].extend(fn(p))

    # Check cross-policy: shadowing → per_policy come prima
    for pid, issues in check_shadowing(policies).items():
        per_policy[pid].extend(issues)

    # Duplicati → direttamente in by_cat come gruppi (non per-policy)
    dup_groups = check_duplicates(policies)

    # Raggruppa per categoria
    policy_map = {p['_id']: p for p in policies}
    by_cat: dict[str, list[dict]] = defaultdict(list)

    for pid, issues in per_policy.items():
        p = policy_map.get(pid, {})
        for issue in issues:
            # Costruisce stringa gruppi/utenti per visualizzazione
            auth_parts = []
            if p.get('groups'):      auth_parts.append('G:' + p.get('groups',''))
            if p.get('users'):       auth_parts.append('U:' + p.get('users',''))
            if p.get('fsso-groups'): auth_parts.append('FSSO:' + p.get('fsso-groups',''))
            auth_str = '  '.join(auth_parts)

            # Destinazione: internet-service o dstaddr
            isvc_dst = p.get('internet-service-name', p.get('internet-service', ''))
            dst_display = p.get('dstaddr', '')
            if isvc_dst:
                dst_display = f'[ISVC] {isvc_dst}'

            by_cat[issue['cat']].append({
                'policy_id':   pid,
                'policy_name': p.get('name', ''),
                'srcintf':     p.get('srcintf', ''),
                'dstintf':     p.get('dstintf', ''),
                'action':      p.get('action', ''),
                'status':      p.get('status', 'enable'),
                'srcaddr':     p.get('srcaddr', ''),
                'dstaddr':     dst_display,
                'service':     p.get('service', ''),
                'auth':        auth_str,
                'severity':    issue['severity'],
                'msg':         issue['msg'],
            })

    # Inserisci i gruppi duplicati direttamente in by_cat['DUPLICATE_POLICY']
    # Ogni entry rappresenta un gruppo (coppia o più), non una singola policy
    for grp in dup_groups:
        by_cat['DUPLICATE_POLICY'].append({
            '_is_group':    True,        # flag per i renderer
            'ids':          grp['ids'],
            'members':      grp['members'],
            'disabled_ids': grp['disabled_ids'],
            'severity':     WARNING,
            'msg':          grp['msg'],
        })

    # Contatori severity (per policy unica)
    sev_pids: dict[str, set] = defaultdict(set)
    for pid, issues in per_policy.items():
        for issue in issues:
            sev_pids[issue['severity']].add(pid)
    # Conta anche le policy coinvolte nei duplicati
    for grp in dup_groups:
        for pid in grp['ids']:
            sev_pids[WARNING].add(pid)

    clean_count = sum(1 for p in policies if not per_policy.get(p['_id']))

    # Categorie ordinate per severity
    sorted_cats = sorted(
        by_cat.keys(),
        key=lambda c: SEVERITY_ORDER.get(CATEGORY_META.get(c, ('', INFO, ''))[1], 99)
    )

    categories = []
    for cat in sorted_cats:
        label, sev, desc = CATEGORY_META.get(cat, (cat, INFO, ''))
        categories.append({
            'code':        cat,
            'label':       label,
            'severity':    sev,
            'description': desc,
            'count':       len(by_cat[cat]),
            'entries':     by_cat[cat],
        })

    return {
        'analysis_date': datetime.now().isoformat(timespec='seconds'),
        'source_file':   meta.get('source_file', ''),
        'filter':        meta.get('filter', {}),
        'zones':         meta.get('zones', {}),
        'stats': {
            'total':   len(policies),
            'clean':   clean_count,
            CRITICAL:  len(sev_pids[CRITICAL]),
            WARNING:   len(sev_pids[WARNING]),
            INFO:      len(sev_pids[INFO]),
        },
        'categories': categories,
    }


# ---------------------------------------------------------------------------
# Renderer TEXT
# ---------------------------------------------------------------------------

def render_text(analysis: dict) -> str:
    s = analysis['stats']
    f = analysis['filter']
    lines = [
        '=' * 80,
        '  FORTIGATE POLICY ANALYSIS REPORT',
        f'  Data   : {analysis["analysis_date"]}',
        f'  File   : {analysis["source_file"]}',
        f'  Filtro : srcintf={f.get("srcintf","*")} → dstintf={f.get("dstintf","*")}',
        '=' * 80,
        f'\n📊 STATISTICHE — {s["total"]} policy analizzate',
        f'   {SEVERITY_EMOJI[CRITICAL]} CRITICAL : {s[CRITICAL]} policy coinvolte',
        f'   {SEVERITY_EMOJI[WARNING]}  WARNING  : {s[WARNING]} policy coinvolte',
        f'   {SEVERITY_EMOJI[INFO]}  INFO     : {s[INFO]} policy coinvolte',
        f'   {SEVERITY_EMOJI[OK]}  CLEAN    : {s["clean"]} policy senza problemi',
    ]
    for cat in analysis['categories']:
        em = SEVERITY_EMOJI[cat['severity']]
        lines += [
            f'\n{"─" * 80}',
            f'{em} [{cat["severity"]}]  {cat["label"]}  ({cat["count"]} occorrenze)',
            f'   {cat["description"]}',
            '─' * 80,
        ]
        for e in cat['entries']:
            if e.get('_is_group'):
                # Visualizzazione a gruppo per i duplicati
                lines.append(f'   ┌─ {e["msg"]}')
                for m in e['members']:
                    dis = ' [DISABILITATA]' if m['status'] == 'disable' else ''
                    lines.append(
                        f'   │  ID {m["policy_id"]:>5}{dis}  |  {(m["policy_name"] or "(no name)"):28}'
                        f'  |  {m["srcintf"]} → {m["dstintf"]}'
                        f'  |  {m["action"].upper()}'
                        f'  |  src:{m["srcaddr"]}  dst:{m["dstaddr"]}'
                    )
                lines.append('   └─')
            else:
                lines.append(
                    f'   ID {e["policy_id"]:>5}  |  {(e["policy_name"] or "(no name)"):30}'
                    f'  |  {e["srcintf"]} → {e["dstintf"]}'
                    f'  |  {e["action"].upper()}'
                )
                lines.append(f'           ↳ {e["msg"]}')
    lines.append('\n' + '=' * 80)
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Renderer HTML
# ---------------------------------------------------------------------------

def render_html(analysis: dict) -> str:
    s = analysis['stats']
    f = analysis['filter']

    sections = ''
    for cat in analysis['categories']:
        sev   = cat['severity']
        color = SEVERITY_COLOR[sev]
        bg    = SEVERITY_BG[sev]
        emoji = SEVERITY_EMOJI[sev]

        is_dup_cat = (cat['code'] == 'DUPLICATE_POLICY')

        rows = ''
        for e in cat['entries']:
            if e.get('_is_group'):
                # ── Riga gruppo duplicati ──
                member_rows = ''
                for m in e['members']:
                    dis_style = 'background:#fff3cd;' if m['status'] == 'disable' else ''
                    dis_badge = '<span style="background:#e67e22;color:#fff;border-radius:3px;padding:1px 5px;font-size:11px;margin-left:4px">DISABLED</span>' if m['status'] == 'disable' else ''
                    act_color = '#27ae60' if m['action'] == 'accept' else '#c0392b'
                    member_rows += (
                        f'<tr style="{dis_style}">'
                        f'<td style="padding:5px 10px;font-weight:bold">{m["policy_id"]}{dis_badge}</td>'
                        f'<td style="padding:5px 10px">{m["policy_name"] or "<em style=color:#aaa>—</em>"}</td>'
                        f'<td style="padding:5px 10px;white-space:nowrap">{m["srcintf"]}</td>'
                        f'<td style="padding:5px 10px;white-space:nowrap">{m["dstintf"]}</td>'
                        f'<td style="padding:5px 10px;font-weight:bold;color:{act_color}">{m["action"].upper()}</td>'
                        f'<td style="padding:5px 10px;font-size:12px">{m["srcaddr"]}</td>'
                        f'<td style="padding:5px 10px;font-size:12px">{m["dstaddr"]}</td>'
                        f'<td style="padding:5px 10px;font-size:12px;color:#555;font-style:italic">{m.get("auth","") or "<em style=color:#ccc>—</em>"}</td>'
                        f'</tr>'
                    )
                rows += (
                    f'<tr><td colspan="9" style="padding:10px;background:#f0f0f0">'
                    f'<div style="font-size:12px;color:#555;margin-bottom:6px">⚠️ {e["msg"]}</div>'
                    f'<table style="width:100%;border-collapse:collapse;background:#fff;border-radius:4px;overflow:hidden">'
                    f'<thead><tr style="background:#555;color:#fff">'
                    f'<th style="padding:5px 10px">ID</th><th style="padding:5px 10px">Nome</th>'
                    f'<th style="padding:5px 10px">SrcIntf</th><th style="padding:5px 10px">DstIntf</th>'
                    f'<th style="padding:5px 10px">Azione</th><th style="padding:5px 10px">Src Addr</th>'
                    f'<th style="padding:5px 10px">Dst Addr</th><th style="padding:5px 10px">Auth/Gruppi</th>'
                    f'</tr></thead>'
                    f'<tbody>{member_rows}</tbody>'
                    f'</table>'
                    f'</td></tr>'
                )
            else:
                # ── Riga normale ──
                act_color = '#27ae60' if e['action'] == 'accept' else '#c0392b'
                rows += (
                    f'<tr>'
                    f'<td style="padding:7px 10px;font-weight:bold">{e["policy_id"]}</td>'
                    f'<td style="padding:7px 10px">{e["policy_name"] or "<em style=color:#aaa>—</em>"}</td>'
                    f'<td style="padding:7px 10px;white-space:nowrap">{e["srcintf"]}</td>'
                    f'<td style="padding:7px 10px;white-space:nowrap">{e["dstintf"]}</td>'
                    f'<td style="padding:7px 10px;font-weight:bold;color:{act_color}">{e["action"].upper()}</td>'
                    f'<td style="padding:7px 10px;font-size:12px">{e["srcaddr"]}</td>'
                    f'<td style="padding:7px 10px;font-size:12px">{e["dstaddr"]}</td>'
                    f'<td style="padding:7px 10px;font-size:12px;color:#555;font-style:italic">{e.get("auth","") or "<em style=color:#ccc>—</em>"}</td>'
                    f'<td style="padding:7px 10px;font-size:12px;color:#444">{e["msg"]}</td>'
                    f'</tr>'
                )

        sections += f'''
<div class="section" style="border-left:5px solid {color};background:{bg}">
  <div class="sec-hdr" onclick="tog(this)">
    <span class="sec-title">{emoji}&nbsp;{cat["label"]}</span>
    <span class="sec-badge" style="background:{color}">{'%d gruppi' % cat['count'] if cat['code'] == 'DUPLICATE_POLICY' else '%d policy' % cat['count']}</span>
    <span class="sec-arr">▼</span>
  </div>
  <div class="sec-body">
    <p class="sec-desc">{cat["description"]}</p>
    <div style="overflow-x:auto">
    <table>
      <thead><tr>
        <th>ID</th><th>Nome</th><th>SrcIntf</th><th>DstIntf</th>
        <th>Azione</th><th>Src Addr</th><th>Dst Addr</th><th>Auth/Gruppi</th>
        {"" if is_dup_cat else "<th>Dettaglio</th>"}
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
    </div>
  </div>
</div>'''

    return f'''<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FortiGate Policy Analysis</title>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:"Segoe UI",Arial,sans-serif;font-size:14px;background:#eef0f3;color:#222;padding:24px}}
h1{{color:#1a252f;margin-bottom:8px;font-size:22px}}
.meta{{background:#fff;padding:12px 18px;border-radius:8px;margin-bottom:20px;
       box-shadow:0 1px 4px #0001;font-size:13px;color:#444;line-height:1.9}}
.meta b{{color:#222}}
code{{background:#eee;padding:1px 5px;border-radius:3px}}
.stats{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:24px}}
.stat{{background:#fff;border-radius:8px;padding:14px 22px;text-align:center;
       box-shadow:0 1px 4px #0001;min-width:100px}}
.stat .num{{font-size:30px;font-weight:700;line-height:1}}
.stat .lbl{{font-size:11px;color:#888;margin-top:5px;text-transform:uppercase;letter-spacing:.5px}}
.section{{background:#fff;border-radius:8px;margin-bottom:16px;box-shadow:0 1px 4px #0001;overflow:hidden}}
.sec-hdr{{display:flex;align-items:center;padding:14px 18px;cursor:pointer;user-select:none;gap:12px}}
.sec-hdr:hover{{background:#f5f7fa}}
.sec-title{{flex:1;font-weight:700;font-size:15px}}
.sec-badge{{color:#fff;border-radius:20px;padding:3px 12px;font-size:12px;font-weight:600;white-space:nowrap}}
.sec-arr{{font-size:12px;color:#888;transition:transform .2s}}
.sec-arr.open{{transform:rotate(180deg)}}
.sec-body{{padding:0 18px 18px}}
.sec-desc{{font-size:13px;color:#555;margin-bottom:12px;padding:10px 14px;
           background:#f8f9fa;border-radius:6px;line-height:1.6}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#2c3e50;color:#fff;padding:9px 10px;text-align:left;font-weight:600;white-space:nowrap}}
tr:nth-child(even){{background:#f9f9f9}}
tr:hover{{background:#eaf0fb}}
td{{border-bottom:1px solid #eee;vertical-align:top}}
</style>
</head>
<body>
<h1>🔐 FortiGate Policy Analysis Report</h1>
<div class="meta">
  <b>File:</b> {analysis["source_file"] or "—"}&emsp;
  <b>Data:</b> {analysis["analysis_date"]}&emsp;
  <b>Filtro:</b> srcintf=<code>{f.get("srcintf","*")}</code> → dstintf=<code>{f.get("dstintf","*")}</code>
</div>
<div class="stats">
  <div class="stat"><div class="num">{s["total"]}</div><div class="lbl">Policy</div></div>
  <div class="stat"><div class="num" style="color:{SEVERITY_COLOR[CRITICAL]}">{s[CRITICAL]}</div><div class="lbl">Critical</div></div>
  <div class="stat"><div class="num" style="color:{SEVERITY_COLOR[WARNING]}">{s[WARNING]}</div><div class="lbl">Warning</div></div>
  <div class="stat"><div class="num" style="color:{SEVERITY_COLOR[INFO]}">{s[INFO]}</div><div class="lbl">Info</div></div>
  <div class="stat"><div class="num" style="color:{SEVERITY_COLOR[OK]}">{s["clean"]}</div><div class="lbl">Clean</div></div>
</div>
{sections}
<script>
function tog(h){{
  var b=h.nextElementSibling,a=h.querySelector('.sec-arr'),open=b.style.display!=='none';
  b.style.display=open?'none':'block';
  a.classList.toggle('open',!open);
}}
document.querySelectorAll('.sec-arr').forEach(function(a){{a.classList.add('open')}});
</script>
</body>
</html>'''


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='FortiGate Policy Analyzer v2 — report raggruppato per tipologia di problema.'
    )
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument('-i', '--input', help='File JSON prodotto da fortigate_policy_extractor.py')
    grp.add_argument('--conf',        help='File .conf FortiGate (estrae + analizza in uno)')

    parser.add_argument('--srcintf',  help='Filtro interfaccia sorgente (con --conf)')
    parser.add_argument('--dstintf',  help='Filtro interfaccia destinazione (con --conf)')
    parser.add_argument('--all',      action='store_true', dest='extract_all',
                                      help='Analizza tutte le policy (con --conf)')
    parser.add_argument('--internet-intf',
                                      help='Override nomi interfacce internet, separati da virgola (es. wan1,pppoe0)')
    parser.add_argument('--format',   choices=['text', 'json', 'html'], default='text')
    parser.add_argument('-o', '--output', help='File di output (default: stdout)')
    args = parser.parse_args()

    # Override pattern interfacce internet
    # Supporta wildcard con '*': es. '*wan*' diventa una ricerca substring
    if args.internet_intf:
        global INTERNET_INTF_RE, INTERNET_INTF_CONTAINS
        exact_names = []
        contains_patterns = []
        for n in args.internet_intf.split(','):
            n = n.strip()
            if '*' in n:
                # Converte '*wan*' in regex substring (rimuove gli asterischi)
                contains_patterns.append(re.escape(n.replace('*', '')))
            else:
                exact_names.append(re.escape(n))
        if exact_names:
            INTERNET_INTF_RE = re.compile(
                '|'.join(f'^{n}$' for n in exact_names), re.IGNORECASE
            )
        if contains_patterns:
            INTERNET_INTF_CONTAINS = re.compile(
                '|'.join(contains_patterns), re.IGNORECASE
            )

    # Carica JSON
    if args.input:
        path = Path(args.input)
        if not path.exists():
            print(f'[ERROR] File non trovato: {path}', file=sys.stderr)
            sys.exit(1)
        report = json.loads(path.read_text(encoding='utf-8'))
    else:
        print('[*] Estrazione policy dal file .conf...', file=sys.stderr)
        extractor = Path(__file__).parent / 'fortigate_policy_extractor.py'
        cmd = [sys.executable, str(extractor), '-f', args.conf]
        if args.extract_all:
            cmd.append('--all')
        else:
            if args.srcintf: cmd += ['--srcintf', args.srcintf]
            if args.dstintf: cmd += ['--dstintf', args.dstintf]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print(f'[ERROR] Extractor fallito:\n{res.stderr}', file=sys.stderr)
            sys.exit(1)
        try:
            report = json.loads(res.stdout)
        except json.JSONDecodeError as e:
            print(f'[ERROR] Output extractor non valido: {e}', file=sys.stderr)
            sys.exit(1)

    print('[*] Analisi in corso...', file=sys.stderr)
    analysis = analyze_all(report)
    s = analysis['stats']
    print(f'[✓] {s["total"]} policy  |  {s[CRITICAL]} critical  |  '
          f'{s[WARNING]} warning  |  {s[INFO]} info  |  {s["clean"]} clean', file=sys.stderr)

    if args.format == 'text':
        out = render_text(analysis)
    elif args.format == 'html':
        out = render_html(analysis)
    else:
        out = json.dumps(analysis, indent=2, ensure_ascii=False)

    if args.output:
        Path(args.output).write_text(out, encoding='utf-8')
        print(f'[✓] Report salvato in: {args.output}', file=sys.stderr)
    else:
        print(out)


if __name__ == '__main__':
    main()
