"""Validate the bounded screen census; optional read-only private image checks.

No game/process/browser access. No integrity checks depend on Python assert.
"""
from pathlib import Path
import argparse
import copy
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parent.parent

# Reviewed operator-action scopes. The private A4 receipts are opaque; this
# binds their declared roles to the observed edge IDs and launch contexts.
OPERATOR_CLAIMS = {
    'r41-operator-route-report': {
        'edge.restore-open': ('Restore Saved Game', ('gdi-A',)),
        'edge.original-cd': ('Original restore selection', ('gdi-A',)),
        'edge.cd-gap': ('External input intervened', ('gdi-A',)),
        'edge.club-link': ('Click managed club label', ('gdi-A',)),
        'edge.profile': ('Click captured roster player row', ('gdi-A',)),
        'edge.profile-back': ('Back', ('gdi-A',)),
        'edge.tactics': ('Tactics', ('gdi-A',)),
        'edge.tactics-cancel': ('Cancel', ('gdi-A',)),
        'edge.continue-squad': ('Continue Game', ('gdi-A',)),
        'edge.confirm-match': ('Continue Game', ('gdi-A',)),
        'edge.enter-match': ('Yes', ('gdi-A',)),
        'edge.options': ('Game Options', ('gdi-B-late',)),
        'edge.restart': ('Restart Game', ('gdi-B-late',)),
        'edge.save-prompt': ('Yes', ('gdi-B-late',)),
        'edge.restart-cancel': ('Cancel', ('gdi-B-late',)),
        'edge.save-separate': ('Save before restart', ('gdi-B-late',)),
        'edge.restart-child': ('Save distinct file; native restart creates child', ('gdi-B-late', 'gdi-restarted-partial')),
    },
    'r41-a4-operator-notes': {
        'edge.exit-yes': ('Yes', ('gdi-restarted-partial',)),
    },
    'r41-a4-index-snapshot': {
        'edge.restore-open': ('Restore Saved Game', ('gdi-A4-restored',)),
        'edge.select-file': ('Select duplicate input row', ('gdi-A4-restored',)),
        'edge.load-info': ('Ok starts loading', ('gdi-A4-restored',)),
        'edge.info-dismiss': ('Ok dismisses information; next loaded fixtures', ('gdi-A4-restored',)),
        'edge.continue-fixture': ('Continue Game', ('gdi-A4-restored',)),
        'edge.confirm-match': ('Continue Game', ('gdi-A4-restored',)),
        'edge.exit-confirm': ('Exit Game', ('gdi-restarted-partial',)),
        'edge.error-ok': ('OK', ('gdi-A4-failed-launch',)),
    },
}

# Frozen topology for this reviewed capture batch. A receipt may support an
# action only at its observed endpoints and with its recorded confidence.
REVIEWED_EDGE_TOPOLOGY = {
    'edge.restore-open': ('ui41.load.menu', 'ui41.load.restore', 'observed-action'),
    'edge.select-file': ('ui41.load.restore', 'ui41.load.restore.selected', 'observed-action'),
    'edge.load-info': ('ui41.load.restore.selected', 'ui41.load.media_info', 'observed-action'),
    'edge.info-dismiss': ('ui41.load.media_info', 'ui41.fixture.evening', 'observed-action'),
    'edge.original-cd': ('ui41.load.restore', 'ui41.load.media_request', 'observed-action'),
    'edge.cd-gap': ('ui41.load.media_request', 'ui41.fixture.evening', 'unresolved-gap'),
    'edge.club-link': ('ui41.fixture.evening', 'ui41.squad.selection', 'observed-action'),
    'edge.profile': ('ui41.squad.selection', 'ui41.player.profile', 'observed-action'),
    'edge.profile-back': ('ui41.player.profile', 'ui41.squad.selection', 'observed-action'),
    'edge.tactics': ('ui41.squad.selection', 'ui41.tactics.overview', 'observed-action'),
    'edge.tactics-cancel': ('ui41.tactics.overview', 'ui41.squad.selection', 'observed-action'),
    'edge.continue-squad': ('ui41.squad.selection', 'ui41.squad.prematch', 'observed-action'),
    'edge.continue-fixture': ('ui41.fixture.evening', 'ui41.squad.prematch', 'observed-action'),
    'edge.confirm-match': ('ui41.squad.prematch', 'ui41.match.confirm', 'observed-action'),
    'edge.enter-match': ('ui41.match.confirm', 'ui41.match.prekickoff', 'observed-action'),
    'edge.running-sequence': ('ui41.match.prekickoff', 'ui41.match.running', 'screenshot-sequence'),
    'edge.result-sequence': ('ui41.match.running', 'ui41.result.fulltime', 'screenshot-sequence'),
    'edge.halftime-sequence': ('ui41.match.prekickoff', 'ui41.match.halftime', 'screenshot-sequence'),
    'edge.b-result-sequence': ('ui41.match.halftime', 'ui41.result.fulltime', 'screenshot-sequence'),
    'edge.options': ('ui41.result.fulltime', 'ui41.game.options', 'observed-action'),
    'edge.restart': ('ui41.game.options', 'ui41.restart.confirm', 'observed-action'),
    'edge.save-prompt': ('ui41.restart.confirm', 'ui41.restart.saveprompt', 'observed-action'),
    'edge.restart-cancel': ('ui41.restart.saveprompt', 'ui41.result.fulltime', 'observed-action'),
    'edge.save-separate': ('ui41.restart.saveprompt', 'ui41.save.dialog', 'observed-action'),
    'edge.restart-child': ('ui41.save.dialog', 'ui41.load.menu', 'observed-action'),
    'edge.exit-confirm': ('ui41.load.menu', 'ui41.exit.confirm', 'observed-action'),
    'edge.exit-yes': ('ui41.exit.confirm', 'ui41.process.exited', 'observed-action'),
    'edge.error-ok': ('ui41.load.language_error', 'ui41.load.config_error', 'observed-action'),
}

REVIEWED_STATE_IDS = frozenset({
    'ui41.load.menu', 'ui41.load.restore', 'ui41.load.restore.selected',
    'ui41.load.media_info', 'ui41.load.language_error', 'ui41.load.config_error',
    'ui41.fixture.evening', 'ui41.squad.selection', 'ui41.squad.prematch',
    'ui41.player.profile', 'ui41.tactics.overview', 'ui41.match.confirm',
    'ui41.match.prekickoff', 'ui41.match.running', 'ui41.match.halftime',
    'ui41.result.fulltime', 'ui41.exit.confirm', 'ui41.load.media_request',
    'ui41.game.options', 'ui41.restart.confirm', 'ui41.restart.saveprompt',
    'ui41.save.dialog', 'ui41.process.exited',
})

# Digest of the complete 60-row reviewed control frontier, ordered by route ID
# and encoded as canonical UTF-8 JSON. Extending the census requires a fresh
# visual review and an intentional update of this batch pin.
REVIEWED_ROUTE_SHA256 = 'ec9061bf37e9952998d52693b911e5f8c4c92a50d17947f24dc981dd3b06819f'
REVIEWED_STATE_CLAIMS_SHA256 = 'ae9000b3478513d3911f1a97fdc611f768bb81c8f587827443d51f7834ff33ef'
REVIEWED_UNKNOWN_SECTIONS_SHA256 = 'ef594ff35e5a3add0543db42260213d285774a5c5878cbe319963b37dcc93f6a'
REVIEWED_BATCH_SECTION_SHA256 = {
    'contexts': 'c732d0015cb29c35ab2ddbe83adc056e63689d2abd4fc8097ac1c0af19a22778',
    'evidence': '0b0c8f118e218fccd1a0488541a7f677eba15056040dec62c698522b19a87858',
    'layouts': 'b243b6201fcda8d5c3763688044d9d062dfcf5d9a127f2888c783dc276e44118',
    'transitions': 'e994cec077e8c69334a299a1733c36b86e2863ea4d1f55c42c893b3d6439adf1',
    'capture_requests': '2a1ef2b0ebaa83b5a3c108b121b23c953f42ab025a28fe1313d92460265b34d8',
}
REVIEWED_STATE_ALIASES_SHA256 = '28045612fd7a3eee022916196df8746b34057dacd4d1e5eaf0a0d1560300fa7a'


def route_digest(rows):
    canonical = json.dumps(sorted(rows, key=lambda row: row['id']), sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def state_claims_digest(rows):
    canonical = json.dumps(sorted(rows, key=lambda row: row['id']), sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def unknown_sections_digest(rows):
    canonical = json.dumps(sorted(rows, key=lambda row: row['id']), sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def batch_section_digest(rows):
    canonical = json.dumps(sorted(rows, key=lambda row: row.get('id', row.get('owner', ''))), sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def indexed(rows, label):
    ids = [row['id'] for row in rows]
    require(len(ids) == len(set(ids)), f'duplicate {label} ID')
    return {row['id']: row for row in rows}


def source_digest(raw):
    """Hash the complete UTF-8 source after CRLF-to-LF normalization only."""
    normalized = raw.replace(b'\r\n', b'\n')
    normalized.decode('utf-8')
    return hashlib.sha256(normalized).hexdigest()


def tracked_source_bytes(source):
    path = (ROOT / source).resolve(strict=True)
    reports_root = (ROOT / 'reports').resolve(strict=True)
    require(path.is_relative_to(reports_root) and source.startswith('reports/') and path.suffix == '.md', 'public report source escaped tracked report scope')
    return path.read_bytes()


def public_report_bytes():
    return tracked_source_bytes('reports/ui-map-41.md')


def text_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from text_values(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from text_values(item)


def validate(data, assets, source_reader=tracked_source_bytes, report_reader=public_report_bytes):
    require(data['schema'] == 'reversal.ui-screen-census-41.v1', 'unsupported schema')
    for section, digest in REVIEWED_BATCH_SECTION_SHA256.items():
        require(batch_section_digest(data[section]) == digest, f'unreviewed {section} batch claims')
    alias_bytes = json.dumps(data['state_aliases'], sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    require(hashlib.sha256(alias_bytes).hexdigest() == REVIEWED_STATE_ALIASES_SHA256, 'unreviewed state aliases')
    contexts = indexed(data['contexts'], 'context')
    evidence = indexed(data['evidence'], 'evidence')
    layouts = indexed(data['layouts'], 'layout')
    states = indexed(data['states'], 'state')
    require(set(states) == REVIEWED_STATE_IDS, 'unreviewed state catalogue')
    require(state_claims_digest(data['states']) == REVIEWED_STATE_CLAIMS_SHA256, 'unreviewed state evidence or kind')
    edges = indexed(data['transitions'], 'transition')
    require(set(edges) == set(REVIEWED_EDGE_TOPOLOGY), 'unreviewed transition set')
    routes = indexed(data['discovered_routes'], 'route')
    require(route_digest(data['discovered_routes']) == REVIEWED_ROUTE_SHA256, 'unreviewed control frontier')
    domains = indexed(data['unknown_sections'], 'domain')
    require(unknown_sections_digest(data['unknown_sections']) == REVIEWED_UNKNOWN_SECTIONS_SHA256, 'unreviewed unknown-section catalogue')
    require(all(alias not in states and target in states for alias,target in data['state_aliases'].items()), 'invalid historical state alias')
    def refs(ids, source):
        require(len(ids) == len(set(ids)) and all(i in source for i in ids), 'unknown/duplicate reference')
    for context in contexts.values():
        for key in ['executable_sha256', 'loaded_input_save_sha256', 'expected_configuration_sha256', 'capture_configuration_sha256']:
            require(context[key] is None or re.fullmatch('[a-f0-9]{64}', context[key]), 'invalid identity hash')
        if context['configuration_status'].endswith('matched'):
            require(context['capture_configuration_sha256'] == context['expected_configuration_sha256'], 'matched configuration identity missing')
    for item in evidence.values():
        require(re.fullmatch('[a-f0-9]{64}', item['sha256']), 'invalid evidence digest')
        require(item['kind'] in ['screenshot', 'operator-report'], 'unknown evidence kind')
        if item['kind'] == 'screenshot':
            require(item['context_id'] in contexts, 'unknown screenshot context')
            require(item['encoding'] == 'JPEG', 'unverified screenshot encoding')
            require(len(item['capture_pixels']) == 2 and all(isinstance(n,int) and n > 0 for n in item['capture_pixels']), 'invalid image dimensions')
            require(item['client_pixels'] in (None, [800,600]), 'unexpected game-client extent')
        else:
            require(item['source_visibility'] in ['public-tracked','private-not-loaded'], 'unknown operator source visibility')
            if item['id'] == 'r41-operator-route-report':
                require(item['source_visibility'] == 'public-tracked' and item['source_digest_basis'] == 'utf8-lf' and item['source'] == 'reports/runtime-capture-41.md', 'operator journey source downgraded or changed')
            if item['source_visibility'] == 'public-tracked':
                require(item['id'] == 'r41-operator-route-report' and item['source'] == 'reports/runtime-capture-41.md', 'unexpected public operator source')
                require(item['source_digest_basis'] == 'utf8-lf', 'unsupported public source digest basis')
                require(source_digest(source_reader(item['source'])) == item['sha256'], 'public operator source digest mismatch')
            else:
                require(item['source'].startswith('private ') and item['source_digest_basis'] == 'raw-bytes', 'private receipt mislabels a public report source')
    for layout in layouts.values():
        require(layout['extent'] == [800,600] and layout['coordinate_space'] == 'game-client-pixels', 'unsupported layout coordinate space')
        for region in layout['regions']:
            x,y,w,h = region['bounds']
            require(all(isinstance(n,int) for n in [x,y,w,h]) and x >= 0 and y >= 0 and w > 0 and h > 0 and x+w <= 800 and y+h <= 600, 'layout outside client')
    for edge in edges.values():
        require(edge['from'] in states and edge['to'] in states, 'dangling graph endpoint')
        require(edge['status'] in ['observed-action', 'screenshot-sequence', 'unresolved-gap'], 'unknown transition confidence')
        require((edge['from'], edge['to'], edge['status']) == REVIEWED_EDGE_TOPOLOGY[edge['id']], 'edge topology changed')
        refs(edge['evidence_ids'], evidence)
        refs(edge['context_ids'], contexts)
        require(bool(edge['evidence_ids']) and bool(edge['context_ids']), 'transition without evidence/context')
        reports = [i for i in edge['evidence_ids'] if evidence[i]['kind'] == 'operator-report']
        claimed_contexts = set()
        for report_id in reports:
            claim = OPERATOR_CLAIMS.get(report_id, {}).get(edge['id'])
            require(claim is not None and claim[0] == edge['action'], 'operator receipt unrelated to claimed action')
            claimed_contexts.update(claim[1])
        images = [i for i in edge['evidence_ids'] if evidence[i]['kind'] == 'screenshot']
        endpoints = set(states[edge['from']]['evidence_ids']) | set(states[edge['to']]['evidence_ids'])
        require(all(i in endpoints and evidence[i]['context_id'] in edge['context_ids'] for i in images), 'transition image outside endpoint/context')
        if edge['status'] in ['observed-action', 'unresolved-gap']:
            require(bool(reports) and set(edge['context_ids']).issubset(claimed_contexts), 'action context without operator claim')
        else:
            require(any(i in states[edge['from']]['evidence_ids'] for i in images) and any(i in states[edge['to']]['evidence_ids'] for i in images), 'screenshot sequence without endpoint images')
    image_owners = {}
    for state in states.values():
        refs(state['evidence_ids'], evidence)
        require(bool(state['evidence_ids']), 'state without evidence')
        require(state['layout_id'] is None or state['layout_id'] in layouts, 'unknown layout')
        screen = any(evidence[i]['kind'] == 'screenshot' for i in state['evidence_ids'])
        for evidence_id in state['evidence_ids']:
            if evidence[evidence_id]['kind'] == 'screenshot':
                digest = evidence[evidence_id]['sha256']
                require(digest not in image_owners or image_owners[digest] == state['id'], 'screenshot reused across states')
                image_owners[digest] = state['id']
        require(state['kind'] in ['screen', 'modal', 'native-dialog', 'operator-only', 'terminal'], 'unknown state kind')
        if state['kind'] in ['operator-only', 'terminal']:
            require(not screen and any(evidence[i]['kind'] == 'operator-report' for i in state['evidence_ids']), 'unconfirmed nonvisual state')
        else:
            require(screen, 'visual state without screenshot')
        observed = [i for i,e in edges.items() if e['status'] == 'observed-action' and state['id'] in (e['from'],e['to'])]
        level = state['coverage']
        require(level['screenshot'] == screen, 'screenshot coverage mismatch')
        require(level['layout'] == bool(screen and state['layout_id']), 'layout coverage without image/layout')
        require(level['observed_transition'] == bool(observed) and level['transition_ids'] == observed, 'image sequence promoted to behavior coverage')
        require(level['engine_binding'] is False and level['engine_evidence_ids'] == [], 'no engine binding admitted by this census schema')
        refs(state['assets']['asset_ids'], assets)
        back = state['back']
        require(back['target_state_id'] is None or back['target_state_id'] in states, 'unknown back target')
        refs(back['evidence_ids'], evidence)
        if back['status'] == 'observed':
            require(any(e['from'] == state['id'] and e['to'] == back['target_state_id'] and e['status'] == 'observed-action' for e in edges.values()), 'back claim without action edge')
    owned_images = {evidence_id for state in states.values() for evidence_id in state['evidence_ids'] if evidence[evidence_id]['kind'] == 'screenshot'}
    require(owned_images == {evidence_id for evidence_id,item in evidence.items() if item['kind'] == 'screenshot'}, 'unowned screenshot evidence')
    expected = {id:[{'to':e['to'],'transition_id':eid} for eid,e in edges.items() if e['from'] == id and e['status'] == 'observed-action'] for id in states}
    require(data['observed_adjacency'] == expected, 'observed adjacency mismatch')
    for route in routes.values():
        require(route['from'] in states and route['target_state_id'] is None and route['status'] == 'discovered-uncaptured', 'unseen destination promoted to screen')
        refs(route['evidence_ids'], evidence)
        require(bool(route['evidence_ids']) and bool(set(route['evidence_ids']).intersection(states[route['from']]['evidence_ids'])), 'discovered route without source-state evidence')
    for request in data['capture_requests']:
        refs(request['route_ids'], routes)
        require(request['owner'] == 'R41-A4', 'capture operator mismatch')
    denominator = data['denominator']
    require(denominator['total_application_screen_states'] is None, 'unknown total application denominator promoted to known')
    expected_sets = {
        'screenshot_confirmed_state_ids':[i for i,s in states.items() if s['coverage']['screenshot']],
        'operator_only_state_ids':[i for i,s in states.items() if s['kind'] == 'operator-only'],
        'terminal_state_ids':[i for i,s in states.items() if s['kind'] == 'terminal'],
        'discovered_uncaptured_route_ids':list(routes), 'unknown_unbounded_section_ids':list(domains)}
    require(all(denominator[k] == v for k,v in expected_sets.items()), 'denominator membership mismatch')
    require(denominator['counts'] == {k:len(v) for k,v in expected_sets.items()}, 'denominator count mismatch')
    public = list(text_values(data)) + [report_reader().decode('utf-8')]
    require(not any(re.search(r'\\\\[^\\/\s"]+[\\/][^\\/\s"]+|[A-Za-z]:[\\/]|(?<![A-Za-z0-9:.])/[^/\s"\\]+(?:/[^/\s"\\]+)*|(?<![A-Za-z0-9._-])(?:results|private-checkpoints|private-native-verify|runtime-capture-41|ui-view-41)[/\\]|\bfile:|\bdata:image|\bbase64\b',part) for part in public), 'private path/payload in census')
    require(not any(re.search(r'\b\d{1,2}(?:-\d{1,2}){3,}\b|[£$€]\d',part) for part in public), 'captured display value in census')
    return {'states':len(states),'screenshots':sum(e['kind']=='screenshot' for e in evidence.values()), 'denominator':denominator['counts'], 'engine_bindings':0}


def jpeg_size(data):
    require(data.startswith(b'\xff\xd8'), 'private image encoding mismatch')
    i = 2
    while i < len(data):
        require(data[i] == 255, 'invalid JPEG marker')
        while i < len(data) and data[i] == 255:
            i += 1
        require(i < len(data), 'truncated JPEG marker')
        marker = data[i]
        i += 1
        if marker in (0xd8,0xd9) or 0xd0 <= marker <= 0xd7:
            continue
        require(i+2 <= len(data), 'truncated JPEG segment')
        size = int.from_bytes(data[i:i+2],'big')
        require(size >= 2 and i+size <= len(data), 'JPEG segment outside file')
        if marker in (0xc0,0xc1,0xc2):
            require(size >= 8,'short JPEG dimensions')
            return [int.from_bytes(data[i+5:i+7],'big'),int.from_bytes(data[i+3:i+5],'big')]
        i += size
    raise ValueError('JPEG dimensions missing')


def check_private_display(snapshot, public):
    """Reject copied display values; tiny/generic values need their field label."""
    exact = set()
    labelled = set()
    def add(label, value, generic=False):
        if not isinstance(value, str) or not value.strip():
            return
        value = value.strip()
        if len(value) >= 3 and not generic:
            exact.add(value)
        labelled.add((label, value))
    for key in ('clubLabel', 'dateLabel'):
        add(key, snapshot['squad'][key])
    row_fields = ('name', 'position', 'form', 'morale', 'condition', 'apps', 'averageRating', 'value')
    for row in snapshot['squad']['rows']:
        for key in row_fields:
            add(key, row[key])
    for key in ('title', 'bio', 'role', 'preferredFoot', 'form', 'morale', 'condition'):
        add(key, snapshot['profile'][key], generic=(key == 'role'))
    for column in snapshot['profile']['attributeColumns']:
        for attribute in column:
            add(attribute['label'], attribute['value'], generic=True)
    require(not any(value in public for value in exact), 'private captured display string present in public catalogue/report')
    require(not any(f'{label}: {value}' in public or f'{label} {value}' in public for label,value in labelled), 'private captured labelled value present in public catalogue/report')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-root',type=Path)
    parser.add_argument('--private-aliases',type=Path)
    parser.add_argument('--private-snapshot',type=Path)
    args = parser.parse_args()
    data = json.loads((ROOT/'evidence/ui-screen-census-41.json').read_text(encoding='utf-8'))
    assets = {a['asset_id']:a for a in json.loads((ROOT/'evidence/ui-assets-41-inventory.json').read_text(encoding='utf-8'))['assets']}
    result = validate(data, assets)
    def escape_report_source(d):
        item = next(e for e in d['evidence'] if e['id'] == 'r41-operator-route-report')
        item['source'] = 'reports/../AGENTS.md'
        item['sha256'] = source_digest((ROOT / 'AGENTS.md').read_bytes())
    def unrelated_report_source(d):
        item = next(e for e in d['evidence'] if e['id'] == 'r41-operator-route-report')
        item['source'] = 'reports/asset-inventory-41.md'
        item['sha256'] = source_digest((ROOT / item['source']).read_bytes())
    def downgrade_operator_source(d):
        item = next(e for e in d['evidence'] if e['id'] == 'r41-operator-route-report')
        item['source_visibility'] = 'private-not-loaded'
        item['source_digest_basis'] = 'raw-bytes'
        item['source'] = 'private opaque replacement'
    def reseal_derived_transitions(d):
        for state in d['states']:
            observed = [edge['id'] for edge in d['transitions'] if edge['status'] == 'observed-action' and state['id'] in (edge['from'], edge['to'])]
            state['coverage']['transition_ids'] = observed
            state['coverage']['observed_transition'] = bool(observed)
        d['observed_adjacency'] = {
            state['id']: [{'to':edge['to'], 'transition_id':edge['id']} for edge in d['transitions'] if edge['from'] == state['id'] and edge['status'] == 'observed-action']
            for state in d['states']
        }
    def retarget_option(d):
        next(edge for edge in d['transitions'] if edge['id'] == 'edge.options')['from'] = 'ui41.match.prekickoff'
        reseal_derived_transitions(d)
    def promote_cd_gap(d):
        next(edge for edge in d['transitions'] if edge['id'] == 'edge.cd-gap')['status'] = 'observed-action'
        reseal_derived_transitions(d)
    def clone_visual_state(d):
        cloned = copy.deepcopy(next(state for state in d['states'] if state['id'] == 'ui41.match.running'))
        cloned['id'] = 'ui41.match.running.cloned'
        cloned['coverage']['transition_ids'] = []
        cloned['coverage']['observed_transition'] = False
        d['states'].append(cloned)
        d['observed_adjacency'][cloned['id']] = []
        d['denominator']['screenshot_confirmed_state_ids'].append(cloned['id'])
        d['denominator']['counts']['screenshot_confirmed_state_ids'] += 1
    def invent_control_route(d):
        invented = copy.deepcopy(d['discovered_routes'][0])
        invented['id'] = 'route.load.menu.invented'
        invented['control_label'] = 'Invented control'
        d['discovered_routes'].append(invented)
        d['denominator']['discovered_uncaptured_route_ids'].append(invented['id'])
        d['denominator']['counts']['discovered_uncaptured_route_ids'] += 1
    def promote_existing_operator(d):
        state = next(state for state in d['states'] if state['id'] == 'ui41.game.options')
        state['kind'] = 'screen'
        state['evidence_ids'].append('r41-ui-01-menu')
        state['coverage']['screenshot'] = True
        d['denominator']['operator_only_state_ids'].remove(state['id'])
        d['denominator']['counts']['operator_only_state_ids'] -= 1
        d['denominator']['screenshot_confirmed_state_ids'].append(state['id'])
        d['denominator']['counts']['screenshot_confirmed_state_ids'] += 1
    def reuse_visual_image(d):
        next(state for state in d['states'] if state['id'] == 'ui41.player.profile')['evidence_ids'].append('r41-ui-01-menu')
    def invent_unknown_section(d):
        invented = copy.deepcopy(d['unknown_sections'][0])
        invented['id'] = 'domain.invented'
        invented['label'] = 'Invented domain'
        d['unknown_sections'].append(invented)
        d['denominator']['unknown_unbounded_section_ids'].append(invented['id'])
        d['denominator']['counts']['unknown_unbounded_section_ids'] += 1
    def append_unowned_screenshot(d):
        invented = copy.deepcopy(next(item for item in d['evidence'] if item['kind'] == 'screenshot'))
        invented['id'] = 'r41-ui-invented-unowned'
        invented['sha256'] = '1' * 64
        d['evidence'].append(invented)
    def mislabel_continue_as_back(d):
        next(state for state in d['states'] if state['id'] == 'ui41.squad.selection')['back'] = {
            'status': 'observed',
            'target_state_id': 'ui41.squad.prematch',
            'evidence_ids': ['r41-operator-route-report'],
        }
    mutations = [
        lambda d:d['transitions'][0].update(to='ui41.unmapped'),
        lambda d:next(e for e in d['transitions'] if e['id']=='edge.profile').update(evidence_ids=['r41-a4-operator-notes'], context_ids=['gdi-A4-failed-launch']),
        lambda d:next(e for e in d['transitions'] if e['id']=='edge.profile').update(context_ids=['gdi-A4-failed-launch']),
        lambda d:next(e for e in d['transitions'] if e['id']=='edge.profile').update(action='Exit Game'),
        retarget_option,
        promote_cd_gap,
        clone_visual_state,
        invent_control_route,
        promote_existing_operator,
        reuse_visual_image,
        invent_unknown_section,
        append_unowned_screenshot,
        mislabel_continue_as_back,
        lambda d:next(item for item in d['evidence'] if item['id'] == 'r41-ui-01-menu').update(sha256='1'*64),
        lambda d:next(item for item in d['evidence'] if item['id'] == 'r41-ui-01-menu').update(capture_pixels=[1,1]),
        lambda d:next(item for item in d['contexts'] if item['id'] == 'gdi-A').update(executable_sha256='1'*64),
        lambda d:d['layouts'][0]['regions'][0].update(bounds=[0,0,1,1]),
        lambda d:next(e for e in d['transitions'] if e['id']=='edge.running-sequence').update(evidence_ids=['r41-ui-09-match-before-kickoff-A']),
        lambda d:d['evidence'].append(d['evidence'][0]),
        lambda d:d['states'][0]['coverage'].update(engine_binding=True),
        lambda d:d['layouts'][0]['regions'][0].update(bounds=[799,0,10,10]),
        lambda d:d['denominator']['screenshot_confirmed_state_ids'].pop(),
        lambda d:d['denominator'].update(total_application_screen_states=100),
        lambda d:d['discovered_routes'][0].update(evidence_ids=[]),
        lambda d:d['discovered_routes'][0].update(evidence_ids=[d['evidence'][-1]['id']]),
        lambda d:next(s for s in d['states'] if s['kind']=='operator-only').update(evidence_ids=[]),
        lambda d:next(s for s in d['states'] if s['kind']=='operator-only').update(kind='screen'),
        lambda d:next(s for s in d['states'] if s['kind']=='terminal').update(evidence_ids=[]),
        escape_report_source,
        unrelated_report_source,
        downgrade_operator_source,
        lambda d:d['states'][0]['assets']['asset_ids'].append('unknown-asset'),
        lambda d:d['observed_adjacency'][d['states'][0]['id']].clear(),
        lambda d:d.update(private_payload='1-2-3-4'),
        lambda d:d.update(private_payload='/home/operator/private/capture.png'),
        lambda d:d.update(private_payload='/tmp/capture.jpg'),
        lambda d:d.update(private_payload='results/private-capture.json'),
        lambda d:d.update(private_payload='runtime-capture-41/results/private-capture.json'),
        lambda d:d['states'][0].update(notes='line\n/tmp/capture.jpg'),
        lambda d:d['states'][0].update(notes='tab\t/home/operator/private/capture.png'),
        lambda d:d['states'][0].update(notes='\\\\server\\share\\private\\capture.png'),
        lambda d:d['contexts'][0].update(capture_configuration_sha256=None),
        lambda d:next(s for s in d['states'] if s['id']=='ui41.match.running')['coverage'].update(observed_transition=True),
        lambda d:next(s for s in d['states'] if s['id']=='ui41.game.options')['coverage'].update(layout=True),
        lambda d:next(e for e in d['evidence'] if e['id']=='r41-operator-route-report').update(sha256='0'*64),
    ]
    for mutation in mutations:
        changed = copy.deepcopy(data)
        mutation(changed)
        try:
            validate(changed,assets)
        except ValueError:
            continue
        raise ValueError('negative validation probe accepted')
    # Both checkout newline modes must match the same tracked-file digest.
    source = next(e for e in data['evidence'] if e['id']=='r41-operator-route-report')
    raw_lf = tracked_source_bytes(source['source']).replace(b'\r\n',b'\n')
    validate(data,assets,source_reader=lambda _:raw_lf)
    validate(data,assets,source_reader=lambda _:raw_lf.replace(b'\n',b'\r\n'))
    try:
        validate(data,assets,source_reader=lambda _:raw_lf+b'\nsynthetic changed source\n')
    except ValueError:
        pass
    else:
        raise ValueError('altered public source accepted')
    report = public_report_bytes()
    report_leaks = (b'\n/tmp/capture.jpg', b'\nresults/private-capture.json', b'\n\\\\server\\share\\private\\capture.png')
    for leaked in report_leaks:
        try:
            validate(data, assets, report_reader=lambda: report + leaked)
        except ValueError:
            pass
        else:
            raise ValueError('private path in public report accepted')
    if args.private_root or args.private_aliases:
        require(args.private_root and args.private_aliases,'private root and aliases must be supplied together')
        root = args.private_root.resolve(strict=True)
        aliases = json.loads(args.private_aliases.read_text(encoding='utf-8'))['aliases']
        for evidence in data['evidence']:
            if evidence['kind'] != 'screenshot':
                continue
            path = (root / aliases[evidence['id']]).resolve(strict=True)
            require(path.is_relative_to(root),'private alias escaped root')
            image = path.read_bytes()
            require(hashlib.sha256(image).hexdigest() == evidence['sha256'],'private screenshot hash mismatch')
            require(jpeg_size(image) == evidence['capture_pixels'],'private screenshot dimensions mismatch')
        result['private_image_checks'] = 'pass'
    if args.private_snapshot:
        snapshot = json.loads(args.private_snapshot.read_text(encoding='utf-8'))
        public = (ROOT/'evidence/ui-screen-census-41.json').read_text(encoding='utf-8') + (ROOT/'reports/ui-map-41.md').read_text(encoding='utf-8')
        check_private_display(snapshot, public)
        for field in (snapshot['squad']['clubLabel'], snapshot['squad']['dateLabel'], snapshot['profile']['bio']):
            try:
                check_private_display(snapshot, public + '\n' + field)
            except ValueError:
                pass
            else:
                raise ValueError('private display leak probe accepted')
        attribute = snapshot['profile']['attributeColumns'][0][0]
        try:
            check_private_display(snapshot, public + '\n' + attribute['label'] + ': ' + attribute['value'])
        except ValueError:
            pass
        else:
            raise ValueError('private attribute leak probe accepted')
        result['private_token_checks'] = 'pass'
        result['private_leak_probes'] = 4
    result['negative_probes'] = len(mutations) + 1 + len(report_leaks)
    result['tracked_source_checks'] = 'LF/CRLF match; changed digest/content rejected'
    print(json.dumps(result,sort_keys=True))


if __name__ == '__main__':
    main()
