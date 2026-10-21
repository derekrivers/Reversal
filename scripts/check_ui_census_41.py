"""Validate the bounded screen census; optional read-only private image checks.

No game/process/browser access. No integrity checks depend on Python assert.
"""
from pathlib import Path
import argparse
from bisect import bisect_right
import copy
import hashlib
import html
from html.parser import HTMLParser
from itertools import combinations
import json
import re
import string
import unicodedata

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
REVIEWED_STATE_CLAIMS_SHA256 = '9f24c76350e8c8871154657e81788d06bcb0a29966c0f4ead40bbeff069a58f6'
REVIEWED_UNKNOWN_SECTIONS_SHA256 = 'ef594ff35e5a3add0543db42260213d285774a5c5878cbe319963b37dcc93f6a'
REVIEWED_BATCH_SECTION_SHA256 = {
    'contexts': 'c732d0015cb29c35ab2ddbe83adc056e63689d2abd4fc8097ac1c0af19a22778',
    'evidence': '80caa7e6d6b9d29a613420d0e8bf2e7c3d202c1102d0016ea8eebc7e044cb65d',
    'layouts': 'b243b6201fcda8d5c3763688044d9d062dfcf5d9a127f2888c783dc276e44118',
    'transitions': 'e994cec077e8c69334a299a1733c36b86e2863ea4d1f55c42c893b3d6439adf1',
    'capture_requests': '2a1ef2b0ebaa83b5a3c108b121b23c953f42ab025a28fe1313d92460265b34d8',
}
REVIEWED_STATE_ALIASES_SHA256 = '28045612fd7a3eee022916196df8746b34057dacd4d1e5eaf0a0d1560300fa7a'
REVIEWED_TOP_LEVEL_CLAIMS_SHA256 = '67fcce40c96f6cc24cb5bb59cbfc03403cca1a8ce71f1eca66d50fa75f04dd8c'
REVIEWED_DENOMINATOR_SCOPE = 'finite catalogue frontier only; not the entire application'
REVIEWED_ROOT_FIELDS = frozenset(('schema', 'cutoff', 'completion_claim', 'coverage_definitions', 'capture_protocol', 'contexts', 'evidence', 'layouts', 'states', 'transitions', 'observed_adjacency', 'discovered_routes', 'capture_requests', 'denominator', 'unknown_sections', 'state_aliases'))
REVIEWED_UI_REPORT_SHA256 = 'd0d62f0d7b8f348ef7f4634db3b39f5686af4ee5be3738939e5b0518c2ef6236'  # Complete public report, normalized CRLF to LF.
PRIVATE_PATH_PAYLOAD = re.compile(r'\\\\[^\\/\s"]+[\\/][^\\/\s"]+|(?<![A-Za-z0-9:])//[^/\s"\\]+(?:/[^/\s"\\]+)+|(?<![A-Za-z0-9])[A-Za-z]:[\\/]|(?<![A-Za-z0-9./])/[^/\s"\\]+(?:/[^/\s"\\]+)*|(?<![A-Za-z0-9._-])(?:results|private-checkpoints|private-native-verify|runtime-capture-41|ui-view-41)[/\\]|\bfile:|\bdata:image|\bbase64\b', re.IGNORECASE)
ROOT_RELATIVE_WINDOWS = re.compile(
    # A rooted path starts a text token; an interior separator of any relative
    # directory name (including names ending in + or @) does not.
    r'(?<![^\s\x22\x27\x28\x5b\x7b\x3d\x3a\x2c\x3b\x2a\x3e\x7c\x3f])\\(?!\\)(?:'
    r'[^\s\\/"<>|:*?][^\\/\r\n\t"<>|:*?]*[\\/][^\s\\/"<>|:*?][^\\/\r\n\t"<>|:*?]*'
    r'|[^\s\\/"<>|:*?][^\\/\r\n\t"<>|:*?]*\.[A-Za-z0-9]{1,10}\b'
    r'|[^\\/\s"<>|:*?]{3,}'
    r')'
)


def render_for_privacy(source):
    """Approximate rendered inline text for public path/payload scanning."""
    block_marker = re.compile(r'(?m)^ {0,3}(?:>[ \t]?|(?:[-+*]|\d{1,9}[.)])(?:[ \t]+|(?=\r?$)))')
    separator = re.compile(r'(?m)^ {0,3}(?:(?:[=-][ \t]*)+|(?:[*_][ \t]*){3,})\r?$')
    while True:
        updated = block_marker.sub('', separator.sub('', source))
        if updated == source:
            break
        source = updated
    heading = re.compile(r'(?m)^ {0,3}#{1,6}(?:[ \t]+([^\r\n]*)|(?=\r?$))')
    source = heading.sub(lambda match: re.sub(r'[ \t]+#+[ \t]*$', '', match.group(1) or ''), source)
    fenced, fence_char, fence_length, pending_code_runs = [], None, 0, set()
    for line in source.splitlines(keepends=True):
        bare = line.rstrip('\r\n')
        if fence_char is None:
            if not bare.strip():
                pending_code_runs.clear()
            opening = re.fullmatch(r' {0,3}(`{3,}|~{3,})[^\r\n]*', bare)
            if opening and opening.group(1)[0] == '`' and len(opening.group(1)) in pending_code_runs:
                opening = None  # Closing a multiline inline span, not opening a fence.
            if opening:
                fence_char, fence_length = opening.group(1)[0], len(opening.group(1))
                fenced.append('\n')
                continue
        elif re.fullmatch(r' {0,3}' + re.escape(fence_char) + '{' + str(fence_length) + r',}[ \t]*', bare):
            fence_char, fence_length = None, 0
            fenced.append('\n')
            continue
        if fence_char is None:
            for run in re.finditer(r'(?<!`)`+(?!`)', bare):
                length = len(run.group())
                if length in pending_code_runs:
                    pending_code_runs.remove(length)
                else:
                    pending_code_runs.add(length)
        fenced.append(line)
    source = ''.join(fenced)
    # GFM footnote definitions render after the body even when their source is
    # between visible words. Keep their text in a separate scan view.
    footnote_definition = re.compile(r'(?m)^ {0,3}\[\^[^\]\r\n]{1,999}\]:[ \t]*(?P<body>[^\r\n]*(?:\r?\n(?:[ \t]*\r?\n)?(?: {4,}|\t)[^\r\n]*)*)')
    footnote_bodies = [match.group('body') for match in footnote_definition.finditer(source)]
    source = footnote_definition.sub('', source)
    fold_ref = lambda value: unicodedata.normalize('NFC', re.sub(r'\s+', ' ', value.strip())).casefold()
    reference_pattern = r'(?m)^ {0,3}\[(?!\^)([^\]]{1,999})\]:[ \t]*(?:\r?\n[ \t]*)?(?P<destination><[^>\r\n]*>|\S+)'
    # A CommonMark reference title may start on the next line and may itself
    # span lines, but cannot contain a blank line.
    quoted_title = r'"(?:\\[^\r\n]|[^"\\\r\n]|\r?\n(?![ \t]*\r?\n))*"'
    single_title = r"'(?:\\[^\r\n]|[^'\\\r\n]|\r?\n(?![ \t]*\r?\n))*'"
    parenthesized_title = r'\((?:\\[^\r\n]|[^)\\\r\n]|\r?\n(?![ \t]*\r?\n))*\)'
    title = '(?:' + '|'.join((quoted_title, single_title, parenthesized_title)) + ')'
    title_after_destination = r'(?:[ \t]+|[ \t]*\r?\n[ \t]*)(?P<title>' + title + r')[ \t]*(?=\r?$)'
    reference_line = re.compile(reference_pattern + r'(?:' + title_after_destination + r')?[^\r\n]*')
    reference_matches = list(reference_line.finditer(source))
    source_references = {fold_ref(match.group(1)) for match in reference_matches}
    visible_titles = [match.group('title') for match in reference_matches if match.group('title')]
    link_destinations = [match.group('destination') for match in reference_matches]
    source = reference_line.sub('', source)
    def render_inline_links(value):
        opener = re.compile(r'!?\[([^\]\r\n]*)\]\(')
        chunks, pos = [], 0
        while match := opener.search(value, pos):
            cursor, depth = match.end(), 1
            while cursor < len(value) and depth and value[cursor] not in '\r\n':
                if value[cursor] == '\\':
                    cursor += 2
                    continue
                if value[cursor] == '(':
                    depth += 1
                elif value[cursor] == ')':
                    depth -= 1
                cursor += 1
            if depth:
                chunks.append(value[pos:match.end()])
                pos = match.end()
                continue
            inline_title = re.search(r'[ \t]+(' + title + r')[ \t]*$', value[match.end():cursor-1])
            if inline_title:
                visible_titles.append(inline_title.group(1))
            link_destinations.append(value[match.end():cursor-1])
            chunks.extend((value[pos:match.start()], match.group(1)))
            pos = cursor
        chunks.append(value[pos:])
        return ''.join(chunks)
    autolink_pattern = re.compile(r'<([A-Za-z][A-Za-z0-9+.-]{1,31}:[^<>\s]+|[^<>\s@]+@[^<>\s@]+\.[^<>\s@]+)>')
    autolink_targets = []
    def capture_autolinks(value):
        autolink_targets.extend(match.group(1) for match in autolink_pattern.finditer(value))
    # Inspect the Markdown source before HTML parsing consumes angle-bracketed
    # destinations as tags. The rendered pass below still supplies link text.
    render_inline_links(source)
    capture_autolinks(source)
    class RenderedHTML(HTMLParser):
        BLOCK_TAGS = frozenset(('address', 'article', 'aside', 'blockquote', 'br', 'canvas', 'dd', 'details', 'dialog', 'div', 'dl', 'dt', 'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hgroup', 'hr', 'legend', 'li', 'main', 'nav', 'ol', 'p', 'pre', 'section', 'summary', 'table', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr', 'ul'))
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.parts = []
            self.attribute_views = {}
            self.paired_attribute_views = {}
        def add_text(self, value):
            self.parts.append(value)
            for parts in self.attribute_views.values():
                parts.append(value)
            for parts in self.paired_attribute_views.values():
                parts.append(value)
        def handle_starttag(self, tag, attrs):
            if tag in self.BLOCK_TAGS:
                self.add_text(' ')
            # Public HTML attributes can expose text as tooltips, form values
            # or accessibility labels. Each local view omits other attributes,
            # so src/type metadata cannot split an adjacent visible value.
            values = {}
            for key,value in attrs:
                if value:
                    values.setdefault(key, []).append(value)
            for key in values:
                if key not in self.attribute_views:
                    self.attribute_views[key] = self.parts.copy()
            for pair in combinations(sorted(values), 2):
                if pair not in self.paired_attribute_views:
                    self.paired_attribute_views[pair] = self.parts.copy()
            for key,parts in self.attribute_views.items():
                value = ''.join(values.get(key, ()))
                if value:
                    parts.append(value if key == 'alt' else ' ' + value + ' ')
            for pair,parts in self.paired_attribute_views.items():
                selected = [''.join(values[key]) for key in pair if key in values]
                if selected:
                    parts.append(' ' + ' '.join(selected) + ' ')
        def handle_startendtag(self, tag, attrs):
            self.handle_starttag(tag, attrs)
        def handle_endtag(self, tag):
            if tag in self.BLOCK_TAGS:
                self.add_text(' ')
        def handle_data(self, data):
            self.add_text(data)
    def html_views(value):
        html_view = RenderedHTML()
        html_view.feed(value)
        html_view.close()
        body_view = ''.join(html_view.parts)
        return [body_view] + [''.join(parts) for parts in html_view.attribute_views.values()] + [''.join(parts) for parts in html_view.paired_attribute_views.values()]
    views = html_views(source)
    for body in footnote_bodies:
        # A moved footnote can contain the same visible HTML, entities, and
        # link metadata as the in-flow body; scan each rendered view in full.
        render_inline_links(body)
        capture_autolinks(body)
        views.extend(html_views(body))
    punctuation_escape = re.compile(r'\\([' + re.escape(string.punctuation) + r'])')
    code_spans = re.compile(r'(?<!`)(?P<ticks>`+)(?!`)(?P<body>[\s\S]*?)(?<!`)(?P=ticks)(?!`)')
    markup = re.compile(r'(?P<marker>\*\*|__|~~|``|\*|_|`)(?P<body>[^\r\n]+?)(?P=marker)')
    def render_view(value):
        rendered = render_inline_links(value)
        # HTML parsing consumes an angle-bracketed Markdown destination as a tag.
        references = source_references | {fold_ref(match.group(1)) for match in re.finditer(reference_pattern, rendered)}
        rendered = reference_line.sub('', rendered)
        rendered = re.sub(r'!?\[([^\]\r\n]*)\]\[([^\]]{0,999})\]', lambda match: match.group(1) if fold_ref(match.group(2) or match.group(1)) in references else match.group(0), rendered)
        rendered = re.sub(r'!?\[([^\]\r\n]+)\]', lambda match: match.group(1) if fold_ref(match.group(1)) in references else match.group(0), rendered)
        rendered = re.sub(r'\\[ \t]*\r?\n', ' ', rendered)
        rendered = punctuation_escape.sub(r'\1', rendered)
        rendered = code_spans.sub(lambda match: re.sub(r'\s+', ' ', match.group('body')), rendered)
        while True:
            previous = rendered
            rendered = markup.sub(lambda match: match.group('body'), rendered)
            if rendered == previous:
                break
        return re.sub(r'\s+', ' ', rendered).strip()
    # A non-whitespace separator prevents tokens and markup from pairing across
    # independent body/attribute views.
    rendered = ' ␞ '.join(render_view(value) for value in dict.fromkeys(views))
    if visible_titles:
        rendered += ' ␞ ' + ' ␞ '.join(punctuation_escape.sub(r'\1', html.unescape(value)) for value in visible_titles)
    if link_destinations:
        rendered += ' ␞ ' + ' ␞ '.join(punctuation_escape.sub(r'\1', html.unescape(value)) for value in link_destinations)
    if autolink_targets:
        rendered += ' ␞ ' + ' ␞ '.join(punctuation_escape.sub(r'\1', html.unescape(value)) for value in autolink_targets)
    return re.sub(r'\s+', ' ', rendered)


# Unicode 17.0 DerivedCoreProperties.txt, Default_Ignorable_Code_Point.
# https://www.unicode.org/Public/17.0.0/ucd/DerivedCoreProperties.txt
DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C),
    (0x115F, 0x1160), (0x17B4, 0x17B5), (0x180B, 0x180F),
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F),
    (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)
DEFAULT_IGNORABLE_STARTS = tuple(start for start, _ in DEFAULT_IGNORABLE_RANGES)


def invisible_format(char):
    category = unicodedata.category(char)
    if category == 'Cf' or (category in ('Mn', 'Me') and unicodedata.combining(char) == 0):
        return True
    index = bisect_right(DEFAULT_IGNORABLE_STARTS, ord(char)) - 1
    return index >= 0 and ord(char) <= DEFAULT_IGNORABLE_RANGES[index][1]


def has_private_path_or_payload(part):
    # Backticks, underscores and tildes can occur in filenames. Treat them as
    # Markdown delimiters only when a matching closing marker is present.
    def rooted_in_spans(source, depth=0):
        if depth >= 16:
            return True  # Too much nested markup to inspect safely.
        spans = re.finditer(r'(?P<marker>`{1,3}|_{1,3}|~{2})(?P<body>[^\r\n]+?)(?P=marker)', source)
        return any(ROOT_RELATIVE_WINDOWS.search(match.group('body')) or rooted_in_spans(match.group('body'), depth+1) for match in spans)
    for candidate in (part, html.unescape(part), render_for_privacy(part)):
        if PRIVATE_PATH_PAYLOAD.search(candidate) or ROOT_RELATIVE_WINDOWS.search(candidate) or rooted_in_spans(candidate):
            return True
        unicode_boundaries = ''.join(' ' if ord(char) > 127 and (unicodedata.category(char)[0] in 'PS' or invisible_format(char)) else char for char in candidate)
        if unicode_boundaries != candidate and ROOT_RELATIVE_WINDOWS.search(unicode_boundaries):
            return True
    return False


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


def unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def strict_json_loads(raw):
    return json.loads(raw, object_pairs_hook=unique_json_pairs)


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
    claims = {key:data[key] for key in ('cutoff', 'completion_claim', 'coverage_definitions', 'capture_protocol')}
    claim_bytes = json.dumps(claims, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    require(hashlib.sha256(claim_bytes).hexdigest() == REVIEWED_TOP_LEVEL_CLAIMS_SHA256, 'unreviewed top-level coverage claims')
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
    operator_public_text = None
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
                source_bytes = source_reader(item['source'])
                require(source_digest(source_bytes) == item['sha256'], 'public operator source digest mismatch')
                operator_public_text = source_bytes.decode('utf-8')
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
            require('Back' in state['controls'], 'observed Back absent from controls')
            require(bool(back['evidence_ids']), 'observed Back without evidence')
            require(any(e['from'] == state['id'] and e['to'] == back['target_state_id'] and e['action'] == 'Back' and e['status'] == 'observed-action' and set(back['evidence_ids']).issubset(e['evidence_ids']) for e in edges.values()), 'back claim without matching Back action edge')
        else:
            require(back['status'] == 'unobserved' and back['target_state_id'] is None and not back['evidence_ids'], 'unobserved Back has target or evidence')
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
    require(denominator['scope'] == REVIEWED_DENOMINATOR_SCOPE, 'unreviewed denominator scope')
    require(denominator['total_application_screen_states'] is None, 'unknown total application denominator promoted to known')
    expected_sets = {
        'screenshot_confirmed_state_ids':[i for i,s in states.items() if s['coverage']['screenshot']],
        'operator_only_state_ids':[i for i,s in states.items() if s['kind'] == 'operator-only'],
        'terminal_state_ids':[i for i,s in states.items() if s['kind'] == 'terminal'],
        'discovered_uncaptured_route_ids':list(routes), 'unknown_unbounded_section_ids':list(domains)}
    require(set(denominator) == {'scope', 'total_application_screen_states', 'counts', *expected_sets}, 'unreviewed denominator fields')
    require(all(denominator[k] == v for k,v in expected_sets.items()), 'denominator membership mismatch')
    require(denominator['counts'] == {k:len(v) for k,v in expected_sets.items()}, 'denominator count mismatch')
    report_bytes = report_reader()
    require(operator_public_text is not None, 'public operator report missing')
    public = list(text_values(data)) + [report_bytes.decode('utf-8'), operator_public_text]
    require(not any(has_private_path_or_payload(part) for part in public), 'private path/payload in census')
    require(set(data) == REVIEWED_ROOT_FIELDS, 'unreviewed root fields')
    require(hashlib.sha256(report_bytes.replace(b'\r\n', b'\n')).hexdigest() == REVIEWED_UI_REPORT_SHA256, 'public UI report digest mismatch')
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-root',type=Path)
    parser.add_argument('--private-aliases',type=Path)
    args = parser.parse_args()
    raw_census = (ROOT/'evidence/ui-screen-census-41.json').read_text(encoding='utf-8')
    data = strict_json_loads(raw_census)
    assets = {a['asset_id']:a for a in strict_json_loads((ROOT/'evidence/ui-assets-41-inventory.json').read_text(encoding='utf-8'))['assets']}
    result = validate(data, assets)
    try:
        strict_json_loads(raw_census.replace('"schema":', '"schema":"/home/operator/private/capture.png","schema":', 1))
    except ValueError:
        pass
    else:
        raise ValueError('duplicate-key private path probe accepted')
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
    def claim_whole_ui_complete(d):
        d['completion_claim'] = 'Complete application UI coverage established'
    def redefine_screenshot_coverage(d):
        d['coverage_definitions']['screenshot'] = 'Screenshot proves observed action behavior'
    def claim_whole_denominator_scope(d):
        d['denominator']['scope'] = 'entire application covered'
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
        claim_whole_ui_complete,
        lambda d:d.update(whole_application_coverage='complete'),
        redefine_screenshot_coverage,
        claim_whole_denominator_scope,
        lambda d:d['denominator'].update(whole_application_coverage='complete'),
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
        lambda d:d.update(private_payload='&#47;tmp/capture.jpg'),
        lambda d:d.update(private_payload='results/private-capture.json'),
        lambda d:d.update(private_payload='Results/private-capture.json'),
        lambda d:d.update(private_payload='DATA:IMAGE/JPEG;BASE64,AAAA'),
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
    for leaked in ('\\Users\\operator\\private\\capture.png', '\\capture.png', '\\UI\\capture.png', '\\Équipe\\capture.png', '\\My Documents\\capture.png', '\\My capture.png', '`\\UI\\capture.png`', '**\\UI\\capture.png**', '_\\UI\\capture.png_', '__\\UI\\capture.png__', '~~\\UI\\capture.png~~', '__private _\\UI\\capture.png_ location__', '~~private _\\UI\\capture.png_ location~~'):
        changed = copy.deepcopy(data)
        changed['private_payload'] = leaked
        try:
            validate(changed, assets)
        except ValueError as exc:
            require(str(exc) == 'private path/payload in census', 'root-relative census path rejected for unrelated reason')
        else:
            raise ValueError('root-relative census path accepted')
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
    operator_payload = raw_lf + b'\n/private/operator/capture.jpg\n'
    operator_mutation = copy.deepcopy(data)
    next(item for item in operator_mutation['evidence'] if item['id']=='r41-operator-route-report')['sha256'] = source_digest(operator_payload)
    reviewed_evidence_digest = REVIEWED_BATCH_SECTION_SHA256['evidence']
    try:
        REVIEWED_BATCH_SECTION_SHA256['evidence'] = batch_section_digest(operator_mutation['evidence'])
        try:
            validate(operator_mutation, assets, source_reader=lambda _: operator_payload)
        except ValueError as exc:
            require(str(exc) == 'private path/payload in census', 'resealed operator path rejected for unrelated reason')
        else:
            raise ValueError('resealed operator path accepted')
    finally:
        REVIEWED_BATCH_SECTION_SHA256['evidence'] = reviewed_evidence_digest
    report = public_report_bytes()
    validate(data, assets, report_reader=lambda: report.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
    changed_count = report.replace(b'| Screenshot-confirmed screen/state IDs | 17 |', b'| Screenshot-confirmed screen/state IDs | 99 |', 1)
    require(changed_count != report, 'missing reviewed public screenshot total')
    try:
        validate(data, assets, report_reader=lambda: changed_count)
    except ValueError as exc:
        require(str(exc) == 'public UI report digest mismatch', 'changed public total rejected for unrelated reason')
    else:
        raise ValueError('changed public coverage total accepted')
    report_leaks = (b'\n/tmp/capture.jpg', b'\nresults/private-capture.json', b'\nResults/private-capture.json', b'\nDATA:IMAGE/JPEG;BASE64,AAAA', b'\n\\\\server\\share\\private\\capture.png', b'\n\\Users\\operator\\private\\capture.png', b'\n\\capture.png', b'\n\\UI\\capture.png', '\n\\Équipe\\capture.png'.encode('utf-8'), b'\n\\My Documents\\capture.png', b'\n\\My capture.png', b'\n`\\UI\\capture.png`', b'\n**\\UI\\capture.png**', b'\n_\\UI\\capture.png_', b'\n__\\UI\\capture.png__', b'\n~~\\UI\\capture.png~~', b'\n__private _\\UI\\capture.png_ location__', b'\n~~private _\\UI\\capture.png_ location~~')
    slash_root_report_leaks = (b'\n//server/share/private/capture.png', b'\n//tmp/private/capture.png', b'\nlocation:/home/operator/private/capture.png')
    encoded_report_leaks = (b'\n&#47;home/operator/private/capture.png', b'\nC&#58;\\Users\\operator\\capture.png', b'\n&#92;UI&#92;capture.png')
    formatted_report_leaks = (b'\nC`:`\\Users\\operator\\private\\capture.png', b'\nC[:](https://example.invalid)\\Users\\operator\\private\\capture.png', b'\nC<code>:</code>\\Users\\operator\\private\\capture.png', b'\nC[](/x):\\Users\\operator\\private\\capture.png', b'\nC:[][ref]\\Users\\operator\\private\\capture.png\n\n[ref]: target', b'\nC:[][ref one]\\Users\\operator\\private\\capture.png\n\n[ref  one]: target')
    whitespace_reference_report_leaks = (
        b'\nC:[][ref\tone]\\Users\\operator\\private\\capture.png\n\n[ref one]: target',
        b'\nC:[][ref\none]\\Users\\operator\\private\\capture.png\n\n[ref one]: target',
        b'\nC:[][ref one]\\Users\\operator\\private\\capture.png\n\n[ref\none]: target',
    )
    next_line_reference_report_leaks = (
        b'\nC:[][ref]\\Users\\operator\\private\\capture.png\n\n[ref]:\n target',
        b'\nC:[][ref]\\Users\\operator\\private\\capture.png\n\n[ref]:\n    target',
        b'\nC:[][ref]\\Users\\operator\\private\\capture.png\n\n[ref]:\n\ttarget',
        b'\nC:[][ref]\\Users\\operator\\private\\capture.png\n\n[ref]: <target>',
        b'\nC:[][ref]\\Users\\operator\\private\\capture.png\n\n[ref]:\n    <target>',
    )
    unicode_boundary_report_leaks = (
        '\nlocation—\\Users\\operator\\private\\capture.png'.encode('utf-8'),
        '\n“\\Users\\operator\\private\\capture.png'.encode('utf-8'),
        '\nlocation📁\\Users\\operator\\private\\capture.png'.encode('utf-8'),
        '\nlocation→\\Users\\operator\\private\\capture.png'.encode('utf-8'),
        '\nlocation\u200b\\Users\\operator\\private\\capture.png'.encode('utf-8'),
        '\nlocation\u2060\\Users\\operator\\private\\capture.png'.encode('utf-8'),
        '\nlocation\u034f\\Users\\operator\\private\\capture.png'.encode('utf-8'),
        '\nlocation\ufe0f\\Users\\operator\\private\\capture.png'.encode('utf-8'),
        '\nlocation\u115f\\Users\\operator\\private\\capture.png'.encode('utf-8'),
        '\nlocation\u3164\\Users\\operator\\private\\capture.png'.encode('utf-8'),
    )
    for leaked in report_leaks + slash_root_report_leaks + encoded_report_leaks + formatted_report_leaks + whitespace_reference_report_leaks + next_line_reference_report_leaks + unicode_boundary_report_leaks:
        try:
            validate(data, assets, report_reader=lambda: report + leaked)
        except ValueError as exc:
            require(str(exc) == 'private path/payload in census', 'public report path rejected for unrelated reason')
        else:
            raise ValueError('private path in public report accepted')
    require(not has_private_path_or_payload('docs\\reference\\ui.md'), 'repository-relative Windows path rejected')
    require(not has_private_path_or_payload('docs-\\reference\\ui.md'), 'hyphenated repository-relative Windows path rejected')
    require(not has_private_path_or_payload('docs+\\reference\\ui.md'), 'plus-suffixed repository-relative Windows path rejected')
    require(not has_private_path_or_payload('docs@\\reference\\ui.md'), 'at-suffixed repository-relative Windows path rejected')
    require(not has_private_path_or_payload('docs`\\reference\\ui.md'), 'backtick-suffixed repository-relative Windows path rejected')
    require(not has_private_path_or_payload('docs_\\reference\\ui.md'), 'underscore-suffixed repository-relative Windows path rejected')
    require(not has_private_path_or_payload('docs~~\\reference\\ui.md'), 'tilde-suffixed repository-relative Windows path rejected')
    require(not has_private_path_or_payload('__private _docs\\reference\\ui.md_ location__'), 'nested relative Windows path rejected')
    require(not has_private_path_or_payload('https://example.invalid/docs/reference/ui.md'), 'ordinary HTTPS URL rejected')
    require(not has_private_path_or_payload('[docs](https://example.invalid/docs/reference/ui.md)'), 'Markdown HTTPS URL rejected')
    require(not has_private_path_or_payload('https://example.invalid/private/capture.png'), 'remote URL path rejected as local path')
    require(not has_private_path_or_payload('escaped \\n punctuation.'), 'ordinary escaped punctuation rejected')
    if args.private_root or args.private_aliases:
        require(args.private_root and args.private_aliases,'private root and aliases must be supplied together')
        root = args.private_root.resolve(strict=True)
        aliases = strict_json_loads(args.private_aliases.read_text(encoding='utf-8'))['aliases']
        for evidence in data['evidence']:
            if evidence['kind'] != 'screenshot':
                continue
            path = (root / aliases[evidence['id']]).resolve(strict=True)
            require(path.is_relative_to(root),'private alias escaped root')
            image = path.read_bytes()
            require(hashlib.sha256(image).hexdigest() == evidence['sha256'],'private screenshot hash mismatch')
            require(jpeg_size(image) == evidence['capture_pixels'],'private screenshot dimensions mismatch')
        result['private_image_checks'] = 'pass'
    result['negative_probes'] = len(mutations) + 17 + len(report_leaks) + len(slash_root_report_leaks) + len(encoded_report_leaks) + len(formatted_report_leaks) + len(whitespace_reference_report_leaks) + len(next_line_reference_report_leaks) + len(unicode_boundary_report_leaks)
    result['public_path_near_miss_probes'] = 12
    result['tracked_source_checks'] = 'LF/CRLF match; changed digest/content rejected'
    result['public_report_checks'] = 'LF/CRLF match; changed coverage total rejected'
    print(json.dumps(result,sort_keys=True))


if __name__ == '__main__':
    main()
