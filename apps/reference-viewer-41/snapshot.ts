export interface PlayerRow {
  id: string;
  picked: string;
  info: string;
  name: string;
  position: string;
  form: string;
  morale: string;
  condition: string;
  apps: string;
  averageRating: string;
  value: string;
}

export interface ReferenceSnapshot {
  schema: 'reversal.ui-reference-41.v1';
  kind: 'captured-read-only' | 'synthetic-example';
  snapshotId: string;
  provenance: {
    executableSha256: string | null;
    configManifestSha256: string | null;
    saveSha256: string | null;
    captureIds: string[];
    resolution: { width: 800; height: 600 };
  };
  squad: { captureId: string; clubLabel: string; dateLabel: string; rows: PlayerRow[] };
  profile: {
    playerId: string;
    captureId: string;
    title: string;
    bio: string;
    role: string;
    attributeColumns: { label: string; value: string }[][];
    preferredFoot: string;
    form: string;
    morale: string;
    condition: string;
  };
}

const rowKeys = ['id', 'picked', 'info', 'name', 'position', 'form', 'morale', 'condition', 'apps', 'averageRating', 'value'];

function requireValue(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function record(value: unknown, keys: string[], at: string): Record<string, unknown> {
  requireValue(value !== null && typeof value === 'object' && !Array.isArray(value), `${at}: expected object`);
  const result = value as Record<string, unknown>;
  requireValue(Object.keys(result).length === keys.length && keys.every(key => Object.hasOwn(result, key)), `${at}: unsupported or missing fields`);
  return result;
}

function text(value: unknown, at: string, allowEmpty = false): string {
  requireValue(typeof value === 'string' && value.length <= 180 && (allowEmpty || value.trim().length > 0), `${at}: expected bounded text`);
  requireValue(!/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value), `${at}: control characters unavailable`);
  return value;
}

/** Validate untrusted local JSON before rendering. All values are display strings;
 * native IDs, executable calls, updates, URLs and game commands are unsupported. */
export function parseSnapshot(value: unknown): ReferenceSnapshot {
  const data = record(value, ['schema', 'kind', 'snapshotId', 'provenance', 'squad', 'profile'], 'snapshot');
  requireValue(data.schema === 'reversal.ui-reference-41.v1', 'Unsupported snapshot schema');
  requireValue(data.kind === 'captured-read-only' || data.kind === 'synthetic-example', 'Unsupported snapshot kind');
  text(data.snapshotId, 'snapshotId');
  const source = record(data.provenance, ['executableSha256', 'configManifestSha256', 'saveSha256', 'captureIds', 'resolution'], 'provenance');
  for (const key of ['executableSha256', 'configManifestSha256', 'saveSha256']) {
    requireValue((data.kind === 'synthetic-example' && source[key] === null) ||
      (typeof source[key] === 'string' && /^[a-f0-9]{64}$/.test(source[key] as string)), `${key}: expected SHA-256 identity`);
  }
  const resolution = record(source.resolution, ['width', 'height'], 'resolution');
  requireValue(resolution.width === 800 && resolution.height === 600, 'Only the observed 800 × 600 view is supported');
  requireValue(Array.isArray(source.captureIds) && source.captureIds.length >= 2 && source.captureIds.length <= 10, 'Expected bounded source capture IDs');
  const captures = source.captureIds.map(id => text(id, 'capture ID'));
  requireValue(new Set(captures).size === captures.length, 'Duplicate capture ID');
  const squad = record(data.squad, ['captureId', 'clubLabel', 'dateLabel', 'rows'], 'squad');
  for (const key of ['captureId', 'clubLabel', 'dateLabel']) text(squad[key], `squad.${key}`);
  requireValue(captures.includes(squad.captureId as string), 'Squad capture missing from provenance');
  requireValue(Array.isArray(squad.rows) && squad.rows.length >= 1 && squad.rows.length <= 50, 'Expected 1–50 captured roster rows');
  const ids = new Set<string>();
  for (const value of squad.rows) {
    const row = record(value, rowKeys, 'player');
    for (const key of rowKeys) text(row[key], `player.${key}`, ['picked', 'info'].includes(key));
    requireValue(!ids.has(row.id as string), 'Duplicate local player ID');
    ids.add(row.id as string);
  }
  const profile = record(data.profile, ['playerId', 'captureId', 'title', 'bio', 'role', 'attributeColumns', 'preferredFoot', 'form', 'morale', 'condition'], 'profile');
  for (const key of ['playerId', 'captureId', 'title', 'bio', 'role', 'preferredFoot', 'form', 'morale', 'condition']) text(profile[key], `profile.${key}`);
  requireValue(ids.has(profile.playerId as string), 'Profile must refer to a captured roster row');
  requireValue(captures.includes(profile.captureId as string), 'Profile capture missing from provenance');
  requireValue(Array.isArray(profile.attributeColumns) && profile.attributeColumns.length === 3, 'Expected three observed attribute columns');
  for (const column of profile.attributeColumns) {
    requireValue(Array.isArray(column) && column.length >= 1 && column.length <= 12, 'Expected bounded attribute column');
    for (const value of column) {
      const attribute = record(value, ['label', 'value'], 'attribute');
      text(attribute.label, 'attribute.label');
      text(attribute.value, 'attribute.value');
    }
  }
  return value as ReferenceSnapshot;
}
