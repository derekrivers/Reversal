/** Bounded 0062ed70 -> 0062c680 -> return on a current cached status row.
 * Two verified disk-code address maps; no producer, resolver or effect join.
 * This path has no RNG call. It preserves the caller's shared RNG object.
 */
import type {RandomState} from './bounded-random.ts';
export type Build41 = 'pinned' | 'gdi';
export interface Memory41 {
  peek(address: number, width: number): number;
  read(site: number, address: number, width: number): number;
  write(site: number, address: number, width: number, value: number): void;
}
export interface Shared41 {
  rng: RandomState;
  x87Control: number;
}
export interface Boundary41 {
  kind: 'refresh-call' | 'refresh-return';
  site: number;
  receiver: number;
  stack: number;
  argument: number | null;
}
export const globals41 = {
  pinned: {flags: 0xb63d10, count: 0xae2364, date: 0xae2c90, lookup: 0xb63d28},
  gdi: {flags: 0xb62c58, count: 0xae12b4, date: 0xae1be0, lookup: 0xb62c70},
};
const addressRanges = [
  [0x62ed70, 0x62e6e0, 0x15], [0x62ede1, 0x62e751, 0x4a],
  [0x62c680, 0x62bff0, 0x116], [0x62cde1, 0x62c751, 0x14],
];
export function site41(address: number, build: Build41): number {
  if (build === 'pinned') return address;
  for (const [start, target, size] of addressRanges)
    if (address >= start && address < start + size) return target + address - start;
  throw new RangeError('unmapped instruction site');
}
function need(ok: unknown, reason: string): asserts ok {
  if (!ok) throw new RangeError(reason);
}
function dword(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
}

export function lookupCached41(
  build: Build41, receiver: number, participant: number, stack: number,
  memory: Memory41, shared: Shared41,
  boundary: (state: Boundary41) => void = () => {},
): {pointer: number; mapping: number; row: number; stack: number; shared: Shared41} {
  need(build === 'pinned' || build === 'gdi', 'unsupported executable identity');
  need([receiver, participant, stack].every(dword), 'DWORD entry addresses required');
  need(receiver !== 0 && participant !== 0 && stack >= 0x260, 'missing entry storage');
  const globals = globals41[build];
  const index = memory.peek(participant, 4) | 0;
  const count = memory.peek(globals.count, 4) | 0;
  need(index >= 0 && index < count, 'staff index outside admitted range');
  need((memory.peek(globals.flags, 1) & 7) === 7, 'helper initialization is unsupported');
  need(memory.peek(participant + 0x61, 4) !== 0, 'null attributes outside cached domain');
  const rows = memory.peek(receiver, 4);
  const row = rows + index * 31;
  need(rows !== 0 && dword(row + 30), 'row pointer overflow or missing storage');
  need(memory.peek(row, 4) === memory.peek(globals.date, 4), 'refresh update is unsupported');
  const initialMapping = memory.peek(row + 0xe, 4) | 0;
  need(initialMapping >= -1, 'negative cache index outside admitted domain');
  if (initialMapping !== -1) {
    const cache = memory.peek(receiver + 4, 4);
    need(cache !== 0 && dword(cache + 48 * initialMapping), 'cache pointer overflow or missing storage');
  }
  need(Object.values(shared.rng).every(dword) && shared.rng.cursorIndex < 51000 &&
    shared.rng.offset <= 65535, 'unsupported shared RNG state');
  need(shared.x87Control === 0x27f || shared.x87Control === 0x37f, 'unvalidated x87 control');
  const read = (site: number, address: number, width = 4) =>
    memory.read(site41(site, build), address >>> 0, width);
  const write = (site: number, address: number, width: number, value: number) =>
    memory.write(site41(site, build), address >>> 0, width, value >>> 0);
  // Lookup's first signed count guard, then the actual nested refresh boundary.
  read(0x62edee, participant);
  read(0x62edf0, globals.count);
  boundary({kind: 'refresh-call', site: site41(0x62edfc, build), receiver,
    stack: stack - 0x20c, argument: participant});
  const oldSeh = read(0x62c687, 0);
  write(0x62c68e, 0, 4, stack - 0x21c);
  read(0x62c698, globals.flags, 1);
  read(0x62c6da, globals.flags, 1);
  read(0x62c705, globals.flags, 1);
  const currentIndex = read(0x62c73e, participant);
  read(0x62c740, globals.count);
  read(0x62c74e, participant + 0x61);
  const currentRows = read(0x62c75d, receiver);
  const currentRow = (currentRows + Math.imul(currentIndex, 31)) >>> 0;
  read(0x62c767, currentRow);
  read(0x62c779, currentRow + 4);
  read(0x62c77c, globals.date + 2, 2);
  read(0x62c789, globals.date, 2);
  write(0x62cde8, 0, 4, oldSeh);
  boundary({kind: 'refresh-return', site: site41(0x62ee01, build), receiver: oldSeh,
    stack: stack - 0x208, argument: null});
  const returnedIndex = read(0x62ee01, participant);
  const returnedRows = read(0x62ee0a, receiver);
  const returnedRow = (returnedRows + Math.imul(returnedIndex, 31)) >>> 0;
  const mapping = read(0x62ee0c, returnedRow + 0xe) | 0;
  const pointer = mapping === -1 ? 0 :
    (read(0x62ee15, receiver + 4) + Math.imul(mapping, 48)) >>> 0;
  return {pointer, mapping, row: returnedRow, stack: stack + 8, shared};
}
