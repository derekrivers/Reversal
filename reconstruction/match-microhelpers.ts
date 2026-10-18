/** Bounded local contracts for 006f0970/007160d0/007160e0.
 * Memory must provide stable, disjoint receiver, match and stack storage.
 * Faults, aliasing, concurrency and game state lifecycle are outside this API.
 */
export interface MicroMemory {
  read8(address: number): number;
  read32(address: number): number;
  write8(address: number, value: number): void;
  write16(address: number, value: number): void;
  write32(address: number, value: number): void;
}
export interface MicroRegisters { eax: number; edx: number; eflags: number }
function dword(value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new RangeError('unsigned DWORD required');
}
function validate(receiver: number, state: MicroRegisters): void {
  dword(receiver); dword(state.eax); dword(state.edx); dword(state.eflags);
}
const at = (base: number, offset: number): number => (base + offset) >>> 0;
const lowByte = (word: number, byte: number): number => ((word & 0xffffff00) | byte) >>> 0;
export function resetMatchMicrostate(receiver: number, state: MicroRegisters, memory: MicroMemory): MicroRegisters {
  validate(receiver, state);
  let edx = memory.read32(at(receiver, 0x19e));
  memory.write32(at(edx, 0x4786), 0);
  edx = memory.read32(at(receiver, 0x19e));
  memory.write8(at(edx, 0x8eae), 255);
  edx = memory.read32(at(receiver, 0x19e));
  memory.write32(at(edx, 0xf582), 0);
  edx = memory.read32(at(receiver, 0x19e));
  memory.write8(at(edx, 0x1a7), 0);
  memory.write16(at(receiver, 0x29), 0);
  memory.write16(at(receiver, 0x19c), 0);
  // XOR's AF is architecturally undefined; zero here records Unicorn 2.1.4's
  // observation, with no claim about AF on other CPUs/emulators.
  return { eax: 0, edx, eflags: ((state.eflags & ~0x8d5) | 0x44) >>> 0 };
}
export function addReceiverByte(receiver: number, argument: number, state: MicroRegisters, memory: MicroMemory): MicroRegisters {
  validate(receiver, state); dword(argument);
  const a = memory.read8(at(receiver, 0x2b)), b = argument & 255, sum = a + b, byte = sum & 255;
  memory.write8(at(receiver, 0x2b), byte);
  const parity = (byte.toString(2).split('1').length - 1) % 2 === 0;
  const flags = (sum > 255 ? 1 : 0) | (parity ? 4 : 0) | (((a ^ b ^ byte) & 16) ? 16 : 0)
    | (byte === 0 ? 64 : 0) | (byte & 128) | ((~(a ^ b) & (a ^ byte) & 128) ? 0x800 : 0);
  return { eax: lowByte(state.eax, b), edx: lowByte(state.edx, byte), eflags: ((state.eflags & ~0x8d5) | flags) >>> 0 };
}
export function setReceiverByte(receiver: number, argument: number, state: MicroRegisters, memory: MicroMemory): MicroRegisters {
  validate(receiver, state); dword(argument);
  const byte = argument & 255;
  memory.write8(at(receiver, 0x2b), byte);
  return { eax: lowByte(state.eax, byte), edx: state.edx, eflags: state.eflags };
}
