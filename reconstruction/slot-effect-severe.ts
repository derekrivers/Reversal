/** 006d0980: admitted kind=-1, severity>50, result<5000, counter<=3 path. */
export type SevereSlotInput = {
  counter: number; latch: number; severity: number; initialFloat: number;
  otherPresent: boolean; otherWord: number;
};

export type SlotWrite = ['match'|'target'|'other', number, number, number];

const bits = new DataView(new ArrayBuffer(4));
function floatBits(x:number):number {
  bits.setFloat32(0,x,true);
  return bits.getUint32(0,true);
}
function signed16(x:number):number { return (x << 16) >> 16; }

export function applySevereSlotEffect(input:SevereSlotInput) {
  const {counter,latch,severity,initialFloat,otherPresent,otherWord} = input;
  if (!Number.isInteger(counter) || counter < -3 || counter > 3
      || (latch !== 0 && latch !== 1)
      || !Number.isInteger(severity) || severity < 51 || severity > 127
      || ![1,500,4000,6000].includes(initialFloat)
      || !Number.isInteger(otherWord) || otherWord < -32768 || otherWord > 32767)
    throw new RangeError('outside original-entry severe slot oracle domain');
  const initial = Math.fround(initialFloat);
  const changed = Math.fround(initial-severity*severity);
  if (!(changed < 5000)) throw new RangeError('may reach transitive setter');
  const writes:SlotWrite[] = [];
  const other = otherPresent ? 0x410000 : 0;
  writes.push(['target',0x55,4,other]);
  const finalOther = otherPresent ? signed16(otherWord-10) : otherWord;
  if (otherPresent) writes.push(['other',0x31,2,finalOther & 0xffff]);
  writes.push(['target',0x1c,1,1]);
  writes.push(['target',0x4d,4,floatBits(changed)]);
  writes.push(['match',0x8eb5,1,1]);
  writes.push(['target',0x1d,1,1]);
  writes.push(['target',0x1c,1,1]);
  const clamped = changed < 1 ? 1 : changed > 10000 ? 10000 : changed;
  writes.push(['target',0x4d,4,floatBits(clamped)]);
  const finalCounter = signed16(counter+1);
  writes.push(['match',0xf639,2,finalCounter & 0xffff]);
  return {result:{match_counter:finalCounter,match_latch:1,
                  target_float_bits:floatBits(clamped),target_flag_1c:1,
                  target_flag_1d:1,target_other:other,other_word:finalOther},
          writes,espDelta:20};
}
