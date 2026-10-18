/** Finite, normal-range x87 arithmetic used by the keeper response slice.
 * Models precision-control=53 or64 bits, round-to-nearest/even for ADD/MUL.
 * Not a general x87 emulator: no exponent limits, special values or DIV.
 */
export type Extended = { coefficient: bigint; exponent: number };
function rounded(coefficient: bigint, exponent: number,precision: 53|64): Extended {
  const negative = coefficient < 0n;
  let magnitude = negative ? -coefficient : coefficient;
  const shift = magnitude.toString(2).length - precision;
  if (shift > 0) {
    const bits = BigInt(shift), half = 1n << (bits - 1n);
    const remainder = magnitude & ((1n << bits) - 1n);
    magnitude >>= bits;
    if (remainder > half || (remainder === half && (magnitude & 1n) !== 0n)) magnitude++;
    exponent += shift;
  }
  return { coefficient: negative ? -magnitude : magnitude, exponent };
}
export function extended(value: number): Extended {
  if (!Number.isFinite(value)) throw new RangeError('Finite numbers only');
  const view = new DataView(new ArrayBuffer(8));view.setFloat64(0,value);
  const bits = view.getBigUint64(0), fraction = bits & ((1n << 52n) - 1n);
  const exponent = Number((bits >> 52n) & 2047n);
  const magnitude = exponent === 0 ? fraction : (1n << 52n) | fraction;
  return { coefficient: bits >> 63n ? -magnitude : magnitude, exponent: exponent === 0 ? -1074 : exponent - 1075 };
}
export function arithmetic(precision: 53|64) {
  if (precision!==53 && precision!==64) throw new RangeError('Supported precision:53 or64 bits');
  return {
    add(a: Extended,b: Extended): Extended {
      const exponent = Math.min(a.exponent,b.exponent);
      return rounded((a.coefficient << BigInt(a.exponent-exponent)) + (b.coefficient << BigInt(b.exponent-exponent)),exponent,precision);
    },
    multiply(a: Extended,b: Extended): Extended {
      return rounded(a.coefficient*b.coefficient,a.exponent+b.exponent,precision);
    }
  };
}
/** __ftol truncation in this bounded slice; outputs fit signed32. */
export function truncate(value: Extended): number {
  const result = value.exponent < 0 ? value.coefficient / (1n << BigInt(-value.exponent)) : value.coefficient << BigInt(value.exponent);
  const number = Number(result);
  if (!Number.isInteger(number) || number < -2147483648 || number > 2147483647) throw new RangeError('Outside signed32 slice domain');
  return number === 0 ? 0 : number;
}
