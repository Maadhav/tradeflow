// .cre_build_tmp.js
var __esm = (fn, res, err) => () => {
  if (fn)
    try {
      res = fn(fn = 0);
    } catch (e) {
      err = [e];
    }
  if (err)
    throw err[0];
  return res;
};
var crypto2;
var init_crypto = __esm(() => {
  crypto2 = typeof globalThis === "object" && "crypto" in globalThis ? globalThis.crypto : undefined;
});
function isBytes2(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function anumber2(n) {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error("positive integer expected, got " + n);
}
function abytes2(b, ...lengths) {
  if (!isBytes2(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}
function ahash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new Error("Hash should be wrapped by utils.createHasher");
  anumber2(h.outputLen);
  anumber2(h.blockLen);
}
function aexists2(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput2(out, instance) {
  abytes2(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}
function clean2(...arrays) {
  for (let i = 0;i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
function utf8ToBytes2(str) {
  if (typeof str !== "string")
    throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes3(data) {
  if (typeof data === "string")
    data = utf8ToBytes2(data);
  abytes2(data);
  return data;
}
function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0;i < arrays.length; i++) {
    const a = arrays[i];
    abytes2(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0;i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}

class Hash2 {
}
function createHasher2(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes3(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}
function randomBytes(bytesLength = 32) {
  if (crypto2 && typeof crypto2.getRandomValues === "function") {
    return crypto2.getRandomValues(new Uint8Array(bytesLength));
  }
  if (crypto2 && typeof crypto2.randomBytes === "function") {
    return Uint8Array.from(crypto2.randomBytes(bytesLength));
  }
  throw new Error("crypto.getRandomValues must be defined");
}
var init_utils = __esm(() => {
  init_crypto();
  /*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
});
function setBigUint64(view, byteOffset, value, isLE) {
  if (typeof view.setBigUint64 === "function")
    return view.setBigUint64(byteOffset, value, isLE);
  const _32n = BigInt(32);
  const _u32_max = BigInt(4294967295);
  const wh = Number(value >> _32n & _u32_max);
  const wl = Number(value & _u32_max);
  const h = isLE ? 4 : 0;
  const l = isLE ? 0 : 4;
  view.setUint32(byteOffset + h, wh, isLE);
  view.setUint32(byteOffset + l, wl, isLE);
}
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
var HashMD;
var SHA256_IV;
var init__md = __esm(() => {
  init_utils();
  HashMD = class HashMD extends Hash2 {
    constructor(blockLen, outputLen, padOffset, isLE) {
      super();
      this.finished = false;
      this.length = 0;
      this.pos = 0;
      this.destroyed = false;
      this.blockLen = blockLen;
      this.outputLen = outputLen;
      this.padOffset = padOffset;
      this.isLE = isLE;
      this.buffer = new Uint8Array(blockLen);
      this.view = createView(this.buffer);
    }
    update(data) {
      aexists2(this);
      data = toBytes3(data);
      abytes2(data);
      const { view, buffer, blockLen } = this;
      const len = data.length;
      for (let pos = 0;pos < len; ) {
        const take = Math.min(blockLen - this.pos, len - pos);
        if (take === blockLen) {
          const dataView = createView(data);
          for (;blockLen <= len - pos; pos += blockLen)
            this.process(dataView, pos);
          continue;
        }
        buffer.set(data.subarray(pos, pos + take), this.pos);
        this.pos += take;
        pos += take;
        if (this.pos === blockLen) {
          this.process(view, 0);
          this.pos = 0;
        }
      }
      this.length += data.length;
      this.roundClean();
      return this;
    }
    digestInto(out) {
      aexists2(this);
      aoutput2(out, this);
      this.finished = true;
      const { buffer, view, blockLen, isLE } = this;
      let { pos } = this;
      buffer[pos++] = 128;
      clean2(this.buffer.subarray(pos));
      if (this.padOffset > blockLen - pos) {
        this.process(view, 0);
        pos = 0;
      }
      for (let i = pos;i < blockLen; i++)
        buffer[i] = 0;
      setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
      this.process(view, 0);
      const oview = createView(out);
      const len = this.outputLen;
      if (len % 4)
        throw new Error("_sha2: outputLen should be aligned to 32bit");
      const outLen = len / 4;
      const state = this.get();
      if (outLen > state.length)
        throw new Error("_sha2: outputLen bigger than state");
      for (let i = 0;i < outLen; i++)
        oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
      const { buffer, outputLen } = this;
      this.digestInto(buffer);
      const res = buffer.slice(0, outputLen);
      this.destroy();
      return res;
    }
    _cloneInto(to) {
      to || (to = new this.constructor);
      to.set(...this.get());
      const { blockLen, buffer, length, finished, destroyed, pos } = this;
      to.destroyed = destroyed;
      to.finished = finished;
      to.length = length;
      to.pos = pos;
      if (length % blockLen)
        to.buffer.set(buffer);
      return to;
    }
    clone() {
      return this._cloneInto();
    }
  };
  SHA256_IV = /* @__PURE__ */ Uint32Array.from([
    1779033703,
    3144134277,
    1013904242,
    2773480762,
    1359893119,
    2600822924,
    528734635,
    1541459225
  ]);
});
var SHA256_K;
var SHA256_W;
var SHA256;
var sha256;
var init_sha2 = __esm(() => {
  init__md();
  init_utils();
  SHA256_K = /* @__PURE__ */ Uint32Array.from([
    1116352408,
    1899447441,
    3049323471,
    3921009573,
    961987163,
    1508970993,
    2453635748,
    2870763221,
    3624381080,
    310598401,
    607225278,
    1426881987,
    1925078388,
    2162078206,
    2614888103,
    3248222580,
    3835390401,
    4022224774,
    264347078,
    604807628,
    770255983,
    1249150122,
    1555081692,
    1996064986,
    2554220882,
    2821834349,
    2952996808,
    3210313671,
    3336571891,
    3584528711,
    113926993,
    338241895,
    666307205,
    773529912,
    1294757372,
    1396182291,
    1695183700,
    1986661051,
    2177026350,
    2456956037,
    2730485921,
    2820302411,
    3259730800,
    3345764771,
    3516065817,
    3600352804,
    4094571909,
    275423344,
    430227734,
    506948616,
    659060556,
    883997877,
    958139571,
    1322822218,
    1537002063,
    1747873779,
    1955562222,
    2024104815,
    2227730452,
    2361852424,
    2428436474,
    2756734187,
    3204031479,
    3329325298
  ]);
  SHA256_W = /* @__PURE__ */ new Uint32Array(64);
  SHA256 = class SHA256 extends HashMD {
    constructor(outputLen = 32) {
      super(64, outputLen, 8, false);
      this.A = SHA256_IV[0] | 0;
      this.B = SHA256_IV[1] | 0;
      this.C = SHA256_IV[2] | 0;
      this.D = SHA256_IV[3] | 0;
      this.E = SHA256_IV[4] | 0;
      this.F = SHA256_IV[5] | 0;
      this.G = SHA256_IV[6] | 0;
      this.H = SHA256_IV[7] | 0;
    }
    get() {
      const { A, B, C, D, E, F, G, H } = this;
      return [A, B, C, D, E, F, G, H];
    }
    set(A, B, C, D, E, F, G, H) {
      this.A = A | 0;
      this.B = B | 0;
      this.C = C | 0;
      this.D = D | 0;
      this.E = E | 0;
      this.F = F | 0;
      this.G = G | 0;
      this.H = H | 0;
    }
    process(view, offset) {
      for (let i = 0;i < 16; i++, offset += 4)
        SHA256_W[i] = view.getUint32(offset, false);
      for (let i = 16;i < 64; i++) {
        const W15 = SHA256_W[i - 15];
        const W2 = SHA256_W[i - 2];
        const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
        const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
        SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
      }
      let { A, B, C, D, E, F, G, H } = this;
      for (let i = 0;i < 64; i++) {
        const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
        const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
        const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
        const T2 = sigma0 + Maj(A, B, C) | 0;
        H = G;
        G = F;
        F = E;
        E = D + T1 | 0;
        D = C;
        C = B;
        B = A;
        A = T1 + T2 | 0;
      }
      A = A + this.A | 0;
      B = B + this.B | 0;
      C = C + this.C | 0;
      D = D + this.D | 0;
      E = E + this.E | 0;
      F = F + this.F | 0;
      G = G + this.G | 0;
      H = H + this.H | 0;
      this.set(A, B, C, D, E, F, G, H);
    }
    roundClean() {
      clean2(SHA256_W);
    }
    destroy() {
      this.set(0, 0, 0, 0, 0, 0, 0, 0);
      clean2(this.buffer);
    }
  };
  sha256 = /* @__PURE__ */ createHasher2(() => new SHA256);
});
var HMAC;
var hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
var init_hmac = __esm(() => {
  init_utils();
  HMAC = class HMAC extends Hash2 {
    constructor(hash, _key) {
      super();
      this.finished = false;
      this.destroyed = false;
      ahash(hash);
      const key = toBytes3(_key);
      this.iHash = hash.create();
      if (typeof this.iHash.update !== "function")
        throw new Error("Expected instance of class which extends utils.Hash");
      this.blockLen = this.iHash.blockLen;
      this.outputLen = this.iHash.outputLen;
      const blockLen = this.blockLen;
      const pad = new Uint8Array(blockLen);
      pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
      for (let i = 0;i < pad.length; i++)
        pad[i] ^= 54;
      this.iHash.update(pad);
      this.oHash = hash.create();
      for (let i = 0;i < pad.length; i++)
        pad[i] ^= 54 ^ 92;
      this.oHash.update(pad);
      clean2(pad);
    }
    update(buf) {
      aexists2(this);
      this.iHash.update(buf);
      return this;
    }
    digestInto(out) {
      aexists2(this);
      abytes2(out, this.outputLen);
      this.finished = true;
      this.iHash.digestInto(out);
      this.oHash.update(out);
      this.oHash.digestInto(out);
      this.destroy();
    }
    digest() {
      const out = new Uint8Array(this.oHash.outputLen);
      this.digestInto(out);
      return out;
    }
    _cloneInto(to) {
      to || (to = Object.create(Object.getPrototypeOf(this), {}));
      const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
      to = to;
      to.finished = finished;
      to.destroyed = destroyed;
      to.blockLen = blockLen;
      to.outputLen = outputLen;
      to.oHash = oHash._cloneInto(to.oHash);
      to.iHash = iHash._cloneInto(to.iHash);
      return to;
    }
    clone() {
      return this._cloneInto();
    }
    destroy() {
      this.destroyed = true;
      this.oHash.destroy();
      this.iHash.destroy();
    }
  };
  hmac.create = (hash, key) => new HMAC(hash, key);
});
function isBytes3(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function abytes3(item) {
  if (!isBytes3(item))
    throw new Error("Uint8Array expected");
}
function abool(title, value) {
  if (typeof value !== "boolean")
    throw new Error(title + " boolean expected, got " + value);
}
function numberToHexUnpadded(num) {
  const hex = num.toString(16);
  return hex.length & 1 ? "0" + hex : hex;
}
function hexToNumber2(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  return hex === "" ? _0n2 : BigInt("0x" + hex);
}
function bytesToHex2(bytes) {
  abytes3(bytes);
  if (hasHexBuiltin)
    return bytes.toHex();
  let hex = "";
  for (let i = 0;i < bytes.length; i++) {
    hex += hexes2[bytes[i]];
  }
  return hex;
}
function asciiToBase16(ch) {
  if (ch >= asciis._0 && ch <= asciis._9)
    return ch - asciis._0;
  if (ch >= asciis.A && ch <= asciis.F)
    return ch - (asciis.A - 10);
  if (ch >= asciis.a && ch <= asciis.f)
    return ch - (asciis.a - 10);
  return;
}
function hexToBytes2(hex) {
  if (typeof hex !== "string")
    throw new Error("hex string expected, got " + typeof hex);
  if (hasHexBuiltin)
    return Uint8Array.fromHex(hex);
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new Error("hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0;ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === undefined || n2 === undefined) {
      const char = hex[hi] + hex[hi + 1];
      throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
function bytesToNumberBE(bytes) {
  return hexToNumber2(bytesToHex2(bytes));
}
function bytesToNumberLE(bytes) {
  abytes3(bytes);
  return hexToNumber2(bytesToHex2(Uint8Array.from(bytes).reverse()));
}
function numberToBytesBE(n, len) {
  return hexToBytes2(n.toString(16).padStart(len * 2, "0"));
}
function numberToBytesLE(n, len) {
  return numberToBytesBE(n, len).reverse();
}
function ensureBytes(title, hex, expectedLength) {
  let res;
  if (typeof hex === "string") {
    try {
      res = hexToBytes2(hex);
    } catch (e) {
      throw new Error(title + " must be hex string or Uint8Array, cause: " + e);
    }
  } else if (isBytes3(hex)) {
    res = Uint8Array.from(hex);
  } else {
    throw new Error(title + " must be hex string or Uint8Array");
  }
  const len = res.length;
  if (typeof expectedLength === "number" && len !== expectedLength)
    throw new Error(title + " of length " + expectedLength + " expected, got " + len);
  return res;
}
function concatBytes2(...arrays) {
  let sum = 0;
  for (let i = 0;i < arrays.length; i++) {
    const a = arrays[i];
    abytes3(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad = 0;i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad);
    pad += a.length;
  }
  return res;
}
function inRange(n, min, max) {
  return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
}
function aInRange(title, n, min, max) {
  if (!inRange(n, min, max))
    throw new Error("expected valid " + title + ": " + min + " <= n < " + max + ", got " + n);
}
function bitLen(n) {
  let len;
  for (len = 0;n > _0n2; n >>= _1n2, len += 1)
    ;
  return len;
}
function createHmacDrbg(hashLen, qByteLen, hmacFn) {
  if (typeof hashLen !== "number" || hashLen < 2)
    throw new Error("hashLen must be a number");
  if (typeof qByteLen !== "number" || qByteLen < 2)
    throw new Error("qByteLen must be a number");
  if (typeof hmacFn !== "function")
    throw new Error("hmacFn must be a function");
  let v = u8n(hashLen);
  let k = u8n(hashLen);
  let i = 0;
  const reset = () => {
    v.fill(1);
    k.fill(0);
    i = 0;
  };
  const h = (...b) => hmacFn(k, v, ...b);
  const reseed = (seed = u8n(0)) => {
    k = h(u8fr([0]), seed);
    v = h();
    if (seed.length === 0)
      return;
    k = h(u8fr([1]), seed);
    v = h();
  };
  const gen = () => {
    if (i++ >= 1000)
      throw new Error("drbg: tried 1000 values");
    let len = 0;
    const out = [];
    while (len < qByteLen) {
      v = h();
      const sl = v.slice();
      out.push(sl);
      len += v.length;
    }
    return concatBytes2(...out);
  };
  const genUntil = (seed, pred) => {
    reset();
    reseed(seed);
    let res = undefined;
    while (!(res = pred(gen())))
      reseed();
    reset();
    return res;
  };
  return genUntil;
}
function validateObject(object, validators, optValidators = {}) {
  const checkField = (fieldName, type, isOptional) => {
    const checkVal = validatorFns[type];
    if (typeof checkVal !== "function")
      throw new Error("invalid validator function");
    const val = object[fieldName];
    if (isOptional && val === undefined)
      return;
    if (!checkVal(val, object)) {
      throw new Error("param " + String(fieldName) + " is invalid. Expected " + type + ", got " + val);
    }
  };
  for (const [fieldName, type] of Object.entries(validators))
    checkField(fieldName, type, false);
  for (const [fieldName, type] of Object.entries(optValidators))
    checkField(fieldName, type, true);
  return object;
}
function memoized(fn) {
  const map = new WeakMap;
  return (arg, ...args) => {
    const val = map.get(arg);
    if (val !== undefined)
      return val;
    const computed = fn(arg, ...args);
    map.set(arg, computed);
    return computed;
  };
}
var _0n2;
var _1n2;
var hasHexBuiltin;
var hexes2;
var asciis;
var isPosBig = (n) => typeof n === "bigint" && _0n2 <= n;
var bitMask = (n) => (_1n2 << BigInt(n)) - _1n2;
var u8n = (len) => new Uint8Array(len);
var u8fr = (arr) => Uint8Array.from(arr);
var validatorFns;
var init_utils2 = __esm(() => {
  /*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
  _0n2 = /* @__PURE__ */ BigInt(0);
  _1n2 = /* @__PURE__ */ BigInt(1);
  hasHexBuiltin = typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function";
  hexes2 = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
  asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
  validatorFns = {
    bigint: (val) => typeof val === "bigint",
    function: (val) => typeof val === "function",
    boolean: (val) => typeof val === "boolean",
    string: (val) => typeof val === "string",
    stringOrUint8Array: (val) => typeof val === "string" || isBytes3(val),
    isSafeInteger: (val) => Number.isSafeInteger(val),
    array: (val) => Array.isArray(val),
    field: (val, object) => object.Fp.isValid(val),
    hash: (val) => typeof val === "function" && Number.isSafeInteger(val.outputLen)
  };
});
function mod(a, b) {
  const result = a % b;
  return result >= _0n3 ? result : b + result;
}
function pow2(x, power, modulo) {
  let res = x;
  while (power-- > _0n3) {
    res *= res;
    res %= modulo;
  }
  return res;
}
function invert(number, modulo) {
  if (number === _0n3)
    throw new Error("invert: expected non-zero number");
  if (modulo <= _0n3)
    throw new Error("invert: expected positive modulus, got " + modulo);
  let a = mod(number, modulo);
  let b = modulo;
  let x = _0n3, y = _1n3, u = _1n3, v = _0n3;
  while (a !== _0n3) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    b = a, a = r, x = u, y = v, u = m, v = n;
  }
  const gcd = b;
  if (gcd !== _1n3)
    throw new Error("invert: does not exist");
  return mod(x, modulo);
}
function sqrt3mod4(Fp, n) {
  const p1div4 = (Fp.ORDER + _1n3) / _4n;
  const root = Fp.pow(n, p1div4);
  if (!Fp.eql(Fp.sqr(root), n))
    throw new Error("Cannot find square root");
  return root;
}
function sqrt5mod8(Fp, n) {
  const p5div8 = (Fp.ORDER - _5n) / _8n;
  const n2 = Fp.mul(n, _2n2);
  const v = Fp.pow(n2, p5div8);
  const nv = Fp.mul(n, v);
  const i = Fp.mul(Fp.mul(nv, _2n2), v);
  const root = Fp.mul(nv, Fp.sub(i, Fp.ONE));
  if (!Fp.eql(Fp.sqr(root), n))
    throw new Error("Cannot find square root");
  return root;
}
function tonelliShanks(P) {
  if (P < BigInt(3))
    throw new Error("sqrt is not defined for small field");
  let Q = P - _1n3;
  let S = 0;
  while (Q % _2n2 === _0n3) {
    Q /= _2n2;
    S++;
  }
  let Z = _2n2;
  const _Fp = Field(P);
  while (FpLegendre(_Fp, Z) === 1) {
    if (Z++ > 1000)
      throw new Error("Cannot find square root: probably non-prime P");
  }
  if (S === 1)
    return sqrt3mod4;
  let cc = _Fp.pow(Z, Q);
  const Q1div2 = (Q + _1n3) / _2n2;
  return function tonelliSlow(Fp, n) {
    if (Fp.is0(n))
      return n;
    if (FpLegendre(Fp, n) !== 1)
      throw new Error("Cannot find square root");
    let M = S;
    let c = Fp.mul(Fp.ONE, cc);
    let t = Fp.pow(n, Q);
    let R = Fp.pow(n, Q1div2);
    while (!Fp.eql(t, Fp.ONE)) {
      if (Fp.is0(t))
        return Fp.ZERO;
      let i = 1;
      let t_tmp = Fp.sqr(t);
      while (!Fp.eql(t_tmp, Fp.ONE)) {
        i++;
        t_tmp = Fp.sqr(t_tmp);
        if (i === M)
          throw new Error("Cannot find square root");
      }
      const exponent = _1n3 << BigInt(M - i - 1);
      const b = Fp.pow(c, exponent);
      M = i;
      c = Fp.sqr(b);
      t = Fp.mul(t, c);
      R = Fp.mul(R, b);
    }
    return R;
  };
}
function FpSqrt(P) {
  if (P % _4n === _3n)
    return sqrt3mod4;
  if (P % _8n === _5n)
    return sqrt5mod8;
  return tonelliShanks(P);
}
function validateField(field) {
  const initial = {
    ORDER: "bigint",
    MASK: "bigint",
    BYTES: "isSafeInteger",
    BITS: "isSafeInteger"
  };
  const opts = FIELD_FIELDS.reduce((map, val) => {
    map[val] = "function";
    return map;
  }, initial);
  return validateObject(field, opts);
}
function FpPow(Fp, num, power) {
  if (power < _0n3)
    throw new Error("invalid exponent, negatives unsupported");
  if (power === _0n3)
    return Fp.ONE;
  if (power === _1n3)
    return num;
  let p = Fp.ONE;
  let d = num;
  while (power > _0n3) {
    if (power & _1n3)
      p = Fp.mul(p, d);
    d = Fp.sqr(d);
    power >>= _1n3;
  }
  return p;
}
function FpInvertBatch(Fp, nums, passZero = false) {
  const inverted = new Array(nums.length).fill(passZero ? Fp.ZERO : undefined);
  const multipliedAcc = nums.reduce((acc, num, i) => {
    if (Fp.is0(num))
      return acc;
    inverted[i] = acc;
    return Fp.mul(acc, num);
  }, Fp.ONE);
  const invertedAcc = Fp.inv(multipliedAcc);
  nums.reduceRight((acc, num, i) => {
    if (Fp.is0(num))
      return acc;
    inverted[i] = Fp.mul(acc, inverted[i]);
    return Fp.mul(acc, num);
  }, invertedAcc);
  return inverted;
}
function FpLegendre(Fp, n) {
  const p1mod2 = (Fp.ORDER - _1n3) / _2n2;
  const powered = Fp.pow(n, p1mod2);
  const yes = Fp.eql(powered, Fp.ONE);
  const zero = Fp.eql(powered, Fp.ZERO);
  const no = Fp.eql(powered, Fp.neg(Fp.ONE));
  if (!yes && !zero && !no)
    throw new Error("invalid Legendre symbol result");
  return yes ? 1 : zero ? 0 : -1;
}
function nLength(n, nBitLength) {
  if (nBitLength !== undefined)
    anumber2(nBitLength);
  const _nBitLength = nBitLength !== undefined ? nBitLength : n.toString(2).length;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}
function Field(ORDER, bitLen, isLE = false, redef = {}) {
  if (ORDER <= _0n3)
    throw new Error("invalid field: expected ORDER > 0, got " + ORDER);
  const { nBitLength: BITS, nByteLength: BYTES } = nLength(ORDER, bitLen);
  if (BYTES > 2048)
    throw new Error("invalid field: expected ORDER of <= 2048 bytes");
  let sqrtP;
  const f = Object.freeze({
    ORDER,
    isLE,
    BITS,
    BYTES,
    MASK: bitMask(BITS),
    ZERO: _0n3,
    ONE: _1n3,
    create: (num) => mod(num, ORDER),
    isValid: (num) => {
      if (typeof num !== "bigint")
        throw new Error("invalid field element: expected bigint, got " + typeof num);
      return _0n3 <= num && num < ORDER;
    },
    is0: (num) => num === _0n3,
    isOdd: (num) => (num & _1n3) === _1n3,
    neg: (num) => mod(-num, ORDER),
    eql: (lhs, rhs) => lhs === rhs,
    sqr: (num) => mod(num * num, ORDER),
    add: (lhs, rhs) => mod(lhs + rhs, ORDER),
    sub: (lhs, rhs) => mod(lhs - rhs, ORDER),
    mul: (lhs, rhs) => mod(lhs * rhs, ORDER),
    pow: (num, power) => FpPow(f, num, power),
    div: (lhs, rhs) => mod(lhs * invert(rhs, ORDER), ORDER),
    sqrN: (num) => num * num,
    addN: (lhs, rhs) => lhs + rhs,
    subN: (lhs, rhs) => lhs - rhs,
    mulN: (lhs, rhs) => lhs * rhs,
    inv: (num) => invert(num, ORDER),
    sqrt: redef.sqrt || ((n) => {
      if (!sqrtP)
        sqrtP = FpSqrt(ORDER);
      return sqrtP(f, n);
    }),
    toBytes: (num) => isLE ? numberToBytesLE(num, BYTES) : numberToBytesBE(num, BYTES),
    fromBytes: (bytes) => {
      if (bytes.length !== BYTES)
        throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
      return isLE ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
    },
    invertBatch: (lst) => FpInvertBatch(f, lst),
    cmov: (a, b, c) => c ? b : a
  });
  return Object.freeze(f);
}
function getFieldBytesLength(fieldOrder) {
  if (typeof fieldOrder !== "bigint")
    throw new Error("field order must be bigint");
  const bitLength = fieldOrder.toString(2).length;
  return Math.ceil(bitLength / 8);
}
function getMinHashLength(fieldOrder) {
  const length = getFieldBytesLength(fieldOrder);
  return length + Math.ceil(length / 2);
}
function mapHashToField(key, fieldOrder, isLE = false) {
  const len = key.length;
  const fieldLen = getFieldBytesLength(fieldOrder);
  const minLen = getMinHashLength(fieldOrder);
  if (len < 16 || len < minLen || len > 1024)
    throw new Error("expected " + minLen + "-1024 bytes of input, got " + len);
  const num = isLE ? bytesToNumberLE(key) : bytesToNumberBE(key);
  const reduced = mod(num, fieldOrder - _1n3) + _1n3;
  return isLE ? numberToBytesLE(reduced, fieldLen) : numberToBytesBE(reduced, fieldLen);
}
var _0n3;
var _1n3;
var _2n2;
var _3n;
var _4n;
var _5n;
var _8n;
var FIELD_FIELDS;
var init_modular = __esm(() => {
  init_utils();
  init_utils2();
  /*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
  _0n3 = BigInt(0);
  _1n3 = BigInt(1);
  _2n2 = /* @__PURE__ */ BigInt(2);
  _3n = /* @__PURE__ */ BigInt(3);
  _4n = /* @__PURE__ */ BigInt(4);
  _5n = /* @__PURE__ */ BigInt(5);
  _8n = /* @__PURE__ */ BigInt(8);
  FIELD_FIELDS = [
    "create",
    "isValid",
    "is0",
    "neg",
    "inv",
    "sqrt",
    "sqr",
    "eql",
    "add",
    "sub",
    "mul",
    "pow",
    "div",
    "addN",
    "subN",
    "mulN",
    "sqrN"
  ];
});
function constTimeNegate(condition, item) {
  const neg = item.negate();
  return condition ? neg : item;
}
function validateW(W, bits) {
  if (!Number.isSafeInteger(W) || W <= 0 || W > bits)
    throw new Error("invalid window size, expected [1.." + bits + "], got W=" + W);
}
function calcWOpts(W, scalarBits) {
  validateW(W, scalarBits);
  const windows = Math.ceil(scalarBits / W) + 1;
  const windowSize = 2 ** (W - 1);
  const maxNumber = 2 ** W;
  const mask = bitMask(W);
  const shiftBy = BigInt(W);
  return { windows, windowSize, mask, maxNumber, shiftBy };
}
function calcOffsets(n, window, wOpts) {
  const { windowSize, mask, maxNumber, shiftBy } = wOpts;
  let wbits = Number(n & mask);
  let nextN = n >> shiftBy;
  if (wbits > windowSize) {
    wbits -= maxNumber;
    nextN += _1n4;
  }
  const offsetStart = window * windowSize;
  const offset = offsetStart + Math.abs(wbits) - 1;
  const isZero = wbits === 0;
  const isNeg = wbits < 0;
  const isNegF = window % 2 !== 0;
  const offsetF = offsetStart;
  return { nextN, offset, isZero, isNeg, isNegF, offsetF };
}
function validateMSMPoints(points, c) {
  if (!Array.isArray(points))
    throw new Error("array expected");
  points.forEach((p, i) => {
    if (!(p instanceof c))
      throw new Error("invalid point at index " + i);
  });
}
function validateMSMScalars(scalars, field) {
  if (!Array.isArray(scalars))
    throw new Error("array of scalars expected");
  scalars.forEach((s, i) => {
    if (!field.isValid(s))
      throw new Error("invalid scalar at index " + i);
  });
}
function getW(P) {
  return pointWindowSizes.get(P) || 1;
}
function wNAF(c, bits) {
  return {
    constTimeNegate,
    hasPrecomputes(elm) {
      return getW(elm) !== 1;
    },
    unsafeLadder(elm, n, p = c.ZERO) {
      let d = elm;
      while (n > _0n4) {
        if (n & _1n4)
          p = p.add(d);
        d = d.double();
        n >>= _1n4;
      }
      return p;
    },
    precomputeWindow(elm, W) {
      const { windows, windowSize } = calcWOpts(W, bits);
      const points = [];
      let p = elm;
      let base = p;
      for (let window = 0;window < windows; window++) {
        base = p;
        points.push(base);
        for (let i = 1;i < windowSize; i++) {
          base = base.add(p);
          points.push(base);
        }
        p = base.double();
      }
      return points;
    },
    wNAF(W, precomputes, n) {
      let p = c.ZERO;
      let f = c.BASE;
      const wo = calcWOpts(W, bits);
      for (let window = 0;window < wo.windows; window++) {
        const { nextN, offset, isZero, isNeg, isNegF, offsetF } = calcOffsets(n, window, wo);
        n = nextN;
        if (isZero) {
          f = f.add(constTimeNegate(isNegF, precomputes[offsetF]));
        } else {
          p = p.add(constTimeNegate(isNeg, precomputes[offset]));
        }
      }
      return { p, f };
    },
    wNAFUnsafe(W, precomputes, n, acc = c.ZERO) {
      const wo = calcWOpts(W, bits);
      for (let window = 0;window < wo.windows; window++) {
        if (n === _0n4)
          break;
        const { nextN, offset, isZero, isNeg } = calcOffsets(n, window, wo);
        n = nextN;
        if (isZero) {
          continue;
        } else {
          const item = precomputes[offset];
          acc = acc.add(isNeg ? item.negate() : item);
        }
      }
      return acc;
    },
    getPrecomputes(W, P, transform) {
      let comp = pointPrecomputes.get(P);
      if (!comp) {
        comp = this.precomputeWindow(P, W);
        if (W !== 1)
          pointPrecomputes.set(P, transform(comp));
      }
      return comp;
    },
    wNAFCached(P, n, transform) {
      const W = getW(P);
      return this.wNAF(W, this.getPrecomputes(W, P, transform), n);
    },
    wNAFCachedUnsafe(P, n, transform, prev) {
      const W = getW(P);
      if (W === 1)
        return this.unsafeLadder(P, n, prev);
      return this.wNAFUnsafe(W, this.getPrecomputes(W, P, transform), n, prev);
    },
    setWindowSize(P, W) {
      validateW(W, bits);
      pointWindowSizes.set(P, W);
      pointPrecomputes.delete(P);
    }
  };
}
function pippenger(c, fieldN, points, scalars) {
  validateMSMPoints(points, c);
  validateMSMScalars(scalars, fieldN);
  const plength = points.length;
  const slength = scalars.length;
  if (plength !== slength)
    throw new Error("arrays of points and scalars must have equal length");
  const zero = c.ZERO;
  const wbits = bitLen(BigInt(plength));
  let windowSize = 1;
  if (wbits > 12)
    windowSize = wbits - 3;
  else if (wbits > 4)
    windowSize = wbits - 2;
  else if (wbits > 0)
    windowSize = 2;
  const MASK = bitMask(windowSize);
  const buckets = new Array(Number(MASK) + 1).fill(zero);
  const lastBits = Math.floor((fieldN.BITS - 1) / windowSize) * windowSize;
  let sum = zero;
  for (let i = lastBits;i >= 0; i -= windowSize) {
    buckets.fill(zero);
    for (let j = 0;j < slength; j++) {
      const scalar = scalars[j];
      const wbits = Number(scalar >> BigInt(i) & MASK);
      buckets[wbits] = buckets[wbits].add(points[j]);
    }
    let resI = zero;
    for (let j = buckets.length - 1, sumI = zero;j > 0; j--) {
      sumI = sumI.add(buckets[j]);
      resI = resI.add(sumI);
    }
    sum = sum.add(resI);
    if (i !== 0)
      for (let j = 0;j < windowSize; j++)
        sum = sum.double();
  }
  return sum;
}
function validateBasic(curve) {
  validateField(curve.Fp);
  validateObject(curve, {
    n: "bigint",
    h: "bigint",
    Gx: "field",
    Gy: "field"
  }, {
    nBitLength: "isSafeInteger",
    nByteLength: "isSafeInteger"
  });
  return Object.freeze({
    ...nLength(curve.n, curve.nBitLength),
    ...curve,
    ...{ p: curve.Fp.ORDER }
  });
}
var _0n4;
var _1n4;
var pointPrecomputes;
var pointWindowSizes;
var init_curve = __esm(() => {
  init_modular();
  init_utils2();
  /*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
  _0n4 = BigInt(0);
  _1n4 = BigInt(1);
  pointPrecomputes = new WeakMap;
  pointWindowSizes = new WeakMap;
});
function validateSigVerOpts(opts) {
  if (opts.lowS !== undefined)
    abool("lowS", opts.lowS);
  if (opts.prehash !== undefined)
    abool("prehash", opts.prehash);
}
function validatePointOpts(curve) {
  const opts = validateBasic(curve);
  validateObject(opts, {
    a: "field",
    b: "field"
  }, {
    allowInfinityPoint: "boolean",
    allowedPrivateKeyLengths: "array",
    clearCofactor: "function",
    fromBytes: "function",
    isTorsionFree: "function",
    toBytes: "function",
    wrapPrivateKey: "boolean"
  });
  const { endo, Fp, a } = opts;
  if (endo) {
    if (!Fp.eql(a, Fp.ZERO)) {
      throw new Error("invalid endo: CURVE.a must be 0");
    }
    if (typeof endo !== "object" || typeof endo.beta !== "bigint" || typeof endo.splitScalar !== "function") {
      throw new Error('invalid endo: expected "beta": bigint and "splitScalar": function');
    }
  }
  return Object.freeze({ ...opts });
}
function numToSizedHex(num, size) {
  return bytesToHex2(numberToBytesBE(num, size));
}
function weierstrassPoints(opts) {
  const CURVE = validatePointOpts(opts);
  const { Fp } = CURVE;
  const Fn = Field(CURVE.n, CURVE.nBitLength);
  const toBytes = CURVE.toBytes || ((_c, point, _isCompressed) => {
    const a = point.toAffine();
    return concatBytes2(Uint8Array.from([4]), Fp.toBytes(a.x), Fp.toBytes(a.y));
  });
  const fromBytes = CURVE.fromBytes || ((bytes) => {
    const tail = bytes.subarray(1);
    const x = Fp.fromBytes(tail.subarray(0, Fp.BYTES));
    const y = Fp.fromBytes(tail.subarray(Fp.BYTES, 2 * Fp.BYTES));
    return { x, y };
  });
  function weierstrassEquation(x) {
    const { a, b } = CURVE;
    const x2 = Fp.sqr(x);
    const x3 = Fp.mul(x2, x);
    return Fp.add(Fp.add(x3, Fp.mul(x, a)), b);
  }
  function isValidXY(x, y) {
    const left = Fp.sqr(y);
    const right = weierstrassEquation(x);
    return Fp.eql(left, right);
  }
  if (!isValidXY(CURVE.Gx, CURVE.Gy))
    throw new Error("bad curve params: generator point");
  const _4a3 = Fp.mul(Fp.pow(CURVE.a, _3n2), _4n2);
  const _27b2 = Fp.mul(Fp.sqr(CURVE.b), BigInt(27));
  if (Fp.is0(Fp.add(_4a3, _27b2)))
    throw new Error("bad curve params: a or b");
  function isWithinCurveOrder(num) {
    return inRange(num, _1n5, CURVE.n);
  }
  function normPrivateKeyToScalar(key) {
    const { allowedPrivateKeyLengths: lengths, nByteLength, wrapPrivateKey, n: N } = CURVE;
    if (lengths && typeof key !== "bigint") {
      if (isBytes3(key))
        key = bytesToHex2(key);
      if (typeof key !== "string" || !lengths.includes(key.length))
        throw new Error("invalid private key");
      key = key.padStart(nByteLength * 2, "0");
    }
    let num;
    try {
      num = typeof key === "bigint" ? key : bytesToNumberBE(ensureBytes("private key", key, nByteLength));
    } catch (error) {
      throw new Error("invalid private key, expected hex or " + nByteLength + " bytes, got " + typeof key);
    }
    if (wrapPrivateKey)
      num = mod(num, N);
    aInRange("private key", num, _1n5, N);
    return num;
  }
  function aprjpoint(other) {
    if (!(other instanceof Point))
      throw new Error("ProjectivePoint expected");
  }
  const toAffineMemo = memoized((p, iz) => {
    const { px: x, py: y, pz: z } = p;
    if (Fp.eql(z, Fp.ONE))
      return { x, y };
    const is0 = p.is0();
    if (iz == null)
      iz = is0 ? Fp.ONE : Fp.inv(z);
    const ax = Fp.mul(x, iz);
    const ay = Fp.mul(y, iz);
    const zz = Fp.mul(z, iz);
    if (is0)
      return { x: Fp.ZERO, y: Fp.ZERO };
    if (!Fp.eql(zz, Fp.ONE))
      throw new Error("invZ was invalid");
    return { x: ax, y: ay };
  });
  const assertValidMemo = memoized((p) => {
    if (p.is0()) {
      if (CURVE.allowInfinityPoint && !Fp.is0(p.py))
        return;
      throw new Error("bad point: ZERO");
    }
    const { x, y } = p.toAffine();
    if (!Fp.isValid(x) || !Fp.isValid(y))
      throw new Error("bad point: x or y not FE");
    if (!isValidXY(x, y))
      throw new Error("bad point: equation left != right");
    if (!p.isTorsionFree())
      throw new Error("bad point: not in prime-order subgroup");
    return true;
  });

  class Point {
    constructor(px, py, pz) {
      if (px == null || !Fp.isValid(px))
        throw new Error("x required");
      if (py == null || !Fp.isValid(py) || Fp.is0(py))
        throw new Error("y required");
      if (pz == null || !Fp.isValid(pz))
        throw new Error("z required");
      this.px = px;
      this.py = py;
      this.pz = pz;
      Object.freeze(this);
    }
    static fromAffine(p) {
      const { x, y } = p || {};
      if (!p || !Fp.isValid(x) || !Fp.isValid(y))
        throw new Error("invalid affine point");
      if (p instanceof Point)
        throw new Error("projective point not allowed");
      const is0 = (i) => Fp.eql(i, Fp.ZERO);
      if (is0(x) && is0(y))
        return Point.ZERO;
      return new Point(x, y, Fp.ONE);
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    static normalizeZ(points) {
      const toInv = FpInvertBatch(Fp, points.map((p) => p.pz));
      return points.map((p, i) => p.toAffine(toInv[i])).map(Point.fromAffine);
    }
    static fromHex(hex) {
      const P = Point.fromAffine(fromBytes(ensureBytes("pointHex", hex)));
      P.assertValidity();
      return P;
    }
    static fromPrivateKey(privateKey) {
      return Point.BASE.multiply(normPrivateKeyToScalar(privateKey));
    }
    static msm(points, scalars) {
      return pippenger(Point, Fn, points, scalars);
    }
    _setWindowSize(windowSize) {
      wnaf.setWindowSize(this, windowSize);
    }
    assertValidity() {
      assertValidMemo(this);
    }
    hasEvenY() {
      const { y } = this.toAffine();
      if (Fp.isOdd)
        return !Fp.isOdd(y);
      throw new Error("Field doesn't support isOdd");
    }
    equals(other) {
      aprjpoint(other);
      const { px: X1, py: Y1, pz: Z1 } = this;
      const { px: X2, py: Y2, pz: Z2 } = other;
      const U1 = Fp.eql(Fp.mul(X1, Z2), Fp.mul(X2, Z1));
      const U2 = Fp.eql(Fp.mul(Y1, Z2), Fp.mul(Y2, Z1));
      return U1 && U2;
    }
    negate() {
      return new Point(this.px, Fp.neg(this.py), this.pz);
    }
    double() {
      const { a, b } = CURVE;
      const b3 = Fp.mul(b, _3n2);
      const { px: X1, py: Y1, pz: Z1 } = this;
      let { ZERO: X3, ZERO: Y3, ZERO: Z3 } = Fp;
      let t0 = Fp.mul(X1, X1);
      let t1 = Fp.mul(Y1, Y1);
      let t2 = Fp.mul(Z1, Z1);
      let t3 = Fp.mul(X1, Y1);
      t3 = Fp.add(t3, t3);
      Z3 = Fp.mul(X1, Z1);
      Z3 = Fp.add(Z3, Z3);
      X3 = Fp.mul(a, Z3);
      Y3 = Fp.mul(b3, t2);
      Y3 = Fp.add(X3, Y3);
      X3 = Fp.sub(t1, Y3);
      Y3 = Fp.add(t1, Y3);
      Y3 = Fp.mul(X3, Y3);
      X3 = Fp.mul(t3, X3);
      Z3 = Fp.mul(b3, Z3);
      t2 = Fp.mul(a, t2);
      t3 = Fp.sub(t0, t2);
      t3 = Fp.mul(a, t3);
      t3 = Fp.add(t3, Z3);
      Z3 = Fp.add(t0, t0);
      t0 = Fp.add(Z3, t0);
      t0 = Fp.add(t0, t2);
      t0 = Fp.mul(t0, t3);
      Y3 = Fp.add(Y3, t0);
      t2 = Fp.mul(Y1, Z1);
      t2 = Fp.add(t2, t2);
      t0 = Fp.mul(t2, t3);
      X3 = Fp.sub(X3, t0);
      Z3 = Fp.mul(t2, t1);
      Z3 = Fp.add(Z3, Z3);
      Z3 = Fp.add(Z3, Z3);
      return new Point(X3, Y3, Z3);
    }
    add(other) {
      aprjpoint(other);
      const { px: X1, py: Y1, pz: Z1 } = this;
      const { px: X2, py: Y2, pz: Z2 } = other;
      let { ZERO: X3, ZERO: Y3, ZERO: Z3 } = Fp;
      const a = CURVE.a;
      const b3 = Fp.mul(CURVE.b, _3n2);
      let t0 = Fp.mul(X1, X2);
      let t1 = Fp.mul(Y1, Y2);
      let t2 = Fp.mul(Z1, Z2);
      let t3 = Fp.add(X1, Y1);
      let t4 = Fp.add(X2, Y2);
      t3 = Fp.mul(t3, t4);
      t4 = Fp.add(t0, t1);
      t3 = Fp.sub(t3, t4);
      t4 = Fp.add(X1, Z1);
      let t5 = Fp.add(X2, Z2);
      t4 = Fp.mul(t4, t5);
      t5 = Fp.add(t0, t2);
      t4 = Fp.sub(t4, t5);
      t5 = Fp.add(Y1, Z1);
      X3 = Fp.add(Y2, Z2);
      t5 = Fp.mul(t5, X3);
      X3 = Fp.add(t1, t2);
      t5 = Fp.sub(t5, X3);
      Z3 = Fp.mul(a, t4);
      X3 = Fp.mul(b3, t2);
      Z3 = Fp.add(X3, Z3);
      X3 = Fp.sub(t1, Z3);
      Z3 = Fp.add(t1, Z3);
      Y3 = Fp.mul(X3, Z3);
      t1 = Fp.add(t0, t0);
      t1 = Fp.add(t1, t0);
      t2 = Fp.mul(a, t2);
      t4 = Fp.mul(b3, t4);
      t1 = Fp.add(t1, t2);
      t2 = Fp.sub(t0, t2);
      t2 = Fp.mul(a, t2);
      t4 = Fp.add(t4, t2);
      t0 = Fp.mul(t1, t4);
      Y3 = Fp.add(Y3, t0);
      t0 = Fp.mul(t5, t4);
      X3 = Fp.mul(t3, X3);
      X3 = Fp.sub(X3, t0);
      t0 = Fp.mul(t3, t1);
      Z3 = Fp.mul(t5, Z3);
      Z3 = Fp.add(Z3, t0);
      return new Point(X3, Y3, Z3);
    }
    subtract(other) {
      return this.add(other.negate());
    }
    is0() {
      return this.equals(Point.ZERO);
    }
    wNAF(n) {
      return wnaf.wNAFCached(this, n, Point.normalizeZ);
    }
    multiplyUnsafe(sc) {
      const { endo, n: N } = CURVE;
      aInRange("scalar", sc, _0n5, N);
      const I = Point.ZERO;
      if (sc === _0n5)
        return I;
      if (this.is0() || sc === _1n5)
        return this;
      if (!endo || wnaf.hasPrecomputes(this))
        return wnaf.wNAFCachedUnsafe(this, sc, Point.normalizeZ);
      let { k1neg, k1, k2neg, k2 } = endo.splitScalar(sc);
      let k1p = I;
      let k2p = I;
      let d = this;
      while (k1 > _0n5 || k2 > _0n5) {
        if (k1 & _1n5)
          k1p = k1p.add(d);
        if (k2 & _1n5)
          k2p = k2p.add(d);
        d = d.double();
        k1 >>= _1n5;
        k2 >>= _1n5;
      }
      if (k1neg)
        k1p = k1p.negate();
      if (k2neg)
        k2p = k2p.negate();
      k2p = new Point(Fp.mul(k2p.px, endo.beta), k2p.py, k2p.pz);
      return k1p.add(k2p);
    }
    multiply(scalar) {
      const { endo, n: N } = CURVE;
      aInRange("scalar", scalar, _1n5, N);
      let point, fake;
      if (endo) {
        const { k1neg, k1, k2neg, k2 } = endo.splitScalar(scalar);
        let { p: k1p, f: f1p } = this.wNAF(k1);
        let { p: k2p, f: f2p } = this.wNAF(k2);
        k1p = wnaf.constTimeNegate(k1neg, k1p);
        k2p = wnaf.constTimeNegate(k2neg, k2p);
        k2p = new Point(Fp.mul(k2p.px, endo.beta), k2p.py, k2p.pz);
        point = k1p.add(k2p);
        fake = f1p.add(f2p);
      } else {
        const { p, f } = this.wNAF(scalar);
        point = p;
        fake = f;
      }
      return Point.normalizeZ([point, fake])[0];
    }
    multiplyAndAddUnsafe(Q, a, b) {
      const G = Point.BASE;
      const mul = (P, a) => a === _0n5 || a === _1n5 || !P.equals(G) ? P.multiplyUnsafe(a) : P.multiply(a);
      const sum = mul(this, a).add(mul(Q, b));
      return sum.is0() ? undefined : sum;
    }
    toAffine(iz) {
      return toAffineMemo(this, iz);
    }
    isTorsionFree() {
      const { h: cofactor, isTorsionFree } = CURVE;
      if (cofactor === _1n5)
        return true;
      if (isTorsionFree)
        return isTorsionFree(Point, this);
      throw new Error("isTorsionFree() has not been declared for the elliptic curve");
    }
    clearCofactor() {
      const { h: cofactor, clearCofactor } = CURVE;
      if (cofactor === _1n5)
        return this;
      if (clearCofactor)
        return clearCofactor(Point, this);
      return this.multiplyUnsafe(CURVE.h);
    }
    toRawBytes(isCompressed = true) {
      abool("isCompressed", isCompressed);
      this.assertValidity();
      return toBytes(Point, this, isCompressed);
    }
    toHex(isCompressed = true) {
      abool("isCompressed", isCompressed);
      return bytesToHex2(this.toRawBytes(isCompressed));
    }
  }
  Point.BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE);
  Point.ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ZERO);
  const { endo, nBitLength } = CURVE;
  const wnaf = wNAF(Point, endo ? Math.ceil(nBitLength / 2) : nBitLength);
  return {
    CURVE,
    ProjectivePoint: Point,
    normPrivateKeyToScalar,
    weierstrassEquation,
    isWithinCurveOrder
  };
}
function validateOpts(curve) {
  const opts = validateBasic(curve);
  validateObject(opts, {
    hash: "hash",
    hmac: "function",
    randomBytes: "function"
  }, {
    bits2int: "function",
    bits2int_modN: "function",
    lowS: "boolean"
  });
  return Object.freeze({ lowS: true, ...opts });
}
function weierstrass(curveDef) {
  const CURVE = validateOpts(curveDef);
  const { Fp, n: CURVE_ORDER, nByteLength, nBitLength } = CURVE;
  const compressedLen = Fp.BYTES + 1;
  const uncompressedLen = 2 * Fp.BYTES + 1;
  function modN(a) {
    return mod(a, CURVE_ORDER);
  }
  function invN(a) {
    return invert(a, CURVE_ORDER);
  }
  const { ProjectivePoint: Point, normPrivateKeyToScalar, weierstrassEquation, isWithinCurveOrder } = weierstrassPoints({
    ...CURVE,
    toBytes(_c, point, isCompressed) {
      const a = point.toAffine();
      const x = Fp.toBytes(a.x);
      const cat = concatBytes2;
      abool("isCompressed", isCompressed);
      if (isCompressed) {
        return cat(Uint8Array.from([point.hasEvenY() ? 2 : 3]), x);
      } else {
        return cat(Uint8Array.from([4]), x, Fp.toBytes(a.y));
      }
    },
    fromBytes(bytes) {
      const len = bytes.length;
      const head = bytes[0];
      const tail = bytes.subarray(1);
      if (len === compressedLen && (head === 2 || head === 3)) {
        const x = bytesToNumberBE(tail);
        if (!inRange(x, _1n5, Fp.ORDER))
          throw new Error("Point is not on curve");
        const y2 = weierstrassEquation(x);
        let y;
        try {
          y = Fp.sqrt(y2);
        } catch (sqrtError) {
          const suffix = sqrtError instanceof Error ? ": " + sqrtError.message : "";
          throw new Error("Point is not on curve" + suffix);
        }
        const isYOdd = (y & _1n5) === _1n5;
        const isHeadOdd = (head & 1) === 1;
        if (isHeadOdd !== isYOdd)
          y = Fp.neg(y);
        return { x, y };
      } else if (len === uncompressedLen && head === 4) {
        const x = Fp.fromBytes(tail.subarray(0, Fp.BYTES));
        const y = Fp.fromBytes(tail.subarray(Fp.BYTES, 2 * Fp.BYTES));
        return { x, y };
      } else {
        const cl = compressedLen;
        const ul = uncompressedLen;
        throw new Error("invalid Point, expected length of " + cl + ", or uncompressed " + ul + ", got " + len);
      }
    }
  });
  function isBiggerThanHalfOrder(number) {
    const HALF = CURVE_ORDER >> _1n5;
    return number > HALF;
  }
  function normalizeS(s) {
    return isBiggerThanHalfOrder(s) ? modN(-s) : s;
  }
  const slcNum = (b, from, to) => bytesToNumberBE(b.slice(from, to));

  class Signature {
    constructor(r, s, recovery) {
      aInRange("r", r, _1n5, CURVE_ORDER);
      aInRange("s", s, _1n5, CURVE_ORDER);
      this.r = r;
      this.s = s;
      if (recovery != null)
        this.recovery = recovery;
      Object.freeze(this);
    }
    static fromCompact(hex) {
      const l = nByteLength;
      hex = ensureBytes("compactSignature", hex, l * 2);
      return new Signature(slcNum(hex, 0, l), slcNum(hex, l, 2 * l));
    }
    static fromDER(hex) {
      const { r, s } = DER.toSig(ensureBytes("DER", hex));
      return new Signature(r, s);
    }
    assertValidity() {}
    addRecoveryBit(recovery) {
      return new Signature(this.r, this.s, recovery);
    }
    recoverPublicKey(msgHash) {
      const { r, s, recovery: rec } = this;
      const h = bits2int_modN(ensureBytes("msgHash", msgHash));
      if (rec == null || ![0, 1, 2, 3].includes(rec))
        throw new Error("recovery id invalid");
      const radj = rec === 2 || rec === 3 ? r + CURVE.n : r;
      if (radj >= Fp.ORDER)
        throw new Error("recovery id 2 or 3 invalid");
      const prefix = (rec & 1) === 0 ? "02" : "03";
      const R = Point.fromHex(prefix + numToSizedHex(radj, Fp.BYTES));
      const ir = invN(radj);
      const u1 = modN(-h * ir);
      const u2 = modN(s * ir);
      const Q = Point.BASE.multiplyAndAddUnsafe(R, u1, u2);
      if (!Q)
        throw new Error("point at infinify");
      Q.assertValidity();
      return Q;
    }
    hasHighS() {
      return isBiggerThanHalfOrder(this.s);
    }
    normalizeS() {
      return this.hasHighS() ? new Signature(this.r, modN(-this.s), this.recovery) : this;
    }
    toDERRawBytes() {
      return hexToBytes2(this.toDERHex());
    }
    toDERHex() {
      return DER.hexFromSig(this);
    }
    toCompactRawBytes() {
      return hexToBytes2(this.toCompactHex());
    }
    toCompactHex() {
      const l = nByteLength;
      return numToSizedHex(this.r, l) + numToSizedHex(this.s, l);
    }
  }
  const utils = {
    isValidPrivateKey(privateKey) {
      try {
        normPrivateKeyToScalar(privateKey);
        return true;
      } catch (error) {
        return false;
      }
    },
    normPrivateKeyToScalar,
    randomPrivateKey: () => {
      const length = getMinHashLength(CURVE.n);
      return mapHashToField(CURVE.randomBytes(length), CURVE.n);
    },
    precompute(windowSize = 8, point = Point.BASE) {
      point._setWindowSize(windowSize);
      point.multiply(BigInt(3));
      return point;
    }
  };
  function getPublicKey(privateKey, isCompressed = true) {
    return Point.fromPrivateKey(privateKey).toRawBytes(isCompressed);
  }
  function isProbPub(item) {
    if (typeof item === "bigint")
      return false;
    if (item instanceof Point)
      return true;
    const arr = ensureBytes("key", item);
    const len = arr.length;
    const fpl = Fp.BYTES;
    const compLen = fpl + 1;
    const uncompLen = 2 * fpl + 1;
    if (CURVE.allowedPrivateKeyLengths || nByteLength === compLen) {
      return;
    } else {
      return len === compLen || len === uncompLen;
    }
  }
  function getSharedSecret(privateA, publicB, isCompressed = true) {
    if (isProbPub(privateA) === true)
      throw new Error("first arg must be private key");
    if (isProbPub(publicB) === false)
      throw new Error("second arg must be public key");
    const b = Point.fromHex(publicB);
    return b.multiply(normPrivateKeyToScalar(privateA)).toRawBytes(isCompressed);
  }
  const bits2int = CURVE.bits2int || function(bytes) {
    if (bytes.length > 8192)
      throw new Error("input is too large");
    const num = bytesToNumberBE(bytes);
    const delta = bytes.length * 8 - nBitLength;
    return delta > 0 ? num >> BigInt(delta) : num;
  };
  const bits2int_modN = CURVE.bits2int_modN || function(bytes) {
    return modN(bits2int(bytes));
  };
  const ORDER_MASK = bitMask(nBitLength);
  function int2octets(num) {
    aInRange("num < 2^" + nBitLength, num, _0n5, ORDER_MASK);
    return numberToBytesBE(num, nByteLength);
  }
  function prepSig(msgHash, privateKey, opts = defaultSigOpts) {
    if (["recovered", "canonical"].some((k) => (k in opts)))
      throw new Error("sign() legacy options not supported");
    const { hash, randomBytes } = CURVE;
    let { lowS, prehash, extraEntropy: ent } = opts;
    if (lowS == null)
      lowS = true;
    msgHash = ensureBytes("msgHash", msgHash);
    validateSigVerOpts(opts);
    if (prehash)
      msgHash = ensureBytes("prehashed msgHash", hash(msgHash));
    const h1int = bits2int_modN(msgHash);
    const d = normPrivateKeyToScalar(privateKey);
    const seedArgs = [int2octets(d), int2octets(h1int)];
    if (ent != null && ent !== false) {
      const e = ent === true ? randomBytes(Fp.BYTES) : ent;
      seedArgs.push(ensureBytes("extraEntropy", e));
    }
    const seed = concatBytes2(...seedArgs);
    const m = h1int;
    function k2sig(kBytes) {
      const k = bits2int(kBytes);
      if (!isWithinCurveOrder(k))
        return;
      const ik = invN(k);
      const q = Point.BASE.multiply(k).toAffine();
      const r = modN(q.x);
      if (r === _0n5)
        return;
      const s = modN(ik * modN(m + r * d));
      if (s === _0n5)
        return;
      let recovery = (q.x === r ? 0 : 2) | Number(q.y & _1n5);
      let normS = s;
      if (lowS && isBiggerThanHalfOrder(s)) {
        normS = normalizeS(s);
        recovery ^= 1;
      }
      return new Signature(r, normS, recovery);
    }
    return { seed, k2sig };
  }
  const defaultSigOpts = { lowS: CURVE.lowS, prehash: false };
  const defaultVerOpts = { lowS: CURVE.lowS, prehash: false };
  function sign(msgHash, privKey, opts = defaultSigOpts) {
    const { seed, k2sig } = prepSig(msgHash, privKey, opts);
    const C = CURVE;
    const drbg = createHmacDrbg(C.hash.outputLen, C.nByteLength, C.hmac);
    return drbg(seed, k2sig);
  }
  Point.BASE._setWindowSize(8);
  function verify(signature, msgHash, publicKey, opts = defaultVerOpts) {
    const sg = signature;
    msgHash = ensureBytes("msgHash", msgHash);
    publicKey = ensureBytes("publicKey", publicKey);
    const { lowS, prehash, format } = opts;
    validateSigVerOpts(opts);
    if ("strict" in opts)
      throw new Error("options.strict was renamed to lowS");
    if (format !== undefined && format !== "compact" && format !== "der")
      throw new Error("format must be compact or der");
    const isHex = typeof sg === "string" || isBytes3(sg);
    const isObj = !isHex && !format && typeof sg === "object" && sg !== null && typeof sg.r === "bigint" && typeof sg.s === "bigint";
    if (!isHex && !isObj)
      throw new Error("invalid signature, expected Uint8Array, hex string or Signature instance");
    let _sig = undefined;
    let P;
    try {
      if (isObj)
        _sig = new Signature(sg.r, sg.s);
      if (isHex) {
        try {
          if (format !== "compact")
            _sig = Signature.fromDER(sg);
        } catch (derError) {
          if (!(derError instanceof DER.Err))
            throw derError;
        }
        if (!_sig && format !== "der")
          _sig = Signature.fromCompact(sg);
      }
      P = Point.fromHex(publicKey);
    } catch (error) {
      return false;
    }
    if (!_sig)
      return false;
    if (lowS && _sig.hasHighS())
      return false;
    if (prehash)
      msgHash = CURVE.hash(msgHash);
    const { r, s } = _sig;
    const h = bits2int_modN(msgHash);
    const is = invN(s);
    const u1 = modN(h * is);
    const u2 = modN(r * is);
    const R = Point.BASE.multiplyAndAddUnsafe(P, u1, u2)?.toAffine();
    if (!R)
      return false;
    const v = modN(R.x);
    return v === r;
  }
  return {
    CURVE,
    getPublicKey,
    getSharedSecret,
    sign,
    verify,
    ProjectivePoint: Point,
    Signature,
    utils
  };
}
var DERErr;
var DER;
var _0n5;
var _1n5;
var _2n3;
var _3n2;
var _4n2;
var init_weierstrass = __esm(() => {
  init_curve();
  init_modular();
  init_utils2();
  /*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
  DERErr = class DERErr extends Error {
    constructor(m = "") {
      super(m);
    }
  };
  DER = {
    Err: DERErr,
    _tlv: {
      encode: (tag, data) => {
        const { Err: E } = DER;
        if (tag < 0 || tag > 256)
          throw new E("tlv.encode: wrong tag");
        if (data.length & 1)
          throw new E("tlv.encode: unpadded data");
        const dataLen = data.length / 2;
        const len = numberToHexUnpadded(dataLen);
        if (len.length / 2 & 128)
          throw new E("tlv.encode: long form length too big");
        const lenLen = dataLen > 127 ? numberToHexUnpadded(len.length / 2 | 128) : "";
        const t = numberToHexUnpadded(tag);
        return t + lenLen + len + data;
      },
      decode(tag, data) {
        const { Err: E } = DER;
        let pos = 0;
        if (tag < 0 || tag > 256)
          throw new E("tlv.encode: wrong tag");
        if (data.length < 2 || data[pos++] !== tag)
          throw new E("tlv.decode: wrong tlv");
        const first = data[pos++];
        const isLong = !!(first & 128);
        let length = 0;
        if (!isLong)
          length = first;
        else {
          const lenLen = first & 127;
          if (!lenLen)
            throw new E("tlv.decode(long): indefinite length not supported");
          if (lenLen > 4)
            throw new E("tlv.decode(long): byte length is too big");
          const lengthBytes = data.subarray(pos, pos + lenLen);
          if (lengthBytes.length !== lenLen)
            throw new E("tlv.decode: length bytes not complete");
          if (lengthBytes[0] === 0)
            throw new E("tlv.decode(long): zero leftmost byte");
          for (const b of lengthBytes)
            length = length << 8 | b;
          pos += lenLen;
          if (length < 128)
            throw new E("tlv.decode(long): not minimal encoding");
        }
        const v = data.subarray(pos, pos + length);
        if (v.length !== length)
          throw new E("tlv.decode: wrong value length");
        return { v, l: data.subarray(pos + length) };
      }
    },
    _int: {
      encode(num) {
        const { Err: E } = DER;
        if (num < _0n5)
          throw new E("integer: negative integers are not allowed");
        let hex = numberToHexUnpadded(num);
        if (Number.parseInt(hex[0], 16) & 8)
          hex = "00" + hex;
        if (hex.length & 1)
          throw new E("unexpected DER parsing assertion: unpadded hex");
        return hex;
      },
      decode(data) {
        const { Err: E } = DER;
        if (data[0] & 128)
          throw new E("invalid signature integer: negative");
        if (data[0] === 0 && !(data[1] & 128))
          throw new E("invalid signature integer: unnecessary leading zero");
        return bytesToNumberBE(data);
      }
    },
    toSig(hex) {
      const { Err: E, _int: int, _tlv: tlv } = DER;
      const data = ensureBytes("signature", hex);
      const { v: seqBytes, l: seqLeftBytes } = tlv.decode(48, data);
      if (seqLeftBytes.length)
        throw new E("invalid signature: left bytes after parsing");
      const { v: rBytes, l: rLeftBytes } = tlv.decode(2, seqBytes);
      const { v: sBytes, l: sLeftBytes } = tlv.decode(2, rLeftBytes);
      if (sLeftBytes.length)
        throw new E("invalid signature: left bytes after parsing");
      return { r: int.decode(rBytes), s: int.decode(sBytes) };
    },
    hexFromSig(sig) {
      const { _tlv: tlv, _int: int } = DER;
      const rs = tlv.encode(2, int.encode(sig.r));
      const ss = tlv.encode(2, int.encode(sig.s));
      const seq = rs + ss;
      return tlv.encode(48, seq);
    }
  };
  _0n5 = BigInt(0);
  _1n5 = BigInt(1);
  _2n3 = BigInt(2);
  _3n2 = BigInt(3);
  _4n2 = BigInt(4);
});
function getHash(hash) {
  return {
    hash,
    hmac: (key, ...msgs) => hmac(hash, key, concatBytes(...msgs)),
    randomBytes
  };
}
function createCurve(curveDef, defHash) {
  const create = (hash) => weierstrass({ ...curveDef, ...getHash(hash) });
  return { ...create(defHash), create };
}
var init__shortw_utils = __esm(() => {
  init_hmac();
  init_utils();
  init_weierstrass();
  /*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
});
function sqrtMod(y) {
  const P = secp256k1P;
  const _3n = BigInt(3), _6n = BigInt(6), _11n = BigInt(11), _22n = BigInt(22);
  const _23n = BigInt(23), _44n = BigInt(44), _88n = BigInt(88);
  const b2 = y * y * y % P;
  const b3 = b2 * b2 * y % P;
  const b6 = pow2(b3, _3n, P) * b3 % P;
  const b9 = pow2(b6, _3n, P) * b3 % P;
  const b11 = pow2(b9, _2n4, P) * b2 % P;
  const b22 = pow2(b11, _11n, P) * b11 % P;
  const b44 = pow2(b22, _22n, P) * b22 % P;
  const b88 = pow2(b44, _44n, P) * b44 % P;
  const b176 = pow2(b88, _88n, P) * b88 % P;
  const b220 = pow2(b176, _44n, P) * b44 % P;
  const b223 = pow2(b220, _3n, P) * b3 % P;
  const t1 = pow2(b223, _23n, P) * b22 % P;
  const t2 = pow2(t1, _6n, P) * b2 % P;
  const root = pow2(t2, _2n4, P);
  if (!Fpk1.eql(Fpk1.sqr(root), y))
    throw new Error("Cannot find square root");
  return root;
}
var secp256k1P;
var secp256k1N;
var _0n6;
var _1n6;
var _2n4;
var divNearest = (a, b) => (a + b / _2n4) / b;
var Fpk1;
var secp256k1;
var init_secp256k1 = __esm(() => {
  init_sha2();
  init__shortw_utils();
  init_modular();
  /*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
  secp256k1P = BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
  secp256k1N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
  _0n6 = BigInt(0);
  _1n6 = BigInt(1);
  _2n4 = BigInt(2);
  Fpk1 = Field(secp256k1P, undefined, undefined, { sqrt: sqrtMod });
  secp256k1 = createCurve({
    a: _0n6,
    b: BigInt(7),
    Fp: Fpk1,
    n: secp256k1N,
    Gx: BigInt("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
    Gy: BigInt("32670510020758816978083085130507043184471273380659243275938904335757337482424"),
    h: BigInt(1),
    lowS: true,
    endo: {
      beta: BigInt("0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"),
      splitScalar: (k) => {
        const n = secp256k1N;
        const a1 = BigInt("0x3086d221a7d46bcde86c90e49284eb15");
        const b1 = -_1n6 * BigInt("0xe4437ed6010e88286f547fa90abfe4c3");
        const a2 = BigInt("0x114ca50f7a8e2f3f657c1108d9d44cfd8");
        const b2 = a1;
        const POW_2_128 = BigInt("0x100000000000000000000000000000000");
        const c1 = divNearest(b2 * k, n);
        const c2 = divNearest(-b1 * k, n);
        let k1 = mod(k - c1 * a1 - c2 * a2, n);
        let k2 = mod(-c1 * b1 - c2 * b2, n);
        const k1neg = k1 > POW_2_128;
        const k2neg = k2 > POW_2_128;
        if (k1neg)
          k1 = n - k1;
        if (k2neg)
          k2 = n - k2;
        if (k1 > POW_2_128 || k2 > POW_2_128) {
          throw new Error("splitScalar: Endomorphism failed, k=" + k);
        }
        return { k1neg, k1, k2neg, k2 };
      }
    }
  }, sha256);
});
var UnrecognisedErrorCode = -1;
var Canceled = 1;
var Unknown = 2;
var InvalidArgument = 3;
var DeadlineExceeded = 4;
var NotFound = 5;
var AlreadyExists = 6;
var PermissionDenied = 7;
var ResourceExhausted = 8;
var FailedPrecondition = 9;
var Aborted = 10;
var OutOfRange = 11;
var Unimplemented = 12;
var Internal = 13;
var Unavailable = 14;
var DataLoss = 15;
var Unauthenticated = 16;
var ConsensusFailed = 100;
var LimitExceeded = 101;
var InsufficientObservations = 102;
var errorCodeToString = new Map([
  [Canceled, "Canceled"],
  [Unknown, "Unknown"],
  [InvalidArgument, "InvalidArgument"],
  [DeadlineExceeded, "DeadlineExceeded"],
  [NotFound, "NotFound"],
  [AlreadyExists, "AlreadyExists"],
  [PermissionDenied, "PermissionDenied"],
  [ResourceExhausted, "ResourceExhausted"],
  [FailedPrecondition, "FailedPrecondition"],
  [Aborted, "Aborted"],
  [OutOfRange, "OutOfRange"],
  [Unimplemented, "Unimplemented"],
  [Internal, "Internal"],
  [Unavailable, "Unavailable"],
  [DataLoss, "DataLoss"],
  [Unauthenticated, "Unauthenticated"],
  [ConsensusFailed, "ConsensusFailed"],
  [LimitExceeded, "LimitExceeded"],
  [InsufficientObservations, "InsufficientObservations"]
]);
var stringToErrorCode = new Map(Array.from(errorCodeToString.entries()).map(([code, name]) => [name, code]));
function errorCodeToStringValue(code) {
  return errorCodeToString.get(code) ?? "UnrecognisedErrorCode";
}
function fromErrorCodeString(str) {
  return stringToErrorCode.get(str) ?? UnrecognisedErrorCode;
}
var OriginSystem = 0;
var OriginUser = 1;
function fromOriginString(s) {
  switch (s) {
    case "System":
      return OriginSystem;
    case "User":
      return OriginUser;
    default:
      return -1;
  }
}
var VisibilityPublic = 0;
var VisibilityPrivate = 1;
function fromVisibilityString(s) {
  switch (s) {
    case "Public":
      return VisibilityPublic;
    case "Private":
      return VisibilityPrivate;
    default:
      return -1;
  }
}

class CapabilityExecutionError extends Error {
  detail;
  visibility;
  origin;
  code;
  name = "CapabilityExecutionError";
  constructor(detail, visibility, origin, code) {
    super(code === UnrecognisedErrorCode ? detail : `[${code}]${errorCodeToStringValue(code)}: ${detail}`);
    this.detail = detail;
    this.visibility = visibility;
    this.origin = origin;
    this.code = code;
  }
  toString() {
    return this.message;
  }
}
var errorMessageSeparator = ":";
function deserializeErrorFromString(errorMsg) {
  const parts = errorMsg.split(errorMessageSeparator);
  if (parts.length < 4) {
    return new Error(errorMsg);
  }
  const visibility = fromVisibilityString(parts[0]);
  const origin = fromOriginString(parts[1]);
  const errorCode = fromErrorCodeString(parts[2]);
  const detail = parts.slice(3).join(errorMessageSeparator);
  return new CapabilityExecutionError(detail, visibility, origin, errorCode);
}
function isMessage(arg, schema) {
  const isMessage = arg !== null && typeof arg == "object" && "$typeName" in arg && typeof arg.$typeName == "string";
  if (!isMessage) {
    return false;
  }
  if (schema === undefined) {
    return true;
  }
  return schema.typeName === arg.$typeName;
}
var ScalarType;
(function(ScalarType) {
  ScalarType[ScalarType["DOUBLE"] = 1] = "DOUBLE";
  ScalarType[ScalarType["FLOAT"] = 2] = "FLOAT";
  ScalarType[ScalarType["INT64"] = 3] = "INT64";
  ScalarType[ScalarType["UINT64"] = 4] = "UINT64";
  ScalarType[ScalarType["INT32"] = 5] = "INT32";
  ScalarType[ScalarType["FIXED64"] = 6] = "FIXED64";
  ScalarType[ScalarType["FIXED32"] = 7] = "FIXED32";
  ScalarType[ScalarType["BOOL"] = 8] = "BOOL";
  ScalarType[ScalarType["STRING"] = 9] = "STRING";
  ScalarType[ScalarType["BYTES"] = 12] = "BYTES";
  ScalarType[ScalarType["UINT32"] = 13] = "UINT32";
  ScalarType[ScalarType["SFIXED32"] = 15] = "SFIXED32";
  ScalarType[ScalarType["SFIXED64"] = 16] = "SFIXED64";
  ScalarType[ScalarType["SINT32"] = 17] = "SINT32";
  ScalarType[ScalarType["SINT64"] = 18] = "SINT64";
})(ScalarType || (ScalarType = {}));
function varint64read() {
  let lowBits = 0;
  let highBits = 0;
  for (let shift = 0;shift < 28; shift += 7) {
    let b = this.buf[this.pos++];
    lowBits |= (b & 127) << shift;
    if ((b & 128) == 0) {
      this.assertBounds();
      return [lowBits, highBits];
    }
  }
  let middleByte = this.buf[this.pos++];
  lowBits |= (middleByte & 15) << 28;
  highBits = (middleByte & 112) >> 4;
  if ((middleByte & 128) == 0) {
    this.assertBounds();
    return [lowBits, highBits];
  }
  for (let shift = 3;shift <= 31; shift += 7) {
    let b = this.buf[this.pos++];
    highBits |= (b & 127) << shift;
    if ((b & 128) == 0) {
      this.assertBounds();
      return [lowBits, highBits];
    }
  }
  throw new Error("invalid varint");
}
function varint64write(lo, hi, bytes) {
  for (let i = 0;i < 28; i = i + 7) {
    const shift = lo >>> i;
    const hasNext = !(shift >>> 7 == 0 && hi == 0);
    const byte = (hasNext ? shift | 128 : shift) & 255;
    bytes.push(byte);
    if (!hasNext) {
      return;
    }
  }
  const splitBits = lo >>> 28 & 15 | (hi & 7) << 4;
  const hasMoreBits = !(hi >> 3 == 0);
  bytes.push((hasMoreBits ? splitBits | 128 : splitBits) & 255);
  if (!hasMoreBits) {
    return;
  }
  for (let i = 3;i < 31; i = i + 7) {
    const shift = hi >>> i;
    const hasNext = !(shift >>> 7 == 0);
    const byte = (hasNext ? shift | 128 : shift) & 255;
    bytes.push(byte);
    if (!hasNext) {
      return;
    }
  }
  bytes.push(hi >>> 31 & 1);
}
var TWO_PWR_32_DBL = 4294967296;
function int64FromString(dec) {
  const minus = dec[0] === "-";
  if (minus) {
    dec = dec.slice(1);
  }
  const base = 1e6;
  let lowBits = 0;
  let highBits = 0;
  function add1e6digit(begin, end) {
    const digit1e6 = Number(dec.slice(begin, end));
    highBits *= base;
    lowBits = lowBits * base + digit1e6;
    if (lowBits >= TWO_PWR_32_DBL) {
      highBits = highBits + (lowBits / TWO_PWR_32_DBL | 0);
      lowBits = lowBits % TWO_PWR_32_DBL;
    }
  }
  add1e6digit(-24, -18);
  add1e6digit(-18, -12);
  add1e6digit(-12, -6);
  add1e6digit(-6);
  return minus ? negate(lowBits, highBits) : newBits(lowBits, highBits);
}
function int64ToString(lo, hi) {
  let bits = newBits(lo, hi);
  const negative = bits.hi & 2147483648;
  if (negative) {
    bits = negate(bits.lo, bits.hi);
  }
  const result = uInt64ToString(bits.lo, bits.hi);
  return negative ? "-" + result : result;
}
function uInt64ToString(lo, hi) {
  ({ lo, hi } = toUnsigned(lo, hi));
  if (hi <= 2097151) {
    return String(TWO_PWR_32_DBL * hi + lo);
  }
  const low = lo & 16777215;
  const mid = (lo >>> 24 | hi << 8) & 16777215;
  const high = hi >> 16 & 65535;
  let digitA = low + mid * 6777216 + high * 6710656;
  let digitB = mid + high * 8147497;
  let digitC = high * 2;
  const base = 1e7;
  if (digitA >= base) {
    digitB += Math.floor(digitA / base);
    digitA %= base;
  }
  if (digitB >= base) {
    digitC += Math.floor(digitB / base);
    digitB %= base;
  }
  return digitC.toString() + decimalFrom1e7WithLeadingZeros(digitB) + decimalFrom1e7WithLeadingZeros(digitA);
}
function toUnsigned(lo, hi) {
  return { lo: lo >>> 0, hi: hi >>> 0 };
}
function newBits(lo, hi) {
  return { lo: lo | 0, hi: hi | 0 };
}
function negate(lowBits, highBits) {
  highBits = ~highBits;
  if (lowBits) {
    lowBits = ~lowBits + 1;
  } else {
    highBits += 1;
  }
  return newBits(lowBits, highBits);
}
var decimalFrom1e7WithLeadingZeros = (digit1e7) => {
  const partial = String(digit1e7);
  return "0000000".slice(partial.length) + partial;
};
function varint32write(value, bytes) {
  if (value >= 0) {
    while (value > 127) {
      bytes.push(value & 127 | 128);
      value = value >>> 7;
    }
    bytes.push(value);
  } else {
    for (let i = 0;i < 9; i++) {
      bytes.push(value & 127 | 128);
      value = value >> 7;
    }
    bytes.push(1);
  }
}
function varint32read() {
  let b = this.buf[this.pos++];
  let result = b & 127;
  if ((b & 128) == 0) {
    this.assertBounds();
    return result;
  }
  b = this.buf[this.pos++];
  result |= (b & 127) << 7;
  if ((b & 128) == 0) {
    this.assertBounds();
    return result;
  }
  b = this.buf[this.pos++];
  result |= (b & 127) << 14;
  if ((b & 128) == 0) {
    this.assertBounds();
    return result;
  }
  b = this.buf[this.pos++];
  result |= (b & 127) << 21;
  if ((b & 128) == 0) {
    this.assertBounds();
    return result;
  }
  b = this.buf[this.pos++];
  result |= (b & 15) << 28;
  for (let readBytes = 5;(b & 128) !== 0 && readBytes < 10; readBytes++)
    b = this.buf[this.pos++];
  if ((b & 128) != 0)
    throw new Error("invalid varint");
  this.assertBounds();
  return result >>> 0;
}
var protoInt64 = /* @__PURE__ */ makeInt64Support();
function makeInt64Support() {
  const dv = new DataView(new ArrayBuffer(8));
  const ok = typeof BigInt === "function" && typeof dv.getBigInt64 === "function" && typeof dv.getBigUint64 === "function" && typeof dv.setBigInt64 === "function" && typeof dv.setBigUint64 === "function" && (typeof process != "object" || typeof process.env != "object" || process.env.BUF_BIGINT_DISABLE !== "1");
  if (ok) {
    const MIN = BigInt("-9223372036854775808");
    const MAX = BigInt("9223372036854775807");
    const UMIN = BigInt("0");
    const UMAX = BigInt("18446744073709551615");
    return {
      zero: BigInt(0),
      supported: true,
      parse(value) {
        const bi = typeof value == "bigint" ? value : BigInt(value);
        if (bi > MAX || bi < MIN) {
          throw new Error(`invalid int64: ${value}`);
        }
        return bi;
      },
      uParse(value) {
        const bi = typeof value == "bigint" ? value : BigInt(value);
        if (bi > UMAX || bi < UMIN) {
          throw new Error(`invalid uint64: ${value}`);
        }
        return bi;
      },
      enc(value) {
        dv.setBigInt64(0, this.parse(value), true);
        return {
          lo: dv.getInt32(0, true),
          hi: dv.getInt32(4, true)
        };
      },
      uEnc(value) {
        dv.setBigInt64(0, this.uParse(value), true);
        return {
          lo: dv.getInt32(0, true),
          hi: dv.getInt32(4, true)
        };
      },
      dec(lo, hi) {
        dv.setInt32(0, lo, true);
        dv.setInt32(4, hi, true);
        return dv.getBigInt64(0, true);
      },
      uDec(lo, hi) {
        dv.setInt32(0, lo, true);
        dv.setInt32(4, hi, true);
        return dv.getBigUint64(0, true);
      }
    };
  }
  return {
    zero: "0",
    supported: false,
    parse(value) {
      if (typeof value != "string") {
        value = value.toString();
      }
      assertInt64String(value);
      return value;
    },
    uParse(value) {
      if (typeof value != "string") {
        value = value.toString();
      }
      assertUInt64String(value);
      return value;
    },
    enc(value) {
      if (typeof value != "string") {
        value = value.toString();
      }
      assertInt64String(value);
      return int64FromString(value);
    },
    uEnc(value) {
      if (typeof value != "string") {
        value = value.toString();
      }
      assertUInt64String(value);
      return int64FromString(value);
    },
    dec(lo, hi) {
      return int64ToString(lo, hi);
    },
    uDec(lo, hi) {
      return uInt64ToString(lo, hi);
    }
  };
}
function assertInt64String(value) {
  if (!/^-?[0-9]+$/.test(value)) {
    throw new Error("invalid int64: " + value);
  }
}
function assertUInt64String(value) {
  if (!/^[0-9]+$/.test(value)) {
    throw new Error("invalid uint64: " + value);
  }
}
function scalarZeroValue(type, longAsString) {
  switch (type) {
    case ScalarType.STRING:
      return "";
    case ScalarType.BOOL:
      return false;
    case ScalarType.DOUBLE:
    case ScalarType.FLOAT:
      return 0;
    case ScalarType.INT64:
    case ScalarType.UINT64:
    case ScalarType.SFIXED64:
    case ScalarType.FIXED64:
    case ScalarType.SINT64:
      return longAsString ? "0" : protoInt64.zero;
    case ScalarType.BYTES:
      return new Uint8Array(0);
    default:
      return 0;
  }
}
function isScalarZeroValue(type, value) {
  switch (type) {
    case ScalarType.BOOL:
      return value === false;
    case ScalarType.STRING:
      return value === "";
    case ScalarType.BYTES:
      return value instanceof Uint8Array && !value.byteLength;
    default:
      return value == 0;
  }
}
var IMPLICIT = 2;
var unsafeLocal = Symbol.for("reflect unsafe local");
function unsafeOneofCase(target, oneof) {
  const c = target[oneof.localName].case;
  if (c === undefined) {
    return c;
  }
  return oneof.fields.find((f) => f.localName === c);
}
function unsafeIsSet(target, field) {
  const name = field.localName;
  if (field.oneof) {
    return target[field.oneof.localName].case === name;
  }
  if (field.presence != IMPLICIT) {
    return target[name] !== undefined && Object.prototype.hasOwnProperty.call(target, name);
  }
  switch (field.fieldKind) {
    case "list":
      return target[name].length > 0;
    case "map":
      return Object.keys(target[name]).length > 0;
    case "scalar":
      return !isScalarZeroValue(field.scalar, target[name]);
    case "enum":
      return target[name] !== field.enum.values[0].number;
  }
  throw new Error("message field with implicit presence");
}
function unsafeIsSetExplicit(target, localName) {
  return Object.prototype.hasOwnProperty.call(target, localName) && target[localName] !== undefined;
}
function unsafeGet(target, field) {
  if (field.oneof) {
    const oneof = target[field.oneof.localName];
    if (oneof.case === field.localName) {
      return oneof.value;
    }
    return;
  }
  return target[field.localName];
}
function unsafeSet(target, field, value) {
  if (field.oneof) {
    target[field.oneof.localName] = {
      case: field.localName,
      value
    };
  } else {
    target[field.localName] = value;
  }
}
function unsafeClear(target, field) {
  const name = field.localName;
  if (field.oneof) {
    const oneofLocalName = field.oneof.localName;
    if (target[oneofLocalName].case === name) {
      target[oneofLocalName] = { case: undefined };
    }
  } else if (field.presence != IMPLICIT) {
    delete target[name];
  } else {
    switch (field.fieldKind) {
      case "map":
        target[name] = {};
        break;
      case "list":
        target[name] = [];
        break;
      case "enum":
        target[name] = field.enum.values[0].number;
        break;
      case "scalar":
        target[name] = scalarZeroValue(field.scalar, field.longAsString);
        break;
    }
  }
}
function isObject(arg) {
  return arg !== null && typeof arg == "object" && !Array.isArray(arg);
}
function isReflectList(arg, field) {
  var _a, _b, _c, _d;
  if (isObject(arg) && unsafeLocal in arg && "add" in arg && "field" in arg && typeof arg.field == "function") {
    if (field !== undefined) {
      const a = field;
      const b = arg.field();
      return a.listKind == b.listKind && a.scalar === b.scalar && ((_a = a.message) === null || _a === undefined ? undefined : _a.typeName) === ((_b = b.message) === null || _b === undefined ? undefined : _b.typeName) && ((_c = a.enum) === null || _c === undefined ? undefined : _c.typeName) === ((_d = b.enum) === null || _d === undefined ? undefined : _d.typeName);
    }
    return true;
  }
  return false;
}
function isReflectMap(arg, field) {
  var _a, _b, _c, _d;
  if (isObject(arg) && unsafeLocal in arg && "has" in arg && "field" in arg && typeof arg.field == "function") {
    if (field !== undefined) {
      const a = field, b = arg.field();
      return a.mapKey === b.mapKey && a.mapKind == b.mapKind && a.scalar === b.scalar && ((_a = a.message) === null || _a === undefined ? undefined : _a.typeName) === ((_b = b.message) === null || _b === undefined ? undefined : _b.typeName) && ((_c = a.enum) === null || _c === undefined ? undefined : _c.typeName) === ((_d = b.enum) === null || _d === undefined ? undefined : _d.typeName);
    }
    return true;
  }
  return false;
}
function isReflectMessage(arg, messageDesc) {
  return isObject(arg) && unsafeLocal in arg && "desc" in arg && isObject(arg.desc) && arg.desc.kind === "message" && (messageDesc === undefined || arg.desc.typeName == messageDesc.typeName);
}
function isWrapper(arg) {
  return isWrapperTypeName(arg.$typeName);
}
function isWrapperDesc(messageDesc) {
  const f = messageDesc.fields[0];
  return isWrapperTypeName(messageDesc.typeName) && f !== undefined && f.fieldKind == "scalar" && f.name == "value" && f.number == 1;
}
function isWrapperTypeName(name) {
  return name.startsWith("google.protobuf.") && [
    "DoubleValue",
    "FloatValue",
    "Int64Value",
    "UInt64Value",
    "Int32Value",
    "UInt32Value",
    "BoolValue",
    "StringValue",
    "BytesValue"
  ].includes(name.substring(16));
}
var EDITION_PROTO3 = 999;
var EDITION_PROTO2 = 998;
var IMPLICIT2 = 2;
function create(schema, init) {
  if (isMessage(init, schema)) {
    return init;
  }
  const message = createZeroMessage(schema);
  if (init !== undefined) {
    initMessage(schema, message, init);
  }
  return message;
}
function initMessage(messageDesc, message, init) {
  for (const member of messageDesc.members) {
    let value = init[member.localName];
    if (value == null) {
      continue;
    }
    let field;
    if (member.kind == "oneof") {
      const oneofField = unsafeOneofCase(init, member);
      if (!oneofField) {
        continue;
      }
      field = oneofField;
      value = unsafeGet(init, oneofField);
    } else {
      field = member;
    }
    switch (field.fieldKind) {
      case "message":
        value = toMessage(field, value);
        break;
      case "scalar":
        value = initScalar(field, value);
        break;
      case "list":
        value = initList(field, value);
        break;
      case "map":
        value = initMap(field, value);
        break;
    }
    unsafeSet(message, field, value);
  }
  return message;
}
function initScalar(field, value) {
  if (field.scalar == ScalarType.BYTES) {
    return toU8Arr(value);
  }
  return value;
}
function initMap(field, value) {
  if (isObject(value)) {
    if (field.scalar == ScalarType.BYTES) {
      return convertObjectValues(value, toU8Arr);
    }
    if (field.mapKind == "message") {
      return convertObjectValues(value, (val) => toMessage(field, val));
    }
  }
  return value;
}
function initList(field, value) {
  if (Array.isArray(value)) {
    if (field.scalar == ScalarType.BYTES) {
      return value.map(toU8Arr);
    }
    if (field.listKind == "message") {
      return value.map((item) => toMessage(field, item));
    }
  }
  return value;
}
function toMessage(field, value) {
  if (field.fieldKind == "message" && !field.oneof && isWrapperDesc(field.message)) {
    return initScalar(field.message.fields[0], value);
  }
  if (isObject(value)) {
    if (field.message.typeName == "google.protobuf.Struct" && field.parent.typeName !== "google.protobuf.Value") {
      return value;
    }
    if (!isMessage(value, field.message)) {
      return create(field.message, value);
    }
  }
  return value;
}
function toU8Arr(value) {
  return Array.isArray(value) ? new Uint8Array(value) : value;
}
function convertObjectValues(obj, fn) {
  const ret = {};
  for (const entry of Object.entries(obj)) {
    ret[entry[0]] = fn(entry[1]);
  }
  return ret;
}
var tokenZeroMessageField = Symbol();
var messagePrototypes = new WeakMap;
function createZeroMessage(desc) {
  let msg;
  if (!needsPrototypeChain(desc)) {
    msg = {
      $typeName: desc.typeName
    };
    for (const member of desc.members) {
      if (member.kind == "oneof" || member.presence == IMPLICIT2) {
        msg[member.localName] = createZeroField(member);
      }
    }
  } else {
    const cached = messagePrototypes.get(desc);
    let prototype;
    let members;
    if (cached) {
      ({ prototype, members } = cached);
    } else {
      prototype = {};
      members = new Set;
      for (const member of desc.members) {
        if (member.kind == "oneof") {
          continue;
        }
        if (member.fieldKind != "scalar" && member.fieldKind != "enum") {
          continue;
        }
        if (member.presence == IMPLICIT2) {
          continue;
        }
        members.add(member);
        prototype[member.localName] = createZeroField(member);
      }
      messagePrototypes.set(desc, { prototype, members });
    }
    msg = Object.create(prototype);
    msg.$typeName = desc.typeName;
    for (const member of desc.members) {
      if (members.has(member)) {
        continue;
      }
      if (member.kind == "field") {
        if (member.fieldKind == "message") {
          continue;
        }
        if (member.fieldKind == "scalar" || member.fieldKind == "enum") {
          if (member.presence != IMPLICIT2) {
            continue;
          }
        }
      }
      msg[member.localName] = createZeroField(member);
    }
  }
  return msg;
}
function needsPrototypeChain(desc) {
  switch (desc.file.edition) {
    case EDITION_PROTO3:
      return false;
    case EDITION_PROTO2:
      return true;
    default:
      return desc.fields.some((f) => f.presence != IMPLICIT2 && f.fieldKind != "message" && !f.oneof);
  }
}
function createZeroField(field) {
  if (field.kind == "oneof") {
    return { case: undefined };
  }
  if (field.fieldKind == "list") {
    return [];
  }
  if (field.fieldKind == "map") {
    return {};
  }
  if (field.fieldKind == "message") {
    return tokenZeroMessageField;
  }
  const defaultValue = field.getDefaultValue();
  if (defaultValue !== undefined) {
    return field.fieldKind == "scalar" && field.longAsString ? defaultValue.toString() : defaultValue;
  }
  return field.fieldKind == "scalar" ? scalarZeroValue(field.scalar, field.longAsString) : field.enum.values[0].number;
}
var errorNames = [
  "FieldValueInvalidError",
  "FieldListRangeError",
  "ForeignFieldError"
];

class FieldError extends Error {
  constructor(fieldOrOneof, message, name = "FieldValueInvalidError") {
    super(message);
    this.name = name;
    this.field = () => fieldOrOneof;
  }
}
function isFieldError(arg) {
  return arg instanceof Error && errorNames.includes(arg.name) && "field" in arg && typeof arg.field == "function";
}
var symbol = Symbol.for("@bufbuild/protobuf/text-encoding");
function getTextEncoding() {
  if (globalThis[symbol] == undefined) {
    const te = new globalThis.TextEncoder;
    const td = new globalThis.TextDecoder;
    globalThis[symbol] = {
      encodeUtf8(text) {
        return te.encode(text);
      },
      decodeUtf8(bytes) {
        return td.decode(bytes);
      },
      checkUtf8(text) {
        try {
          encodeURIComponent(text);
          return true;
        } catch (_) {
          return false;
        }
      }
    };
  }
  return globalThis[symbol];
}
var WireType;
(function(WireType) {
  WireType[WireType["Varint"] = 0] = "Varint";
  WireType[WireType["Bit64"] = 1] = "Bit64";
  WireType[WireType["LengthDelimited"] = 2] = "LengthDelimited";
  WireType[WireType["StartGroup"] = 3] = "StartGroup";
  WireType[WireType["EndGroup"] = 4] = "EndGroup";
  WireType[WireType["Bit32"] = 5] = "Bit32";
})(WireType || (WireType = {}));
var FLOAT32_MAX = 340282346638528860000000000000000000000;
var FLOAT32_MIN = -340282346638528860000000000000000000000;
var UINT32_MAX = 4294967295;
var INT32_MAX = 2147483647;
var INT32_MIN = -2147483648;

class BinaryWriter {
  constructor(encodeUtf8 = getTextEncoding().encodeUtf8) {
    this.encodeUtf8 = encodeUtf8;
    this.stack = [];
    this.chunks = [];
    this.buf = [];
  }
  finish() {
    if (this.buf.length) {
      this.chunks.push(new Uint8Array(this.buf));
      this.buf = [];
    }
    let len = 0;
    for (let i = 0;i < this.chunks.length; i++)
      len += this.chunks[i].length;
    let bytes = new Uint8Array(len);
    let offset = 0;
    for (let i = 0;i < this.chunks.length; i++) {
      bytes.set(this.chunks[i], offset);
      offset += this.chunks[i].length;
    }
    this.chunks = [];
    return bytes;
  }
  fork() {
    this.stack.push({ chunks: this.chunks, buf: this.buf });
    this.chunks = [];
    this.buf = [];
    return this;
  }
  join() {
    let chunk = this.finish();
    let prev = this.stack.pop();
    if (!prev)
      throw new Error("invalid state, fork stack empty");
    this.chunks = prev.chunks;
    this.buf = prev.buf;
    this.uint32(chunk.byteLength);
    return this.raw(chunk);
  }
  tag(fieldNo, type) {
    return this.uint32((fieldNo << 3 | type) >>> 0);
  }
  raw(chunk) {
    if (this.buf.length) {
      this.chunks.push(new Uint8Array(this.buf));
      this.buf = [];
    }
    this.chunks.push(chunk);
    return this;
  }
  uint32(value) {
    assertUInt32(value);
    while (value > 127) {
      this.buf.push(value & 127 | 128);
      value = value >>> 7;
    }
    this.buf.push(value);
    return this;
  }
  int32(value) {
    assertInt32(value);
    varint32write(value, this.buf);
    return this;
  }
  bool(value) {
    this.buf.push(value ? 1 : 0);
    return this;
  }
  bytes(value) {
    this.uint32(value.byteLength);
    return this.raw(value);
  }
  string(value) {
    let chunk = this.encodeUtf8(value);
    this.uint32(chunk.byteLength);
    return this.raw(chunk);
  }
  float(value) {
    assertFloat32(value);
    let chunk = new Uint8Array(4);
    new DataView(chunk.buffer).setFloat32(0, value, true);
    return this.raw(chunk);
  }
  double(value) {
    let chunk = new Uint8Array(8);
    new DataView(chunk.buffer).setFloat64(0, value, true);
    return this.raw(chunk);
  }
  fixed32(value) {
    assertUInt32(value);
    let chunk = new Uint8Array(4);
    new DataView(chunk.buffer).setUint32(0, value, true);
    return this.raw(chunk);
  }
  sfixed32(value) {
    assertInt32(value);
    let chunk = new Uint8Array(4);
    new DataView(chunk.buffer).setInt32(0, value, true);
    return this.raw(chunk);
  }
  sint32(value) {
    assertInt32(value);
    value = (value << 1 ^ value >> 31) >>> 0;
    varint32write(value, this.buf);
    return this;
  }
  sfixed64(value) {
    let chunk = new Uint8Array(8), view = new DataView(chunk.buffer), tc = protoInt64.enc(value);
    view.setInt32(0, tc.lo, true);
    view.setInt32(4, tc.hi, true);
    return this.raw(chunk);
  }
  fixed64(value) {
    let chunk = new Uint8Array(8), view = new DataView(chunk.buffer), tc = protoInt64.uEnc(value);
    view.setInt32(0, tc.lo, true);
    view.setInt32(4, tc.hi, true);
    return this.raw(chunk);
  }
  int64(value) {
    let tc = protoInt64.enc(value);
    varint64write(tc.lo, tc.hi, this.buf);
    return this;
  }
  sint64(value) {
    const tc = protoInt64.enc(value), sign = tc.hi >> 31, lo = tc.lo << 1 ^ sign, hi = (tc.hi << 1 | tc.lo >>> 31) ^ sign;
    varint64write(lo, hi, this.buf);
    return this;
  }
  uint64(value) {
    const tc = protoInt64.uEnc(value);
    varint64write(tc.lo, tc.hi, this.buf);
    return this;
  }
}

class BinaryReader {
  constructor(buf, decodeUtf8 = getTextEncoding().decodeUtf8) {
    this.decodeUtf8 = decodeUtf8;
    this.varint64 = varint64read;
    this.uint32 = varint32read;
    this.buf = buf;
    this.len = buf.length;
    this.pos = 0;
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  tag() {
    let tag = this.uint32(), fieldNo = tag >>> 3, wireType = tag & 7;
    if (fieldNo <= 0 || wireType < 0 || wireType > 5)
      throw new Error("illegal tag: field no " + fieldNo + " wire type " + wireType);
    return [fieldNo, wireType];
  }
  skip(wireType, fieldNo) {
    let start = this.pos;
    switch (wireType) {
      case WireType.Varint:
        while (this.buf[this.pos++] & 128) {}
        break;
      case WireType.Bit64:
        this.pos += 4;
      case WireType.Bit32:
        this.pos += 4;
        break;
      case WireType.LengthDelimited:
        let len = this.uint32();
        this.pos += len;
        break;
      case WireType.StartGroup:
        for (;; ) {
          const [fn, wt] = this.tag();
          if (wt === WireType.EndGroup) {
            if (fieldNo !== undefined && fn !== fieldNo) {
              throw new Error("invalid end group tag");
            }
            break;
          }
          this.skip(wt, fn);
        }
        break;
      default:
        throw new Error("cant skip wire type " + wireType);
    }
    this.assertBounds();
    return this.buf.subarray(start, this.pos);
  }
  assertBounds() {
    if (this.pos > this.len)
      throw new RangeError("premature EOF");
  }
  int32() {
    return this.uint32() | 0;
  }
  sint32() {
    let zze = this.uint32();
    return zze >>> 1 ^ -(zze & 1);
  }
  int64() {
    return protoInt64.dec(...this.varint64());
  }
  uint64() {
    return protoInt64.uDec(...this.varint64());
  }
  sint64() {
    let [lo, hi] = this.varint64();
    let s = -(lo & 1);
    lo = (lo >>> 1 | (hi & 1) << 31) ^ s;
    hi = hi >>> 1 ^ s;
    return protoInt64.dec(lo, hi);
  }
  bool() {
    let [lo, hi] = this.varint64();
    return lo !== 0 || hi !== 0;
  }
  fixed32() {
    return this.view.getUint32((this.pos += 4) - 4, true);
  }
  sfixed32() {
    return this.view.getInt32((this.pos += 4) - 4, true);
  }
  fixed64() {
    return protoInt64.uDec(this.sfixed32(), this.sfixed32());
  }
  sfixed64() {
    return protoInt64.dec(this.sfixed32(), this.sfixed32());
  }
  float() {
    return this.view.getFloat32((this.pos += 4) - 4, true);
  }
  double() {
    return this.view.getFloat64((this.pos += 8) - 8, true);
  }
  bytes() {
    let len = this.uint32(), start = this.pos;
    this.pos += len;
    this.assertBounds();
    return this.buf.subarray(start, start + len);
  }
  string() {
    return this.decodeUtf8(this.bytes());
  }
}
function assertInt32(arg) {
  if (typeof arg == "string") {
    arg = Number(arg);
  } else if (typeof arg != "number") {
    throw new Error("invalid int32: " + typeof arg);
  }
  if (!Number.isInteger(arg) || arg > INT32_MAX || arg < INT32_MIN)
    throw new Error("invalid int32: " + arg);
}
function assertUInt32(arg) {
  if (typeof arg == "string") {
    arg = Number(arg);
  } else if (typeof arg != "number") {
    throw new Error("invalid uint32: " + typeof arg);
  }
  if (!Number.isInteger(arg) || arg > UINT32_MAX || arg < 0)
    throw new Error("invalid uint32: " + arg);
}
function assertFloat32(arg) {
  if (typeof arg == "string") {
    const o = arg;
    arg = Number(arg);
    if (Number.isNaN(arg) && o !== "NaN") {
      throw new Error("invalid float32: " + o);
    }
  } else if (typeof arg != "number") {
    throw new Error("invalid float32: " + typeof arg);
  }
  if (Number.isFinite(arg) && (arg > FLOAT32_MAX || arg < FLOAT32_MIN))
    throw new Error("invalid float32: " + arg);
}
function checkField(field, value) {
  const check = field.fieldKind == "list" ? isReflectList(value, field) : field.fieldKind == "map" ? isReflectMap(value, field) : checkSingular(field, value);
  if (check === true) {
    return;
  }
  let reason;
  switch (field.fieldKind) {
    case "list":
      reason = `expected ${formatReflectList(field)}, got ${formatVal(value)}`;
      break;
    case "map":
      reason = `expected ${formatReflectMap(field)}, got ${formatVal(value)}`;
      break;
    default: {
      reason = reasonSingular(field, value, check);
    }
  }
  return new FieldError(field, reason);
}
function checkListItem(field, index, value) {
  const check = checkSingular(field, value);
  if (check !== true) {
    return new FieldError(field, `list item #${index + 1}: ${reasonSingular(field, value, check)}`);
  }
  return;
}
function checkMapEntry(field, key, value) {
  const checkKey = checkScalarValue(key, field.mapKey);
  if (checkKey !== true) {
    return new FieldError(field, `invalid map key: ${reasonSingular({ scalar: field.mapKey }, key, checkKey)}`);
  }
  const checkVal = checkSingular(field, value);
  if (checkVal !== true) {
    return new FieldError(field, `map entry ${formatVal(key)}: ${reasonSingular(field, value, checkVal)}`);
  }
  return;
}
function checkSingular(field, value) {
  if (field.scalar !== undefined) {
    return checkScalarValue(value, field.scalar);
  }
  if (field.enum !== undefined) {
    if (field.enum.open) {
      return Number.isInteger(value);
    }
    return field.enum.values.some((v) => v.number === value);
  }
  return isReflectMessage(value, field.message);
}
function checkScalarValue(value, scalar) {
  switch (scalar) {
    case ScalarType.DOUBLE:
      return typeof value == "number";
    case ScalarType.FLOAT:
      if (typeof value != "number") {
        return false;
      }
      if (Number.isNaN(value) || !Number.isFinite(value)) {
        return true;
      }
      if (value > FLOAT32_MAX || value < FLOAT32_MIN) {
        return `${value.toFixed()} out of range`;
      }
      return true;
    case ScalarType.INT32:
    case ScalarType.SFIXED32:
    case ScalarType.SINT32:
      if (typeof value !== "number" || !Number.isInteger(value)) {
        return false;
      }
      if (value > INT32_MAX || value < INT32_MIN) {
        return `${value.toFixed()} out of range`;
      }
      return true;
    case ScalarType.FIXED32:
    case ScalarType.UINT32:
      if (typeof value !== "number" || !Number.isInteger(value)) {
        return false;
      }
      if (value > UINT32_MAX || value < 0) {
        return `${value.toFixed()} out of range`;
      }
      return true;
    case ScalarType.BOOL:
      return typeof value == "boolean";
    case ScalarType.STRING:
      if (typeof value != "string") {
        return false;
      }
      return getTextEncoding().checkUtf8(value) || "invalid UTF8";
    case ScalarType.BYTES:
      return value instanceof Uint8Array;
    case ScalarType.INT64:
    case ScalarType.SFIXED64:
    case ScalarType.SINT64:
      if (typeof value == "bigint" || typeof value == "number" || typeof value == "string" && value.length > 0) {
        try {
          protoInt64.parse(value);
          return true;
        } catch (_) {
          return `${value} out of range`;
        }
      }
      return false;
    case ScalarType.FIXED64:
    case ScalarType.UINT64:
      if (typeof value == "bigint" || typeof value == "number" || typeof value == "string" && value.length > 0) {
        try {
          protoInt64.uParse(value);
          return true;
        } catch (_) {
          return `${value} out of range`;
        }
      }
      return false;
  }
}
function reasonSingular(field, val, details) {
  details = typeof details == "string" ? `: ${details}` : `, got ${formatVal(val)}`;
  if (field.scalar !== undefined) {
    return `expected ${scalarTypeDescription(field.scalar)}` + details;
  }
  if (field.enum !== undefined) {
    return `expected ${field.enum.toString()}` + details;
  }
  return `expected ${formatReflectMessage(field.message)}` + details;
}
function formatVal(val) {
  switch (typeof val) {
    case "object":
      if (val === null) {
        return "null";
      }
      if (val instanceof Uint8Array) {
        return `Uint8Array(${val.length})`;
      }
      if (Array.isArray(val)) {
        return `Array(${val.length})`;
      }
      if (isReflectList(val)) {
        return formatReflectList(val.field());
      }
      if (isReflectMap(val)) {
        return formatReflectMap(val.field());
      }
      if (isReflectMessage(val)) {
        return formatReflectMessage(val.desc);
      }
      if (isMessage(val)) {
        return `message ${val.$typeName}`;
      }
      return "object";
    case "string":
      return val.length > 30 ? "string" : `"${val.split('"').join("\\\"")}"`;
    case "boolean":
      return String(val);
    case "number":
      return String(val);
    case "bigint":
      return String(val) + "n";
    default:
      return typeof val;
  }
}
function formatReflectMessage(desc) {
  return `ReflectMessage (${desc.typeName})`;
}
function formatReflectList(field) {
  switch (field.listKind) {
    case "message":
      return `ReflectList (${field.message.toString()})`;
    case "enum":
      return `ReflectList (${field.enum.toString()})`;
    case "scalar":
      return `ReflectList (${ScalarType[field.scalar]})`;
  }
}
function formatReflectMap(field) {
  switch (field.mapKind) {
    case "message":
      return `ReflectMap (${ScalarType[field.mapKey]}, ${field.message.toString()})`;
    case "enum":
      return `ReflectMap (${ScalarType[field.mapKey]}, ${field.enum.toString()})`;
    case "scalar":
      return `ReflectMap (${ScalarType[field.mapKey]}, ${ScalarType[field.scalar]})`;
  }
}
function scalarTypeDescription(scalar) {
  switch (scalar) {
    case ScalarType.STRING:
      return "string";
    case ScalarType.BOOL:
      return "boolean";
    case ScalarType.INT64:
    case ScalarType.SINT64:
    case ScalarType.SFIXED64:
      return "bigint (int64)";
    case ScalarType.UINT64:
    case ScalarType.FIXED64:
      return "bigint (uint64)";
    case ScalarType.BYTES:
      return "Uint8Array";
    case ScalarType.DOUBLE:
      return "number (float64)";
    case ScalarType.FLOAT:
      return "number (float32)";
    case ScalarType.FIXED32:
    case ScalarType.UINT32:
      return "number (uint32)";
    case ScalarType.INT32:
    case ScalarType.SFIXED32:
    case ScalarType.SINT32:
      return "number (int32)";
  }
}
function reflect(messageDesc, message, check = true) {
  return new ReflectMessageImpl(messageDesc, message, check);
}

class ReflectMessageImpl {
  get sortedFields() {
    var _a;
    return (_a = this._sortedFields) !== null && _a !== undefined ? _a : this._sortedFields = this.desc.fields.concat().sort((a, b) => a.number - b.number);
  }
  constructor(messageDesc, message, check = true) {
    this.lists = new Map;
    this.maps = new Map;
    this.check = check;
    this.desc = messageDesc;
    this.message = this[unsafeLocal] = message !== null && message !== undefined ? message : create(messageDesc);
    this.fields = messageDesc.fields;
    this.oneofs = messageDesc.oneofs;
    this.members = messageDesc.members;
  }
  findNumber(number) {
    if (!this._fieldsByNumber) {
      this._fieldsByNumber = new Map(this.desc.fields.map((f) => [f.number, f]));
    }
    return this._fieldsByNumber.get(number);
  }
  oneofCase(oneof) {
    assertOwn(this.message, oneof);
    return unsafeOneofCase(this.message, oneof);
  }
  isSet(field) {
    assertOwn(this.message, field);
    return unsafeIsSet(this.message, field);
  }
  clear(field) {
    assertOwn(this.message, field);
    unsafeClear(this.message, field);
  }
  get(field) {
    assertOwn(this.message, field);
    const value = unsafeGet(this.message, field);
    switch (field.fieldKind) {
      case "list":
        let list = this.lists.get(field);
        if (!list || list[unsafeLocal] !== value) {
          this.lists.set(field, list = new ReflectListImpl(field, value, this.check));
        }
        return list;
      case "map":
        let map = this.maps.get(field);
        if (!map || map[unsafeLocal] !== value) {
          this.maps.set(field, map = new ReflectMapImpl(field, value, this.check));
        }
        return map;
      case "message":
        return messageToReflect(field, value, this.check);
      case "scalar":
        return value === undefined ? scalarZeroValue(field.scalar, false) : longToReflect(field, value);
      case "enum":
        return value !== null && value !== undefined ? value : field.enum.values[0].number;
    }
  }
  set(field, value) {
    assertOwn(this.message, field);
    if (this.check) {
      const err = checkField(field, value);
      if (err) {
        throw err;
      }
    }
    let local;
    if (field.fieldKind == "message") {
      local = messageToLocal(field, value);
    } else if (isReflectMap(value) || isReflectList(value)) {
      local = value[unsafeLocal];
    } else {
      local = longToLocal(field, value);
    }
    unsafeSet(this.message, field, local);
  }
  getUnknown() {
    return this.message.$unknown;
  }
  setUnknown(value) {
    this.message.$unknown = value;
  }
}
function assertOwn(owner, member) {
  if (member.parent.typeName !== owner.$typeName) {
    throw new FieldError(member, `cannot use ${member.toString()} with message ${owner.$typeName}`, "ForeignFieldError");
  }
}

class ReflectListImpl {
  field() {
    return this._field;
  }
  get size() {
    return this._arr.length;
  }
  constructor(field, unsafeInput, check) {
    this._field = field;
    this._arr = this[unsafeLocal] = unsafeInput;
    this.check = check;
  }
  get(index) {
    const item = this._arr[index];
    return item === undefined ? undefined : listItemToReflect(this._field, item, this.check);
  }
  set(index, item) {
    if (index < 0 || index >= this._arr.length) {
      throw new FieldError(this._field, `list item #${index + 1}: out of range`);
    }
    if (this.check) {
      const err = checkListItem(this._field, index, item);
      if (err) {
        throw err;
      }
    }
    this._arr[index] = listItemToLocal(this._field, item);
  }
  add(item) {
    if (this.check) {
      const err = checkListItem(this._field, this._arr.length, item);
      if (err) {
        throw err;
      }
    }
    this._arr.push(listItemToLocal(this._field, item));
    return;
  }
  clear() {
    this._arr.splice(0, this._arr.length);
  }
  [Symbol.iterator]() {
    return this.values();
  }
  keys() {
    return this._arr.keys();
  }
  *values() {
    for (const item of this._arr) {
      yield listItemToReflect(this._field, item, this.check);
    }
  }
  *entries() {
    for (let i = 0;i < this._arr.length; i++) {
      yield [i, listItemToReflect(this._field, this._arr[i], this.check)];
    }
  }
}

class ReflectMapImpl {
  constructor(field, unsafeInput, check = true) {
    this.obj = this[unsafeLocal] = unsafeInput !== null && unsafeInput !== undefined ? unsafeInput : {};
    this.check = check;
    this._field = field;
  }
  field() {
    return this._field;
  }
  set(key, value) {
    if (this.check) {
      const err = checkMapEntry(this._field, key, value);
      if (err) {
        throw err;
      }
    }
    this.obj[mapKeyToLocal(key)] = mapValueToLocal(this._field, value);
    return this;
  }
  delete(key) {
    const k = mapKeyToLocal(key);
    const has = Object.prototype.hasOwnProperty.call(this.obj, k);
    if (has) {
      delete this.obj[k];
    }
    return has;
  }
  clear() {
    for (const key of Object.keys(this.obj)) {
      delete this.obj[key];
    }
  }
  get(key) {
    let val = this.obj[mapKeyToLocal(key)];
    if (val !== undefined) {
      val = mapValueToReflect(this._field, val, this.check);
    }
    return val;
  }
  has(key) {
    return Object.prototype.hasOwnProperty.call(this.obj, mapKeyToLocal(key));
  }
  *keys() {
    for (const objKey of Object.keys(this.obj)) {
      yield mapKeyToReflect(objKey, this._field.mapKey);
    }
  }
  *entries() {
    for (const objEntry of Object.entries(this.obj)) {
      yield [
        mapKeyToReflect(objEntry[0], this._field.mapKey),
        mapValueToReflect(this._field, objEntry[1], this.check)
      ];
    }
  }
  [Symbol.iterator]() {
    return this.entries();
  }
  get size() {
    return Object.keys(this.obj).length;
  }
  *values() {
    for (const val of Object.values(this.obj)) {
      yield mapValueToReflect(this._field, val, this.check);
    }
  }
  forEach(callbackfn, thisArg) {
    for (const mapEntry of this.entries()) {
      callbackfn.call(thisArg, mapEntry[1], mapEntry[0], this);
    }
  }
}
function messageToLocal(field, value) {
  if (!isReflectMessage(value)) {
    return value;
  }
  if (isWrapper(value.message) && !field.oneof && field.fieldKind == "message") {
    return value.message.value;
  }
  if (value.desc.typeName == "google.protobuf.Struct" && field.parent.typeName != "google.protobuf.Value") {
    return wktStructToLocal(value.message);
  }
  return value.message;
}
function messageToReflect(field, value, check) {
  if (value !== undefined) {
    if (isWrapperDesc(field.message) && !field.oneof && field.fieldKind == "message") {
      value = {
        $typeName: field.message.typeName,
        value: longToReflect(field.message.fields[0], value)
      };
    } else if (field.message.typeName == "google.protobuf.Struct" && field.parent.typeName != "google.protobuf.Value" && isObject(value)) {
      value = wktStructToReflect(value);
    }
  }
  return new ReflectMessageImpl(field.message, value, check);
}
function listItemToLocal(field, value) {
  if (field.listKind == "message") {
    return messageToLocal(field, value);
  }
  return longToLocal(field, value);
}
function listItemToReflect(field, value, check) {
  if (field.listKind == "message") {
    return messageToReflect(field, value, check);
  }
  return longToReflect(field, value);
}
function mapValueToLocal(field, value) {
  if (field.mapKind == "message") {
    return messageToLocal(field, value);
  }
  return longToLocal(field, value);
}
function mapValueToReflect(field, value, check) {
  if (field.mapKind == "message") {
    return messageToReflect(field, value, check);
  }
  return value;
}
function mapKeyToLocal(key) {
  return typeof key == "string" || typeof key == "number" ? key : String(key);
}
function mapKeyToReflect(key, type) {
  switch (type) {
    case ScalarType.STRING:
      return key;
    case ScalarType.INT32:
    case ScalarType.FIXED32:
    case ScalarType.UINT32:
    case ScalarType.SFIXED32:
    case ScalarType.SINT32: {
      const n = Number.parseInt(key);
      if (Number.isFinite(n)) {
        return n;
      }
      break;
    }
    case ScalarType.BOOL:
      switch (key) {
        case "true":
          return true;
        case "false":
          return false;
      }
      break;
    case ScalarType.UINT64:
    case ScalarType.FIXED64:
      try {
        return protoInt64.uParse(key);
      } catch (_a) {}
      break;
    default:
      try {
        return protoInt64.parse(key);
      } catch (_b) {}
      break;
  }
  return key;
}
function longToReflect(field, value) {
  switch (field.scalar) {
    case ScalarType.INT64:
    case ScalarType.SFIXED64:
    case ScalarType.SINT64:
      if ("longAsString" in field && field.longAsString && typeof value == "string") {
        value = protoInt64.parse(value);
      }
      break;
    case ScalarType.FIXED64:
    case ScalarType.UINT64:
      if ("longAsString" in field && field.longAsString && typeof value == "string") {
        value = protoInt64.uParse(value);
      }
      break;
  }
  return value;
}
function longToLocal(field, value) {
  switch (field.scalar) {
    case ScalarType.INT64:
    case ScalarType.SFIXED64:
    case ScalarType.SINT64:
      if ("longAsString" in field && field.longAsString) {
        value = String(value);
      } else if (typeof value == "string" || typeof value == "number") {
        value = protoInt64.parse(value);
      }
      break;
    case ScalarType.FIXED64:
    case ScalarType.UINT64:
      if ("longAsString" in field && field.longAsString) {
        value = String(value);
      } else if (typeof value == "string" || typeof value == "number") {
        value = protoInt64.uParse(value);
      }
      break;
  }
  return value;
}
function wktStructToReflect(json) {
  const struct = {
    $typeName: "google.protobuf.Struct",
    fields: {}
  };
  if (isObject(json)) {
    for (const [k, v] of Object.entries(json)) {
      struct.fields[k] = wktValueToReflect(v);
    }
  }
  return struct;
}
function wktStructToLocal(val) {
  const json = {};
  for (const [k, v] of Object.entries(val.fields)) {
    json[k] = wktValueToLocal(v);
  }
  return json;
}
function wktValueToLocal(val) {
  switch (val.kind.case) {
    case "structValue":
      return wktStructToLocal(val.kind.value);
    case "listValue":
      return val.kind.value.values.map(wktValueToLocal);
    case "nullValue":
    case undefined:
      return null;
    default:
      return val.kind.value;
  }
}
function wktValueToReflect(json) {
  const value = {
    $typeName: "google.protobuf.Value",
    kind: { case: undefined }
  };
  switch (typeof json) {
    case "number":
      value.kind = { case: "numberValue", value: json };
      break;
    case "string":
      value.kind = { case: "stringValue", value: json };
      break;
    case "boolean":
      value.kind = { case: "boolValue", value: json };
      break;
    case "object":
      if (json === null) {
        const nullValue = 0;
        value.kind = { case: "nullValue", value: nullValue };
      } else if (Array.isArray(json)) {
        const listValue = {
          $typeName: "google.protobuf.ListValue",
          values: []
        };
        if (Array.isArray(json)) {
          for (const e of json) {
            listValue.values.push(wktValueToReflect(e));
          }
        }
        value.kind = {
          case: "listValue",
          value: listValue
        };
      } else {
        value.kind = {
          case: "structValue",
          value: wktStructToReflect(json)
        };
      }
      break;
  }
  return value;
}
function base64Decode(base64Str) {
  const table = getDecodeTable();
  let es = base64Str.length * 3 / 4;
  if (base64Str[base64Str.length - 2] == "=")
    es -= 2;
  else if (base64Str[base64Str.length - 1] == "=")
    es -= 1;
  let bytes = new Uint8Array(es), bytePos = 0, groupPos = 0, b, p = 0;
  for (let i = 0;i < base64Str.length; i++) {
    b = table[base64Str.charCodeAt(i)];
    if (b === undefined) {
      switch (base64Str[i]) {
        case "=":
          groupPos = 0;
        case `
`:
        case "\r":
        case "\t":
        case " ":
          continue;
        default:
          throw Error("invalid base64 string");
      }
    }
    switch (groupPos) {
      case 0:
        p = b;
        groupPos = 1;
        break;
      case 1:
        bytes[bytePos++] = p << 2 | (b & 48) >> 4;
        p = b;
        groupPos = 2;
        break;
      case 2:
        bytes[bytePos++] = (p & 15) << 4 | (b & 60) >> 2;
        p = b;
        groupPos = 3;
        break;
      case 3:
        bytes[bytePos++] = (p & 3) << 6 | b;
        groupPos = 0;
        break;
    }
  }
  if (groupPos == 1)
    throw Error("invalid base64 string");
  return bytes.subarray(0, bytePos);
}
var encodeTableStd;
var encodeTableUrl;
var decodeTable;
function getEncodeTable(encoding) {
  if (!encodeTableStd) {
    encodeTableStd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".split("");
    encodeTableUrl = encodeTableStd.slice(0, -2).concat("-", "_");
  }
  return encoding == "url" ? encodeTableUrl : encodeTableStd;
}
function getDecodeTable() {
  if (!decodeTable) {
    decodeTable = [];
    const encodeTable = getEncodeTable("std");
    for (let i = 0;i < encodeTable.length; i++)
      decodeTable[encodeTable[i].charCodeAt(0)] = i;
    decodeTable[45] = encodeTable.indexOf("+");
    decodeTable[95] = encodeTable.indexOf("/");
  }
  return decodeTable;
}
function protoCamelCase(snakeCase) {
  let capNext = false;
  const b = [];
  for (let i = 0;i < snakeCase.length; i++) {
    let c = snakeCase.charAt(i);
    switch (c) {
      case "_":
        capNext = true;
        break;
      case "0":
      case "1":
      case "2":
      case "3":
      case "4":
      case "5":
      case "6":
      case "7":
      case "8":
      case "9":
        b.push(c);
        capNext = false;
        break;
      default:
        if (capNext) {
          capNext = false;
          c = c.toUpperCase();
        }
        b.push(c);
        break;
    }
  }
  return b.join("");
}
var reservedObjectProperties = new Set([
  "constructor",
  "toString",
  "toJSON",
  "valueOf"
]);
function safeObjectProperty(name) {
  return reservedObjectProperties.has(name) ? name + "$" : name;
}
function restoreJsonNames(message) {
  for (const f of message.field) {
    if (!unsafeIsSetExplicit(f, "jsonName")) {
      f.jsonName = protoCamelCase(f.name);
    }
  }
  message.nestedType.forEach(restoreJsonNames);
}
function parseTextFormatEnumValue(descEnum, value) {
  const enumValue = descEnum.values.find((v) => v.name === value);
  if (!enumValue) {
    throw new Error(`cannot parse ${descEnum} default value: ${value}`);
  }
  return enumValue.number;
}
function parseTextFormatScalarValue(type, value) {
  switch (type) {
    case ScalarType.STRING:
      return value;
    case ScalarType.BYTES: {
      const u = unescapeBytesDefaultValue(value);
      if (u === false) {
        throw new Error(`cannot parse ${ScalarType[type]} default value: ${value}`);
      }
      return u;
    }
    case ScalarType.INT64:
    case ScalarType.SFIXED64:
    case ScalarType.SINT64:
      return protoInt64.parse(value);
    case ScalarType.UINT64:
    case ScalarType.FIXED64:
      return protoInt64.uParse(value);
    case ScalarType.DOUBLE:
    case ScalarType.FLOAT:
      switch (value) {
        case "inf":
          return Number.POSITIVE_INFINITY;
        case "-inf":
          return Number.NEGATIVE_INFINITY;
        case "nan":
          return Number.NaN;
        default:
          return parseFloat(value);
      }
    case ScalarType.BOOL:
      return value === "true";
    case ScalarType.INT32:
    case ScalarType.UINT32:
    case ScalarType.SINT32:
    case ScalarType.FIXED32:
    case ScalarType.SFIXED32:
      return parseInt(value, 10);
  }
}
function unescapeBytesDefaultValue(str) {
  const b = [];
  const input = {
    tail: str,
    c: "",
    next() {
      if (this.tail.length == 0) {
        return false;
      }
      this.c = this.tail[0];
      this.tail = this.tail.substring(1);
      return true;
    },
    take(n) {
      if (this.tail.length >= n) {
        const r = this.tail.substring(0, n);
        this.tail = this.tail.substring(n);
        return r;
      }
      return false;
    }
  };
  while (input.next()) {
    switch (input.c) {
      case "\\":
        if (input.next()) {
          switch (input.c) {
            case "\\":
              b.push(input.c.charCodeAt(0));
              break;
            case "b":
              b.push(8);
              break;
            case "f":
              b.push(12);
              break;
            case "n":
              b.push(10);
              break;
            case "r":
              b.push(13);
              break;
            case "t":
              b.push(9);
              break;
            case "v":
              b.push(11);
              break;
            case "0":
            case "1":
            case "2":
            case "3":
            case "4":
            case "5":
            case "6":
            case "7": {
              const s = input.c;
              const t = input.take(2);
              if (t === false) {
                return false;
              }
              const n = parseInt(s + t, 8);
              if (Number.isNaN(n)) {
                return false;
              }
              b.push(n);
              break;
            }
            case "x": {
              const s = input.c;
              const t = input.take(2);
              if (t === false) {
                return false;
              }
              const n = parseInt(s + t, 16);
              if (Number.isNaN(n)) {
                return false;
              }
              b.push(n);
              break;
            }
            case "u": {
              const s = input.c;
              const t = input.take(4);
              if (t === false) {
                return false;
              }
              const n = parseInt(s + t, 16);
              if (Number.isNaN(n)) {
                return false;
              }
              const chunk = new Uint8Array(4);
              const view = new DataView(chunk.buffer);
              view.setInt32(0, n, true);
              b.push(chunk[0], chunk[1], chunk[2], chunk[3]);
              break;
            }
            case "U": {
              const s = input.c;
              const t = input.take(8);
              if (t === false) {
                return false;
              }
              const tc = protoInt64.uEnc(s + t);
              const chunk = new Uint8Array(8);
              const view = new DataView(chunk.buffer);
              view.setInt32(0, tc.lo, true);
              view.setInt32(4, tc.hi, true);
              b.push(chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7]);
              break;
            }
          }
        }
        break;
      default:
        b.push(input.c.charCodeAt(0));
    }
  }
  return new Uint8Array(b);
}
function* nestedTypes(desc) {
  switch (desc.kind) {
    case "file":
      for (const message of desc.messages) {
        yield message;
        yield* nestedTypes(message);
      }
      yield* desc.enums;
      yield* desc.services;
      yield* desc.extensions;
      break;
    case "message":
      for (const message of desc.nestedMessages) {
        yield message;
        yield* nestedTypes(message);
      }
      yield* desc.nestedEnums;
      yield* desc.nestedExtensions;
      break;
  }
}
function createFileRegistry(...args) {
  const registry = createBaseRegistry();
  if (!args.length) {
    return registry;
  }
  if ("$typeName" in args[0] && args[0].$typeName == "google.protobuf.FileDescriptorSet") {
    for (const file of args[0].file) {
      addFile(file, registry);
    }
    return registry;
  }
  if ("$typeName" in args[0]) {
    let recurseDeps = function(file) {
      const deps = [];
      for (const protoFileName of file.dependency) {
        if (registry.getFile(protoFileName) != null) {
          continue;
        }
        if (seen.has(protoFileName)) {
          continue;
        }
        const dep = resolve(protoFileName);
        if (!dep) {
          throw new Error(`Unable to resolve ${protoFileName}, imported by ${file.name}`);
        }
        if ("kind" in dep) {
          registry.addFile(dep, false, true);
        } else {
          seen.add(dep.name);
          deps.push(dep);
        }
      }
      return deps.concat(...deps.map(recurseDeps));
    };
    const input = args[0];
    const resolve = args[1];
    const seen = new Set;
    for (const file of [input, ...recurseDeps(input)].reverse()) {
      addFile(file, registry);
    }
  } else {
    for (const fileReg of args) {
      for (const file of fileReg.files) {
        registry.addFile(file);
      }
    }
  }
  return registry;
}
function createBaseRegistry() {
  const types = new Map;
  const extendees = new Map;
  const files = new Map;
  return {
    kind: "registry",
    types,
    extendees,
    [Symbol.iterator]() {
      return types.values();
    },
    get files() {
      return files.values();
    },
    addFile(file, skipTypes, withDeps) {
      files.set(file.proto.name, file);
      if (!skipTypes) {
        for (const type of nestedTypes(file)) {
          this.add(type);
        }
      }
      if (withDeps) {
        for (const f of file.dependencies) {
          this.addFile(f, skipTypes, withDeps);
        }
      }
    },
    add(desc) {
      if (desc.kind == "extension") {
        let numberToExt = extendees.get(desc.extendee.typeName);
        if (!numberToExt) {
          extendees.set(desc.extendee.typeName, numberToExt = new Map);
        }
        numberToExt.set(desc.number, desc);
      }
      types.set(desc.typeName, desc);
    },
    get(typeName) {
      return types.get(typeName);
    },
    getFile(fileName) {
      return files.get(fileName);
    },
    getMessage(typeName) {
      const t = types.get(typeName);
      return (t === null || t === undefined ? undefined : t.kind) == "message" ? t : undefined;
    },
    getEnum(typeName) {
      const t = types.get(typeName);
      return (t === null || t === undefined ? undefined : t.kind) == "enum" ? t : undefined;
    },
    getExtension(typeName) {
      const t = types.get(typeName);
      return (t === null || t === undefined ? undefined : t.kind) == "extension" ? t : undefined;
    },
    getExtensionFor(extendee, no) {
      var _a;
      return (_a = extendees.get(extendee.typeName)) === null || _a === undefined ? undefined : _a.get(no);
    },
    getService(typeName) {
      const t = types.get(typeName);
      return (t === null || t === undefined ? undefined : t.kind) == "service" ? t : undefined;
    }
  };
}
var EDITION_PROTO22 = 998;
var EDITION_PROTO32 = 999;
var TYPE_STRING = 9;
var TYPE_GROUP = 10;
var TYPE_MESSAGE = 11;
var TYPE_BYTES = 12;
var TYPE_ENUM = 14;
var LABEL_REPEATED = 3;
var LABEL_REQUIRED = 2;
var JS_STRING = 1;
var IDEMPOTENCY_UNKNOWN = 0;
var EXPLICIT = 1;
var IMPLICIT3 = 2;
var LEGACY_REQUIRED = 3;
var PACKED = 1;
var DELIMITED = 2;
var OPEN = 1;
var featureDefaults = {
  998: {
    fieldPresence: 1,
    enumType: 2,
    repeatedFieldEncoding: 2,
    utf8Validation: 3,
    messageEncoding: 1,
    jsonFormat: 2,
    enforceNamingStyle: 2,
    defaultSymbolVisibility: 1
  },
  999: {
    fieldPresence: 2,
    enumType: 1,
    repeatedFieldEncoding: 1,
    utf8Validation: 2,
    messageEncoding: 1,
    jsonFormat: 1,
    enforceNamingStyle: 2,
    defaultSymbolVisibility: 1
  },
  1000: {
    fieldPresence: 1,
    enumType: 1,
    repeatedFieldEncoding: 1,
    utf8Validation: 2,
    messageEncoding: 1,
    jsonFormat: 1,
    enforceNamingStyle: 2,
    defaultSymbolVisibility: 1
  }
};
function addFile(proto, reg) {
  var _a, _b;
  const file = {
    kind: "file",
    proto,
    deprecated: (_b = (_a = proto.options) === null || _a === undefined ? undefined : _a.deprecated) !== null && _b !== undefined ? _b : false,
    edition: getFileEdition(proto),
    name: proto.name.replace(/\.proto$/, ""),
    dependencies: findFileDependencies(proto, reg),
    enums: [],
    messages: [],
    extensions: [],
    services: [],
    toString() {
      return `file ${proto.name}`;
    }
  };
  const mapEntriesStore = new Map;
  const mapEntries = {
    get(typeName) {
      return mapEntriesStore.get(typeName);
    },
    add(desc) {
      var _a;
      assert(((_a = desc.proto.options) === null || _a === undefined ? undefined : _a.mapEntry) === true);
      mapEntriesStore.set(desc.typeName, desc);
    }
  };
  for (const enumProto of proto.enumType) {
    addEnum(enumProto, file, undefined, reg);
  }
  for (const messageProto of proto.messageType) {
    addMessage(messageProto, file, undefined, reg, mapEntries);
  }
  for (const serviceProto of proto.service) {
    addService(serviceProto, file, reg);
  }
  addExtensions(file, reg);
  for (const mapEntry of mapEntriesStore.values()) {
    addFields(mapEntry, reg, mapEntries);
  }
  for (const message of file.messages) {
    addFields(message, reg, mapEntries);
    addExtensions(message, reg);
  }
  reg.addFile(file, true);
}
function addExtensions(desc, reg) {
  switch (desc.kind) {
    case "file":
      for (const proto of desc.proto.extension) {
        const ext = newField(proto, desc, reg);
        desc.extensions.push(ext);
        reg.add(ext);
      }
      break;
    case "message":
      for (const proto of desc.proto.extension) {
        const ext = newField(proto, desc, reg);
        desc.nestedExtensions.push(ext);
        reg.add(ext);
      }
      for (const message of desc.nestedMessages) {
        addExtensions(message, reg);
      }
      break;
  }
}
function addFields(message, reg, mapEntries) {
  const allOneofs = message.proto.oneofDecl.map((proto) => newOneof(proto, message));
  const oneofsSeen = new Set;
  for (const proto of message.proto.field) {
    const oneof = findOneof(proto, allOneofs);
    const field = newField(proto, message, reg, oneof, mapEntries);
    message.fields.push(field);
    message.field[field.localName] = field;
    if (oneof === undefined) {
      message.members.push(field);
    } else {
      oneof.fields.push(field);
      if (!oneofsSeen.has(oneof)) {
        oneofsSeen.add(oneof);
        message.members.push(oneof);
      }
    }
  }
  for (const oneof of allOneofs.filter((o) => oneofsSeen.has(o))) {
    message.oneofs.push(oneof);
  }
  for (const child of message.nestedMessages) {
    addFields(child, reg, mapEntries);
  }
}
function addEnum(proto, file, parent, reg) {
  var _a, _b, _c, _d, _e;
  const sharedPrefix = findEnumSharedPrefix(proto.name, proto.value);
  const desc = {
    kind: "enum",
    proto,
    deprecated: (_b = (_a = proto.options) === null || _a === undefined ? undefined : _a.deprecated) !== null && _b !== undefined ? _b : false,
    file,
    parent,
    open: true,
    name: proto.name,
    typeName: makeTypeName(proto, parent, file),
    value: {},
    values: [],
    sharedPrefix,
    toString() {
      return `enum ${this.typeName}`;
    }
  };
  desc.open = isEnumOpen(desc);
  reg.add(desc);
  for (const p of proto.value) {
    const name = p.name;
    desc.values.push(desc.value[p.number] = {
      kind: "enum_value",
      proto: p,
      deprecated: (_d = (_c = p.options) === null || _c === undefined ? undefined : _c.deprecated) !== null && _d !== undefined ? _d : false,
      parent: desc,
      name,
      localName: safeObjectProperty(sharedPrefix == undefined ? name : name.substring(sharedPrefix.length)),
      number: p.number,
      toString() {
        return `enum value ${desc.typeName}.${name}`;
      }
    });
  }
  ((_e = parent === null || parent === undefined ? undefined : parent.nestedEnums) !== null && _e !== undefined ? _e : file.enums).push(desc);
}
function addMessage(proto, file, parent, reg, mapEntries) {
  var _a, _b, _c, _d;
  const desc = {
    kind: "message",
    proto,
    deprecated: (_b = (_a = proto.options) === null || _a === undefined ? undefined : _a.deprecated) !== null && _b !== undefined ? _b : false,
    file,
    parent,
    name: proto.name,
    typeName: makeTypeName(proto, parent, file),
    fields: [],
    field: {},
    oneofs: [],
    members: [],
    nestedEnums: [],
    nestedMessages: [],
    nestedExtensions: [],
    toString() {
      return `message ${this.typeName}`;
    }
  };
  if (((_c = proto.options) === null || _c === undefined ? undefined : _c.mapEntry) === true) {
    mapEntries.add(desc);
  } else {
    ((_d = parent === null || parent === undefined ? undefined : parent.nestedMessages) !== null && _d !== undefined ? _d : file.messages).push(desc);
    reg.add(desc);
  }
  for (const enumProto of proto.enumType) {
    addEnum(enumProto, file, desc, reg);
  }
  for (const messageProto of proto.nestedType) {
    addMessage(messageProto, file, desc, reg, mapEntries);
  }
}
function addService(proto, file, reg) {
  var _a, _b;
  const desc = {
    kind: "service",
    proto,
    deprecated: (_b = (_a = proto.options) === null || _a === undefined ? undefined : _a.deprecated) !== null && _b !== undefined ? _b : false,
    file,
    name: proto.name,
    typeName: makeTypeName(proto, undefined, file),
    methods: [],
    method: {},
    toString() {
      return `service ${this.typeName}`;
    }
  };
  file.services.push(desc);
  reg.add(desc);
  for (const methodProto of proto.method) {
    const method = newMethod(methodProto, desc, reg);
    desc.methods.push(method);
    desc.method[method.localName] = method;
  }
}
function newMethod(proto, parent, reg) {
  var _a, _b, _c, _d;
  let methodKind;
  if (proto.clientStreaming && proto.serverStreaming) {
    methodKind = "bidi_streaming";
  } else if (proto.clientStreaming) {
    methodKind = "client_streaming";
  } else if (proto.serverStreaming) {
    methodKind = "server_streaming";
  } else {
    methodKind = "unary";
  }
  const input = reg.getMessage(trimLeadingDot(proto.inputType));
  const output = reg.getMessage(trimLeadingDot(proto.outputType));
  assert(input, `invalid MethodDescriptorProto: input_type ${proto.inputType} not found`);
  assert(output, `invalid MethodDescriptorProto: output_type ${proto.inputType} not found`);
  const name = proto.name;
  return {
    kind: "rpc",
    proto,
    deprecated: (_b = (_a = proto.options) === null || _a === undefined ? undefined : _a.deprecated) !== null && _b !== undefined ? _b : false,
    parent,
    name,
    localName: safeObjectProperty(name.length ? safeObjectProperty(name[0].toLowerCase() + name.substring(1)) : name),
    methodKind,
    input,
    output,
    idempotency: (_d = (_c = proto.options) === null || _c === undefined ? undefined : _c.idempotencyLevel) !== null && _d !== undefined ? _d : IDEMPOTENCY_UNKNOWN,
    toString() {
      return `rpc ${parent.typeName}.${name}`;
    }
  };
}
function newOneof(proto, parent) {
  return {
    kind: "oneof",
    proto,
    deprecated: false,
    parent,
    fields: [],
    name: proto.name,
    localName: safeObjectProperty(protoCamelCase(proto.name)),
    toString() {
      return `oneof ${parent.typeName}.${this.name}`;
    }
  };
}
function newField(proto, parentOrFile, reg, oneof, mapEntries) {
  var _a, _b, _c;
  const isExtension = mapEntries === undefined;
  const field = {
    kind: "field",
    proto,
    deprecated: (_b = (_a = proto.options) === null || _a === undefined ? undefined : _a.deprecated) !== null && _b !== undefined ? _b : false,
    name: proto.name,
    number: proto.number,
    scalar: undefined,
    message: undefined,
    enum: undefined,
    presence: getFieldPresence(proto, oneof, isExtension, parentOrFile),
    listKind: undefined,
    mapKind: undefined,
    mapKey: undefined,
    delimitedEncoding: undefined,
    packed: undefined,
    longAsString: false,
    getDefaultValue: undefined
  };
  if (isExtension) {
    const file = parentOrFile.kind == "file" ? parentOrFile : parentOrFile.file;
    const parent = parentOrFile.kind == "file" ? undefined : parentOrFile;
    const typeName = makeTypeName(proto, parent, file);
    field.kind = "extension";
    field.file = file;
    field.parent = parent;
    field.oneof = undefined;
    field.typeName = typeName;
    field.jsonName = `[${typeName}]`;
    field.toString = () => `extension ${typeName}`;
    const extendee = reg.getMessage(trimLeadingDot(proto.extendee));
    assert(extendee, `invalid FieldDescriptorProto: extendee ${proto.extendee} not found`);
    field.extendee = extendee;
  } else {
    const parent = parentOrFile;
    assert(parent.kind == "message");
    field.parent = parent;
    field.oneof = oneof;
    field.localName = oneof ? protoCamelCase(proto.name) : safeObjectProperty(protoCamelCase(proto.name));
    field.jsonName = proto.jsonName;
    field.toString = () => `field ${parent.typeName}.${proto.name}`;
  }
  const label = proto.label;
  const type = proto.type;
  const jstype = (_c = proto.options) === null || _c === undefined ? undefined : _c.jstype;
  if (label === LABEL_REPEATED) {
    const mapEntry = type == TYPE_MESSAGE ? mapEntries === null || mapEntries === undefined ? undefined : mapEntries.get(trimLeadingDot(proto.typeName)) : undefined;
    if (mapEntry) {
      field.fieldKind = "map";
      const { key, value } = findMapEntryFields(mapEntry);
      field.mapKey = key.scalar;
      field.mapKind = value.fieldKind;
      field.message = value.message;
      field.delimitedEncoding = false;
      field.enum = value.enum;
      field.scalar = value.scalar;
      return field;
    }
    field.fieldKind = "list";
    switch (type) {
      case TYPE_MESSAGE:
      case TYPE_GROUP:
        field.listKind = "message";
        field.message = reg.getMessage(trimLeadingDot(proto.typeName));
        assert(field.message);
        field.delimitedEncoding = isDelimitedEncoding(proto, parentOrFile);
        break;
      case TYPE_ENUM:
        field.listKind = "enum";
        field.enum = reg.getEnum(trimLeadingDot(proto.typeName));
        assert(field.enum);
        break;
      default:
        field.listKind = "scalar";
        field.scalar = type;
        field.longAsString = jstype == JS_STRING;
        break;
    }
    field.packed = isPackedField(proto, parentOrFile);
    return field;
  }
  switch (type) {
    case TYPE_MESSAGE:
    case TYPE_GROUP:
      field.fieldKind = "message";
      field.message = reg.getMessage(trimLeadingDot(proto.typeName));
      assert(field.message, `invalid FieldDescriptorProto: type_name ${proto.typeName} not found`);
      field.delimitedEncoding = isDelimitedEncoding(proto, parentOrFile);
      field.getDefaultValue = () => {
        return;
      };
      break;
    case TYPE_ENUM: {
      const enumeration = reg.getEnum(trimLeadingDot(proto.typeName));
      assert(enumeration !== undefined, `invalid FieldDescriptorProto: type_name ${proto.typeName} not found`);
      field.fieldKind = "enum";
      field.enum = reg.getEnum(trimLeadingDot(proto.typeName));
      field.getDefaultValue = () => {
        return unsafeIsSetExplicit(proto, "defaultValue") ? parseTextFormatEnumValue(enumeration, proto.defaultValue) : undefined;
      };
      break;
    }
    default: {
      field.fieldKind = "scalar";
      field.scalar = type;
      field.longAsString = jstype == JS_STRING;
      field.getDefaultValue = () => {
        return unsafeIsSetExplicit(proto, "defaultValue") ? parseTextFormatScalarValue(type, proto.defaultValue) : undefined;
      };
      break;
    }
  }
  return field;
}
function getFileEdition(proto) {
  switch (proto.syntax) {
    case "":
    case "proto2":
      return EDITION_PROTO22;
    case "proto3":
      return EDITION_PROTO32;
    case "editions":
      if (proto.edition in featureDefaults) {
        return proto.edition;
      }
      throw new Error(`${proto.name}: unsupported edition`);
    default:
      throw new Error(`${proto.name}: unsupported syntax "${proto.syntax}"`);
  }
}
function findFileDependencies(proto, reg) {
  return proto.dependency.map((wantName) => {
    const dep = reg.getFile(wantName);
    if (!dep) {
      throw new Error(`Cannot find ${wantName}, imported by ${proto.name}`);
    }
    return dep;
  });
}
function findEnumSharedPrefix(enumName, values) {
  const prefix = camelToSnakeCase(enumName) + "_";
  for (const value of values) {
    if (!value.name.toLowerCase().startsWith(prefix)) {
      return;
    }
    const shortName = value.name.substring(prefix.length);
    if (shortName.length == 0) {
      return;
    }
    if (/^\d/.test(shortName)) {
      return;
    }
  }
  return prefix;
}
function camelToSnakeCase(camel) {
  return (camel.substring(0, 1) + camel.substring(1).replace(/[A-Z]/g, (c) => "_" + c)).toLowerCase();
}
function makeTypeName(proto, parent, file) {
  let typeName;
  if (parent) {
    typeName = `${parent.typeName}.${proto.name}`;
  } else if (file.proto.package.length > 0) {
    typeName = `${file.proto.package}.${proto.name}`;
  } else {
    typeName = `${proto.name}`;
  }
  return typeName;
}
function trimLeadingDot(typeName) {
  return typeName.startsWith(".") ? typeName.substring(1) : typeName;
}
function findOneof(proto, allOneofs) {
  if (!unsafeIsSetExplicit(proto, "oneofIndex")) {
    return;
  }
  if (proto.proto3Optional) {
    return;
  }
  const oneof = allOneofs[proto.oneofIndex];
  assert(oneof, `invalid FieldDescriptorProto: oneof #${proto.oneofIndex} for field #${proto.number} not found`);
  return oneof;
}
function getFieldPresence(proto, oneof, isExtension, parent) {
  if (proto.label == LABEL_REQUIRED) {
    return LEGACY_REQUIRED;
  }
  if (proto.label == LABEL_REPEATED) {
    return IMPLICIT3;
  }
  if (!!oneof || proto.proto3Optional) {
    return EXPLICIT;
  }
  if (isExtension) {
    return EXPLICIT;
  }
  const resolved = resolveFeature("fieldPresence", { proto, parent });
  if (resolved == IMPLICIT3 && (proto.type == TYPE_MESSAGE || proto.type == TYPE_GROUP)) {
    return EXPLICIT;
  }
  return resolved;
}
function isPackedField(proto, parent) {
  if (proto.label != LABEL_REPEATED) {
    return false;
  }
  switch (proto.type) {
    case TYPE_STRING:
    case TYPE_BYTES:
    case TYPE_GROUP:
    case TYPE_MESSAGE:
      return false;
  }
  const o = proto.options;
  if (o && unsafeIsSetExplicit(o, "packed")) {
    return o.packed;
  }
  return PACKED == resolveFeature("repeatedFieldEncoding", {
    proto,
    parent
  });
}
function findMapEntryFields(mapEntry) {
  const key = mapEntry.fields.find((f) => f.number === 1);
  const value = mapEntry.fields.find((f) => f.number === 2);
  assert(key && key.fieldKind == "scalar" && key.scalar != ScalarType.BYTES && key.scalar != ScalarType.FLOAT && key.scalar != ScalarType.DOUBLE && value && value.fieldKind != "list" && value.fieldKind != "map");
  return { key, value };
}
function isEnumOpen(desc) {
  var _a;
  return OPEN == resolveFeature("enumType", {
    proto: desc.proto,
    parent: (_a = desc.parent) !== null && _a !== undefined ? _a : desc.file
  });
}
function isDelimitedEncoding(proto, parent) {
  if (proto.type == TYPE_GROUP) {
    return true;
  }
  return DELIMITED == resolveFeature("messageEncoding", {
    proto,
    parent
  });
}
function resolveFeature(name, ref) {
  var _a, _b;
  const featureSet = (_a = ref.proto.options) === null || _a === undefined ? undefined : _a.features;
  if (featureSet) {
    const val = featureSet[name];
    if (val != 0) {
      return val;
    }
  }
  if ("kind" in ref) {
    if (ref.kind == "message") {
      return resolveFeature(name, (_b = ref.parent) !== null && _b !== undefined ? _b : ref.file);
    }
    const editionDefaults = featureDefaults[ref.edition];
    if (!editionDefaults) {
      throw new Error(`feature default for edition ${ref.edition} not found`);
    }
    return editionDefaults[name];
  }
  return resolveFeature(name, ref.parent);
}
function assert(condition, msg) {
  if (!condition) {
    throw new Error(msg);
  }
}
function boot(boot) {
  const root = bootFileDescriptorProto(boot);
  root.messageType.forEach(restoreJsonNames);
  const reg = createFileRegistry(root, () => {
    return;
  });
  return reg.getFile(root.name);
}
function bootFileDescriptorProto(init) {
  const proto = Object.create({
    syntax: "",
    edition: 0
  });
  return Object.assign(proto, Object.assign(Object.assign({ $typeName: "google.protobuf.FileDescriptorProto", dependency: [], publicDependency: [], weakDependency: [], optionDependency: [], service: [], extension: [] }, init), { messageType: init.messageType.map(bootDescriptorProto), enumType: init.enumType.map(bootEnumDescriptorProto) }));
}
function bootDescriptorProto(init) {
  var _a, _b, _c, _d, _e, _f, _g, _h;
  const proto = Object.create({
    visibility: 0
  });
  return Object.assign(proto, {
    $typeName: "google.protobuf.DescriptorProto",
    name: init.name,
    field: (_b = (_a = init.field) === null || _a === undefined ? undefined : _a.map(bootFieldDescriptorProto)) !== null && _b !== undefined ? _b : [],
    extension: [],
    nestedType: (_d = (_c = init.nestedType) === null || _c === undefined ? undefined : _c.map(bootDescriptorProto)) !== null && _d !== undefined ? _d : [],
    enumType: (_f = (_e = init.enumType) === null || _e === undefined ? undefined : _e.map(bootEnumDescriptorProto)) !== null && _f !== undefined ? _f : [],
    extensionRange: (_h = (_g = init.extensionRange) === null || _g === undefined ? undefined : _g.map((e) => Object.assign({ $typeName: "google.protobuf.DescriptorProto.ExtensionRange" }, e))) !== null && _h !== undefined ? _h : [],
    oneofDecl: [],
    reservedRange: [],
    reservedName: []
  });
}
function bootFieldDescriptorProto(init) {
  const proto = Object.create({
    label: 1,
    typeName: "",
    extendee: "",
    defaultValue: "",
    oneofIndex: 0,
    jsonName: "",
    proto3Optional: false
  });
  return Object.assign(proto, Object.assign(Object.assign({ $typeName: "google.protobuf.FieldDescriptorProto" }, init), { options: init.options ? bootFieldOptions(init.options) : undefined }));
}
function bootFieldOptions(init) {
  var _a, _b, _c;
  const proto = Object.create({
    ctype: 0,
    packed: false,
    jstype: 0,
    lazy: false,
    unverifiedLazy: false,
    deprecated: false,
    weak: false,
    debugRedact: false,
    retention: 0
  });
  return Object.assign(proto, Object.assign(Object.assign({ $typeName: "google.protobuf.FieldOptions" }, init), { targets: (_a = init.targets) !== null && _a !== undefined ? _a : [], editionDefaults: (_c = (_b = init.editionDefaults) === null || _b === undefined ? undefined : _b.map((e) => Object.assign({ $typeName: "google.protobuf.FieldOptions.EditionDefault" }, e))) !== null && _c !== undefined ? _c : [], uninterpretedOption: [] }));
}
function bootEnumDescriptorProto(init) {
  const proto = Object.create({
    visibility: 0
  });
  return Object.assign(proto, {
    $typeName: "google.protobuf.EnumDescriptorProto",
    name: init.name,
    reservedName: [],
    reservedRange: [],
    value: init.value.map((e) => Object.assign({ $typeName: "google.protobuf.EnumValueDescriptorProto" }, e))
  });
}
function messageDesc(file, path, ...paths) {
  return paths.reduce((acc, cur) => acc.nestedMessages[cur], file.messages[path]);
}
var file_google_protobuf_descriptor = /* @__PURE__ */ boot({ name: "google/protobuf/descriptor.proto", package: "google.protobuf", messageType: [{ name: "FileDescriptorSet", field: [{ name: "file", number: 1, type: 11, label: 3, typeName: ".google.protobuf.FileDescriptorProto" }], extensionRange: [{ start: 536000000, end: 536000001 }] }, { name: "FileDescriptorProto", field: [{ name: "name", number: 1, type: 9, label: 1 }, { name: "package", number: 2, type: 9, label: 1 }, { name: "dependency", number: 3, type: 9, label: 3 }, { name: "public_dependency", number: 10, type: 5, label: 3 }, { name: "weak_dependency", number: 11, type: 5, label: 3 }, { name: "option_dependency", number: 15, type: 9, label: 3 }, { name: "message_type", number: 4, type: 11, label: 3, typeName: ".google.protobuf.DescriptorProto" }, { name: "enum_type", number: 5, type: 11, label: 3, typeName: ".google.protobuf.EnumDescriptorProto" }, { name: "service", number: 6, type: 11, label: 3, typeName: ".google.protobuf.ServiceDescriptorProto" }, { name: "extension", number: 7, type: 11, label: 3, typeName: ".google.protobuf.FieldDescriptorProto" }, { name: "options", number: 8, type: 11, label: 1, typeName: ".google.protobuf.FileOptions" }, { name: "source_code_info", number: 9, type: 11, label: 1, typeName: ".google.protobuf.SourceCodeInfo" }, { name: "syntax", number: 12, type: 9, label: 1 }, { name: "edition", number: 14, type: 14, label: 1, typeName: ".google.protobuf.Edition" }] }, { name: "DescriptorProto", field: [{ name: "name", number: 1, type: 9, label: 1 }, { name: "field", number: 2, type: 11, label: 3, typeName: ".google.protobuf.FieldDescriptorProto" }, { name: "extension", number: 6, type: 11, label: 3, typeName: ".google.protobuf.FieldDescriptorProto" }, { name: "nested_type", number: 3, type: 11, label: 3, typeName: ".google.protobuf.DescriptorProto" }, { name: "enum_type", number: 4, type: 11, label: 3, typeName: ".google.protobuf.EnumDescriptorProto" }, { name: "extension_range", number: 5, type: 11, label: 3, typeName: ".google.protobuf.DescriptorProto.ExtensionRange" }, { name: "oneof_decl", number: 8, type: 11, label: 3, typeName: ".google.protobuf.OneofDescriptorProto" }, { name: "options", number: 7, type: 11, label: 1, typeName: ".google.protobuf.MessageOptions" }, { name: "reserved_range", number: 9, type: 11, label: 3, typeName: ".google.protobuf.DescriptorProto.ReservedRange" }, { name: "reserved_name", number: 10, type: 9, label: 3 }, { name: "visibility", number: 11, type: 14, label: 1, typeName: ".google.protobuf.SymbolVisibility" }], nestedType: [{ name: "ExtensionRange", field: [{ name: "start", number: 1, type: 5, label: 1 }, { name: "end", number: 2, type: 5, label: 1 }, { name: "options", number: 3, type: 11, label: 1, typeName: ".google.protobuf.ExtensionRangeOptions" }] }, { name: "ReservedRange", field: [{ name: "start", number: 1, type: 5, label: 1 }, { name: "end", number: 2, type: 5, label: 1 }] }] }, { name: "ExtensionRangeOptions", field: [{ name: "uninterpreted_option", number: 999, type: 11, label: 3, typeName: ".google.protobuf.UninterpretedOption" }, { name: "declaration", number: 2, type: 11, label: 3, typeName: ".google.protobuf.ExtensionRangeOptions.Declaration", options: { retention: 2 } }, { name: "features", number: 50, type: 11, label: 1, typeName: ".google.protobuf.FeatureSet" }, { name: "verification", number: 3, type: 14, label: 1, typeName: ".google.protobuf.ExtensionRangeOptions.VerificationState", defaultValue: "UNVERIFIED", options: { retention: 2 } }], nestedType: [{ name: "Declaration", field: [{ name: "number", number: 1, type: 5, label: 1 }, { name: "full_name", number: 2, type: 9, label: 1 }, { name: "type", number: 3, type: 9, label: 1 }, { name: "reserved", number: 5, type: 8, label: 1 }, { name: "repeated", number: 6, type: 8, label: 1 }] }], enumType: [{ name: "VerificationState", value: [{ name: "DECLARATION", number: 0 }, { name: "UNVERIFIED", number: 1 }] }], extensionRange: [{ start: 1000, end: 536870912 }] }, { name: "FieldDescriptorProto", field: [{ name: "name", number: 1, type: 9, label: 1 }, { name: "number", number: 3, type: 5, label: 1 }, { name: "label", number: 4, type: 14, label: 1, typeName: ".google.protobuf.FieldDescriptorProto.Label" }, { name: "type", number: 5, type: 14, label: 1, typeName: ".google.protobuf.FieldDescriptorProto.Type" }, { name: "type_name", number: 6, type: 9, label: 1 }, { name: "extendee", number: 2, type: 9, label: 1 }, { name: "default_value", number: 7, type: 9, label: 1 }, { name: "oneof_index", number: 9, type: 5, label: 1 }, { name: "json_name", number: 10, type: 9, label: 1 }, { name: "options", number: 8, type: 11, label: 1, typeName: ".google.protobuf.FieldOptions" }, { name: "proto3_optional", number: 17, type: 8, label: 1 }], enumType: [{ name: "Type", value: [{ name: "TYPE_DOUBLE", number: 1 }, { name: "TYPE_FLOAT", number: 2 }, { name: "TYPE_INT64", number: 3 }, { name: "TYPE_UINT64", number: 4 }, { name: "TYPE_INT32", number: 5 }, { name: "TYPE_FIXED64", number: 6 }, { name: "TYPE_FIXED32", number: 7 }, { name: "TYPE_BOOL", number: 8 }, { name: "TYPE_STRING", number: 9 }, { name: "TYPE_GROUP", number: 10 }, { name: "TYPE_MESSAGE", number: 11 }, { name: "TYPE_BYTES", number: 12 }, { name: "TYPE_UINT32", number: 13 }, { name: "TYPE_ENUM", number: 14 }, { name: "TYPE_SFIXED32", number: 15 }, { name: "TYPE_SFIXED64", number: 16 }, { name: "TYPE_SINT32", number: 17 }, { name: "TYPE_SINT64", number: 18 }] }, { name: "Label", value: [{ name: "LABEL_OPTIONAL", number: 1 }, { name: "LABEL_REPEATED", number: 3 }, { name: "LABEL_REQUIRED", number: 2 }] }] }, { name: "OneofDescriptorProto", field: [{ name: "name", number: 1, type: 9, label: 1 }, { name: "options", number: 2, type: 11, label: 1, typeName: ".google.protobuf.OneofOptions" }] }, { name: "EnumDescriptorProto", field: [{ name: "name", number: 1, type: 9, label: 1 }, { name: "value", number: 2, type: 11, label: 3, typeName: ".google.protobuf.EnumValueDescriptorProto" }, { name: "options", number: 3, type: 11, label: 1, typeName: ".google.protobuf.EnumOptions" }, { name: "reserved_range", number: 4, type: 11, label: 3, typeName: ".google.protobuf.EnumDescriptorProto.EnumReservedRange" }, { name: "reserved_name", number: 5, type: 9, label: 3 }, { name: "visibility", number: 6, type: 14, label: 1, typeName: ".google.protobuf.SymbolVisibility" }], nestedType: [{ name: "EnumReservedRange", field: [{ name: "start", number: 1, type: 5, label: 1 }, { name: "end", number: 2, type: 5, label: 1 }] }] }, { name: "EnumValueDescriptorProto", field: [{ name: "name", number: 1, type: 9, label: 1 }, { name: "number", number: 2, type: 5, label: 1 }, { name: "options", number: 3, type: 11, label: 1, typeName: ".google.protobuf.EnumValueOptions" }] }, { name: "ServiceDescriptorProto", field: [{ name: "name", number: 1, type: 9, label: 1 }, { name: "method", number: 2, type: 11, label: 3, typeName: ".google.protobuf.MethodDescriptorProto" }, { name: "options", number: 3, type: 11, label: 1, typeName: ".google.protobuf.ServiceOptions" }] }, { name: "MethodDescriptorProto", field: [{ name: "name", number: 1, type: 9, label: 1 }, { name: "input_type", number: 2, type: 9, label: 1 }, { name: "output_type", number: 3, type: 9, label: 1 }, { name: "options", number: 4, type: 11, label: 1, typeName: ".google.protobuf.MethodOptions" }, { name: "client_streaming", number: 5, type: 8, label: 1, defaultValue: "false" }, { name: "server_streaming", number: 6, type: 8, label: 1, defaultValue: "false" }] }, { name: "FileOptions", field: [{ name: "java_package", number: 1, type: 9, label: 1 }, { name: "java_outer_classname", number: 8, type: 9, label: 1 }, { name: "java_multiple_files", number: 10, type: 8, label: 1, defaultValue: "false" }, { name: "java_generate_equals_and_hash", number: 20, type: 8, label: 1, options: { deprecated: true } }, { name: "java_string_check_utf8", number: 27, type: 8, label: 1, defaultValue: "false" }, { name: "optimize_for", number: 9, type: 14, label: 1, typeName: ".google.protobuf.FileOptions.OptimizeMode", defaultValue: "SPEED" }, { name: "go_package", number: 11, type: 9, label: 1 }, { name: "cc_generic_services", number: 16, type: 8, label: 1, defaultValue: "false" }, { name: "java_generic_services", number: 17, type: 8, label: 1, defaultValue: "false" }, { name: "py_generic_services", number: 18, type: 8, label: 1, defaultValue: "false" }, { name: "deprecated", number: 23, type: 8, label: 1, defaultValue: "false" }, { name: "cc_enable_arenas", number: 31, type: 8, label: 1, defaultValue: "true" }, { name: "objc_class_prefix", number: 36, type: 9, label: 1 }, { name: "csharp_namespace", number: 37, type: 9, label: 1 }, { name: "swift_prefix", number: 39, type: 9, label: 1 }, { name: "php_class_prefix", number: 40, type: 9, label: 1 }, { name: "php_namespace", number: 41, type: 9, label: 1 }, { name: "php_metadata_namespace", number: 44, type: 9, label: 1 }, { name: "ruby_package", number: 45, type: 9, label: 1 }, { name: "features", number: 50, type: 11, label: 1, typeName: ".google.protobuf.FeatureSet" }, { name: "uninterpreted_option", number: 999, type: 11, label: 3, typeName: ".google.protobuf.UninterpretedOption" }], enumType: [{ name: "OptimizeMode", value: [{ name: "SPEED", number: 1 }, { name: "CODE_SIZE", number: 2 }, { name: "LITE_RUNTIME", number: 3 }] }], extensionRange: [{ start: 1000, end: 536870912 }] }, { name: "MessageOptions", field: [{ name: "message_set_wire_format", number: 1, type: 8, label: 1, defaultValue: "false" }, { name: "no_standard_descriptor_accessor", number: 2, type: 8, label: 1, defaultValue: "false" }, { name: "deprecated", number: 3, type: 8, label: 1, defaultValue: "false" }, { name: "map_entry", number: 7, type: 8, label: 1 }, { name: "deprecated_legacy_json_field_conflicts", number: 11, type: 8, label: 1, options: { deprecated: true } }, { name: "features", number: 12, type: 11, label: 1, typeName: ".google.protobuf.FeatureSet" }, { name: "uninterpreted_option", number: 999, type: 11, label: 3, typeName: ".google.protobuf.UninterpretedOption" }], extensionRange: [{ start: 1000, end: 536870912 }] }, { name: "FieldOptions", field: [{ name: "ctype", number: 1, type: 14, label: 1, typeName: ".google.protobuf.FieldOptions.CType", defaultValue: "STRING" }, { name: "packed", number: 2, type: 8, label: 1 }, { name: "jstype", number: 6, type: 14, label: 1, typeName: ".google.protobuf.FieldOptions.JSType", defaultValue: "JS_NORMAL" }, { name: "lazy", number: 5, type: 8, label: 1, defaultValue: "false" }, { name: "unverified_lazy", number: 15, type: 8, label: 1, defaultValue: "false" }, { name: "deprecated", number: 3, type: 8, label: 1, defaultValue: "false" }, { name: "weak", number: 10, type: 8, label: 1, defaultValue: "false" }, { name: "debug_redact", number: 16, type: 8, label: 1, defaultValue: "false" }, { name: "retention", number: 17, type: 14, label: 1, typeName: ".google.protobuf.FieldOptions.OptionRetention" }, { name: "targets", number: 19, type: 14, label: 3, typeName: ".google.protobuf.FieldOptions.OptionTargetType" }, { name: "edition_defaults", number: 20, type: 11, label: 3, typeName: ".google.protobuf.FieldOptions.EditionDefault" }, { name: "features", number: 21, type: 11, label: 1, typeName: ".google.protobuf.FeatureSet" }, { name: "feature_support", number: 22, type: 11, label: 1, typeName: ".google.protobuf.FieldOptions.FeatureSupport" }, { name: "uninterpreted_option", number: 999, type: 11, label: 3, typeName: ".google.protobuf.UninterpretedOption" }], nestedType: [{ name: "EditionDefault", field: [{ name: "edition", number: 3, type: 14, label: 1, typeName: ".google.protobuf.Edition" }, { name: "value", number: 2, type: 9, label: 1 }] }, { name: "FeatureSupport", field: [{ name: "edition_introduced", number: 1, type: 14, label: 1, typeName: ".google.protobuf.Edition" }, { name: "edition_deprecated", number: 2, type: 14, label: 1, typeName: ".google.protobuf.Edition" }, { name: "deprecation_warning", number: 3, type: 9, label: 1 }, { name: "edition_removed", number: 4, type: 14, label: 1, typeName: ".google.protobuf.Edition" }] }], enumType: [{ name: "CType", value: [{ name: "STRING", number: 0 }, { name: "CORD", number: 1 }, { name: "STRING_PIECE", number: 2 }] }, { name: "JSType", value: [{ name: "JS_NORMAL", number: 0 }, { name: "JS_STRING", number: 1 }, { name: "JS_NUMBER", number: 2 }] }, { name: "OptionRetention", value: [{ name: "RETENTION_UNKNOWN", number: 0 }, { name: "RETENTION_RUNTIME", number: 1 }, { name: "RETENTION_SOURCE", number: 2 }] }, { name: "OptionTargetType", value: [{ name: "TARGET_TYPE_UNKNOWN", number: 0 }, { name: "TARGET_TYPE_FILE", number: 1 }, { name: "TARGET_TYPE_EXTENSION_RANGE", number: 2 }, { name: "TARGET_TYPE_MESSAGE", number: 3 }, { name: "TARGET_TYPE_FIELD", number: 4 }, { name: "TARGET_TYPE_ONEOF", number: 5 }, { name: "TARGET_TYPE_ENUM", number: 6 }, { name: "TARGET_TYPE_ENUM_ENTRY", number: 7 }, { name: "TARGET_TYPE_SERVICE", number: 8 }, { name: "TARGET_TYPE_METHOD", number: 9 }] }], extensionRange: [{ start: 1000, end: 536870912 }] }, { name: "OneofOptions", field: [{ name: "features", number: 1, type: 11, label: 1, typeName: ".google.protobuf.FeatureSet" }, { name: "uninterpreted_option", number: 999, type: 11, label: 3, typeName: ".google.protobuf.UninterpretedOption" }], extensionRange: [{ start: 1000, end: 536870912 }] }, { name: "EnumOptions", field: [{ name: "allow_alias", number: 2, type: 8, label: 1 }, { name: "deprecated", number: 3, type: 8, label: 1, defaultValue: "false" }, { name: "deprecated_legacy_json_field_conflicts", number: 6, type: 8, label: 1, options: { deprecated: true } }, { name: "features", number: 7, type: 11, label: 1, typeName: ".google.protobuf.FeatureSet" }, { name: "uninterpreted_option", number: 999, type: 11, label: 3, typeName: ".google.protobuf.UninterpretedOption" }], extensionRange: [{ start: 1000, end: 536870912 }] }, { name: "EnumValueOptions", field: [{ name: "deprecated", number: 1, type: 8, label: 1, defaultValue: "false" }, { name: "features", number: 2, type: 11, label: 1, typeName: ".google.protobuf.FeatureSet" }, { name: "debug_redact", number: 3, type: 8, label: 1, defaultValue: "false" }, { name: "feature_support", number: 4, type: 11, label: 1, typeName: ".google.protobuf.FieldOptions.FeatureSupport" }, { name: "uninterpreted_option", number: 999, type: 11, label: 3, typeName: ".google.protobuf.UninterpretedOption" }], extensionRange: [{ start: 1000, end: 536870912 }] }, { name: "ServiceOptions", field: [{ name: "features", number: 34, type: 11, label: 1, typeName: ".google.protobuf.FeatureSet" }, { name: "deprecated", number: 33, type: 8, label: 1, defaultValue: "false" }, { name: "uninterpreted_option", number: 999, type: 11, label: 3, typeName: ".google.protobuf.UninterpretedOption" }], extensionRange: [{ start: 1000, end: 536870912 }] }, { name: "MethodOptions", field: [{ name: "deprecated", number: 33, type: 8, label: 1, defaultValue: "false" }, { name: "idempotency_level", number: 34, type: 14, label: 1, typeName: ".google.protobuf.MethodOptions.IdempotencyLevel", defaultValue: "IDEMPOTENCY_UNKNOWN" }, { name: "features", number: 35, type: 11, label: 1, typeName: ".google.protobuf.FeatureSet" }, { name: "uninterpreted_option", number: 999, type: 11, label: 3, typeName: ".google.protobuf.UninterpretedOption" }], enumType: [{ name: "IdempotencyLevel", value: [{ name: "IDEMPOTENCY_UNKNOWN", number: 0 }, { name: "NO_SIDE_EFFECTS", number: 1 }, { name: "IDEMPOTENT", number: 2 }] }], extensionRange: [{ start: 1000, end: 536870912 }] }, { name: "UninterpretedOption", field: [{ name: "name", number: 2, type: 11, label: 3, typeName: ".google.protobuf.UninterpretedOption.NamePart" }, { name: "identifier_value", number: 3, type: 9, label: 1 }, { name: "positive_int_value", number: 4, type: 4, label: 1 }, { name: "negative_int_value", number: 5, type: 3, label: 1 }, { name: "double_value", number: 6, type: 1, label: 1 }, { name: "string_value", number: 7, type: 12, label: 1 }, { name: "aggregate_value", number: 8, type: 9, label: 1 }], nestedType: [{ name: "NamePart", field: [{ name: "name_part", number: 1, type: 9, label: 2 }, { name: "is_extension", number: 2, type: 8, label: 2 }] }] }, { name: "FeatureSet", field: [{ name: "field_presence", number: 1, type: 14, label: 1, typeName: ".google.protobuf.FeatureSet.FieldPresence", options: { retention: 1, targets: [4, 1], editionDefaults: [{ value: "EXPLICIT", edition: 900 }, { value: "IMPLICIT", edition: 999 }, { value: "EXPLICIT", edition: 1000 }] } }, { name: "enum_type", number: 2, type: 14, label: 1, typeName: ".google.protobuf.FeatureSet.EnumType", options: { retention: 1, targets: [6, 1], editionDefaults: [{ value: "CLOSED", edition: 900 }, { value: "OPEN", edition: 999 }] } }, { name: "repeated_field_encoding", number: 3, type: 14, label: 1, typeName: ".google.protobuf.FeatureSet.RepeatedFieldEncoding", options: { retention: 1, targets: [4, 1], editionDefaults: [{ value: "EXPANDED", edition: 900 }, { value: "PACKED", edition: 999 }] } }, { name: "utf8_validation", number: 4, type: 14, label: 1, typeName: ".google.protobuf.FeatureSet.Utf8Validation", options: { retention: 1, targets: [4, 1], editionDefaults: [{ value: "NONE", edition: 900 }, { value: "VERIFY", edition: 999 }] } }, { name: "message_encoding", number: 5, type: 14, label: 1, typeName: ".google.protobuf.FeatureSet.MessageEncoding", options: { retention: 1, targets: [4, 1], editionDefaults: [{ value: "LENGTH_PREFIXED", edition: 900 }] } }, { name: "json_format", number: 6, type: 14, label: 1, typeName: ".google.protobuf.FeatureSet.JsonFormat", options: { retention: 1, targets: [3, 6, 1], editionDefaults: [{ value: "LEGACY_BEST_EFFORT", edition: 900 }, { value: "ALLOW", edition: 999 }] } }, { name: "enforce_naming_style", number: 7, type: 14, label: 1, typeName: ".google.protobuf.FeatureSet.EnforceNamingStyle", options: { retention: 2, targets: [1, 2, 3, 4, 5, 6, 7, 8, 9], editionDefaults: [{ value: "STYLE_LEGACY", edition: 900 }, { value: "STYLE2024", edition: 1001 }] } }, { name: "default_symbol_visibility", number: 8, type: 14, label: 1, typeName: ".google.protobuf.FeatureSet.VisibilityFeature.DefaultSymbolVisibility", options: { retention: 2, targets: [1], editionDefaults: [{ value: "EXPORT_ALL", edition: 900 }, { value: "EXPORT_TOP_LEVEL", edition: 1001 }] } }], nestedType: [{ name: "VisibilityFeature", enumType: [{ name: "DefaultSymbolVisibility", value: [{ name: "DEFAULT_SYMBOL_VISIBILITY_UNKNOWN", number: 0 }, { name: "EXPORT_ALL", number: 1 }, { name: "EXPORT_TOP_LEVEL", number: 2 }, { name: "LOCAL_ALL", number: 3 }, { name: "STRICT", number: 4 }] }] }], enumType: [{ name: "FieldPresence", value: [{ name: "FIELD_PRESENCE_UNKNOWN", number: 0 }, { name: "EXPLICIT", number: 1 }, { name: "IMPLICIT", number: 2 }, { name: "LEGACY_REQUIRED", number: 3 }] }, { name: "EnumType", value: [{ name: "ENUM_TYPE_UNKNOWN", number: 0 }, { name: "OPEN", number: 1 }, { name: "CLOSED", number: 2 }] }, { name: "RepeatedFieldEncoding", value: [{ name: "REPEATED_FIELD_ENCODING_UNKNOWN", number: 0 }, { name: "PACKED", number: 1 }, { name: "EXPANDED", number: 2 }] }, { name: "Utf8Validation", value: [{ name: "UTF8_VALIDATION_UNKNOWN", number: 0 }, { name: "VERIFY", number: 2 }, { name: "NONE", number: 3 }] }, { name: "MessageEncoding", value: [{ name: "MESSAGE_ENCODING_UNKNOWN", number: 0 }, { name: "LENGTH_PREFIXED", number: 1 }, { name: "DELIMITED", number: 2 }] }, { name: "JsonFormat", value: [{ name: "JSON_FORMAT_UNKNOWN", number: 0 }, { name: "ALLOW", number: 1 }, { name: "LEGACY_BEST_EFFORT", number: 2 }] }, { name: "EnforceNamingStyle", value: [{ name: "ENFORCE_NAMING_STYLE_UNKNOWN", number: 0 }, { name: "STYLE2024", number: 1 }, { name: "STYLE_LEGACY", number: 2 }] }], extensionRange: [{ start: 1000, end: 9995 }, { start: 9995, end: 1e4 }, { start: 1e4, end: 10001 }] }, { name: "FeatureSetDefaults", field: [{ name: "defaults", number: 1, type: 11, label: 3, typeName: ".google.protobuf.FeatureSetDefaults.FeatureSetEditionDefault" }, { name: "minimum_edition", number: 4, type: 14, label: 1, typeName: ".google.protobuf.Edition" }, { name: "maximum_edition", number: 5, type: 14, label: 1, typeName: ".google.protobuf.Edition" }], nestedType: [{ name: "FeatureSetEditionDefault", field: [{ name: "edition", number: 3, type: 14, label: 1, typeName: ".google.protobuf.Edition" }, { name: "overridable_features", number: 4, type: 11, label: 1, typeName: ".google.protobuf.FeatureSet" }, { name: "fixed_features", number: 5, type: 11, label: 1, typeName: ".google.protobuf.FeatureSet" }] }] }, { name: "SourceCodeInfo", field: [{ name: "location", number: 1, type: 11, label: 3, typeName: ".google.protobuf.SourceCodeInfo.Location" }], nestedType: [{ name: "Location", field: [{ name: "path", number: 1, type: 5, label: 3, options: { packed: true } }, { name: "span", number: 2, type: 5, label: 3, options: { packed: true } }, { name: "leading_comments", number: 3, type: 9, label: 1 }, { name: "trailing_comments", number: 4, type: 9, label: 1 }, { name: "leading_detached_comments", number: 6, type: 9, label: 3 }] }], extensionRange: [{ start: 536000000, end: 536000001 }] }, { name: "GeneratedCodeInfo", field: [{ name: "annotation", number: 1, type: 11, label: 3, typeName: ".google.protobuf.GeneratedCodeInfo.Annotation" }], nestedType: [{ name: "Annotation", field: [{ name: "path", number: 1, type: 5, label: 3, options: { packed: true } }, { name: "source_file", number: 2, type: 9, label: 1 }, { name: "begin", number: 3, type: 5, label: 1 }, { name: "end", number: 4, type: 5, label: 1 }, { name: "semantic", number: 5, type: 14, label: 1, typeName: ".google.protobuf.GeneratedCodeInfo.Annotation.Semantic" }], enumType: [{ name: "Semantic", value: [{ name: "NONE", number: 0 }, { name: "SET", number: 1 }, { name: "ALIAS", number: 2 }] }] }] }], enumType: [{ name: "Edition", value: [{ name: "EDITION_UNKNOWN", number: 0 }, { name: "EDITION_LEGACY", number: 900 }, { name: "EDITION_PROTO2", number: 998 }, { name: "EDITION_PROTO3", number: 999 }, { name: "EDITION_2023", number: 1000 }, { name: "EDITION_2024", number: 1001 }, { name: "EDITION_1_TEST_ONLY", number: 1 }, { name: "EDITION_2_TEST_ONLY", number: 2 }, { name: "EDITION_99997_TEST_ONLY", number: 99997 }, { name: "EDITION_99998_TEST_ONLY", number: 99998 }, { name: "EDITION_99999_TEST_ONLY", number: 99999 }, { name: "EDITION_MAX", number: 2147483647 }] }, { name: "SymbolVisibility", value: [{ name: "VISIBILITY_UNSET", number: 0 }, { name: "VISIBILITY_LOCAL", number: 1 }, { name: "VISIBILITY_EXPORT", number: 2 }] }] });
var FileDescriptorProtoSchema = /* @__PURE__ */ messageDesc(file_google_protobuf_descriptor, 1);
var ExtensionRangeOptions_VerificationState;
(function(ExtensionRangeOptions_VerificationState) {
  ExtensionRangeOptions_VerificationState[ExtensionRangeOptions_VerificationState["DECLARATION"] = 0] = "DECLARATION";
  ExtensionRangeOptions_VerificationState[ExtensionRangeOptions_VerificationState["UNVERIFIED"] = 1] = "UNVERIFIED";
})(ExtensionRangeOptions_VerificationState || (ExtensionRangeOptions_VerificationState = {}));
var FieldDescriptorProto_Type;
(function(FieldDescriptorProto_Type) {
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["DOUBLE"] = 1] = "DOUBLE";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["FLOAT"] = 2] = "FLOAT";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["INT64"] = 3] = "INT64";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["UINT64"] = 4] = "UINT64";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["INT32"] = 5] = "INT32";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["FIXED64"] = 6] = "FIXED64";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["FIXED32"] = 7] = "FIXED32";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["BOOL"] = 8] = "BOOL";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["STRING"] = 9] = "STRING";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["GROUP"] = 10] = "GROUP";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["MESSAGE"] = 11] = "MESSAGE";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["BYTES"] = 12] = "BYTES";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["UINT32"] = 13] = "UINT32";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["ENUM"] = 14] = "ENUM";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["SFIXED32"] = 15] = "SFIXED32";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["SFIXED64"] = 16] = "SFIXED64";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["SINT32"] = 17] = "SINT32";
  FieldDescriptorProto_Type[FieldDescriptorProto_Type["SINT64"] = 18] = "SINT64";
})(FieldDescriptorProto_Type || (FieldDescriptorProto_Type = {}));
var FieldDescriptorProto_Label;
(function(FieldDescriptorProto_Label) {
  FieldDescriptorProto_Label[FieldDescriptorProto_Label["OPTIONAL"] = 1] = "OPTIONAL";
  FieldDescriptorProto_Label[FieldDescriptorProto_Label["REPEATED"] = 3] = "REPEATED";
  FieldDescriptorProto_Label[FieldDescriptorProto_Label["REQUIRED"] = 2] = "REQUIRED";
})(FieldDescriptorProto_Label || (FieldDescriptorProto_Label = {}));
var FileOptions_OptimizeMode;
(function(FileOptions_OptimizeMode) {
  FileOptions_OptimizeMode[FileOptions_OptimizeMode["SPEED"] = 1] = "SPEED";
  FileOptions_OptimizeMode[FileOptions_OptimizeMode["CODE_SIZE"] = 2] = "CODE_SIZE";
  FileOptions_OptimizeMode[FileOptions_OptimizeMode["LITE_RUNTIME"] = 3] = "LITE_RUNTIME";
})(FileOptions_OptimizeMode || (FileOptions_OptimizeMode = {}));
var FieldOptions_CType;
(function(FieldOptions_CType) {
  FieldOptions_CType[FieldOptions_CType["STRING"] = 0] = "STRING";
  FieldOptions_CType[FieldOptions_CType["CORD"] = 1] = "CORD";
  FieldOptions_CType[FieldOptions_CType["STRING_PIECE"] = 2] = "STRING_PIECE";
})(FieldOptions_CType || (FieldOptions_CType = {}));
var FieldOptions_JSType;
(function(FieldOptions_JSType) {
  FieldOptions_JSType[FieldOptions_JSType["JS_NORMAL"] = 0] = "JS_NORMAL";
  FieldOptions_JSType[FieldOptions_JSType["JS_STRING"] = 1] = "JS_STRING";
  FieldOptions_JSType[FieldOptions_JSType["JS_NUMBER"] = 2] = "JS_NUMBER";
})(FieldOptions_JSType || (FieldOptions_JSType = {}));
var FieldOptions_OptionRetention;
(function(FieldOptions_OptionRetention) {
  FieldOptions_OptionRetention[FieldOptions_OptionRetention["RETENTION_UNKNOWN"] = 0] = "RETENTION_UNKNOWN";
  FieldOptions_OptionRetention[FieldOptions_OptionRetention["RETENTION_RUNTIME"] = 1] = "RETENTION_RUNTIME";
  FieldOptions_OptionRetention[FieldOptions_OptionRetention["RETENTION_SOURCE"] = 2] = "RETENTION_SOURCE";
})(FieldOptions_OptionRetention || (FieldOptions_OptionRetention = {}));
var FieldOptions_OptionTargetType;
(function(FieldOptions_OptionTargetType) {
  FieldOptions_OptionTargetType[FieldOptions_OptionTargetType["TARGET_TYPE_UNKNOWN"] = 0] = "TARGET_TYPE_UNKNOWN";
  FieldOptions_OptionTargetType[FieldOptions_OptionTargetType["TARGET_TYPE_FILE"] = 1] = "TARGET_TYPE_FILE";
  FieldOptions_OptionTargetType[FieldOptions_OptionTargetType["TARGET_TYPE_EXTENSION_RANGE"] = 2] = "TARGET_TYPE_EXTENSION_RANGE";
  FieldOptions_OptionTargetType[FieldOptions_OptionTargetType["TARGET_TYPE_MESSAGE"] = 3] = "TARGET_TYPE_MESSAGE";
  FieldOptions_OptionTargetType[FieldOptions_OptionTargetType["TARGET_TYPE_FIELD"] = 4] = "TARGET_TYPE_FIELD";
  FieldOptions_OptionTargetType[FieldOptions_OptionTargetType["TARGET_TYPE_ONEOF"] = 5] = "TARGET_TYPE_ONEOF";
  FieldOptions_OptionTargetType[FieldOptions_OptionTargetType["TARGET_TYPE_ENUM"] = 6] = "TARGET_TYPE_ENUM";
  FieldOptions_OptionTargetType[FieldOptions_OptionTargetType["TARGET_TYPE_ENUM_ENTRY"] = 7] = "TARGET_TYPE_ENUM_ENTRY";
  FieldOptions_OptionTargetType[FieldOptions_OptionTargetType["TARGET_TYPE_SERVICE"] = 8] = "TARGET_TYPE_SERVICE";
  FieldOptions_OptionTargetType[FieldOptions_OptionTargetType["TARGET_TYPE_METHOD"] = 9] = "TARGET_TYPE_METHOD";
})(FieldOptions_OptionTargetType || (FieldOptions_OptionTargetType = {}));
var MethodOptions_IdempotencyLevel;
(function(MethodOptions_IdempotencyLevel) {
  MethodOptions_IdempotencyLevel[MethodOptions_IdempotencyLevel["IDEMPOTENCY_UNKNOWN"] = 0] = "IDEMPOTENCY_UNKNOWN";
  MethodOptions_IdempotencyLevel[MethodOptions_IdempotencyLevel["NO_SIDE_EFFECTS"] = 1] = "NO_SIDE_EFFECTS";
  MethodOptions_IdempotencyLevel[MethodOptions_IdempotencyLevel["IDEMPOTENT"] = 2] = "IDEMPOTENT";
})(MethodOptions_IdempotencyLevel || (MethodOptions_IdempotencyLevel = {}));
var FeatureSet_VisibilityFeature_DefaultSymbolVisibility;
(function(FeatureSet_VisibilityFeature_DefaultSymbolVisibility) {
  FeatureSet_VisibilityFeature_DefaultSymbolVisibility[FeatureSet_VisibilityFeature_DefaultSymbolVisibility["DEFAULT_SYMBOL_VISIBILITY_UNKNOWN"] = 0] = "DEFAULT_SYMBOL_VISIBILITY_UNKNOWN";
  FeatureSet_VisibilityFeature_DefaultSymbolVisibility[FeatureSet_VisibilityFeature_DefaultSymbolVisibility["EXPORT_ALL"] = 1] = "EXPORT_ALL";
  FeatureSet_VisibilityFeature_DefaultSymbolVisibility[FeatureSet_VisibilityFeature_DefaultSymbolVisibility["EXPORT_TOP_LEVEL"] = 2] = "EXPORT_TOP_LEVEL";
  FeatureSet_VisibilityFeature_DefaultSymbolVisibility[FeatureSet_VisibilityFeature_DefaultSymbolVisibility["LOCAL_ALL"] = 3] = "LOCAL_ALL";
  FeatureSet_VisibilityFeature_DefaultSymbolVisibility[FeatureSet_VisibilityFeature_DefaultSymbolVisibility["STRICT"] = 4] = "STRICT";
})(FeatureSet_VisibilityFeature_DefaultSymbolVisibility || (FeatureSet_VisibilityFeature_DefaultSymbolVisibility = {}));
var FeatureSet_FieldPresence;
(function(FeatureSet_FieldPresence) {
  FeatureSet_FieldPresence[FeatureSet_FieldPresence["FIELD_PRESENCE_UNKNOWN"] = 0] = "FIELD_PRESENCE_UNKNOWN";
  FeatureSet_FieldPresence[FeatureSet_FieldPresence["EXPLICIT"] = 1] = "EXPLICIT";
  FeatureSet_FieldPresence[FeatureSet_FieldPresence["IMPLICIT"] = 2] = "IMPLICIT";
  FeatureSet_FieldPresence[FeatureSet_FieldPresence["LEGACY_REQUIRED"] = 3] = "LEGACY_REQUIRED";
})(FeatureSet_FieldPresence || (FeatureSet_FieldPresence = {}));
var FeatureSet_EnumType;
(function(FeatureSet_EnumType) {
  FeatureSet_EnumType[FeatureSet_EnumType["ENUM_TYPE_UNKNOWN"] = 0] = "ENUM_TYPE_UNKNOWN";
  FeatureSet_EnumType[FeatureSet_EnumType["OPEN"] = 1] = "OPEN";
  FeatureSet_EnumType[FeatureSet_EnumType["CLOSED"] = 2] = "CLOSED";
})(FeatureSet_EnumType || (FeatureSet_EnumType = {}));
var FeatureSet_RepeatedFieldEncoding;
(function(FeatureSet_RepeatedFieldEncoding) {
  FeatureSet_RepeatedFieldEncoding[FeatureSet_RepeatedFieldEncoding["REPEATED_FIELD_ENCODING_UNKNOWN"] = 0] = "REPEATED_FIELD_ENCODING_UNKNOWN";
  FeatureSet_RepeatedFieldEncoding[FeatureSet_RepeatedFieldEncoding["PACKED"] = 1] = "PACKED";
  FeatureSet_RepeatedFieldEncoding[FeatureSet_RepeatedFieldEncoding["EXPANDED"] = 2] = "EXPANDED";
})(FeatureSet_RepeatedFieldEncoding || (FeatureSet_RepeatedFieldEncoding = {}));
var FeatureSet_Utf8Validation;
(function(FeatureSet_Utf8Validation) {
  FeatureSet_Utf8Validation[FeatureSet_Utf8Validation["UTF8_VALIDATION_UNKNOWN"] = 0] = "UTF8_VALIDATION_UNKNOWN";
  FeatureSet_Utf8Validation[FeatureSet_Utf8Validation["VERIFY"] = 2] = "VERIFY";
  FeatureSet_Utf8Validation[FeatureSet_Utf8Validation["NONE"] = 3] = "NONE";
})(FeatureSet_Utf8Validation || (FeatureSet_Utf8Validation = {}));
var FeatureSet_MessageEncoding;
(function(FeatureSet_MessageEncoding) {
  FeatureSet_MessageEncoding[FeatureSet_MessageEncoding["MESSAGE_ENCODING_UNKNOWN"] = 0] = "MESSAGE_ENCODING_UNKNOWN";
  FeatureSet_MessageEncoding[FeatureSet_MessageEncoding["LENGTH_PREFIXED"] = 1] = "LENGTH_PREFIXED";
  FeatureSet_MessageEncoding[FeatureSet_MessageEncoding["DELIMITED"] = 2] = "DELIMITED";
})(FeatureSet_MessageEncoding || (FeatureSet_MessageEncoding = {}));
var FeatureSet_JsonFormat;
(function(FeatureSet_JsonFormat) {
  FeatureSet_JsonFormat[FeatureSet_JsonFormat["JSON_FORMAT_UNKNOWN"] = 0] = "JSON_FORMAT_UNKNOWN";
  FeatureSet_JsonFormat[FeatureSet_JsonFormat["ALLOW"] = 1] = "ALLOW";
  FeatureSet_JsonFormat[FeatureSet_JsonFormat["LEGACY_BEST_EFFORT"] = 2] = "LEGACY_BEST_EFFORT";
})(FeatureSet_JsonFormat || (FeatureSet_JsonFormat = {}));
var FeatureSet_EnforceNamingStyle;
(function(FeatureSet_EnforceNamingStyle) {
  FeatureSet_EnforceNamingStyle[FeatureSet_EnforceNamingStyle["ENFORCE_NAMING_STYLE_UNKNOWN"] = 0] = "ENFORCE_NAMING_STYLE_UNKNOWN";
  FeatureSet_EnforceNamingStyle[FeatureSet_EnforceNamingStyle["STYLE2024"] = 1] = "STYLE2024";
  FeatureSet_EnforceNamingStyle[FeatureSet_EnforceNamingStyle["STYLE_LEGACY"] = 2] = "STYLE_LEGACY";
})(FeatureSet_EnforceNamingStyle || (FeatureSet_EnforceNamingStyle = {}));
var GeneratedCodeInfo_Annotation_Semantic;
(function(GeneratedCodeInfo_Annotation_Semantic) {
  GeneratedCodeInfo_Annotation_Semantic[GeneratedCodeInfo_Annotation_Semantic["NONE"] = 0] = "NONE";
  GeneratedCodeInfo_Annotation_Semantic[GeneratedCodeInfo_Annotation_Semantic["SET"] = 1] = "SET";
  GeneratedCodeInfo_Annotation_Semantic[GeneratedCodeInfo_Annotation_Semantic["ALIAS"] = 2] = "ALIAS";
})(GeneratedCodeInfo_Annotation_Semantic || (GeneratedCodeInfo_Annotation_Semantic = {}));
var Edition;
(function(Edition) {
  Edition[Edition["EDITION_UNKNOWN"] = 0] = "EDITION_UNKNOWN";
  Edition[Edition["EDITION_LEGACY"] = 900] = "EDITION_LEGACY";
  Edition[Edition["EDITION_PROTO2"] = 998] = "EDITION_PROTO2";
  Edition[Edition["EDITION_PROTO3"] = 999] = "EDITION_PROTO3";
  Edition[Edition["EDITION_2023"] = 1000] = "EDITION_2023";
  Edition[Edition["EDITION_2024"] = 1001] = "EDITION_2024";
  Edition[Edition["EDITION_1_TEST_ONLY"] = 1] = "EDITION_1_TEST_ONLY";
  Edition[Edition["EDITION_2_TEST_ONLY"] = 2] = "EDITION_2_TEST_ONLY";
  Edition[Edition["EDITION_99997_TEST_ONLY"] = 99997] = "EDITION_99997_TEST_ONLY";
  Edition[Edition["EDITION_99998_TEST_ONLY"] = 99998] = "EDITION_99998_TEST_ONLY";
  Edition[Edition["EDITION_99999_TEST_ONLY"] = 99999] = "EDITION_99999_TEST_ONLY";
  Edition[Edition["EDITION_MAX"] = 2147483647] = "EDITION_MAX";
})(Edition || (Edition = {}));
var SymbolVisibility;
(function(SymbolVisibility) {
  SymbolVisibility[SymbolVisibility["VISIBILITY_UNSET"] = 0] = "VISIBILITY_UNSET";
  SymbolVisibility[SymbolVisibility["VISIBILITY_LOCAL"] = 1] = "VISIBILITY_LOCAL";
  SymbolVisibility[SymbolVisibility["VISIBILITY_EXPORT"] = 2] = "VISIBILITY_EXPORT";
})(SymbolVisibility || (SymbolVisibility = {}));
var readDefaults = {
  readUnknownFields: true
};
function makeReadOptions(options) {
  return options ? Object.assign(Object.assign({}, readDefaults), options) : readDefaults;
}
function fromBinary(schema, bytes, options) {
  const msg = reflect(schema, undefined, false);
  readMessage(msg, new BinaryReader(bytes), makeReadOptions(options), false, bytes.byteLength);
  return msg.message;
}
function readMessage(message, reader, options, delimited, lengthOrDelimitedFieldNo) {
  var _a;
  const end = delimited ? reader.len : reader.pos + lengthOrDelimitedFieldNo;
  let fieldNo;
  let wireType;
  const unknownFields = (_a = message.getUnknown()) !== null && _a !== undefined ? _a : [];
  while (reader.pos < end) {
    [fieldNo, wireType] = reader.tag();
    if (delimited && wireType == WireType.EndGroup) {
      break;
    }
    const field = message.findNumber(fieldNo);
    if (!field) {
      const data = reader.skip(wireType, fieldNo);
      if (options.readUnknownFields) {
        unknownFields.push({ no: fieldNo, wireType, data });
      }
      continue;
    }
    readField(message, reader, field, wireType, options);
  }
  if (delimited) {
    if (wireType != WireType.EndGroup || fieldNo !== lengthOrDelimitedFieldNo) {
      throw new Error("invalid end group tag");
    }
  }
  if (unknownFields.length > 0) {
    message.setUnknown(unknownFields);
  }
}
function readField(message, reader, field, wireType, options) {
  var _a;
  switch (field.fieldKind) {
    case "scalar":
      message.set(field, readScalar(reader, field.scalar));
      break;
    case "enum":
      const val = readScalar(reader, ScalarType.INT32);
      if (field.enum.open) {
        message.set(field, val);
      } else {
        const ok = field.enum.values.some((v) => v.number === val);
        if (ok) {
          message.set(field, val);
        } else if (options.readUnknownFields) {
          const data = new BinaryWriter().int32(val).finish();
          const unknownFields = (_a = message.getUnknown()) !== null && _a !== undefined ? _a : [];
          unknownFields.push({ no: field.number, wireType, data });
          message.setUnknown(unknownFields);
        }
      }
      break;
    case "message":
      message.set(field, readMessageField(reader, options, field, message.get(field)));
      break;
    case "list":
      readListField(reader, wireType, message.get(field), options);
      break;
    case "map":
      readMapEntry(reader, message.get(field), options);
      break;
  }
}
function readMapEntry(reader, map, options) {
  const field = map.field();
  let key;
  let val;
  const len = reader.uint32();
  const end = reader.pos + len;
  while (reader.pos < end) {
    const [fieldNo] = reader.tag();
    switch (fieldNo) {
      case 1:
        key = readScalar(reader, field.mapKey);
        break;
      case 2:
        switch (field.mapKind) {
          case "scalar":
            val = readScalar(reader, field.scalar);
            break;
          case "enum":
            val = reader.int32();
            break;
          case "message":
            val = readMessageField(reader, options, field);
            break;
        }
        break;
    }
  }
  if (key === undefined) {
    key = scalarZeroValue(field.mapKey, false);
  }
  if (val === undefined) {
    switch (field.mapKind) {
      case "scalar":
        val = scalarZeroValue(field.scalar, false);
        break;
      case "enum":
        val = field.enum.values[0].number;
        break;
      case "message":
        val = reflect(field.message, undefined, false);
        break;
    }
  }
  map.set(key, val);
}
function readListField(reader, wireType, list, options) {
  var _a;
  const field = list.field();
  if (field.listKind === "message") {
    list.add(readMessageField(reader, options, field));
    return;
  }
  const scalarType = (_a = field.scalar) !== null && _a !== undefined ? _a : ScalarType.INT32;
  const packed = wireType == WireType.LengthDelimited && scalarType != ScalarType.STRING && scalarType != ScalarType.BYTES;
  if (!packed) {
    list.add(readScalar(reader, scalarType));
    return;
  }
  const e = reader.uint32() + reader.pos;
  while (reader.pos < e) {
    list.add(readScalar(reader, scalarType));
  }
}
function readMessageField(reader, options, field, mergeMessage) {
  const delimited = field.delimitedEncoding;
  const message = mergeMessage !== null && mergeMessage !== undefined ? mergeMessage : reflect(field.message, undefined, false);
  readMessage(message, reader, options, delimited, delimited ? field.number : reader.uint32());
  return message;
}
function readScalar(reader, type) {
  switch (type) {
    case ScalarType.STRING:
      return reader.string();
    case ScalarType.BOOL:
      return reader.bool();
    case ScalarType.DOUBLE:
      return reader.double();
    case ScalarType.FLOAT:
      return reader.float();
    case ScalarType.INT32:
      return reader.int32();
    case ScalarType.INT64:
      return reader.int64();
    case ScalarType.UINT64:
      return reader.uint64();
    case ScalarType.FIXED64:
      return reader.fixed64();
    case ScalarType.BYTES:
      return reader.bytes();
    case ScalarType.FIXED32:
      return reader.fixed32();
    case ScalarType.SFIXED32:
      return reader.sfixed32();
    case ScalarType.SFIXED64:
      return reader.sfixed64();
    case ScalarType.SINT64:
      return reader.sint64();
    case ScalarType.UINT32:
      return reader.uint32();
    case ScalarType.SINT32:
      return reader.sint32();
  }
}
function fileDesc(b64, imports) {
  var _a;
  const root = fromBinary(FileDescriptorProtoSchema, base64Decode(b64));
  root.messageType.forEach(restoreJsonNames);
  root.dependency = (_a = imports === null || imports === undefined ? undefined : imports.map((f) => f.proto.name)) !== null && _a !== undefined ? _a : [];
  const reg = createFileRegistry(root, (protoFileName) => imports === null || imports === undefined ? undefined : imports.find((f) => f.proto.name === protoFileName));
  return reg.getFile(root.name);
}
var file_google_protobuf_timestamp = /* @__PURE__ */ fileDesc("Ch9nb29nbGUvcHJvdG9idWYvdGltZXN0YW1wLnByb3RvEg9nb29nbGUucHJvdG9idWYiKwoJVGltZXN0YW1wEg8KB3NlY29uZHMYASABKAMSDQoFbmFub3MYAiABKAVChQEKE2NvbS5nb29nbGUucHJvdG9idWZCDlRpbWVzdGFtcFByb3RvUAFaMmdvb2dsZS5nb2xhbmcub3JnL3Byb3RvYnVmL3R5cGVzL2tub3duL3RpbWVzdGFtcHBi+AEBogIDR1BCqgIeR29vZ2xlLlByb3RvYnVmLldlbGxLbm93blR5cGVzYgZwcm90bzM");
var TimestampSchema = /* @__PURE__ */ messageDesc(file_google_protobuf_timestamp, 0);
function timestampFromDate(date) {
  return timestampFromMs(date.getTime());
}
function timestampDate(timestamp) {
  return new Date(timestampMs(timestamp));
}
function timestampFromMs(timestampMs) {
  const seconds = Math.floor(timestampMs / 1000);
  return create(TimestampSchema, {
    seconds: protoInt64.parse(seconds),
    nanos: (timestampMs - seconds * 1000) * 1e6
  });
}
function timestampMs(timestamp) {
  return Number(timestamp.seconds) * 1000 + Math.round(timestamp.nanos / 1e6);
}
var file_google_protobuf_any = /* @__PURE__ */ fileDesc("Chlnb29nbGUvcHJvdG9idWYvYW55LnByb3RvEg9nb29nbGUucHJvdG9idWYiJgoDQW55EhAKCHR5cGVfdXJsGAEgASgJEg0KBXZhbHVlGAIgASgMQnYKE2NvbS5nb29nbGUucHJvdG9idWZCCEFueVByb3RvUAFaLGdvb2dsZS5nb2xhbmcub3JnL3Byb3RvYnVmL3R5cGVzL2tub3duL2FueXBiogIDR1BCqgIeR29vZ2xlLlByb3RvYnVmLldlbGxLbm93blR5cGVzYgZwcm90bzM");
var AnySchema = /* @__PURE__ */ messageDesc(file_google_protobuf_any, 0);
var LEGACY_REQUIRED2 = 3;
var writeDefaults = {
  writeUnknownFields: true
};
function makeWriteOptions(options) {
  return options ? Object.assign(Object.assign({}, writeDefaults), options) : writeDefaults;
}
function toBinary(schema, message, options) {
  return writeFields(new BinaryWriter, makeWriteOptions(options), reflect(schema, message)).finish();
}
function writeFields(writer, opts, msg) {
  var _a;
  for (const f of msg.sortedFields) {
    if (!msg.isSet(f)) {
      if (f.presence == LEGACY_REQUIRED2) {
        throw new Error(`cannot encode ${f} to binary: required field not set`);
      }
      continue;
    }
    writeField(writer, opts, msg, f);
  }
  if (opts.writeUnknownFields) {
    for (const { no, wireType, data } of (_a = msg.getUnknown()) !== null && _a !== undefined ? _a : []) {
      writer.tag(no, wireType).raw(data);
    }
  }
  return writer;
}
function writeField(writer, opts, msg, field) {
  var _a;
  switch (field.fieldKind) {
    case "scalar":
    case "enum":
      writeScalar(writer, msg.desc.typeName, field.name, (_a = field.scalar) !== null && _a !== undefined ? _a : ScalarType.INT32, field.number, msg.get(field));
      break;
    case "list":
      writeListField(writer, opts, field, msg.get(field));
      break;
    case "message":
      writeMessageField(writer, opts, field, msg.get(field));
      break;
    case "map":
      for (const [key, val] of msg.get(field)) {
        writeMapEntry(writer, opts, field, key, val);
      }
      break;
  }
}
function writeScalar(writer, msgName, fieldName, scalarType, fieldNo, value) {
  writeScalarValue(writer.tag(fieldNo, writeTypeOfScalar(scalarType)), msgName, fieldName, scalarType, value);
}
function writeMessageField(writer, opts, field, message) {
  if (field.delimitedEncoding) {
    writeFields(writer.tag(field.number, WireType.StartGroup), opts, message).tag(field.number, WireType.EndGroup);
  } else {
    writeFields(writer.tag(field.number, WireType.LengthDelimited).fork(), opts, message).join();
  }
}
function writeListField(writer, opts, field, list) {
  var _a;
  if (field.listKind == "message") {
    for (const item of list) {
      writeMessageField(writer, opts, field, item);
    }
    return;
  }
  const scalarType = (_a = field.scalar) !== null && _a !== undefined ? _a : ScalarType.INT32;
  if (field.packed) {
    if (!list.size) {
      return;
    }
    writer.tag(field.number, WireType.LengthDelimited).fork();
    for (const item of list) {
      writeScalarValue(writer, field.parent.typeName, field.name, scalarType, item);
    }
    writer.join();
    return;
  }
  for (const item of list) {
    writeScalar(writer, field.parent.typeName, field.name, scalarType, field.number, item);
  }
}
function writeMapEntry(writer, opts, field, key, value) {
  var _a;
  writer.tag(field.number, WireType.LengthDelimited).fork();
  writeScalar(writer, field.parent.typeName, field.name, field.mapKey, 1, key);
  switch (field.mapKind) {
    case "scalar":
    case "enum":
      writeScalar(writer, field.parent.typeName, field.name, (_a = field.scalar) !== null && _a !== undefined ? _a : ScalarType.INT32, 2, value);
      break;
    case "message":
      writeFields(writer.tag(2, WireType.LengthDelimited).fork(), opts, value).join();
      break;
  }
  writer.join();
}
function writeScalarValue(writer, msgName, fieldName, type, value) {
  try {
    switch (type) {
      case ScalarType.STRING:
        writer.string(value);
        break;
      case ScalarType.BOOL:
        writer.bool(value);
        break;
      case ScalarType.DOUBLE:
        writer.double(value);
        break;
      case ScalarType.FLOAT:
        writer.float(value);
        break;
      case ScalarType.INT32:
        writer.int32(value);
        break;
      case ScalarType.INT64:
        writer.int64(value);
        break;
      case ScalarType.UINT64:
        writer.uint64(value);
        break;
      case ScalarType.FIXED64:
        writer.fixed64(value);
        break;
      case ScalarType.BYTES:
        writer.bytes(value);
        break;
      case ScalarType.FIXED32:
        writer.fixed32(value);
        break;
      case ScalarType.SFIXED32:
        writer.sfixed32(value);
        break;
      case ScalarType.SFIXED64:
        writer.sfixed64(value);
        break;
      case ScalarType.SINT64:
        writer.sint64(value);
        break;
      case ScalarType.UINT32:
        writer.uint32(value);
        break;
      case ScalarType.SINT32:
        writer.sint32(value);
        break;
    }
  } catch (e) {
    if (e instanceof Error) {
      throw new Error(`cannot encode field ${msgName}.${fieldName} to binary: ${e.message}`);
    }
    throw e;
  }
}
function writeTypeOfScalar(type) {
  switch (type) {
    case ScalarType.BYTES:
    case ScalarType.STRING:
      return WireType.LengthDelimited;
    case ScalarType.DOUBLE:
    case ScalarType.FIXED64:
    case ScalarType.SFIXED64:
      return WireType.Bit64;
    case ScalarType.FIXED32:
    case ScalarType.SFIXED32:
    case ScalarType.FLOAT:
      return WireType.Bit32;
    default:
      return WireType.Varint;
  }
}
function anyPack(schema, message, into) {
  let ret = false;
  if (!into) {
    into = create(AnySchema);
    ret = true;
  }
  into.value = toBinary(schema, message);
  into.typeUrl = typeNameToUrl(message.$typeName);
  return ret ? into : undefined;
}
function anyIs(any, descOrTypeName) {
  if (any.typeUrl === "") {
    return false;
  }
  const want = typeof descOrTypeName == "string" ? descOrTypeName : descOrTypeName.typeName;
  const got = typeUrlToName(any.typeUrl);
  return want === got;
}
function anyUnpack(any, registryOrMessageDesc) {
  if (any.typeUrl === "") {
    return;
  }
  const desc = registryOrMessageDesc.kind == "message" ? registryOrMessageDesc : registryOrMessageDesc.getMessage(typeUrlToName(any.typeUrl));
  if (!desc || !anyIs(any, desc)) {
    return;
  }
  return fromBinary(desc, any.value);
}
function typeNameToUrl(name) {
  return `type.googleapis.com/${name}`;
}
function typeUrlToName(url) {
  const slash = url.lastIndexOf("/");
  const name = slash >= 0 ? url.substring(slash + 1) : url;
  if (!name.length) {
    throw new Error(`invalid type url: ${url}`);
  }
  return name;
}
var file_google_protobuf_duration = /* @__PURE__ */ fileDesc("Ch5nb29nbGUvcHJvdG9idWYvZHVyYXRpb24ucHJvdG8SD2dvb2dsZS5wcm90b2J1ZiIqCghEdXJhdGlvbhIPCgdzZWNvbmRzGAEgASgDEg0KBW5hbm9zGAIgASgFQoMBChNjb20uZ29vZ2xlLnByb3RvYnVmQg1EdXJhdGlvblByb3RvUAFaMWdvb2dsZS5nb2xhbmcub3JnL3Byb3RvYnVmL3R5cGVzL2tub3duL2R1cmF0aW9ucGL4AQGiAgNHUEKqAh5Hb29nbGUuUHJvdG9idWYuV2VsbEtub3duVHlwZXNiBnByb3RvMw");
var file_google_protobuf_empty = /* @__PURE__ */ fileDesc("Chtnb29nbGUvcHJvdG9idWYvZW1wdHkucHJvdG8SD2dvb2dsZS5wcm90b2J1ZiIHCgVFbXB0eUJ9ChNjb20uZ29vZ2xlLnByb3RvYnVmQgpFbXB0eVByb3RvUAFaLmdvb2dsZS5nb2xhbmcub3JnL3Byb3RvYnVmL3R5cGVzL2tub3duL2VtcHR5cGL4AQGiAgNHUEKqAh5Hb29nbGUuUHJvdG9idWYuV2VsbEtub3duVHlwZXNiBnByb3RvMw");
var file_google_protobuf_struct = /* @__PURE__ */ fileDesc("Chxnb29nbGUvcHJvdG9idWYvc3RydWN0LnByb3RvEg9nb29nbGUucHJvdG9idWYihAEKBlN0cnVjdBIzCgZmaWVsZHMYASADKAsyIy5nb29nbGUucHJvdG9idWYuU3RydWN0LkZpZWxkc0VudHJ5GkUKC0ZpZWxkc0VudHJ5EgsKA2tleRgBIAEoCRIlCgV2YWx1ZRgCIAEoCzIWLmdvb2dsZS5wcm90b2J1Zi5WYWx1ZToCOAEi6gEKBVZhbHVlEjAKCm51bGxfdmFsdWUYASABKA4yGi5nb29nbGUucHJvdG9idWYuTnVsbFZhbHVlSAASFgoMbnVtYmVyX3ZhbHVlGAIgASgBSAASFgoMc3RyaW5nX3ZhbHVlGAMgASgJSAASFAoKYm9vbF92YWx1ZRgEIAEoCEgAEi8KDHN0cnVjdF92YWx1ZRgFIAEoCzIXLmdvb2dsZS5wcm90b2J1Zi5TdHJ1Y3RIABIwCgpsaXN0X3ZhbHVlGAYgASgLMhouZ29vZ2xlLnByb3RvYnVmLkxpc3RWYWx1ZUgAQgYKBGtpbmQiMwoJTGlzdFZhbHVlEiYKBnZhbHVlcxgBIAMoCzIWLmdvb2dsZS5wcm90b2J1Zi5WYWx1ZSobCglOdWxsVmFsdWUSDgoKTlVMTF9WQUxVRRAAQn8KE2NvbS5nb29nbGUucHJvdG9idWZCC1N0cnVjdFByb3RvUAFaL2dvb2dsZS5nb2xhbmcub3JnL3Byb3RvYnVmL3R5cGVzL2tub3duL3N0cnVjdHBi+AEBogIDR1BCqgIeR29vZ2xlLlByb3RvYnVmLldlbGxLbm93blR5cGVzYgZwcm90bzM");
var StructSchema = /* @__PURE__ */ messageDesc(file_google_protobuf_struct, 0);
var ValueSchema = /* @__PURE__ */ messageDesc(file_google_protobuf_struct, 1);
var ListValueSchema = /* @__PURE__ */ messageDesc(file_google_protobuf_struct, 2);
var NullValue;
(function(NullValue) {
  NullValue[NullValue["NULL_VALUE"] = 0] = "NULL_VALUE";
})(NullValue || (NullValue = {}));
function setExtension(message, extension, value) {
  var _a;
  assertExtendee(extension, message);
  const ufs = ((_a = message.$unknown) !== null && _a !== undefined ? _a : []).filter((uf) => uf.no !== extension.number);
  const [container, field] = createExtensionContainer(extension, value);
  const writer = new BinaryWriter;
  writeField(writer, { writeUnknownFields: true }, container, field);
  const reader = new BinaryReader(writer.finish());
  while (reader.pos < reader.len) {
    const [no, wireType] = reader.tag();
    const data = reader.skip(wireType, no);
    ufs.push({ no, wireType, data });
  }
  message.$unknown = ufs;
}
function createExtensionContainer(extension, value) {
  const localName = extension.typeName;
  const field = Object.assign(Object.assign({}, extension), { kind: "field", parent: extension.extendee, localName });
  const desc = Object.assign(Object.assign({}, extension.extendee), { fields: [field], members: [field], oneofs: [] });
  const container = create(desc, value !== undefined ? { [localName]: value } : undefined);
  return [
    reflect(desc, container),
    field,
    () => {
      const value = container[localName];
      if (value === undefined) {
        const desc = extension.message;
        if (isWrapperDesc(desc)) {
          return scalarZeroValue(desc.fields[0].scalar, desc.fields[0].longAsString);
        }
        return create(desc);
      }
      return value;
    }
  ];
}
function assertExtendee(extension, message) {
  if (extension.extendee.typeName != message.$typeName) {
    throw new Error(`extension ${extension.typeName} can only be applied to message ${extension.extendee.typeName}`);
  }
}
var jsonReadDefaults = {
  ignoreUnknownFields: false
};
function makeReadOptions2(options) {
  return options ? Object.assign(Object.assign({}, jsonReadDefaults), options) : jsonReadDefaults;
}
function fromJson(schema, json, options) {
  const msg = reflect(schema);
  try {
    readMessage2(msg, json, makeReadOptions2(options));
  } catch (e) {
    if (isFieldError(e)) {
      throw new Error(`cannot decode ${e.field()} from JSON: ${e.message}`, {
        cause: e
      });
    }
    throw e;
  }
  return msg.message;
}
function readMessage2(msg, json, opts) {
  var _a;
  if (tryWktFromJson(msg, json, opts)) {
    return;
  }
  if (json == null || Array.isArray(json) || typeof json != "object") {
    throw new Error(`cannot decode ${msg.desc} from JSON: ${formatVal(json)}`);
  }
  const oneofSeen = new Map;
  const jsonNames = new Map;
  for (const field of msg.desc.fields) {
    jsonNames.set(field.name, field).set(field.jsonName, field);
  }
  for (const [jsonKey, jsonValue] of Object.entries(json)) {
    const field = jsonNames.get(jsonKey);
    if (field) {
      if (field.oneof) {
        if (jsonValue === null && field.fieldKind == "scalar") {
          continue;
        }
        const seen = oneofSeen.get(field.oneof);
        if (seen !== undefined) {
          throw new FieldError(field.oneof, `oneof set multiple times by ${seen.name} and ${field.name}`);
        }
        oneofSeen.set(field.oneof, field);
      }
      readField2(msg, field, jsonValue, opts);
    } else {
      let extension = undefined;
      if (jsonKey.startsWith("[") && jsonKey.endsWith("]") && (extension = (_a = opts.registry) === null || _a === undefined ? undefined : _a.getExtension(jsonKey.substring(1, jsonKey.length - 1))) && extension.extendee.typeName === msg.desc.typeName) {
        const [container, field, get] = createExtensionContainer(extension);
        readField2(container, field, jsonValue, opts);
        setExtension(msg.message, extension, get());
      }
      if (!extension && !opts.ignoreUnknownFields) {
        throw new Error(`cannot decode ${msg.desc} from JSON: key "${jsonKey}" is unknown`);
      }
    }
  }
}
function readField2(msg, field, json, opts) {
  switch (field.fieldKind) {
    case "scalar":
      readScalarField(msg, field, json);
      break;
    case "enum":
      readEnumField(msg, field, json, opts);
      break;
    case "message":
      readMessageField2(msg, field, json, opts);
      break;
    case "list":
      readListField2(msg.get(field), json, opts);
      break;
    case "map":
      readMapField(msg.get(field), json, opts);
      break;
  }
}
function readMapField(map, json, opts) {
  if (json === null) {
    return;
  }
  const field = map.field();
  if (typeof json != "object" || Array.isArray(json)) {
    throw new FieldError(field, "expected object, got " + formatVal(json));
  }
  for (const [jsonMapKey, jsonMapValue] of Object.entries(json)) {
    if (jsonMapValue === null) {
      throw new FieldError(field, "map value must not be null");
    }
    let value;
    switch (field.mapKind) {
      case "message":
        const msgValue = reflect(field.message);
        readMessage2(msgValue, jsonMapValue, opts);
        value = msgValue;
        break;
      case "enum":
        value = readEnum(field.enum, jsonMapValue, opts.ignoreUnknownFields, true);
        if (value === tokenIgnoredUnknownEnum) {
          return;
        }
        break;
      case "scalar":
        value = scalarFromJson(field, jsonMapValue, true);
        break;
    }
    const key = mapKeyFromJson(field.mapKey, jsonMapKey);
    map.set(key, value);
  }
}
function readListField2(list, json, opts) {
  if (json === null) {
    return;
  }
  const field = list.field();
  if (!Array.isArray(json)) {
    throw new FieldError(field, "expected Array, got " + formatVal(json));
  }
  for (const jsonItem of json) {
    if (jsonItem === null) {
      throw new FieldError(field, "list item must not be null");
    }
    switch (field.listKind) {
      case "message":
        const msgValue = reflect(field.message);
        readMessage2(msgValue, jsonItem, opts);
        list.add(msgValue);
        break;
      case "enum":
        const enumValue = readEnum(field.enum, jsonItem, opts.ignoreUnknownFields, true);
        if (enumValue !== tokenIgnoredUnknownEnum) {
          list.add(enumValue);
        }
        break;
      case "scalar":
        list.add(scalarFromJson(field, jsonItem, true));
        break;
    }
  }
}
function readMessageField2(msg, field, json, opts) {
  if (json === null && field.message.typeName != "google.protobuf.Value") {
    msg.clear(field);
    return;
  }
  const msgValue = msg.isSet(field) ? msg.get(field) : reflect(field.message);
  readMessage2(msgValue, json, opts);
  msg.set(field, msgValue);
}
function readEnumField(msg, field, json, opts) {
  const enumValue = readEnum(field.enum, json, opts.ignoreUnknownFields, false);
  if (enumValue === tokenNull) {
    msg.clear(field);
  } else if (enumValue !== tokenIgnoredUnknownEnum) {
    msg.set(field, enumValue);
  }
}
function readScalarField(msg, field, json) {
  const scalarValue = scalarFromJson(field, json, false);
  if (scalarValue === tokenNull) {
    msg.clear(field);
  } else {
    msg.set(field, scalarValue);
  }
}
var tokenIgnoredUnknownEnum = Symbol();
function readEnum(desc, json, ignoreUnknownFields, nullAsZeroValue) {
  if (json === null) {
    if (desc.typeName == "google.protobuf.NullValue") {
      return 0;
    }
    return nullAsZeroValue ? desc.values[0].number : tokenNull;
  }
  switch (typeof json) {
    case "number":
      if (Number.isInteger(json)) {
        return json;
      }
      break;
    case "string":
      const value = desc.values.find((ev) => ev.name === json);
      if (value !== undefined) {
        return value.number;
      }
      if (ignoreUnknownFields) {
        return tokenIgnoredUnknownEnum;
      }
      break;
  }
  throw new Error(`cannot decode ${desc} from JSON: ${formatVal(json)}`);
}
var tokenNull = Symbol();
function scalarFromJson(field, json, nullAsZeroValue) {
  if (json === null) {
    if (nullAsZeroValue) {
      return scalarZeroValue(field.scalar, false);
    }
    return tokenNull;
  }
  switch (field.scalar) {
    case ScalarType.DOUBLE:
    case ScalarType.FLOAT:
      if (json === "NaN")
        return NaN;
      if (json === "Infinity")
        return Number.POSITIVE_INFINITY;
      if (json === "-Infinity")
        return Number.NEGATIVE_INFINITY;
      if (typeof json == "number") {
        if (Number.isNaN(json)) {
          throw new FieldError(field, "unexpected NaN number");
        }
        if (!Number.isFinite(json)) {
          throw new FieldError(field, "unexpected infinite number");
        }
        break;
      }
      if (typeof json == "string") {
        if (json === "") {
          break;
        }
        if (json.trim().length !== json.length) {
          break;
        }
        const float = Number(json);
        if (!Number.isFinite(float)) {
          break;
        }
        return float;
      }
      break;
    case ScalarType.INT32:
    case ScalarType.FIXED32:
    case ScalarType.SFIXED32:
    case ScalarType.SINT32:
    case ScalarType.UINT32:
      return int32FromJson(json);
    case ScalarType.BYTES:
      if (typeof json == "string") {
        if (json === "") {
          return new Uint8Array(0);
        }
        try {
          return base64Decode(json);
        } catch (e) {
          const message = e instanceof Error ? e.message : String(e);
          throw new FieldError(field, message);
        }
      }
      break;
  }
  return json;
}
function mapKeyFromJson(type, json) {
  switch (type) {
    case ScalarType.BOOL:
      switch (json) {
        case "true":
          return true;
        case "false":
          return false;
      }
      return json;
    case ScalarType.INT32:
    case ScalarType.FIXED32:
    case ScalarType.UINT32:
    case ScalarType.SFIXED32:
    case ScalarType.SINT32:
      return int32FromJson(json);
    default:
      return json;
  }
}
function int32FromJson(json) {
  if (typeof json == "string") {
    if (json === "") {
      return json;
    }
    if (json.trim().length !== json.length) {
      return json;
    }
    const num = Number(json);
    if (Number.isNaN(num)) {
      return json;
    }
    return num;
  }
  return json;
}
function tryWktFromJson(msg, jsonValue, opts) {
  if (!msg.desc.typeName.startsWith("google.protobuf.")) {
    return false;
  }
  switch (msg.desc.typeName) {
    case "google.protobuf.Any":
      anyFromJson(msg.message, jsonValue, opts);
      return true;
    case "google.protobuf.Timestamp":
      timestampFromJson(msg.message, jsonValue);
      return true;
    case "google.protobuf.Duration":
      durationFromJson(msg.message, jsonValue);
      return true;
    case "google.protobuf.FieldMask":
      fieldMaskFromJson(msg.message, jsonValue);
      return true;
    case "google.protobuf.Struct":
      structFromJson(msg.message, jsonValue);
      return true;
    case "google.protobuf.Value":
      valueFromJson(msg.message, jsonValue);
      return true;
    case "google.protobuf.ListValue":
      listValueFromJson(msg.message, jsonValue);
      return true;
    default:
      if (isWrapperDesc(msg.desc)) {
        const valueField = msg.desc.fields[0];
        if (jsonValue === null) {
          msg.clear(valueField);
        } else {
          msg.set(valueField, scalarFromJson(valueField, jsonValue, true));
        }
        return true;
      }
      return false;
  }
}
function anyFromJson(any, json, opts) {
  var _a;
  if (json === null || Array.isArray(json) || typeof json != "object") {
    throw new Error(`cannot decode message ${any.$typeName} from JSON: expected object but got ${formatVal(json)}`);
  }
  if (Object.keys(json).length == 0) {
    return;
  }
  const typeUrl = json["@type"];
  if (typeof typeUrl != "string" || typeUrl == "") {
    throw new Error(`cannot decode message ${any.$typeName} from JSON: "@type" is empty`);
  }
  const typeName = typeUrl.includes("/") ? typeUrl.substring(typeUrl.lastIndexOf("/") + 1) : typeUrl;
  if (!typeName.length) {
    throw new Error(`cannot decode message ${any.$typeName} from JSON: "@type" is invalid`);
  }
  const desc = (_a = opts.registry) === null || _a === undefined ? undefined : _a.getMessage(typeName);
  if (!desc) {
    throw new Error(`cannot decode message ${any.$typeName} from JSON: ${typeUrl} is not in the type registry`);
  }
  const msg = reflect(desc);
  if (typeName.startsWith("google.protobuf.") && Object.prototype.hasOwnProperty.call(json, "value")) {
    const value = json.value;
    readMessage2(msg, value, opts);
  } else {
    const copy = Object.assign({}, json);
    delete copy["@type"];
    readMessage2(msg, copy, opts);
  }
  anyPack(msg.desc, msg.message, any);
}
function timestampFromJson(timestamp, json) {
  if (typeof json !== "string") {
    throw new Error(`cannot decode message ${timestamp.$typeName} from JSON: ${formatVal(json)}`);
  }
  const matches = json.match(/^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(?:Z|([+-][0-9][0-9]:[0-9][0-9]))$/);
  if (!matches) {
    throw new Error(`cannot decode message ${timestamp.$typeName} from JSON: invalid RFC 3339 string`);
  }
  const ms = Date.parse(matches[1] + "-" + matches[2] + "-" + matches[3] + "T" + matches[4] + ":" + matches[5] + ":" + matches[6] + (matches[8] ? matches[8] : "Z"));
  if (Number.isNaN(ms)) {
    throw new Error(`cannot decode message ${timestamp.$typeName} from JSON: invalid RFC 3339 string`);
  }
  if (ms < Date.parse("0001-01-01T00:00:00Z") || ms > Date.parse("9999-12-31T23:59:59Z")) {
    throw new Error(`cannot decode message ${timestamp.$typeName} from JSON: must be from 0001-01-01T00:00:00Z to 9999-12-31T23:59:59Z inclusive`);
  }
  timestamp.seconds = protoInt64.parse(ms / 1000);
  timestamp.nanos = 0;
  if (matches[7]) {
    timestamp.nanos = parseInt("1" + matches[7] + "0".repeat(9 - matches[7].length)) - 1e9;
  }
}
function durationFromJson(duration, json) {
  if (typeof json !== "string") {
    throw new Error(`cannot decode message ${duration.$typeName} from JSON: ${formatVal(json)}`);
  }
  const match = json.match(/^(-?[0-9]+)(?:\.([0-9]+))?s/);
  if (match === null) {
    throw new Error(`cannot decode message ${duration.$typeName} from JSON: ${formatVal(json)}`);
  }
  const longSeconds = Number(match[1]);
  if (longSeconds > 315576000000 || longSeconds < -315576000000) {
    throw new Error(`cannot decode message ${duration.$typeName} from JSON: ${formatVal(json)}`);
  }
  duration.seconds = protoInt64.parse(longSeconds);
  if (typeof match[2] !== "string") {
    return;
  }
  const nanosStr = match[2] + "0".repeat(9 - match[2].length);
  duration.nanos = parseInt(nanosStr);
  if (longSeconds < 0 || Object.is(longSeconds, -0)) {
    duration.nanos = -duration.nanos;
  }
}
function fieldMaskFromJson(fieldMask, json) {
  if (typeof json !== "string") {
    throw new Error(`cannot decode message ${fieldMask.$typeName} from JSON: ${formatVal(json)}`);
  }
  if (json === "") {
    return;
  }
  function camelToSnake(str) {
    if (str.includes("_")) {
      throw new Error(`cannot decode message ${fieldMask.$typeName} from JSON: path names must be lowerCamelCase`);
    }
    const sc = str.replace(/[A-Z]/g, (letter) => "_" + letter.toLowerCase());
    return sc[0] === "_" ? sc.substring(1) : sc;
  }
  fieldMask.paths = json.split(",").map(camelToSnake);
}
function structFromJson(struct, json) {
  if (typeof json != "object" || json == null || Array.isArray(json)) {
    throw new Error(`cannot decode message ${struct.$typeName} from JSON ${formatVal(json)}`);
  }
  for (const [k, v] of Object.entries(json)) {
    const parsedV = create(ValueSchema);
    valueFromJson(parsedV, v);
    struct.fields[k] = parsedV;
  }
}
function valueFromJson(value, json) {
  switch (typeof json) {
    case "number":
      value.kind = { case: "numberValue", value: json };
      break;
    case "string":
      value.kind = { case: "stringValue", value: json };
      break;
    case "boolean":
      value.kind = { case: "boolValue", value: json };
      break;
    case "object":
      if (json === null) {
        value.kind = { case: "nullValue", value: NullValue.NULL_VALUE };
      } else if (Array.isArray(json)) {
        const listValue = create(ListValueSchema);
        listValueFromJson(listValue, json);
        value.kind = { case: "listValue", value: listValue };
      } else {
        const struct = create(StructSchema);
        structFromJson(struct, json);
        value.kind = { case: "structValue", value: struct };
      }
      break;
    default:
      throw new Error(`cannot decode message ${value.$typeName} from JSON ${formatVal(json)}`);
  }
  return value;
}
function listValueFromJson(listValue, json) {
  if (!Array.isArray(json)) {
    throw new Error(`cannot decode message ${listValue.$typeName} from JSON ${formatVal(json)}`);
  }
  for (const e of json) {
    const value = create(ValueSchema);
    valueFromJson(value, e);
    listValue.values.push(value);
  }
}
var file_values_v1_values = /* @__PURE__ */ fileDesc("ChZ2YWx1ZXMvdjEvdmFsdWVzLnByb3RvEgl2YWx1ZXMudjEigQMKBVZhbHVlEhYKDHN0cmluZ192YWx1ZRgBIAEoCUgAEhQKCmJvb2xfdmFsdWUYAiABKAhIABIVCgtieXRlc192YWx1ZRgDIAEoDEgAEiMKCW1hcF92YWx1ZRgEIAEoCzIOLnZhbHVlcy52MS5NYXBIABIlCgpsaXN0X3ZhbHVlGAUgASgLMg8udmFsdWVzLnYxLkxpc3RIABIrCg1kZWNpbWFsX3ZhbHVlGAYgASgLMhIudmFsdWVzLnYxLkRlY2ltYWxIABIZCgtpbnQ2NF92YWx1ZRgHIAEoA0ICMABIABIpCgxiaWdpbnRfdmFsdWUYCSABKAsyES52YWx1ZXMudjEuQmlnSW50SAASMAoKdGltZV92YWx1ZRgKIAEoCzIaLmdvb2dsZS5wcm90b2J1Zi5UaW1lc3RhbXBIABIXCg1mbG9hdDY0X3ZhbHVlGAsgASgBSAASGgoMdWludDY0X3ZhbHVlGAwgASgEQgIwAEgAQgcKBXZhbHVlSgQICBAJIisKBkJpZ0ludBIPCgdhYnNfdmFsGAEgASgMEhAKBHNpZ24YAiABKANCAjAAInIKA01hcBIqCgZmaWVsZHMYASADKAsyGi52YWx1ZXMudjEuTWFwLkZpZWxkc0VudHJ5Gj8KC0ZpZWxkc0VudHJ5EgsKA2tleRgBIAEoCRIfCgV2YWx1ZRgCIAEoCzIQLnZhbHVlcy52MS5WYWx1ZToCOAEiKAoETGlzdBIgCgZmaWVsZHMYAiADKAsyEC52YWx1ZXMudjEuVmFsdWUiQwoHRGVjaW1hbBImCgtjb2VmZmljaWVudBgBIAEoCzIRLnZhbHVlcy52MS5CaWdJbnQSEAoIZXhwb25lbnQYAiABKAVCYQoNY29tLnZhbHVlcy52MUILVmFsdWVzUHJvdG9QAaICA1ZYWKoCCVZhbHVlcy5WMcoCCVZhbHVlc1xWMeICFVZhbHVlc1xWMVxHUEJNZXRhZGF0YeoCClZhbHVlczo6VjFiBnByb3RvMw", [file_google_protobuf_timestamp]);
var ValueSchema2 = /* @__PURE__ */ messageDesc(file_values_v1_values, 0);
var BigIntSchema = /* @__PURE__ */ messageDesc(file_values_v1_values, 1);
var MapSchema = /* @__PURE__ */ messageDesc(file_values_v1_values, 2);
var ListSchema = /* @__PURE__ */ messageDesc(file_values_v1_values, 3);
var DecimalSchema = /* @__PURE__ */ messageDesc(file_values_v1_values, 4);
var file_sdk_v1alpha_sdk = /* @__PURE__ */ fileDesc("ChVzZGsvdjFhbHBoYS9zZGsucHJvdG8SC3Nkay52MWFscGhhIrQBChVTaW1wbGVDb25zZW5zdXNJbnB1dHMSIQoFdmFsdWUYASABKAsyEC52YWx1ZXMudjEuVmFsdWVIABIPCgVlcnJvchgCIAEoCUgAEjUKC2Rlc2NyaXB0b3JzGAMgASgLMiAuc2RrLnYxYWxwaGEuQ29uc2Vuc3VzRGVzY3JpcHRvchIhCgdkZWZhdWx0GAQgASgLMhAudmFsdWVzLnYxLlZhbHVlQg0KC29ic2VydmF0aW9uIpABCglGaWVsZHNNYXASMgoGZmllbGRzGAEgAygLMiIuc2RrLnYxYWxwaGEuRmllbGRzTWFwLkZpZWxkc0VudHJ5Gk8KC0ZpZWxkc0VudHJ5EgsKA2tleRgBIAEoCRIvCgV2YWx1ZRgCIAEoCzIgLnNkay52MWFscGhhLkNvbnNlbnN1c0Rlc2NyaXB0b3I6AjgBIoYBChNDb25zZW5zdXNEZXNjcmlwdG9yEjMKC2FnZ3JlZ2F0aW9uGAEgASgOMhwuc2RrLnYxYWxwaGEuQWdncmVnYXRpb25UeXBlSAASLAoKZmllbGRzX21hcBgCIAEoCzIWLnNkay52MWFscGhhLkZpZWxkc01hcEgAQgwKCmRlc2NyaXB0b3IiagoNUmVwb3J0UmVxdWVzdBIXCg9lbmNvZGVkX3BheWxvYWQYASABKAwSFAoMZW5jb2Rlcl9uYW1lGAIgASgJEhQKDHNpZ25pbmdfYWxnbxgDIAEoCRIUCgxoYXNoaW5nX2FsZ28YBCABKAkilwEKDlJlcG9ydFJlc3BvbnNlEhUKDWNvbmZpZ19kaWdlc3QYASABKAwSEgoGc2VxX25yGAIgASgEQgIwABIWCg5yZXBvcnRfY29udGV4dBgDIAEoDBISCgpyYXdfcmVwb3J0GAQgASgMEi4KBHNpZ3MYBSADKAsyIC5zZGsudjFhbHBoYS5BdHRyaWJ1dGVkU2lnbmF0dXJlIjsKE0F0dHJpYnV0ZWRTaWduYXR1cmUSEQoJc2lnbmF0dXJlGAEgASgMEhEKCXNpZ25lcl9pZBgCIAEoDSJrChFDYXBhYmlsaXR5UmVxdWVzdBIKCgJpZBgBIAEoCRIlCgdwYXlsb2FkGAIgASgLMhQuZ29vZ2xlLnByb3RvYnVmLkFueRIOCgZtZXRob2QYAyABKAkSEwoLY2FsbGJhY2tfaWQYBCABKAUiWgoSQ2FwYWJpbGl0eVJlc3BvbnNlEicKB3BheWxvYWQYASABKAsyFC5nb29nbGUucHJvdG9idWYuQW55SAASDwoFZXJyb3IYAiABKAlIAEIKCghyZXNwb25zZSKbAQoTVHJpZ2dlclN1YnNjcmlwdGlvbhIKCgJpZBgBIAEoCRIlCgdwYXlsb2FkGAIgASgLMhQuZ29vZ2xlLnByb3RvYnVmLkFueRIOCgZtZXRob2QYAyABKAkSLwoMcmVxdWlyZW1lbnRzGAQgASgLMhkuc2RrLnYxYWxwaGEuUmVxdWlyZW1lbnRzEhAKCHByZV9ob29rGAUgASgIIkgKEVRlZVR5cGVBbmRSZWdpb25zEiIKBHR5cGUYASABKA4yFC5zZGsudjFhbHBoYS5UZWVUeXBlEg8KB3JlZ2lvbnMYAyADKAkiVQoaVHJpZ2dlclN1YnNjcmlwdGlvblJlcXVlc3QSNwoNc3Vic2NyaXB0aW9ucxgBIAMoCzIgLnNkay52MWFscGhhLlRyaWdnZXJTdWJzY3JpcHRpb24iQAoHVHJpZ2dlchIOCgJpZBgBIAEoBEICMAASJQoHcGF5bG9hZBgCIAEoCzIULmdvb2dsZS5wcm90b2J1Zi5BbnkiGgoHUmVnaW9ucxIPCgdyZWdpb25zGAEgAygJIlIKElRlZVR5cGVzQW5kUmVnaW9ucxI8ChR0ZWVfdHlwZV9hbmRfcmVnaW9ucxgBIAMoCzIeLnNkay52MWFscGhhLlRlZVR5cGVBbmRSZWdpb25zInwKA1RlZRIrCgthbnlfcmVnaW9ucxgBIAEoCzIULnNkay52MWFscGhhLlJlZ2lvbnNIABJAChV0ZWVfdHlwZXNfYW5kX3JlZ2lvbnMYAiABKAsyHy5zZGsudjFhbHBoYS5UZWVUeXBlc0FuZFJlZ2lvbnNIAEIGCgRpdGVtIi0KDFJlcXVpcmVtZW50cxIdCgN0ZWUYASABKAsyEC5zZGsudjFhbHBoYS5UZWUiJwoYQXdhaXRDYXBhYmlsaXRpZXNSZXF1ZXN0EgsKA2lkcxgBIAMoBSK4AQoZQXdhaXRDYXBhYmlsaXRpZXNSZXNwb25zZRJICglyZXNwb25zZXMYASADKAsyNS5zZGsudjFhbHBoYS5Bd2FpdENhcGFiaWxpdGllc1Jlc3BvbnNlLlJlc3BvbnNlc0VudHJ5GlEKDlJlc3BvbnNlc0VudHJ5EgsKA2tleRgBIAEoBRIuCgV2YWx1ZRgCIAEoCzIfLnNkay52MWFscGhhLkNhcGFiaWxpdHlSZXNwb25zZToCOAEiygEKDkV4ZWN1dGVSZXF1ZXN0Eg4KBmNvbmZpZxgBIAEoDBIrCglzdWJzY3JpYmUYAiABKAsyFi5nb29nbGUucHJvdG9idWYuRW1wdHlIABInCgd0cmlnZ2VyGAMgASgLMhQuc2RrLnYxYWxwaGEuVHJpZ2dlckgAEigKCHByZV9ob29rGAUgASgLMhQuc2RrLnYxYWxwaGEuVHJpZ2dlckgAEh0KEW1heF9yZXNwb25zZV9zaXplGAQgASgEQgIwAEIJCgdyZXF1ZXN0IswBCg9FeGVjdXRpb25SZXN1bHQSIQoFdmFsdWUYASABKAsyEC52YWx1ZXMudjEuVmFsdWVIABIPCgVlcnJvchgCIAEoCUgAEkgKFXRyaWdnZXJfc3Vic2NyaXB0aW9ucxgDIAEoCzInLnNkay52MWFscGhhLlRyaWdnZXJTdWJzY3JpcHRpb25SZXF1ZXN0SAASMQoMcmVzdHJpY3Rpb25zGAQgASgLMhkuc2RrLnYxYWxwaGEuUmVzdHJpY3Rpb25zSABCCAoGcmVzdWx0IlYKEUdldFNlY3JldHNSZXF1ZXN0EiwKCHJlcXVlc3RzGAEgAygLMhouc2RrLnYxYWxwaGEuU2VjcmV0UmVxdWVzdBITCgtjYWxsYmFja19pZBgCIAEoBSIiChNBd2FpdFNlY3JldHNSZXF1ZXN0EgsKA2lkcxgBIAMoBSKrAQoUQXdhaXRTZWNyZXRzUmVzcG9uc2USQwoJcmVzcG9uc2VzGAEgAygLMjAuc2RrLnYxYWxwaGEuQXdhaXRTZWNyZXRzUmVzcG9uc2UuUmVzcG9uc2VzRW50cnkaTgoOUmVzcG9uc2VzRW50cnkSCwoDa2V5GAEgASgFEisKBXZhbHVlGAIgASgLMhwuc2RrLnYxYWxwaGEuU2VjcmV0UmVzcG9uc2VzOgI4ASIuCg1TZWNyZXRSZXF1ZXN0EgoKAmlkGAEgASgJEhEKCW5hbWVzcGFjZRgCIAEoCSJFCgZTZWNyZXQSCgoCaWQYASABKAkSEQoJbmFtZXNwYWNlGAIgASgJEg0KBW93bmVyGAMgASgJEg0KBXZhbHVlGAQgASgJIkoKC1NlY3JldEVycm9yEgoKAmlkGAEgASgJEhEKCW5hbWVzcGFjZRgCIAEoCRINCgVvd25lchgDIAEoCRINCgVlcnJvchgEIAEoCSJuCg5TZWNyZXRSZXNwb25zZRIlCgZzZWNyZXQYASABKAsyEy5zZGsudjFhbHBoYS5TZWNyZXRIABIpCgVlcnJvchgCIAEoCzIYLnNkay52MWFscGhhLlNlY3JldEVycm9ySABCCgoIcmVzcG9uc2UiQQoPU2VjcmV0UmVzcG9uc2VzEi4KCXJlc3BvbnNlcxgBIAMoCzIbLnNkay52MWFscGhhLlNlY3JldFJlc3BvbnNlIkIKEU1ldGhvZFJlc3RyaWN0aW9uEgoKAmlkGAEgASgJEg4KBm1ldGhvZBgCIAEoCRIRCgltYXhfY2FsbHMYAyABKA0iWAoVQ2FwYWJpbGl0eVJlc3RyaWN0aW9uEjAKBm1ldGhvZBgBIAEoCzIeLnNkay52MWFscGhhLk1ldGhvZFJlc3RyaWN0aW9uSABCDQoLcmVzdHJpY3Rpb24ioQEKFkNhcGFiaWxpdHlSZXN0cmljdGlvbnMSOAoMcmVzdHJpY3Rpb25zGAEgAygLMiIuc2RrLnYxYWxwaGEuQ2FwYWJpbGl0eVJlc3RyaWN0aW9uEhcKD21heF90b3RhbF9jYWxscxgCIAEoDRI0CgR0eXBlGAMgASgOMiYuc2RrLnYxYWxwaGEuQ2FwYWJpbGl0eVJlc3RyaWN0aW9uVHlwZSJRChdTZWNyZXRQcmVmaXhSZXN0cmljdGlvbhIOCgZwcmVmaXgYASABKAkSEQoJbmFtZXNwYWNlGAIgASgJEhMKC21heF9zZWNyZXRzGAMgASgNIpABChFTZWNyZXRSZXN0cmljdGlvbhIrCgxleGFjdF9zZWNyZXQYASABKAsyEy5zZGsudjFhbHBoYS5TZWNyZXRIABI/Cg9wcmVmaXhlZF9zZWNyZXQYAiABKAsyJC5zZGsudjFhbHBoYS5TZWNyZXRQcmVmaXhSZXN0cmljdGlvbkgAQg0KC3Jlc3RyaWN0aW9uIl8KElNlY3JldHNSZXN0cml0aW9ucxI0CgxyZXN0cmljdGlvbnMYASADKAsyHi5zZGsudjFhbHBoYS5TZWNyZXRSZXN0cmljdGlvbhITCgttYXhfc2VjcmV0cxgCIAEoDSJ7CgxSZXN0cmljdGlvbnMSMAoHc2VjcmV0cxgBIAEoCzIfLnNkay52MWFscGhhLlNlY3JldHNSZXN0cml0aW9ucxI5CgxjYXBhYmlsaXRpZXMYAiABKAsyIy5zZGsudjFhbHBoYS5DYXBhYmlsaXR5UmVzdHJpY3Rpb25zKt0BCg9BZ2dyZWdhdGlvblR5cGUSIAocQUdHUkVHQVRJT05fVFlQRV9VTlNQRUNJRklFRBAAEhsKF0FHR1JFR0FUSU9OX1RZUEVfTUVESUFOEAESHgoaQUdHUkVHQVRJT05fVFlQRV9JREVOVElDQUwQAhIiCh5BR0dSRUdBVElPTl9UWVBFX0NPTU1PTl9QUkVGSVgQAxIiCh5BR0dSRUdBVElPTl9UWVBFX0NPTU1PTl9TVUZGSVgQBBIjCh9BR0dSRUdBVElPTl9UWVBFX0ZSRVFVRU5DWV9MSVNUEAUqOQoETW9kZRIUChBNT0RFX1VOU1BFQ0lGSUVEEAASDAoITU9ERV9ET04QARINCglNT0RFX05PREUQAio7CgdUZWVUeXBlEhgKFFRFRV9UWVBFX1VOU1BFQ0lGSUVEEAASFgoSVEVFX1RZUEVfQVdTX05JVFJPEAEqaQoZQ2FwYWJpbGl0eVJlc3RyaWN0aW9uVHlwZRImCiJDQVBBQklMSVRZX1JFU1RSSUNUSU9OX1RZUEVfQ0xPU0VEEAASJAogQ0FQQUJJTElUWV9SRVNUUklDVElPTl9UWVBFX09QRU4QAUJoCg9jb20uc2RrLnYxYWxwaGFCCFNka1Byb3RvUAGiAgNTWFiqAgtTZGsuVjFhbHBoYcoCC1Nka1xWMWFscGhh4gIXU2RrXFYxYWxwaGFcR1BCTWV0YWRhdGHqAgxTZGs6OlYxYWxwaGFiBnByb3RvMw", [file_google_protobuf_any, file_google_protobuf_empty, file_values_v1_values]);
var SimpleConsensusInputsSchema = /* @__PURE__ */ messageDesc(file_sdk_v1alpha_sdk, 0);
var ReportRequestSchema = /* @__PURE__ */ messageDesc(file_sdk_v1alpha_sdk, 3);
var ReportResponseSchema = /* @__PURE__ */ messageDesc(file_sdk_v1alpha_sdk, 4);
var AttributedSignatureSchema = /* @__PURE__ */ messageDesc(file_sdk_v1alpha_sdk, 5);
var CapabilityRequestSchema = /* @__PURE__ */ messageDesc(file_sdk_v1alpha_sdk, 6);
var TriggerSubscriptionRequestSchema = /* @__PURE__ */ messageDesc(file_sdk_v1alpha_sdk, 10);
var AwaitCapabilitiesRequestSchema = /* @__PURE__ */ messageDesc(file_sdk_v1alpha_sdk, 16);
var AwaitCapabilitiesResponseSchema = /* @__PURE__ */ messageDesc(file_sdk_v1alpha_sdk, 17);
var ExecuteRequestSchema = /* @__PURE__ */ messageDesc(file_sdk_v1alpha_sdk, 18);
var ExecutionResultSchema = /* @__PURE__ */ messageDesc(file_sdk_v1alpha_sdk, 19);
var GetSecretsRequestSchema = /* @__PURE__ */ messageDesc(file_sdk_v1alpha_sdk, 20);
var AwaitSecretsRequestSchema = /* @__PURE__ */ messageDesc(file_sdk_v1alpha_sdk, 21);
var AwaitSecretsResponseSchema = /* @__PURE__ */ messageDesc(file_sdk_v1alpha_sdk, 22);
var SecretRequestSchema = /* @__PURE__ */ messageDesc(file_sdk_v1alpha_sdk, 23);
var RestrictionsSchema = /* @__PURE__ */ messageDesc(file_sdk_v1alpha_sdk, 34);
var AggregationType;
(function(AggregationType) {
  AggregationType[AggregationType["UNSPECIFIED"] = 0] = "UNSPECIFIED";
  AggregationType[AggregationType["MEDIAN"] = 1] = "MEDIAN";
  AggregationType[AggregationType["IDENTICAL"] = 2] = "IDENTICAL";
  AggregationType[AggregationType["COMMON_PREFIX"] = 3] = "COMMON_PREFIX";
  AggregationType[AggregationType["COMMON_SUFFIX"] = 4] = "COMMON_SUFFIX";
  AggregationType[AggregationType["FREQUENCY_LIST"] = 5] = "FREQUENCY_LIST";
})(AggregationType || (AggregationType = {}));
var Mode;
(function(Mode) {
  Mode[Mode["UNSPECIFIED"] = 0] = "UNSPECIFIED";
  Mode[Mode["DON"] = 1] = "DON";
  Mode[Mode["NODE"] = 2] = "NODE";
})(Mode || (Mode = {}));
var TeeType;
(function(TeeType) {
  TeeType[TeeType["UNSPECIFIED"] = 0] = "UNSPECIFIED";
  TeeType[TeeType["AWS_NITRO"] = 1] = "AWS_NITRO";
})(TeeType || (TeeType = {}));
var CapabilityRestrictionType;
(function(CapabilityRestrictionType) {
  CapabilityRestrictionType[CapabilityRestrictionType["CLOSED"] = 0] = "CLOSED";
  CapabilityRestrictionType[CapabilityRestrictionType["OPEN"] = 1] = "OPEN";
})(CapabilityRestrictionType || (CapabilityRestrictionType = {}));
var file_tools_generator_v1alpha_cre_metadata = /* @__PURE__ */ fileDesc("Cip0b29scy9nZW5lcmF0b3IvdjFhbHBoYS9jcmVfbWV0YWRhdGEucHJvdG8SF3Rvb2xzLmdlbmVyYXRvci52MWFscGhhIoQBCgtTdHJpbmdMYWJlbBJECghkZWZhdWx0cxgBIAMoCzIyLnRvb2xzLmdlbmVyYXRvci52MWFscGhhLlN0cmluZ0xhYmVsLkRlZmF1bHRzRW50cnkaLwoNRGVmYXVsdHNFbnRyeRILCgNrZXkYASABKAkSDQoFdmFsdWUYAiABKAk6AjgBIogBCgtVaW50NjRMYWJlbBJECghkZWZhdWx0cxgBIAMoCzIyLnRvb2xzLmdlbmVyYXRvci52MWFscGhhLlVpbnQ2NExhYmVsLkRlZmF1bHRzRW50cnkaMwoNRGVmYXVsdHNFbnRyeRILCgNrZXkYASABKAkSEQoFdmFsdWUYAiABKARCAjAAOgI4ASKEAQoLVWludDMyTGFiZWwSRAoIZGVmYXVsdHMYASADKAsyMi50b29scy5nZW5lcmF0b3IudjFhbHBoYS5VaW50MzJMYWJlbC5EZWZhdWx0c0VudHJ5Gi8KDURlZmF1bHRzRW50cnkSCwoDa2V5GAEgASgJEg0KBXZhbHVlGAIgASgNOgI4ASKGAQoKSW50NjRMYWJlbBJDCghkZWZhdWx0cxgBIAMoCzIxLnRvb2xzLmdlbmVyYXRvci52MWFscGhhLkludDY0TGFiZWwuRGVmYXVsdHNFbnRyeRozCg1EZWZhdWx0c0VudHJ5EgsKA2tleRgBIAEoCRIRCgV2YWx1ZRgCIAEoA0ICMAA6AjgBIoIBCgpJbnQzMkxhYmVsEkMKCGRlZmF1bHRzGAEgAygLMjEudG9vbHMuZ2VuZXJhdG9yLnYxYWxwaGEuSW50MzJMYWJlbC5EZWZhdWx0c0VudHJ5Gi8KDURlZmF1bHRzRW50cnkSCwoDa2V5GAEgASgJEg0KBXZhbHVlGAIgASgFOgI4ASLBAgoFTGFiZWwSPAoMc3RyaW5nX2xhYmVsGAEgASgLMiQudG9vbHMuZ2VuZXJhdG9yLnYxYWxwaGEuU3RyaW5nTGFiZWxIABI8Cgx1aW50NjRfbGFiZWwYAiABKAsyJC50b29scy5nZW5lcmF0b3IudjFhbHBoYS5VaW50NjRMYWJlbEgAEjoKC2ludDY0X2xhYmVsGAMgASgLMiMudG9vbHMuZ2VuZXJhdG9yLnYxYWxwaGEuSW50NjRMYWJlbEgAEjwKDHVpbnQzMl9sYWJlbBgEIAEoCzIkLnRvb2xzLmdlbmVyYXRvci52MWFscGhhLlVpbnQzMkxhYmVsSAASOgoLaW50MzJfbGFiZWwYBSABKAsyIy50b29scy5nZW5lcmF0b3IudjFhbHBoYS5JbnQzMkxhYmVsSABCBgoEa2luZCK2AgoSQ2FwYWJpbGl0eU1ldGFkYXRhEh8KBG1vZGUYASABKA4yES5zZGsudjFhbHBoYS5Nb2RlEhUKDWNhcGFiaWxpdHlfaWQYAiABKAkSRwoGbGFiZWxzGAMgAygLMjcudG9vbHMuZ2VuZXJhdG9yLnYxYWxwaGEuQ2FwYWJpbGl0eU1ldGFkYXRhLkxhYmVsc0VudHJ5ElAKF2FkZGl0aW9uYWxfZW52aXJvbm1lbnRzGAQgAygOMi8udG9vbHMuZ2VuZXJhdG9yLnYxYWxwaGEuQWRkaXRpb25hbEVudmlyb25tZW50cxpNCgtMYWJlbHNFbnRyeRILCgNrZXkYASABKAkSLQoFdmFsdWUYAiABKAsyHi50b29scy5nZW5lcmF0b3IudjFhbHBoYS5MYWJlbDoCOAEiNgoYQ2FwYWJpbGl0eU1ldGhvZE1ldGFkYXRhEhoKEm1hcF90b191bnR5cGVkX2FwaRgBIAEoCCpiChZBZGRpdGlvbmFsRW52aXJvbm1lbnRzEicKI0FERElUSU9OQUxfRU5WSVJPTk1FTlRTX1VOU1BFQ0lGSUVEEAASHwobQURESVRJT05BTF9FTlZJUk9OTUVOVFNfVEVFEAE6bgoKY2FwYWJpbGl0eRIfLmdvb2dsZS5wcm90b2J1Zi5TZXJ2aWNlT3B0aW9ucxjQhgMgASgLMisudG9vbHMuZ2VuZXJhdG9yLnYxYWxwaGEuQ2FwYWJpbGl0eU1ldGFkYXRhUgpjYXBhYmlsaXR5OmsKBm1ldGhvZBIeLmdvb2dsZS5wcm90b2J1Zi5NZXRob2RPcHRpb25zGNGGAyABKAsyMS50b29scy5nZW5lcmF0b3IudjFhbHBoYS5DYXBhYmlsaXR5TWV0aG9kTWV0YWRhdGFSBm1ldGhvZEKvAQobY29tLnRvb2xzLmdlbmVyYXRvci52MWFscGhhQhBDcmVNZXRhZGF0YVByb3RvUAGiAgNUR1iqAhdUb29scy5HZW5lcmF0b3IuVjFhbHBoYcoCGFRvb2xzXEdlbmVyYXRvcl9cVjFhbHBoYeICJFRvb2xzXEdlbmVyYXRvcl9cVjFhbHBoYVxHUEJNZXRhZGF0YeoCGVRvb2xzOjpHZW5lcmF0b3I6OlYxYWxwaGFiBnByb3RvMw", [file_google_protobuf_descriptor, file_sdk_v1alpha_sdk]);
var AdditionalEnvironments;
(function(AdditionalEnvironments) {
  AdditionalEnvironments[AdditionalEnvironments["UNSPECIFIED"] = 0] = "UNSPECIFIED";
  AdditionalEnvironments[AdditionalEnvironments["TEE"] = 1] = "TEE";
})(AdditionalEnvironments || (AdditionalEnvironments = {}));
var file_capabilities_blockchain_evm_v1alpha_client = /* @__PURE__ */ fileDesc("CjBjYXBhYmlsaXRpZXMvYmxvY2tjaGFpbi9ldm0vdjFhbHBoYS9jbGllbnQucHJvdG8SI2NhcGFiaWxpdGllcy5ibG9ja2NoYWluLmV2bS52MWFscGhhIh0KC1RvcGljVmFsdWVzEg4KBnZhbHVlcxgBIAMoDCK4AQoXRmlsdGVyTG9nVHJpZ2dlclJlcXVlc3QSEQoJYWRkcmVzc2VzGAEgAygMEkAKBnRvcGljcxgCIAMoCzIwLmNhcGFiaWxpdGllcy5ibG9ja2NoYWluLmV2bS52MWFscGhhLlRvcGljVmFsdWVzEkgKCmNvbmZpZGVuY2UYAyABKA4yNC5jYXBhYmlsaXRpZXMuYmxvY2tjaGFpbi5ldm0udjFhbHBoYS5Db25maWRlbmNlTGV2ZWwiegoTQ2FsbENvbnRyYWN0UmVxdWVzdBI6CgRjYWxsGAEgASgLMiwuY2FwYWJpbGl0aWVzLmJsb2NrY2hhaW4uZXZtLnYxYWxwaGEuQ2FsbE1zZxInCgxibG9ja19udW1iZXIYAiABKAsyES52YWx1ZXMudjEuQmlnSW50IiEKEUNhbGxDb250cmFjdFJlcGx5EgwKBGRhdGEYASABKAwiWwoRRmlsdGVyTG9nc1JlcXVlc3QSRgoMZmlsdGVyX3F1ZXJ5GAEgASgLMjAuY2FwYWJpbGl0aWVzLmJsb2NrY2hhaW4uZXZtLnYxYWxwaGEuRmlsdGVyUXVlcnkiSQoPRmlsdGVyTG9nc1JlcGx5EjYKBGxvZ3MYASADKAsyKC5jYXBhYmlsaXRpZXMuYmxvY2tjaGFpbi5ldm0udjFhbHBoYS5Mb2cixwEKA0xvZxIPCgdhZGRyZXNzGAEgASgMEg4KBnRvcGljcxgCIAMoDBIPCgd0eF9oYXNoGAMgASgMEhIKCmJsb2NrX2hhc2gYBCABKAwSDAoEZGF0YRgFIAEoDBIRCglldmVudF9zaWcYBiABKAwSJwoMYmxvY2tfbnVtYmVyGAcgASgLMhEudmFsdWVzLnYxLkJpZ0ludBIQCgh0eF9pbmRleBgIIAEoDRINCgVpbmRleBgJIAEoDRIPCgdyZW1vdmVkGAogASgIIjEKB0NhbGxNc2cSDAoEZnJvbRgBIAEoDBIKCgJ0bxgCIAEoDBIMCgRkYXRhGAMgASgMIr0BCgtGaWx0ZXJRdWVyeRISCgpibG9ja19oYXNoGAEgASgMEiUKCmZyb21fYmxvY2sYAiABKAsyES52YWx1ZXMudjEuQmlnSW50EiMKCHRvX2Jsb2NrGAMgASgLMhEudmFsdWVzLnYxLkJpZ0ludBIRCglhZGRyZXNzZXMYBCADKAwSOwoGdG9waWNzGAUgAygLMisuY2FwYWJpbGl0aWVzLmJsb2NrY2hhaW4uZXZtLnYxYWxwaGEuVG9waWNzIhcKBlRvcGljcxINCgV0b3BpYxgBIAMoDCJMChBCYWxhbmNlQXRSZXF1ZXN0Eg8KB2FjY291bnQYASABKAwSJwoMYmxvY2tfbnVtYmVyGAIgASgLMhEudmFsdWVzLnYxLkJpZ0ludCI0Cg5CYWxhbmNlQXRSZXBseRIiCgdiYWxhbmNlGAEgASgLMhEudmFsdWVzLnYxLkJpZ0ludCJPChJFc3RpbWF0ZUdhc1JlcXVlc3QSOQoDbXNnGAEgASgLMiwuY2FwYWJpbGl0aWVzLmJsb2NrY2hhaW4uZXZtLnYxYWxwaGEuQ2FsbE1zZyIjChBFc3RpbWF0ZUdhc1JlcGx5Eg8KA2dhcxgBIAEoBEICMAAiKwobR2V0VHJhbnNhY3Rpb25CeUhhc2hSZXF1ZXN0EgwKBGhhc2gYASABKAwiYgoZR2V0VHJhbnNhY3Rpb25CeUhhc2hSZXBseRJFCgt0cmFuc2FjdGlvbhgBIAEoCzIwLmNhcGFiaWxpdGllcy5ibG9ja2NoYWluLmV2bS52MWFscGhhLlRyYW5zYWN0aW9uIqEBCgtUcmFuc2FjdGlvbhIRCgVub25jZRgBIAEoBEICMAASDwoDZ2FzGAIgASgEQgIwABIKCgJ0bxgDIAEoDBIMCgRkYXRhGAQgASgMEgwKBGhhc2gYBSABKAwSIAoFdmFsdWUYBiABKAsyES52YWx1ZXMudjEuQmlnSW50EiQKCWdhc19wcmljZRgHIAEoCzIRLnZhbHVlcy52MS5CaWdJbnQiLAocR2V0VHJhbnNhY3Rpb25SZWNlaXB0UmVxdWVzdBIMCgRoYXNoGAEgASgMIlsKGkdldFRyYW5zYWN0aW9uUmVjZWlwdFJlcGx5Ej0KB3JlY2VpcHQYASABKAsyLC5jYXBhYmlsaXRpZXMuYmxvY2tjaGFpbi5ldm0udjFhbHBoYS5SZWNlaXB0IpkCCgdSZWNlaXB0EhIKBnN0YXR1cxgBIAEoBEICMAASFAoIZ2FzX3VzZWQYAiABKARCAjAAEhQKCHR4X2luZGV4GAMgASgEQgIwABISCgpibG9ja19oYXNoGAQgASgMEjYKBGxvZ3MYBiADKAsyKC5jYXBhYmlsaXRpZXMuYmxvY2tjaGFpbi5ldm0udjFhbHBoYS5Mb2cSDwoHdHhfaGFzaBgHIAEoDBIuChNlZmZlY3RpdmVfZ2FzX3ByaWNlGAggASgLMhEudmFsdWVzLnYxLkJpZ0ludBInCgxibG9ja19udW1iZXIYCSABKAsyES52YWx1ZXMudjEuQmlnSW50EhgKEGNvbnRyYWN0X2FkZHJlc3MYCiABKAwiQAoVSGVhZGVyQnlOdW1iZXJSZXF1ZXN0EicKDGJsb2NrX251bWJlchgBIAEoCzIRLnZhbHVlcy52MS5CaWdJbnQiUgoTSGVhZGVyQnlOdW1iZXJSZXBseRI7CgZoZWFkZXIYASABKAsyKy5jYXBhYmlsaXRpZXMuYmxvY2tjaGFpbi5ldm0udjFhbHBoYS5IZWFkZXIiawoGSGVhZGVyEhUKCXRpbWVzdGFtcBgBIAEoBEICMAASJwoMYmxvY2tfbnVtYmVyGAIgASgLMhEudmFsdWVzLnYxLkJpZ0ludBIMCgRoYXNoGAMgASgMEhMKC3BhcmVudF9oYXNoGAQgASgMIqsBChJXcml0ZVJlcG9ydFJlcXVlc3QSEAoIcmVjZWl2ZXIYASABKAwSKwoGcmVwb3J0GAIgASgLMhsuc2RrLnYxYWxwaGEuUmVwb3J0UmVzcG9uc2USRwoKZ2FzX2NvbmZpZxgDIAEoCzIuLmNhcGFiaWxpdGllcy5ibG9ja2NoYWluLmV2bS52MWFscGhhLkdhc0NvbmZpZ0gAiAEBQg0KC19nYXNfY29uZmlnIiIKCUdhc0NvbmZpZxIVCglnYXNfbGltaXQYASABKARCAjAAIocDChBXcml0ZVJlcG9ydFJlcGx5EkAKCXR4X3N0YXR1cxgBIAEoDjItLmNhcGFiaWxpdGllcy5ibG9ja2NoYWluLmV2bS52MWFscGhhLlR4U3RhdHVzEnUKInJlY2VpdmVyX2NvbnRyYWN0X2V4ZWN1dGlvbl9zdGF0dXMYAiABKA4yRC5jYXBhYmlsaXRpZXMuYmxvY2tjaGFpbi5ldm0udjFhbHBoYS5SZWNlaXZlckNvbnRyYWN0RXhlY3V0aW9uU3RhdHVzSACIAQESFAoHdHhfaGFzaBgDIAEoDEgBiAEBEi8KD3RyYW5zYWN0aW9uX2ZlZRgEIAEoCzIRLnZhbHVlcy52MS5CaWdJbnRIAogBARIaCg1lcnJvcl9tZXNzYWdlGAUgASgJSAOIAQFCJQojX3JlY2VpdmVyX2NvbnRyYWN0X2V4ZWN1dGlvbl9zdGF0dXNCCgoIX3R4X2hhc2hCEgoQX3RyYW5zYWN0aW9uX2ZlZUIQCg5fZXJyb3JfbWVzc2FnZSppCg9Db25maWRlbmNlTGV2ZWwSGQoVQ09ORklERU5DRV9MRVZFTF9TQUZFEAASGwoXQ09ORklERU5DRV9MRVZFTF9MQVRFU1QQARIeChpDT05GSURFTkNFX0xFVkVMX0ZJTkFMSVpFRBACKoIBCh9SZWNlaXZlckNvbnRyYWN0RXhlY3V0aW9uU3RhdHVzEi4KKlJFQ0VJVkVSX0NPTlRSQUNUX0VYRUNVVElPTl9TVEFUVVNfU1VDQ0VTUxAAEi8KK1JFQ0VJVkVSX0NPTlRSQUNUX0VYRUNVVElPTl9TVEFUVVNfUkVWRVJURUQQASpOCghUeFN0YXR1cxITCg9UWF9TVEFUVVNfRkFUQUwQABIWChJUWF9TVEFUVVNfUkVWRVJURUQQARIVChFUWF9TVEFUVVNfU1VDQ0VTUxACMuMbCgZDbGllbnQSgAEKDENhbGxDb250cmFjdBI4LmNhcGFiaWxpdGllcy5ibG9ja2NoYWluLmV2bS52MWFscGhhLkNhbGxDb250cmFjdFJlcXVlc3QaNi5jYXBhYmlsaXRpZXMuYmxvY2tjaGFpbi5ldm0udjFhbHBoYS5DYWxsQ29udHJhY3RSZXBseRJ6CgpGaWx0ZXJMb2dzEjYuY2FwYWJpbGl0aWVzLmJsb2NrY2hhaW4uZXZtLnYxYWxwaGEuRmlsdGVyTG9nc1JlcXVlc3QaNC5jYXBhYmlsaXRpZXMuYmxvY2tjaGFpbi5ldm0udjFhbHBoYS5GaWx0ZXJMb2dzUmVwbHkSdwoJQmFsYW5jZUF0EjUuY2FwYWJpbGl0aWVzLmJsb2NrY2hhaW4uZXZtLnYxYWxwaGEuQmFsYW5jZUF0UmVxdWVzdBozLmNhcGFiaWxpdGllcy5ibG9ja2NoYWluLmV2bS52MWFscGhhLkJhbGFuY2VBdFJlcGx5En0KC0VzdGltYXRlR2FzEjcuY2FwYWJpbGl0aWVzLmJsb2NrY2hhaW4uZXZtLnYxYWxwaGEuRXN0aW1hdGVHYXNSZXF1ZXN0GjUuY2FwYWJpbGl0aWVzLmJsb2NrY2hhaW4uZXZtLnYxYWxwaGEuRXN0aW1hdGVHYXNSZXBseRKYAQoUR2V0VHJhbnNhY3Rpb25CeUhhc2gSQC5jYXBhYmlsaXRpZXMuYmxvY2tjaGFpbi5ldm0udjFhbHBoYS5HZXRUcmFuc2FjdGlvbkJ5SGFzaFJlcXVlc3QaPi5jYXBhYmlsaXRpZXMuYmxvY2tjaGFpbi5ldm0udjFhbHBoYS5HZXRUcmFuc2FjdGlvbkJ5SGFzaFJlcGx5EpsBChVHZXRUcmFuc2FjdGlvblJlY2VpcHQSQS5jYXBhYmlsaXRpZXMuYmxvY2tjaGFpbi5ldm0udjFhbHBoYS5HZXRUcmFuc2FjdGlvblJlY2VpcHRSZXF1ZXN0Gj8uY2FwYWJpbGl0aWVzLmJsb2NrY2hhaW4uZXZtLnYxYWxwaGEuR2V0VHJhbnNhY3Rpb25SZWNlaXB0UmVwbHkShgEKDkhlYWRlckJ5TnVtYmVyEjouY2FwYWJpbGl0aWVzLmJsb2NrY2hhaW4uZXZtLnYxYWxwaGEuSGVhZGVyQnlOdW1iZXJSZXF1ZXN0GjguY2FwYWJpbGl0aWVzLmJsb2NrY2hhaW4uZXZtLnYxYWxwaGEuSGVhZGVyQnlOdW1iZXJSZXBseRJ2CgpMb2dUcmlnZ2VyEjwuY2FwYWJpbGl0aWVzLmJsb2NrY2hhaW4uZXZtLnYxYWxwaGEuRmlsdGVyTG9nVHJpZ2dlclJlcXVlc3QaKC5jYXBhYmlsaXRpZXMuYmxvY2tjaGFpbi5ldm0udjFhbHBoYS5Mb2cwARJ9CgtXcml0ZVJlcG9ydBI3LmNhcGFiaWxpdGllcy5ibG9ja2NoYWluLmV2bS52MWFscGhhLldyaXRlUmVwb3J0UmVxdWVzdBo1LmNhcGFiaWxpdGllcy5ibG9ja2NoYWluLmV2bS52MWFscGhhLldyaXRlUmVwb3J0UmVwbHkaqBKCtRijEggBEglldm1AMS4wLjAakxIKDUNoYWluU2VsZWN0b3ISgRIS/hEKFwoLYWRpLW1haW5uZXQQ/PDmwrfn3ao4ChgKC2FkaS10ZXN0bmV0EP2myPr5hozaggEKJAoXYXBlY2hhaW4tdGVzdG5ldC1jdXJ0aXMQwcO0+I3EkrKJAQoXCgthcmMtdGVzdG5ldBDnxoye19fQjSoKHQoRYXZhbGFuY2hlLW1haW5uZXQQ1eeKwOHVmKRZCiMKFmF2YWxhbmNoZS10ZXN0bmV0LWZ1amkQm/n8kKLjqPjMAQooChtiaW5hbmNlX3NtYXJ0X2NoYWluLW1haW5uZXQQz/eU8djtlbidAQooChtiaW5hbmNlX3NtYXJ0X2NoYWluLXRlc3RuZXQQ+62+nICu5Iq4AQoYCgxjZWxvLW1haW5uZXQQhtTo2IaTiNcSChgKDGNlbG8tc2Vwb2xpYRDEw/yL/OedmjQKGgoOY3Jvbm9zLXRlc3RuZXQQ/dnureDe2sgpCiIKFWR0Y2MtbWFpbm5ldC1hcHBjaGFpbhDU1LHj17uKzsABCiIKFWR0Y2MtdGVzdG5ldC1hbmRlc2l0ZRDSg+PQmZblpNcBChwKEGV0aGVyZXVtLW1haW5uZXQQlfbx5M+ypsJFCicKG2V0aGVyZXVtLW1haW5uZXQtYXJiaXRydW0tMRDE6I3Njpuh10QKJAoXZXRoZXJldW0tbWFpbm5ldC1iYXNlLTEQgv+rov65kNPdAQoiChZldGhlcmV1bS1tYWlubmV0LWluay0xEKCwpum35qqEMAokChhldGhlcmV1bS1tYWlubmV0LWxpbmVhLTEQtrrpmMu9sJtACiUKGWV0aGVyZXVtLW1haW5uZXQtbWFudGxlLTEQiue0leewg8wVCicKG2V0aGVyZXVtLW1haW5uZXQtb3B0aW1pc20tMRC4lY/D9/7Q6TMKJgoZZXRoZXJldW0tbWFpbm5ldC1zY3JvbGwtMRC4vOTrxL7In7cBCikKHWV0aGVyZXVtLW1haW5uZXQtd29ybGRjaGFpbi0xEIfvurfFtsK4HAolChlldGhlcmV1bS1tYWlubmV0LXhsYXllci0xEJal/JymqO/tKQolChlldGhlcmV1bS1tYWlubmV0LXprc3luYy0xEJTul9nttLHXFQojChZldGhlcmV1bS10ZXN0bmV0LWhvb2RpEIOkr4ny2q2IkAEKJQoYZXRoZXJldW0tdGVzdG5ldC1zZXBvbGlhENm15M78ye6g3gEKLwojZXRoZXJldW0tdGVzdG5ldC1zZXBvbGlhLWFyYml0cnVtLTEQ6s7u/+q2hKMwCiwKH2V0aGVyZXVtLXRlc3RuZXQtc2Vwb2xpYS1iYXNlLTEQuMq57/aQrsiPAQosCiBldGhlcmV1bS10ZXN0bmV0LXNlcG9saWEtbGluZWEtMRDrqtT+gvnmr08KLQohZXRoZXJldW0tdGVzdG5ldC1zZXBvbGlhLW1hbnRsZS0xENXGuO7N9vKmcgovCiNldGhlcmV1bS10ZXN0bmV0LXNlcG9saWEtb3B0aW1pc20tMRCfhsWhvtjDwEgKLQohZXRoZXJldW0tdGVzdG5ldC1zZXBvbGlhLXNjcm9sbC0xEIvptL7buu3RHwowCiNldGhlcmV1bS10ZXN0bmV0LXNlcG9saWEtdW5pY2hhaW4tMRC03v7g7JeplsQBCjEKJWV0aGVyZXVtLXRlc3RuZXQtc2Vwb2xpYS13b3JsZGNoYWluLTEQut/gxcep88VJCi0KIWV0aGVyZXVtLXRlc3RuZXQtc2Vwb2xpYS16a3N5bmMtMRC3wfz98sSA3l8KIAoUZ25vc2lzX2NoYWluLW1haW5uZXQQ9JKt2vKirroGCicKG2dub3Npc19jaGFpbi10ZXN0bmV0LWNoaWFkbxCzsYLQm6WPj3sKHwoTaHlwZXJsaXF1aWQtbWFpbm5ldBCns/jdztHp8iEKHwoTaHlwZXJsaXF1aWQtdGVzdG5ldBCIzt3Il+DJvTsKIAoTaW5rLXRlc3RuZXQtc2Vwb2xpYRDo9Kel8+aWwIcBChkKDWpvdmF5LW1haW5uZXQQtcPEmqGA35IVChkKDWpvdmF5LXRlc3RuZXQQ5M+KhN6y3o4NChsKD21lZ2FldGgtbWFpbm5ldBDqlbbIvOSmyFQKHgoRbWVnYWV0aC10ZXN0bmV0LTIQ443eiLGP/ZP9AQoZCg1tb25hZC1tYWlubmV0EPnAycz/jufadQoZCg1tb25hZC10ZXN0bmV0ENCQz5Gm9OilHgokChdwaGFyb3MtYXRsYW50aWMtdGVzdG5ldBDMme3gzryvtN8BChoKDnBoYXJvcy1tYWlubmV0EMjBh571782hbAobCg5wbGFzbWEtbWFpbm5ldBD4m/HR2snVxoEBChoKDnBsYXNtYS10ZXN0bmV0ENWbv6XDtJmHNwobCg9wb2x5Z29uLW1haW5uZXQQsavk8JqShp04CiEKFHBvbHlnb24tdGVzdG5ldC1hbW95EM2P1t/xx5D64QEKJAoYcHJpdmF0ZS10ZXN0bmV0LWFuZGVzaXRlENSmmKXBj9z8XwojChZwcml2YXRlLXRlc3RuZXQtYmFzYWx0EP/t5OTou7vp/gEKIgoWcHJpdmF0ZS10ZXN0bmV0LXB1bWljZRD5wsS2xKXE2xUKJQoZcHJpdmF0ZS10ZXN0bmV0LXF1YXJ0eml0ZRD58KLdrN2H+jkKJAoYcHJpdmF0ZS10ZXN0bmV0LXJoeW9saXRlEIH6ievhtNuxCAodChFyb2Jpbmhvb2QtdGVzdG5ldBDI7fy+ppGomxwKGQoNc29uaWMtbWFpbm5ldBDRsuXt2aCynRcKGQoNc29uaWMtdGVzdG5ldBDIiPvUtMb6vBgKGwoOc3RhYmxlLXRlc3RuZXQQnZGLs6WgpdWjAQoaCg10LXJleC10ZXN0bmV0EP3A49zL/Yi19AEKGAoLdGFjLXRlc3RuZXQQ1duN4/ufk9eDAQoiChZ0ZW1wby10ZXN0bmV0LW1vZGVyYXRvEJObwOnkhI2wdQobCg54bGF5ZXItdGVzdG5ldBDJvqG0rcy83Y0BQuUBCidjb20uY2FwYWJpbGl0aWVzLmJsb2NrY2hhaW4uZXZtLnYxYWxwaGFCC0NsaWVudFByb3RvUAGiAgNDQkWqAiNDYXBhYmlsaXRpZXMuQmxvY2tjaGFpbi5Fdm0uVjFhbHBoYcoCI0NhcGFiaWxpdGllc1xCbG9ja2NoYWluXEV2bVxWMWFscGhh4gIvQ2FwYWJpbGl0aWVzXEJsb2NrY2hhaW5cRXZtXFYxYWxwaGFcR1BCTWV0YWRhdGHqAiZDYXBhYmlsaXRpZXM6OkJsb2NrY2hhaW46OkV2bTo6VjFhbHBoYWIGcHJvdG8z", [file_sdk_v1alpha_sdk, file_tools_generator_v1alpha_cre_metadata, file_values_v1_values]);
var FilterLogTriggerRequestSchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 1);
var CallContractRequestSchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 2);
var CallContractReplySchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 3);
var FilterLogsRequestSchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 4);
var FilterLogsReplySchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 5);
var LogSchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 6);
var BalanceAtRequestSchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 10);
var BalanceAtReplySchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 11);
var EstimateGasRequestSchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 12);
var EstimateGasReplySchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 13);
var GetTransactionByHashRequestSchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 14);
var GetTransactionByHashReplySchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 15);
var GetTransactionReceiptRequestSchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 17);
var GetTransactionReceiptReplySchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 18);
var HeaderByNumberRequestSchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 20);
var HeaderByNumberReplySchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 21);
var WriteReportRequestSchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 23);
var GasConfigSchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 24);
var WriteReportReplySchema = /* @__PURE__ */ messageDesc(file_capabilities_blockchain_evm_v1alpha_client, 25);
var ConfidenceLevel;
(function(ConfidenceLevel) {
  ConfidenceLevel[ConfidenceLevel["SAFE"] = 0] = "SAFE";
  ConfidenceLevel[ConfidenceLevel["LATEST"] = 1] = "LATEST";
  ConfidenceLevel[ConfidenceLevel["FINALIZED"] = 2] = "FINALIZED";
})(ConfidenceLevel || (ConfidenceLevel = {}));
var ReceiverContractExecutionStatus;
(function(ReceiverContractExecutionStatus) {
  ReceiverContractExecutionStatus[ReceiverContractExecutionStatus["SUCCESS"] = 0] = "SUCCESS";
  ReceiverContractExecutionStatus[ReceiverContractExecutionStatus["REVERTED"] = 1] = "REVERTED";
})(ReceiverContractExecutionStatus || (ReceiverContractExecutionStatus = {}));
var TxStatus;
(function(TxStatus) {
  TxStatus[TxStatus["FATAL"] = 0] = "FATAL";
  TxStatus[TxStatus["REVERTED"] = 1] = "REVERTED";
  TxStatus[TxStatus["SUCCESS"] = 2] = "SUCCESS";
})(TxStatus || (TxStatus = {}));
function execTyped(regex, string) {
  const match = regex.exec(string);
  return match?.groups;
}
var bytesRegex = /^bytes([1-9]|1[0-9]|2[0-9]|3[0-2])?$/;
var integerRegex = /^u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?$/;
var isTupleRegex = /^\(.+?\).*?$/;
var tupleRegex = /^tuple(?<array>(\[(\d*)\])*)$/;
function formatAbiParameter(abiParameter) {
  let type = abiParameter.type;
  if (tupleRegex.test(abiParameter.type) && "components" in abiParameter) {
    type = "(";
    const length = abiParameter.components.length;
    for (let i = 0;i < length; i++) {
      const component = abiParameter.components[i];
      type += formatAbiParameter(component);
      if (i < length - 1)
        type += ", ";
    }
    const result = execTyped(tupleRegex, abiParameter.type);
    type += `)${result?.array || ""}`;
    return formatAbiParameter({
      ...abiParameter,
      type
    });
  }
  if ("indexed" in abiParameter && abiParameter.indexed)
    type = `${type} indexed`;
  if (abiParameter.name)
    return `${type} ${abiParameter.name}`;
  return type;
}
function formatAbiParameters(abiParameters) {
  let params = "";
  const length = abiParameters.length;
  for (let i = 0;i < length; i++) {
    const abiParameter = abiParameters[i];
    params += formatAbiParameter(abiParameter);
    if (i !== length - 1)
      params += ", ";
  }
  return params;
}
function formatAbiItem(abiItem) {
  if (abiItem.type === "function")
    return `function ${abiItem.name}(${formatAbiParameters(abiItem.inputs)})${abiItem.stateMutability && abiItem.stateMutability !== "nonpayable" ? ` ${abiItem.stateMutability}` : ""}${abiItem.outputs?.length ? ` returns (${formatAbiParameters(abiItem.outputs)})` : ""}`;
  if (abiItem.type === "event")
    return `event ${abiItem.name}(${formatAbiParameters(abiItem.inputs)})`;
  if (abiItem.type === "error")
    return `error ${abiItem.name}(${formatAbiParameters(abiItem.inputs)})`;
  if (abiItem.type === "constructor")
    return `constructor(${formatAbiParameters(abiItem.inputs)})${abiItem.stateMutability === "payable" ? " payable" : ""}`;
  if (abiItem.type === "fallback")
    return `fallback() external${abiItem.stateMutability === "payable" ? " payable" : ""}`;
  return "receive() external payable";
}
var errorSignatureRegex = /^error (?<name>[a-zA-Z$_][a-zA-Z0-9$_]*)\((?<parameters>.*?)\)$/;
function isErrorSignature(signature) {
  return errorSignatureRegex.test(signature);
}
function execErrorSignature(signature) {
  return execTyped(errorSignatureRegex, signature);
}
var eventSignatureRegex = /^event (?<name>[a-zA-Z$_][a-zA-Z0-9$_]*)\((?<parameters>.*?)\)$/;
function isEventSignature(signature) {
  return eventSignatureRegex.test(signature);
}
function execEventSignature(signature) {
  return execTyped(eventSignatureRegex, signature);
}
var functionSignatureRegex = /^function (?<name>[a-zA-Z$_][a-zA-Z0-9$_]*)\((?<parameters>.*?)\)(?: (?<scope>external|public{1}))?(?: (?<stateMutability>pure|view|nonpayable|payable{1}))?(?: returns\s?\((?<returns>.*?)\))?$/;
function isFunctionSignature(signature) {
  return functionSignatureRegex.test(signature);
}
function execFunctionSignature(signature) {
  return execTyped(functionSignatureRegex, signature);
}
var structSignatureRegex = /^struct (?<name>[a-zA-Z$_][a-zA-Z0-9$_]*) \{(?<properties>.*?)\}$/;
function isStructSignature(signature) {
  return structSignatureRegex.test(signature);
}
function execStructSignature(signature) {
  return execTyped(structSignatureRegex, signature);
}
var constructorSignatureRegex = /^constructor\((?<parameters>.*?)\)(?:\s(?<stateMutability>payable{1}))?$/;
function isConstructorSignature(signature) {
  return constructorSignatureRegex.test(signature);
}
function execConstructorSignature(signature) {
  return execTyped(constructorSignatureRegex, signature);
}
var fallbackSignatureRegex = /^fallback\(\) external(?:\s(?<stateMutability>payable{1}))?$/;
function isFallbackSignature(signature) {
  return fallbackSignatureRegex.test(signature);
}
function execFallbackSignature(signature) {
  return execTyped(fallbackSignatureRegex, signature);
}
var receiveSignatureRegex = /^receive\(\) external payable$/;
function isReceiveSignature(signature) {
  return receiveSignatureRegex.test(signature);
}
var modifiers = new Set([
  "memory",
  "indexed",
  "storage",
  "calldata"
]);
var eventModifiers = new Set(["indexed"]);
var functionModifiers = new Set([
  "calldata",
  "memory",
  "storage"
]);
var version = "1.2.3";

class BaseError extends Error {
  constructor(shortMessage, args = {}) {
    const details = args.cause instanceof BaseError ? args.cause.details : args.cause?.message ? args.cause.message : args.details;
    const docsPath = args.cause instanceof BaseError ? args.cause.docsPath || args.docsPath : args.docsPath;
    const message = [
      shortMessage || "An error occurred.",
      "",
      ...args.metaMessages ? [...args.metaMessages, ""] : [],
      ...docsPath ? [`Docs: https://abitype.dev${docsPath}`] : [],
      ...details ? [`Details: ${details}`] : [],
      `Version: abitype@${version}`
    ].join(`
`);
    super(message);
    Object.defineProperty(this, "details", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "docsPath", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "metaMessages", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "shortMessage", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "AbiTypeError"
    });
    if (args.cause)
      this.cause = args.cause;
    this.details = details;
    this.docsPath = docsPath;
    this.metaMessages = args.metaMessages;
    this.shortMessage = shortMessage;
  }
}

class UnknownTypeError extends BaseError {
  constructor({ type }) {
    super("Unknown type.", {
      metaMessages: [
        `Type "${type}" is not a valid ABI type. Perhaps you forgot to include a struct signature?`
      ]
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "UnknownTypeError"
    });
  }
}

class UnknownSolidityTypeError extends BaseError {
  constructor({ type }) {
    super("Unknown type.", {
      metaMessages: [`Type "${type}" is not a valid ABI type.`]
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "UnknownSolidityTypeError"
    });
  }
}

class InvalidAbiParametersError extends BaseError {
  constructor({ params }) {
    super("Failed to parse ABI parameters.", {
      details: `parseAbiParameters(${JSON.stringify(params, null, 2)})`,
      docsPath: "/api/human#parseabiparameters-1"
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "InvalidAbiParametersError"
    });
  }
}

class InvalidParameterError extends BaseError {
  constructor({ param }) {
    super("Invalid ABI parameter.", {
      details: param
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "InvalidParameterError"
    });
  }
}

class SolidityProtectedKeywordError extends BaseError {
  constructor({ param, name }) {
    super("Invalid ABI parameter.", {
      details: param,
      metaMessages: [
        `"${name}" is a protected Solidity keyword. More info: https://docs.soliditylang.org/en/latest/cheatsheet.html`
      ]
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "SolidityProtectedKeywordError"
    });
  }
}

class InvalidModifierError extends BaseError {
  constructor({ param, type, modifier }) {
    super("Invalid ABI parameter.", {
      details: param,
      metaMessages: [
        `Modifier "${modifier}" not allowed${type ? ` in "${type}" type` : ""}.`
      ]
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "InvalidModifierError"
    });
  }
}

class InvalidFunctionModifierError extends BaseError {
  constructor({ param, type, modifier }) {
    super("Invalid ABI parameter.", {
      details: param,
      metaMessages: [
        `Modifier "${modifier}" not allowed${type ? ` in "${type}" type` : ""}.`,
        `Data location can only be specified for array, struct, or mapping types, but "${modifier}" was given.`
      ]
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "InvalidFunctionModifierError"
    });
  }
}

class InvalidAbiTypeParameterError extends BaseError {
  constructor({ abiParameter }) {
    super("Invalid ABI parameter.", {
      details: JSON.stringify(abiParameter, null, 2),
      metaMessages: ["ABI parameter type is invalid."]
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "InvalidAbiTypeParameterError"
    });
  }
}

class InvalidSignatureError extends BaseError {
  constructor({ signature, type }) {
    super(`Invalid ${type} signature.`, {
      details: signature
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "InvalidSignatureError"
    });
  }
}

class UnknownSignatureError extends BaseError {
  constructor({ signature }) {
    super("Unknown signature.", {
      details: signature
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "UnknownSignatureError"
    });
  }
}

class InvalidStructSignatureError extends BaseError {
  constructor({ signature }) {
    super("Invalid struct signature.", {
      details: signature,
      metaMessages: ["No properties exist."]
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "InvalidStructSignatureError"
    });
  }
}

class CircularReferenceError extends BaseError {
  constructor({ type }) {
    super("Circular reference detected.", {
      metaMessages: [`Struct "${type}" is a circular reference.`]
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "CircularReferenceError"
    });
  }
}

class InvalidParenthesisError extends BaseError {
  constructor({ current, depth }) {
    super("Unbalanced parentheses.", {
      metaMessages: [
        `"${current.trim()}" has too many ${depth > 0 ? "opening" : "closing"} parentheses.`
      ],
      details: `Depth "${depth}"`
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "InvalidParenthesisError"
    });
  }
}
function getParameterCacheKey(param, type, structs) {
  let structKey = "";
  if (structs)
    for (const struct of Object.entries(structs)) {
      if (!struct)
        continue;
      let propertyKey = "";
      for (const property of struct[1]) {
        propertyKey += `[${property.type}${property.name ? `:${property.name}` : ""}]`;
      }
      structKey += `(${struct[0]}{${propertyKey}})`;
    }
  if (type)
    return `${type}:${param}${structKey}`;
  return `${param}${structKey}`;
}
var parameterCache = new Map([
  ["address", { type: "address" }],
  ["bool", { type: "bool" }],
  ["bytes", { type: "bytes" }],
  ["bytes32", { type: "bytes32" }],
  ["int", { type: "int256" }],
  ["int256", { type: "int256" }],
  ["string", { type: "string" }],
  ["uint", { type: "uint256" }],
  ["uint8", { type: "uint8" }],
  ["uint16", { type: "uint16" }],
  ["uint24", { type: "uint24" }],
  ["uint32", { type: "uint32" }],
  ["uint64", { type: "uint64" }],
  ["uint96", { type: "uint96" }],
  ["uint112", { type: "uint112" }],
  ["uint160", { type: "uint160" }],
  ["uint192", { type: "uint192" }],
  ["uint256", { type: "uint256" }],
  ["address owner", { type: "address", name: "owner" }],
  ["address to", { type: "address", name: "to" }],
  ["bool approved", { type: "bool", name: "approved" }],
  ["bytes _data", { type: "bytes", name: "_data" }],
  ["bytes data", { type: "bytes", name: "data" }],
  ["bytes signature", { type: "bytes", name: "signature" }],
  ["bytes32 hash", { type: "bytes32", name: "hash" }],
  ["bytes32 r", { type: "bytes32", name: "r" }],
  ["bytes32 root", { type: "bytes32", name: "root" }],
  ["bytes32 s", { type: "bytes32", name: "s" }],
  ["string name", { type: "string", name: "name" }],
  ["string symbol", { type: "string", name: "symbol" }],
  ["string tokenURI", { type: "string", name: "tokenURI" }],
  ["uint tokenId", { type: "uint256", name: "tokenId" }],
  ["uint8 v", { type: "uint8", name: "v" }],
  ["uint256 balance", { type: "uint256", name: "balance" }],
  ["uint256 tokenId", { type: "uint256", name: "tokenId" }],
  ["uint256 value", { type: "uint256", name: "value" }],
  [
    "event:address indexed from",
    { type: "address", name: "from", indexed: true }
  ],
  ["event:address indexed to", { type: "address", name: "to", indexed: true }],
  [
    "event:uint indexed tokenId",
    { type: "uint256", name: "tokenId", indexed: true }
  ],
  [
    "event:uint256 indexed tokenId",
    { type: "uint256", name: "tokenId", indexed: true }
  ]
]);
function parseSignature(signature, structs = {}) {
  if (isFunctionSignature(signature))
    return parseFunctionSignature(signature, structs);
  if (isEventSignature(signature))
    return parseEventSignature(signature, structs);
  if (isErrorSignature(signature))
    return parseErrorSignature(signature, structs);
  if (isConstructorSignature(signature))
    return parseConstructorSignature(signature, structs);
  if (isFallbackSignature(signature))
    return parseFallbackSignature(signature);
  if (isReceiveSignature(signature))
    return {
      type: "receive",
      stateMutability: "payable"
    };
  throw new UnknownSignatureError({ signature });
}
function parseFunctionSignature(signature, structs = {}) {
  const match = execFunctionSignature(signature);
  if (!match)
    throw new InvalidSignatureError({ signature, type: "function" });
  const inputParams = splitParameters(match.parameters);
  const inputs = [];
  const inputLength = inputParams.length;
  for (let i = 0;i < inputLength; i++) {
    inputs.push(parseAbiParameter(inputParams[i], {
      modifiers: functionModifiers,
      structs,
      type: "function"
    }));
  }
  const outputs = [];
  if (match.returns) {
    const outputParams = splitParameters(match.returns);
    const outputLength = outputParams.length;
    for (let i = 0;i < outputLength; i++) {
      outputs.push(parseAbiParameter(outputParams[i], {
        modifiers: functionModifiers,
        structs,
        type: "function"
      }));
    }
  }
  return {
    name: match.name,
    type: "function",
    stateMutability: match.stateMutability ?? "nonpayable",
    inputs,
    outputs
  };
}
function parseEventSignature(signature, structs = {}) {
  const match = execEventSignature(signature);
  if (!match)
    throw new InvalidSignatureError({ signature, type: "event" });
  const params = splitParameters(match.parameters);
  const abiParameters = [];
  const length = params.length;
  for (let i = 0;i < length; i++)
    abiParameters.push(parseAbiParameter(params[i], {
      modifiers: eventModifiers,
      structs,
      type: "event"
    }));
  return { name: match.name, type: "event", inputs: abiParameters };
}
function parseErrorSignature(signature, structs = {}) {
  const match = execErrorSignature(signature);
  if (!match)
    throw new InvalidSignatureError({ signature, type: "error" });
  const params = splitParameters(match.parameters);
  const abiParameters = [];
  const length = params.length;
  for (let i = 0;i < length; i++)
    abiParameters.push(parseAbiParameter(params[i], { structs, type: "error" }));
  return { name: match.name, type: "error", inputs: abiParameters };
}
function parseConstructorSignature(signature, structs = {}) {
  const match = execConstructorSignature(signature);
  if (!match)
    throw new InvalidSignatureError({ signature, type: "constructor" });
  const params = splitParameters(match.parameters);
  const abiParameters = [];
  const length = params.length;
  for (let i = 0;i < length; i++)
    abiParameters.push(parseAbiParameter(params[i], { structs, type: "constructor" }));
  return {
    type: "constructor",
    stateMutability: match.stateMutability ?? "nonpayable",
    inputs: abiParameters
  };
}
function parseFallbackSignature(signature) {
  const match = execFallbackSignature(signature);
  if (!match)
    throw new InvalidSignatureError({ signature, type: "fallback" });
  return {
    type: "fallback",
    stateMutability: match.stateMutability ?? "nonpayable"
  };
}
var abiParameterWithoutTupleRegex = /^(?<type>[a-zA-Z$_][a-zA-Z0-9$_]*(?:\spayable)?)(?<array>(?:\[\d*?\])+?)?(?:\s(?<modifier>calldata|indexed|memory|storage{1}))?(?:\s(?<name>[a-zA-Z$_][a-zA-Z0-9$_]*))?$/;
var abiParameterWithTupleRegex = /^\((?<type>.+?)\)(?<array>(?:\[\d*?\])+?)?(?:\s(?<modifier>calldata|indexed|memory|storage{1}))?(?:\s(?<name>[a-zA-Z$_][a-zA-Z0-9$_]*))?$/;
var dynamicIntegerRegex = /^u?int$/;
function parseAbiParameter(param, options) {
  const parameterCacheKey = getParameterCacheKey(param, options?.type, options?.structs);
  if (parameterCache.has(parameterCacheKey))
    return parameterCache.get(parameterCacheKey);
  const isTuple = isTupleRegex.test(param);
  const match = execTyped(isTuple ? abiParameterWithTupleRegex : abiParameterWithoutTupleRegex, param);
  if (!match)
    throw new InvalidParameterError({ param });
  if (match.name && isSolidityKeyword(match.name))
    throw new SolidityProtectedKeywordError({ param, name: match.name });
  const name = match.name ? { name: match.name } : {};
  const indexed = match.modifier === "indexed" ? { indexed: true } : {};
  const structs = options?.structs ?? {};
  let type;
  let components = {};
  if (isTuple) {
    type = "tuple";
    const params = splitParameters(match.type);
    const components_ = [];
    const length = params.length;
    for (let i = 0;i < length; i++) {
      components_.push(parseAbiParameter(params[i], { structs }));
    }
    components = { components: components_ };
  } else if (match.type in structs) {
    type = "tuple";
    components = { components: structs[match.type] };
  } else if (dynamicIntegerRegex.test(match.type)) {
    type = `${match.type}256`;
  } else if (match.type === "address payable") {
    type = "address";
  } else {
    type = match.type;
    if (!(options?.type === "struct") && !isSolidityType(type))
      throw new UnknownSolidityTypeError({ type });
  }
  if (match.modifier) {
    if (!options?.modifiers?.has?.(match.modifier))
      throw new InvalidModifierError({
        param,
        type: options?.type,
        modifier: match.modifier
      });
    if (functionModifiers.has(match.modifier) && !isValidDataLocation(type, !!match.array))
      throw new InvalidFunctionModifierError({
        param,
        type: options?.type,
        modifier: match.modifier
      });
  }
  const abiParameter = {
    type: `${type}${match.array ?? ""}`,
    ...name,
    ...indexed,
    ...components
  };
  parameterCache.set(parameterCacheKey, abiParameter);
  return abiParameter;
}
function splitParameters(params, result = [], current = "", depth = 0) {
  const length = params.trim().length;
  for (let i = 0;i < length; i++) {
    const char = params[i];
    const tail = params.slice(i + 1);
    switch (char) {
      case ",":
        return depth === 0 ? splitParameters(tail, [...result, current.trim()]) : splitParameters(tail, result, `${current}${char}`, depth);
      case "(":
        return splitParameters(tail, result, `${current}${char}`, depth + 1);
      case ")":
        return splitParameters(tail, result, `${current}${char}`, depth - 1);
      default:
        return splitParameters(tail, result, `${current}${char}`, depth);
    }
  }
  if (current === "")
    return result;
  if (depth !== 0)
    throw new InvalidParenthesisError({ current, depth });
  result.push(current.trim());
  return result;
}
function isSolidityType(type) {
  return type === "address" || type === "bool" || type === "function" || type === "string" || bytesRegex.test(type) || integerRegex.test(type);
}
var protectedKeywordsRegex = /^(?:after|alias|anonymous|apply|auto|byte|calldata|case|catch|constant|copyof|default|defined|error|event|external|false|final|function|immutable|implements|in|indexed|inline|internal|let|mapping|match|memory|mutable|null|of|override|partial|private|promise|public|pure|reference|relocatable|return|returns|sizeof|static|storage|struct|super|supports|switch|this|true|try|typedef|typeof|var|view|virtual)$/;
function isSolidityKeyword(name) {
  return name === "address" || name === "bool" || name === "function" || name === "string" || name === "tuple" || bytesRegex.test(name) || integerRegex.test(name) || protectedKeywordsRegex.test(name);
}
function isValidDataLocation(type, isArray) {
  return isArray || type === "bytes" || type === "string" || type === "tuple";
}
function parseStructs(signatures) {
  const shallowStructs = {};
  const signaturesLength = signatures.length;
  for (let i = 0;i < signaturesLength; i++) {
    const signature = signatures[i];
    if (!isStructSignature(signature))
      continue;
    const match = execStructSignature(signature);
    if (!match)
      throw new InvalidSignatureError({ signature, type: "struct" });
    const properties = match.properties.split(";");
    const components = [];
    const propertiesLength = properties.length;
    for (let k = 0;k < propertiesLength; k++) {
      const property = properties[k];
      const trimmed = property.trim();
      if (!trimmed)
        continue;
      const abiParameter = parseAbiParameter(trimmed, {
        type: "struct"
      });
      components.push(abiParameter);
    }
    if (!components.length)
      throw new InvalidStructSignatureError({ signature });
    shallowStructs[match.name] = components;
  }
  const resolvedStructs = {};
  const entries = Object.entries(shallowStructs);
  const entriesLength = entries.length;
  for (let i = 0;i < entriesLength; i++) {
    const [name, parameters] = entries[i];
    resolvedStructs[name] = resolveStructs(parameters, shallowStructs);
  }
  return resolvedStructs;
}
var typeWithoutTupleRegex = /^(?<type>[a-zA-Z$_][a-zA-Z0-9$_]*)(?<array>(?:\[\d*?\])+?)?$/;
function resolveStructs(abiParameters = [], structs = {}, ancestors = new Set) {
  const components = [];
  const length = abiParameters.length;
  for (let i = 0;i < length; i++) {
    const abiParameter = abiParameters[i];
    const isTuple = isTupleRegex.test(abiParameter.type);
    if (isTuple)
      components.push(abiParameter);
    else {
      const match = execTyped(typeWithoutTupleRegex, abiParameter.type);
      if (!match?.type)
        throw new InvalidAbiTypeParameterError({ abiParameter });
      const { array, type } = match;
      if (type in structs) {
        if (ancestors.has(type))
          throw new CircularReferenceError({ type });
        components.push({
          ...abiParameter,
          type: `tuple${array ?? ""}`,
          components: resolveStructs(structs[type], structs, new Set([...ancestors, type]))
        });
      } else {
        if (isSolidityType(type))
          components.push(abiParameter);
        else
          throw new UnknownTypeError({ type });
      }
    }
  }
  return components;
}
function parseAbi(signatures) {
  const structs = parseStructs(signatures);
  const abi = [];
  const length = signatures.length;
  for (let i = 0;i < length; i++) {
    const signature = signatures[i];
    if (isStructSignature(signature))
      continue;
    abi.push(parseSignature(signature, structs));
  }
  return abi;
}
function parseAbiParameters(params) {
  const abiParameters = [];
  if (typeof params === "string") {
    const parameters = splitParameters(params);
    const length = parameters.length;
    for (let i = 0;i < length; i++) {
      abiParameters.push(parseAbiParameter(parameters[i], { modifiers }));
    }
  } else {
    const structs = parseStructs(params);
    const length = params.length;
    for (let i = 0;i < length; i++) {
      const signature = params[i];
      if (isStructSignature(signature))
        continue;
      const parameters = splitParameters(signature);
      const length = parameters.length;
      for (let k = 0;k < length; k++) {
        abiParameters.push(parseAbiParameter(parameters[k], { modifiers, structs }));
      }
    }
  }
  if (abiParameters.length === 0)
    throw new InvalidAbiParametersError({ params });
  return abiParameters;
}
var zeroAddress = "0x0000000000000000000000000000000000000000";
function formatAbiItem2(abiItem, { includeName = false } = {}) {
  if (abiItem.type !== "function" && abiItem.type !== "event" && abiItem.type !== "error")
    throw new InvalidDefinitionTypeError(abiItem.type);
  return `${abiItem.name}(${formatAbiParams(abiItem.inputs, { includeName })})`;
}
function formatAbiParams(params, { includeName = false } = {}) {
  if (!params)
    return "";
  return params.map((param) => formatAbiParam(param, { includeName })).join(includeName ? ", " : ",");
}
function formatAbiParam(param, { includeName }) {
  if (param.type.startsWith("tuple")) {
    return `(${formatAbiParams(param.components, { includeName })})${param.type.slice("tuple".length)}`;
  }
  return param.type + (includeName && param.name ? ` ${param.name}` : "");
}
function isHex(value, { strict = true } = {}) {
  if (!value)
    return false;
  if (typeof value !== "string")
    return false;
  return strict ? /^0x[0-9a-fA-F]*$/.test(value) : value.startsWith("0x");
}
function size(value) {
  if (isHex(value, { strict: false }))
    return Math.ceil((value.length - 2) / 2);
  return value.length;
}
var version2 = "2.57.3";
var errorConfig = {
  getDocsUrl: ({ docsBaseUrl, docsPath = "", docsSlug }) => docsPath ? `${docsBaseUrl ?? "https://viem.sh"}${docsPath}${docsSlug ? `#${docsSlug}` : ""}` : undefined,
  version: `viem@${version2}`
};

class BaseError3 extends Error {
  constructor(shortMessage, args = {}) {
    const details = (() => {
      if (args.cause instanceof BaseError3)
        return args.cause.details;
      if (args.cause?.message)
        return args.cause.message;
      return args.details;
    })();
    const docsPath = (() => {
      if (args.cause instanceof BaseError3)
        return args.cause.docsPath || args.docsPath;
      return args.docsPath;
    })();
    const docsUrl = errorConfig.getDocsUrl?.({ ...args, docsPath });
    const message = [
      shortMessage || "An error occurred.",
      "",
      ...args.metaMessages ? [...args.metaMessages, ""] : [],
      ...docsUrl ? [`Docs: ${docsUrl}`] : [],
      ...details ? [`Details: ${details}`] : [],
      ...errorConfig.version ? [`Version: ${errorConfig.version}`] : []
    ].join(`
`);
    super(message, args.cause ? { cause: args.cause } : undefined);
    Object.defineProperty(this, "details", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "docsPath", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "metaMessages", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "shortMessage", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "version", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "name", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: "BaseError"
    });
    this.details = details;
    this.docsPath = docsPath;
    this.metaMessages = args.metaMessages;
    this.name = args.name ?? this.name;
    this.shortMessage = shortMessage;
    this.version = version2;
  }
  walk(fn) {
    return walk(this, fn);
  }
}
function walk(err, fn) {
  if (fn?.(err))
    return err;
  if (err && typeof err === "object" && "cause" in err && err.cause !== undefined)
    return walk(err.cause, fn);
  return fn ? null : err;
}

class AbiDecodingDataSizeTooSmallError extends BaseError3 {
  constructor({ data, params, size }) {
    super([`Data size of ${size} bytes is too small for given parameters.`].join(`
`), {
      metaMessages: [
        `Params: (${formatAbiParams(params, { includeName: true })})`,
        `Data:   ${data} (${size} bytes)`
      ],
      name: "AbiDecodingDataSizeTooSmallError"
    });
    Object.defineProperty(this, "data", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "params", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    Object.defineProperty(this, "size", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.data = data;
    this.params = params;
    this.size = size;
  }
}

class AbiDecodingZeroDataError extends BaseError3 {
  constructor({ cause } = {}) {
    super('Cannot decode zero data ("0x") with ABI parameters.', {
      name: "AbiDecodingZeroDataError",
      cause
    });
  }
}

class AbiEncodingArrayLengthMismatchError extends BaseError3 {
  constructor({ expectedLength, givenLength, type }) {
    super([
      `ABI encoding array length mismatch for type ${type}.`,
      `Expected length: ${expectedLength}`,
      `Given length: ${givenLength}`
    ].join(`
`), { name: "AbiEncodingArrayLengthMismatchError" });
  }
}

class AbiEncodingBytesSizeMismatchError extends BaseError3 {
  constructor({ expectedSize, value }) {
    super(`Size of bytes "${value}" (bytes${size(value)}) does not match expected size (bytes${expectedSize}).`, { name: "AbiEncodingBytesSizeMismatchError" });
  }
}

class AbiEncodingLengthMismatchError extends BaseError3 {
  constructor({ expectedLength, givenLength }) {
    super([
      "ABI encoding params/values length mismatch.",
      `Expected length (params): ${expectedLength}`,
      `Given length (values): ${givenLength}`
    ].join(`
`), { name: "AbiEncodingLengthMismatchError" });
  }
}

class AbiFunctionNotFoundError extends BaseError3 {
  constructor(functionName, { docsPath } = {}) {
    super([
      `Function ${functionName ? `"${functionName}" ` : ""}not found on ABI.`,
      "Make sure you are using the correct ABI and that the function exists on it."
    ].join(`
`), {
      docsPath,
      name: "AbiFunctionNotFoundError"
    });
  }
}

class AbiFunctionOutputsNotFoundError extends BaseError3 {
  constructor(functionName, { docsPath }) {
    super([
      `Function "${functionName}" does not contain any \`outputs\` on ABI.`,
      "Cannot decode function result without knowing what the parameter types are.",
      "Make sure you are using the correct ABI and that the function exists on it."
    ].join(`
`), {
      docsPath,
      name: "AbiFunctionOutputsNotFoundError"
    });
  }
}

class AbiItemAmbiguityError extends BaseError3 {
  constructor(x, y) {
    super("Found ambiguous types in overloaded ABI items.", {
      metaMessages: [
        `\`${x.type}\` in \`${formatAbiItem2(x.abiItem)}\`, and`,
        `\`${y.type}\` in \`${formatAbiItem2(y.abiItem)}\``,
        "",
        "These types encode differently and cannot be distinguished at runtime.",
        "Remove one of the ambiguous items in the ABI."
      ],
      name: "AbiItemAmbiguityError"
    });
  }
}

class InvalidAbiEncodingTypeError extends BaseError3 {
  constructor(type, { docsPath }) {
    super([
      `Type "${type}" is not a valid encoding type.`,
      "Please provide a valid ABI type."
    ].join(`
`), { docsPath, name: "InvalidAbiEncodingType" });
  }
}

class InvalidAbiDecodingTypeError extends BaseError3 {
  constructor(type, { docsPath }) {
    super([
      `Type "${type}" is not a valid decoding type.`,
      "Please provide a valid ABI type."
    ].join(`
`), { docsPath, name: "InvalidAbiDecodingType" });
  }
}

class InvalidArrayError extends BaseError3 {
  constructor(value) {
    super([`Value "${value}" is not a valid array.`].join(`
`), {
      name: "InvalidArrayError"
    });
  }
}

class InvalidDefinitionTypeError extends BaseError3 {
  constructor(type) {
    super([
      `"${type}" is not a valid definition type.`,
      'Valid types: "function", "event", "error"'
    ].join(`
`), { name: "InvalidDefinitionTypeError" });
  }
}

class InvalidAddressError extends BaseError3 {
  constructor({ address }) {
    super(`Address "${address}" is invalid.`, {
      metaMessages: [
        "- Address must be a hex value of 20 bytes (40 hex characters).",
        "- Address must match its checksum counterpart."
      ],
      name: "InvalidAddressError"
    });
  }
}

class SliceOffsetOutOfBoundsError extends BaseError3 {
  constructor({ offset, position, size }) {
    super(`Slice ${position === "start" ? "starting" : "ending"} at offset "${offset}" is out-of-bounds (size: ${size}).`, { name: "SliceOffsetOutOfBoundsError" });
  }
}

class SizeExceedsPaddingSizeError extends BaseError3 {
  constructor({ size, targetSize, type }) {
    super(`${type.charAt(0).toUpperCase()}${type.slice(1).toLowerCase()} size (${size}) exceeds padding size (${targetSize}).`, { name: "SizeExceedsPaddingSizeError" });
  }
}
function pad(hexOrBytes, { dir, size = 32 } = {}) {
  if (typeof hexOrBytes === "string")
    return padHex(hexOrBytes, { dir, size });
  return padBytes(hexOrBytes, { dir, size });
}
function padHex(hex_, { dir, size = 32 } = {}) {
  if (size === null)
    return hex_;
  const hex = hex_.replace("0x", "");
  if (hex.length > size * 2)
    throw new SizeExceedsPaddingSizeError({
      size: Math.ceil(hex.length / 2),
      targetSize: size,
      type: "hex"
    });
  return `0x${hex[dir === "right" ? "padEnd" : "padStart"](size * 2, "0")}`;
}
function padBytes(bytes, { dir, size = 32 } = {}) {
  if (size === null)
    return bytes;
  if (bytes.length > size)
    throw new SizeExceedsPaddingSizeError({
      size: bytes.length,
      targetSize: size,
      type: "bytes"
    });
  const paddedBytes = new Uint8Array(size);
  for (let i = 0;i < size; i++) {
    const padEnd = dir === "right";
    paddedBytes[padEnd ? i : size - i - 1] = bytes[padEnd ? i : bytes.length - i - 1];
  }
  return paddedBytes;
}

class IntegerOutOfRangeError extends BaseError3 {
  constructor({ max, min, signed, size, value }) {
    super(`Number "${value}" is not in safe ${size ? `${size * 8}-bit ${signed ? "signed" : "unsigned"} ` : ""}integer range ${max ? `(${min} to ${max})` : `(above ${min})`}`, { name: "IntegerOutOfRangeError" });
  }
}

class InvalidBytesBooleanError extends BaseError3 {
  constructor(bytes) {
    super(`Bytes value "${bytes}" is not a valid boolean. The bytes array must contain a single byte of either a 0 or 1 value.`, {
      name: "InvalidBytesBooleanError"
    });
  }
}

class SizeOverflowError extends BaseError3 {
  constructor({ givenSize, maxSize }) {
    super(`Size cannot exceed ${maxSize} bytes. Given size: ${givenSize} bytes.`, { name: "SizeOverflowError" });
  }
}
function trim(hexOrBytes, { dir = "left" } = {}) {
  let data = typeof hexOrBytes === "string" ? hexOrBytes.replace("0x", "") : hexOrBytes;
  let sliceLength = 0;
  for (let i = 0;i < data.length - 1; i++) {
    if (data[dir === "left" ? i : data.length - i - 1].toString() === "0")
      sliceLength++;
    else
      break;
  }
  data = dir === "left" ? data.slice(sliceLength) : data.slice(0, data.length - sliceLength);
  if (typeof hexOrBytes === "string") {
    if (data.length === 1 && dir === "right")
      data = `${data}0`;
    return `0x${data.length % 2 === 1 ? `0${data}` : data}`;
  }
  return data;
}
function assertSize(hexOrBytes, { size: size2 }) {
  if (size(hexOrBytes) > size2)
    throw new SizeOverflowError({
      givenSize: size(hexOrBytes),
      maxSize: size2
    });
}
function hexToBigInt(hex, opts = {}) {
  const { signed } = opts;
  if (opts.size)
    assertSize(hex, { size: opts.size });
  const value = BigInt(hex);
  if (!signed)
    return value;
  const size = Math.ceil((hex.length - 2) / 2);
  const max = (1n << BigInt(size) * 8n - 1n) - 1n;
  if (value <= max)
    return value;
  return value - BigInt(`0x${"f".padStart(size * 2, "f")}`) - 1n;
}
function hexToNumber(hex, opts = {}) {
  const value = hexToBigInt(hex, opts);
  const number = Number(value);
  if (!Number.isSafeInteger(number))
    throw new IntegerOutOfRangeError({
      max: `${Number.MAX_SAFE_INTEGER}`,
      min: `${Number.MIN_SAFE_INTEGER}`,
      signed: opts.signed,
      size: opts.size,
      value: `${value}n`
    });
  return number;
}
var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_v, i) => i.toString(16).padStart(2, "0"));
function toHex(value, opts = {}) {
  if (typeof value === "number" || typeof value === "bigint")
    return numberToHex(value, opts);
  if (typeof value === "string") {
    return stringToHex(value, opts);
  }
  if (typeof value === "boolean")
    return boolToHex(value, opts);
  return bytesToHex(value, opts);
}
function boolToHex(value, opts = {}) {
  const hex = `0x${Number(value)}`;
  if (typeof opts.size === "number") {
    assertSize(hex, { size: opts.size });
    return pad(hex, { size: opts.size });
  }
  return hex;
}
function bytesToHex(value, opts = {}) {
  let string = "";
  for (let i = 0;i < value.length; i++) {
    string += hexes[value[i]];
  }
  const hex = `0x${string}`;
  if (typeof opts.size === "number") {
    assertSize(hex, { size: opts.size });
    return pad(hex, { dir: "right", size: opts.size });
  }
  return hex;
}
function numberToHex(value_, opts = {}) {
  const { signed, size } = opts;
  const value = BigInt(value_);
  let maxValue;
  if (size) {
    if (signed)
      maxValue = (1n << BigInt(size) * 8n - 1n) - 1n;
    else
      maxValue = 2n ** (BigInt(size) * 8n) - 1n;
  } else if (typeof value_ === "number") {
    maxValue = BigInt(Number.MAX_SAFE_INTEGER);
  }
  const minValue = typeof maxValue === "bigint" && signed ? -maxValue - 1n : 0;
  if (maxValue && value > maxValue || value < minValue) {
    const suffix = typeof value_ === "bigint" ? "n" : "";
    throw new IntegerOutOfRangeError({
      max: maxValue ? `${maxValue}${suffix}` : undefined,
      min: `${minValue}${suffix}`,
      signed,
      size,
      value: `${value_}${suffix}`
    });
  }
  const hex = `0x${(signed && value < 0 ? (1n << BigInt(size * 8)) + BigInt(value) : value).toString(16)}`;
  if (size)
    return pad(hex, { size });
  return hex;
}
var encoder = /* @__PURE__ */ new TextEncoder;
function stringToHex(value_, opts = {}) {
  const value = encoder.encode(value_);
  return bytesToHex(value, opts);
}
var encoder2 = /* @__PURE__ */ new TextEncoder;
function toBytes(value, opts = {}) {
  if (typeof value === "number" || typeof value === "bigint")
    return numberToBytes(value, opts);
  if (typeof value === "boolean")
    return boolToBytes(value, opts);
  if (isHex(value))
    return hexToBytes(value, opts);
  return stringToBytes(value, opts);
}
function boolToBytes(value, opts = {}) {
  const bytes = new Uint8Array(1);
  bytes[0] = Number(value);
  if (typeof opts.size === "number") {
    assertSize(bytes, { size: opts.size });
    return pad(bytes, { size: opts.size });
  }
  return bytes;
}
var charCodeMap = {
  zero: 48,
  nine: 57,
  A: 65,
  F: 70,
  a: 97,
  f: 102
};
function charCodeToBase16(char) {
  if (char >= charCodeMap.zero && char <= charCodeMap.nine)
    return char - charCodeMap.zero;
  if (char >= charCodeMap.A && char <= charCodeMap.F)
    return char - (charCodeMap.A - 10);
  if (char >= charCodeMap.a && char <= charCodeMap.f)
    return char - (charCodeMap.a - 10);
  return;
}
function hexToBytes(hex_, opts = {}) {
  let hex = hex_;
  if (opts.size) {
    assertSize(hex, { size: opts.size });
    hex = pad(hex, { dir: "right", size: opts.size });
  }
  let hexString = hex.slice(2);
  if (hexString.length % 2)
    hexString = `0${hexString}`;
  const length = hexString.length / 2;
  const bytes = new Uint8Array(length);
  for (let index = 0, j = 0;index < length; index++) {
    const nibbleLeft = charCodeToBase16(hexString.charCodeAt(j++));
    const nibbleRight = charCodeToBase16(hexString.charCodeAt(j++));
    if (nibbleLeft === undefined || nibbleRight === undefined) {
      throw new BaseError3(`Invalid byte sequence ("${hexString[j - 2]}${hexString[j - 1]}" in "${hexString}").`);
    }
    bytes[index] = nibbleLeft * 16 + nibbleRight;
  }
  return bytes;
}
function numberToBytes(value, opts) {
  const hex = numberToHex(value, opts);
  return hexToBytes(hex);
}
function stringToBytes(value, opts = {}) {
  const bytes = encoder2.encode(value);
  if (typeof opts.size === "number") {
    assertSize(bytes, { size: opts.size });
    return pad(bytes, { dir: "right", size: opts.size });
  }
  return bytes;
}
var U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
var _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
  if (le)
    return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
  return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
  const len = lst.length;
  let Ah = new Uint32Array(len);
  let Al = new Uint32Array(len);
  for (let i = 0;i < len; i++) {
    const { h, l } = fromBig(lst[i], le);
    [Ah[i], Al[i]] = [h, l];
  }
  return [Ah, Al];
}
var rotlSH = (h, l, s) => h << s | l >>> 32 - s;
var rotlSL = (h, l, s) => l << s | h >>> 32 - s;
var rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
var rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array";
}
function anumber(n) {
  if (!Number.isSafeInteger(n) || n < 0)
    throw new Error("positive integer expected, got " + n);
}
function abytes(b, ...lengths) {
  if (!isBytes(b))
    throw new Error("Uint8Array expected");
  if (lengths.length > 0 && !lengths.includes(b.length))
    throw new Error("Uint8Array expected of length " + lengths + ", got length=" + b.length);
}
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (checkFinished && instance.finished)
    throw new Error("Hash#digest() has already been called");
}
function aoutput(out, instance) {
  abytes(out);
  const min = instance.outputLen;
  if (out.length < min) {
    throw new Error("digestInto() expects output buffer of length at least " + min);
  }
}
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean(...arrays) {
  for (let i = 0;i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
function byteSwap32(arr) {
  for (let i = 0;i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
var swap32IfBE = isLE ? (u) => u : byteSwap32;
function utf8ToBytes(str) {
  if (typeof str !== "string")
    throw new Error("string expected");
  return new Uint8Array(new TextEncoder().encode(str));
}
function toBytes2(data) {
  if (typeof data === "string")
    data = utf8ToBytes(data);
  abytes(data);
  return data;
}

class Hash {
}
function createHasher(hashCons) {
  const hashC = (msg) => hashCons().update(toBytes2(msg)).digest();
  const tmp = hashCons();
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.create = () => hashCons();
  return hashC;
}
var _0n = BigInt(0);
var _1n = BigInt(1);
var _2n = BigInt(2);
var _7n = BigInt(7);
var _256n = BigInt(256);
var _0x71n = BigInt(113);
var SHA3_PI = [];
var SHA3_ROTL = [];
var _SHA3_IOTA = [];
for (let round = 0, R = _1n, x = 1, y = 0;round < 24; round++) {
  [x, y] = [y, (2 * x + 3 * y) % 5];
  SHA3_PI.push(2 * (5 * y + x));
  SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
  let t = _0n;
  for (let j = 0;j < 7; j++) {
    R = (R << _1n ^ (R >> _7n) * _0x71n) % _256n;
    if (R & _2n)
      t ^= _1n << (_1n << /* @__PURE__ */ BigInt(j)) - _1n;
  }
  _SHA3_IOTA.push(t);
}
var IOTAS = split(_SHA3_IOTA, true);
var SHA3_IOTA_H = IOTAS[0];
var SHA3_IOTA_L = IOTAS[1];
var rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
var rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
function keccakP(s, rounds = 24) {
  const B = new Uint32Array(5 * 2);
  for (let round = 24 - rounds;round < 24; round++) {
    for (let x = 0;x < 10; x++)
      B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
    for (let x = 0;x < 10; x += 2) {
      const idx1 = (x + 8) % 10;
      const idx0 = (x + 2) % 10;
      const B0 = B[idx0];
      const B1 = B[idx0 + 1];
      const Th = rotlH(B0, B1, 1) ^ B[idx1];
      const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
      for (let y = 0;y < 50; y += 10) {
        s[x + y] ^= Th;
        s[x + y + 1] ^= Tl;
      }
    }
    let curH = s[2];
    let curL = s[3];
    for (let t = 0;t < 24; t++) {
      const shift = SHA3_ROTL[t];
      const Th = rotlH(curH, curL, shift);
      const Tl = rotlL(curH, curL, shift);
      const PI = SHA3_PI[t];
      curH = s[PI];
      curL = s[PI + 1];
      s[PI] = Th;
      s[PI + 1] = Tl;
    }
    for (let y = 0;y < 50; y += 10) {
      for (let x = 0;x < 10; x++)
        B[x] = s[y + x];
      for (let x = 0;x < 10; x++)
        s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
    }
    s[0] ^= SHA3_IOTA_H[round];
    s[1] ^= SHA3_IOTA_L[round];
  }
  clean(B);
}

class Keccak extends Hash {
  constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
    super();
    this.pos = 0;
    this.posOut = 0;
    this.finished = false;
    this.destroyed = false;
    this.enableXOF = false;
    this.blockLen = blockLen;
    this.suffix = suffix;
    this.outputLen = outputLen;
    this.enableXOF = enableXOF;
    this.rounds = rounds;
    anumber(outputLen);
    if (!(0 < blockLen && blockLen < 200))
      throw new Error("only keccak-f1600 function is supported");
    this.state = new Uint8Array(200);
    this.state32 = u32(this.state);
  }
  clone() {
    return this._cloneInto();
  }
  keccak() {
    swap32IfBE(this.state32);
    keccakP(this.state32, this.rounds);
    swap32IfBE(this.state32);
    this.posOut = 0;
    this.pos = 0;
  }
  update(data) {
    aexists(this);
    data = toBytes2(data);
    abytes(data);
    const { blockLen, state } = this;
    const len = data.length;
    for (let pos = 0;pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      for (let i = 0;i < take; i++)
        state[this.pos++] ^= data[pos++];
      if (this.pos === blockLen)
        this.keccak();
    }
    return this;
  }
  finish() {
    if (this.finished)
      return;
    this.finished = true;
    const { state, suffix, pos, blockLen } = this;
    state[pos] ^= suffix;
    if ((suffix & 128) !== 0 && pos === blockLen - 1)
      this.keccak();
    state[blockLen - 1] ^= 128;
    this.keccak();
  }
  writeInto(out) {
    aexists(this, false);
    abytes(out);
    this.finish();
    const bufferOut = this.state;
    const { blockLen } = this;
    for (let pos = 0, len = out.length;pos < len; ) {
      if (this.posOut >= blockLen)
        this.keccak();
      const take = Math.min(blockLen - this.posOut, len - pos);
      out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
      this.posOut += take;
      pos += take;
    }
    return out;
  }
  xofInto(out) {
    if (!this.enableXOF)
      throw new Error("XOF is not possible for this instance");
    return this.writeInto(out);
  }
  xof(bytes) {
    anumber(bytes);
    return this.xofInto(new Uint8Array(bytes));
  }
  digestInto(out) {
    aoutput(out, this);
    if (this.finished)
      throw new Error("digest() was already called");
    this.writeInto(out);
    this.destroy();
    return out;
  }
  digest() {
    return this.digestInto(new Uint8Array(this.outputLen));
  }
  destroy() {
    this.destroyed = true;
    clean(this.state);
  }
  _cloneInto(to) {
    const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
    to || (to = new Keccak(blockLen, suffix, outputLen, enableXOF, rounds));
    to.state32.set(this.state32);
    to.pos = this.pos;
    to.posOut = this.posOut;
    to.finished = this.finished;
    to.rounds = rounds;
    to.suffix = suffix;
    to.outputLen = outputLen;
    to.enableXOF = enableXOF;
    to.destroyed = this.destroyed;
    return to;
  }
}
var gen = (suffix, blockLen, outputLen) => createHasher(() => new Keccak(blockLen, suffix, outputLen));
var keccak_256 = /* @__PURE__ */ (() => gen(1, 136, 256 / 8))();
function keccak256(value, to_) {
  const to = to_ || "hex";
  const bytes = keccak_256(isHex(value, { strict: false }) ? toBytes(value) : value);
  if (to === "bytes")
    return bytes;
  return toHex(bytes);
}

class LruMap extends Map {
  constructor(size) {
    super();
    Object.defineProperty(this, "maxSize", {
      enumerable: true,
      configurable: true,
      writable: true,
      value: undefined
    });
    this.maxSize = size;
  }
  get(key) {
    const value = super.get(key);
    if (super.has(key)) {
      super.delete(key);
      super.set(key, value);
    }
    return value;
  }
  set(key, value) {
    if (super.has(key))
      super.delete(key);
    super.set(key, value);
    if (this.maxSize && this.size > this.maxSize) {
      const firstKey = super.keys().next().value;
      if (firstKey !== undefined)
        super.delete(firstKey);
    }
    return this;
  }
}
var addressRegex = /^0x[a-fA-F0-9]{40}$/;
var isAddressCache = /* @__PURE__ */ new LruMap(8192);
function isAddress(address, options) {
  const { strict = true } = options ?? {};
  const cacheKey = `${address}.${strict}`;
  if (isAddressCache.has(cacheKey))
    return isAddressCache.get(cacheKey);
  const result = (() => {
    if (!addressRegex.test(address))
      return false;
    if (address.toLowerCase() === address)
      return true;
    if (strict)
      return checksumAddress(address) === address;
    return true;
  })();
  isAddressCache.set(cacheKey, result);
  return result;
}
var checksumAddressCache = /* @__PURE__ */ new LruMap(8192);
function checksumAddress(address_, chainId) {
  if (checksumAddressCache.has(`${address_}.${chainId}`))
    return checksumAddressCache.get(`${address_}.${chainId}`);
  const hexAddress = chainId ? `${chainId}${address_.toLowerCase()}` : address_.substring(2).toLowerCase();
  const hash = keccak256(stringToBytes(hexAddress), "bytes");
  const address = (chainId ? hexAddress.substring(`${chainId}0x`.length) : hexAddress).split("");
  for (let i = 0;i < 40; i += 2) {
    if (hash[i >> 1] >> 4 >= 8 && address[i]) {
      address[i] = address[i].toUpperCase();
    }
    if ((hash[i >> 1] & 15) >= 8 && address[i + 1]) {
      address[i + 1] = address[i + 1].toUpperCase();
    }
  }
  const result = `0x${address.join("")}`;
  checksumAddressCache.set(`${address_}.${chainId}`, result);
  return result;
}
function getAddress(address, chainId) {
  if (!isAddress(address, { strict: false }))
    throw new InvalidAddressError({ address });
  return checksumAddress(address, chainId);
}

class NegativeOffsetError extends BaseError3 {
  constructor({ offset }) {
    super(`Offset \`${offset}\` cannot be negative.`, {
      name: "NegativeOffsetError"
    });
  }
}

class PositionOutOfBoundsError extends BaseError3 {
  constructor({ length, position }) {
    super(`Position \`${position}\` is out of bounds (\`0 < position < ${length}\`).`, { name: "PositionOutOfBoundsError" });
  }
}

class RecursiveReadLimitExceededError extends BaseError3 {
  constructor({ count, limit }) {
    super(`Recursive read limit of \`${limit}\` exceeded (recursive read count: \`${count}\`).`, { name: "RecursiveReadLimitExceededError" });
  }
}
var staticCursor = {
  bytes: new Uint8Array,
  dataView: new DataView(new ArrayBuffer(0)),
  position: 0,
  positionReadCount: new Map,
  recursiveReadCount: 0,
  recursiveReadLimit: Number.POSITIVE_INFINITY,
  assertReadLimit() {
    if (this.recursiveReadCount >= this.recursiveReadLimit)
      throw new RecursiveReadLimitExceededError({
        count: this.recursiveReadCount + 1,
        limit: this.recursiveReadLimit
      });
  },
  assertPosition(position) {
    if (position < 0 || position > this.bytes.length - 1)
      throw new PositionOutOfBoundsError({
        length: this.bytes.length,
        position
      });
  },
  decrementPosition(offset) {
    if (offset < 0)
      throw new NegativeOffsetError({ offset });
    const position = this.position - offset;
    this.assertPosition(position);
    this.position = position;
  },
  getReadCount(position) {
    return this.positionReadCount.get(position || this.position) || 0;
  },
  incrementPosition(offset) {
    if (offset < 0)
      throw new NegativeOffsetError({ offset });
    const position = this.position + offset;
    this.assertPosition(position);
    this.position = position;
  },
  inspectByte(position_) {
    const position = position_ ?? this.position;
    this.assertPosition(position);
    return this.bytes[position];
  },
  inspectBytes(length, position_) {
    const position = position_ ?? this.position;
    this.assertPosition(position + length - 1);
    return this.bytes.subarray(position, position + length);
  },
  inspectUint8(position_) {
    const position = position_ ?? this.position;
    this.assertPosition(position);
    return this.bytes[position];
  },
  inspectUint16(position_) {
    const position = position_ ?? this.position;
    this.assertPosition(position + 1);
    return this.dataView.getUint16(position);
  },
  inspectUint24(position_) {
    const position = position_ ?? this.position;
    this.assertPosition(position + 2);
    return (this.dataView.getUint16(position) << 8) + this.dataView.getUint8(position + 2);
  },
  inspectUint32(position_) {
    const position = position_ ?? this.position;
    this.assertPosition(position + 3);
    return this.dataView.getUint32(position);
  },
  pushByte(byte) {
    this.assertPosition(this.position);
    this.bytes[this.position] = byte;
    this.position++;
  },
  pushBytes(bytes) {
    this.assertPosition(this.position + bytes.length - 1);
    this.bytes.set(bytes, this.position);
    this.position += bytes.length;
  },
  pushUint8(value) {
    this.assertPosition(this.position);
    this.bytes[this.position] = value;
    this.position++;
  },
  pushUint16(value) {
    this.assertPosition(this.position + 1);
    this.dataView.setUint16(this.position, value);
    this.position += 2;
  },
  pushUint24(value) {
    this.assertPosition(this.position + 2);
    this.dataView.setUint16(this.position, value >> 8);
    this.dataView.setUint8(this.position + 2, value & ~4294967040);
    this.position += 3;
  },
  pushUint32(value) {
    this.assertPosition(this.position + 3);
    this.dataView.setUint32(this.position, value);
    this.position += 4;
  },
  readByte() {
    this.assertReadLimit();
    this._touch();
    const value = this.inspectByte();
    this.position++;
    return value;
  },
  readBytes(length, size) {
    this.assertReadLimit();
    this._touch();
    const value = this.inspectBytes(length);
    this.position += size ?? length;
    return value;
  },
  readUint8() {
    this.assertReadLimit();
    this._touch();
    const value = this.inspectUint8();
    this.position += 1;
    return value;
  },
  readUint16() {
    this.assertReadLimit();
    this._touch();
    const value = this.inspectUint16();
    this.position += 2;
    return value;
  },
  readUint24() {
    this.assertReadLimit();
    this._touch();
    const value = this.inspectUint24();
    this.position += 3;
    return value;
  },
  readUint32() {
    this.assertReadLimit();
    this._touch();
    const value = this.inspectUint32();
    this.position += 4;
    return value;
  },
  get remaining() {
    return this.bytes.length - this.position;
  },
  setPosition(position) {
    const oldPosition = this.position;
    this.assertPosition(position);
    this.position = position;
    return () => this.position = oldPosition;
  },
  _touch() {
    if (this.recursiveReadLimit === Number.POSITIVE_INFINITY)
      return;
    const count = this.getReadCount();
    this.positionReadCount.set(this.position, count + 1);
    if (count > 0)
      this.recursiveReadCount++;
  }
};
function createCursor(bytes, { recursiveReadLimit = 8192 } = {}) {
  const cursor = Object.create(staticCursor);
  cursor.bytes = bytes;
  cursor.dataView = new DataView(bytes.buffer ?? bytes, bytes.byteOffset, bytes.byteLength);
  cursor.positionReadCount = new Map;
  cursor.recursiveReadLimit = recursiveReadLimit;
  return cursor;
}
function slice(value, start, end, { strict } = {}) {
  if (isHex(value, { strict: false }))
    return sliceHex(value, start, end, {
      strict
    });
  return sliceBytes(value, start, end, {
    strict
  });
}
function assertStartOffset(value, start) {
  if (typeof start === "number" && start > 0 && start > size(value) - 1)
    throw new SliceOffsetOutOfBoundsError({
      offset: start,
      position: "start",
      size: size(value)
    });
}
function assertEndOffset(value, start, end) {
  if (typeof start === "number" && typeof end === "number" && size(value) !== end - start) {
    throw new SliceOffsetOutOfBoundsError({
      offset: end,
      position: "end",
      size: size(value)
    });
  }
}
function sliceBytes(value_, start, end, { strict } = {}) {
  assertStartOffset(value_, start);
  const value = value_.slice(start, end);
  if (strict)
    assertEndOffset(value, start, end);
  return value;
}
function sliceHex(value_, start, end, { strict } = {}) {
  assertStartOffset(value_, start);
  const value = `0x${value_.replace("0x", "").slice((start ?? 0) * 2, (end ?? value_.length) * 2)}`;
  if (strict)
    assertEndOffset(value, start, end);
  return value;
}
function bytesToBigInt(bytes, opts = {}) {
  if (typeof opts.size !== "undefined")
    assertSize(bytes, { size: opts.size });
  const hex = bytesToHex(bytes);
  return hexToBigInt(hex, opts);
}
function bytesToBool(bytes_, opts = {}) {
  let bytes = bytes_;
  if (typeof opts.size !== "undefined") {
    assertSize(bytes, { size: opts.size });
    bytes = trim(bytes);
  }
  if (bytes.length > 1 || bytes[0] > 1)
    throw new InvalidBytesBooleanError(bytes);
  return Boolean(bytes[0]);
}
function bytesToNumber(bytes, opts = {}) {
  if (typeof opts.size !== "undefined")
    assertSize(bytes, { size: opts.size });
  const hex = bytesToHex(bytes);
  return hexToNumber(hex, opts);
}
function bytesToString(bytes_, opts = {}) {
  let bytes = bytes_;
  if (typeof opts.size !== "undefined") {
    assertSize(bytes, { size: opts.size });
    bytes = trim(bytes, { dir: "right" });
  }
  return new TextDecoder().decode(bytes);
}
function concatHex(values) {
  return `0x${values.reduce((acc, x) => acc + x.replace("0x", ""), "")}`;
}
var integerRegex2 = /^(u?int)(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?$/;
function encodeAbiParameters(params, values) {
  if (params.length !== values.length)
    throw new AbiEncodingLengthMismatchError({
      expectedLength: params.length,
      givenLength: values.length
    });
  const preparedParams = prepareParams({
    params,
    values
  });
  return encodeParams(preparedParams);
}
function prepareParams({ params, values }) {
  const preparedParams = [];
  for (let i = 0;i < params.length; i++) {
    preparedParams.push(prepareParam({ param: params[i], value: values[i] }));
  }
  return preparedParams;
}
function prepareParam({ param, value }) {
  const arrayComponents = getArrayComponents(param.type);
  if (arrayComponents) {
    const [length, type] = arrayComponents;
    return encodeArray(value, { length, param: { ...param, type } });
  }
  if (param.type === "tuple") {
    return encodeTuple(value, {
      param
    });
  }
  if (param.type === "address") {
    return encodeAddress(value);
  }
  if (param.type === "bool") {
    return encodeBool(value);
  }
  if (param.type.startsWith("uint") || param.type.startsWith("int")) {
    const signed = param.type.startsWith("int");
    const [, , size = "256"] = integerRegex2.exec(param.type) ?? [];
    return encodeNumber(value, {
      signed,
      size: Number(size)
    });
  }
  if (param.type.startsWith("bytes")) {
    return encodeBytes(value, { param });
  }
  if (param.type === "string") {
    return encodeString(value);
  }
  throw new InvalidAbiEncodingTypeError(param.type, {
    docsPath: "/docs/contract/encodeAbiParameters"
  });
}
function encodeParams(preparedParams) {
  let staticSize = 0;
  for (let i = 0;i < preparedParams.length; i++) {
    const { dynamic, encoded } = preparedParams[i];
    if (dynamic)
      staticSize += 32;
    else
      staticSize += size(encoded);
  }
  const staticParams = [];
  const dynamicParams = [];
  let dynamicSize = 0;
  for (let i = 0;i < preparedParams.length; i++) {
    const { dynamic, encoded } = preparedParams[i];
    if (dynamic) {
      staticParams.push(numberToHex(staticSize + dynamicSize, { size: 32 }));
      dynamicParams.push(encoded);
      dynamicSize += size(encoded);
    } else {
      staticParams.push(encoded);
    }
  }
  return concatHex([...staticParams, ...dynamicParams]);
}
function encodeAddress(value) {
  if (!isAddress(value))
    throw new InvalidAddressError({ address: value });
  return { dynamic: false, encoded: padHex(value.toLowerCase()) };
}
function encodeArray(value, { length, param }) {
  const dynamic = length === null;
  if (!Array.isArray(value))
    throw new InvalidArrayError(value);
  if (!dynamic && value.length !== length)
    throw new AbiEncodingArrayLengthMismatchError({
      expectedLength: length,
      givenLength: value.length,
      type: `${param.type}[${length}]`
    });
  let dynamicChild = value.length === 0 && isDynamicType(param);
  const preparedParams = [];
  for (let i = 0;i < value.length; i++) {
    const preparedParam = prepareParam({ param, value: value[i] });
    if (preparedParam.dynamic)
      dynamicChild = true;
    preparedParams.push(preparedParam);
  }
  if (dynamic || dynamicChild) {
    const data = encodeParams(preparedParams);
    if (dynamic) {
      const length = numberToHex(preparedParams.length, { size: 32 });
      return {
        dynamic: true,
        encoded: concatHex([length, data])
      };
    }
    if (dynamicChild)
      return { dynamic: true, encoded: data };
  }
  return {
    dynamic: false,
    encoded: concatHex(preparedParams.map(({ encoded }) => encoded))
  };
}
function encodeBytes(value, { param }) {
  const [, paramSize] = param.type.split("bytes");
  const bytesSize = size(value);
  if (!paramSize) {
    let value_ = value;
    if (bytesSize % 32 !== 0)
      value_ = padHex(value_, {
        dir: "right",
        size: Math.ceil((value.length - 2) / 2 / 32) * 32
      });
    return {
      dynamic: true,
      encoded: concatHex([
        padHex(numberToHex(bytesSize, { size: 32 })),
        value_
      ])
    };
  }
  if (bytesSize !== Number.parseInt(paramSize, 10))
    throw new AbiEncodingBytesSizeMismatchError({
      expectedSize: Number.parseInt(paramSize, 10),
      value
    });
  return { dynamic: false, encoded: padHex(value, { dir: "right" }) };
}
function encodeBool(value) {
  if (typeof value !== "boolean")
    throw new BaseError3(`Invalid boolean value: "${value}" (type: ${typeof value}). Expected: \`true\` or \`false\`.`);
  return { dynamic: false, encoded: padHex(boolToHex(value)) };
}
function encodeNumber(value, { signed, size = 256 }) {
  if (typeof size === "number") {
    const max = 2n ** (BigInt(size) - (signed ? 1n : 0n)) - 1n;
    const min = signed ? -max - 1n : 0n;
    if (value > max || value < min)
      throw new IntegerOutOfRangeError({
        max: max.toString(),
        min: min.toString(),
        signed,
        size: size / 8,
        value: value.toString()
      });
  }
  return {
    dynamic: false,
    encoded: numberToHex(value, {
      size: 32,
      signed
    })
  };
}
function encodeString(value) {
  const hexValue = stringToHex(value);
  const partsLength = Math.ceil(size(hexValue) / 32);
  const parts = [];
  for (let i = 0;i < partsLength; i++) {
    parts.push(padHex(slice(hexValue, i * 32, (i + 1) * 32), {
      dir: "right"
    }));
  }
  return {
    dynamic: true,
    encoded: concatHex([
      padHex(numberToHex(size(hexValue), { size: 32 })),
      ...parts
    ])
  };
}
function encodeTuple(value, { param }) {
  let dynamic = false;
  const preparedParams = [];
  for (let i = 0;i < param.components.length; i++) {
    const param_ = param.components[i];
    const index = Array.isArray(value) ? i : param_.name;
    const preparedParam = prepareParam({
      param: param_,
      value: value[index]
    });
    preparedParams.push(preparedParam);
    if (preparedParam.dynamic)
      dynamic = true;
  }
  return {
    dynamic,
    encoded: dynamic ? encodeParams(preparedParams) : concatHex(preparedParams.map(({ encoded }) => encoded))
  };
}
function getArrayComponents(type) {
  const matches = type.match(/^(.*)\[(\d+)?\]$/);
  return matches ? [matches[2] ? Number(matches[2]) : null, matches[1]] : undefined;
}
function isDynamicType(param) {
  const { type } = param;
  if (type === "string")
    return true;
  if (type === "bytes")
    return true;
  if (type.endsWith("[]"))
    return true;
  if (type === "tuple")
    return param.components.some(isDynamicType);
  const arrayComponents = getArrayComponents(type);
  if (arrayComponents)
    return isDynamicType({ ...param, type: arrayComponents[1] });
  return false;
}
function decodeAbiParameters(params, data) {
  const bytes = typeof data === "string" ? hexToBytes(data) : data;
  const cursor = createCursor(bytes);
  if (size(bytes) === 0 && params.length > 0)
    throw new AbiDecodingZeroDataError;
  if (size(data) && size(data) < 32)
    throw new AbiDecodingDataSizeTooSmallError({
      data: typeof data === "string" ? data : bytesToHex(data),
      params,
      size: size(data)
    });
  let consumed = 0;
  const values = [];
  for (let i = 0;i < params.length; ++i) {
    const param = params[i];
    if (consumed < bytes.length)
      cursor.setPosition(consumed);
    const [data, consumed_] = decodeParameter(cursor, param, {
      staticPosition: 0
    });
    consumed += consumed_;
    values.push(data);
  }
  return values;
}
function decodeParameter(cursor, param, { staticPosition }) {
  const arrayComponents = getArrayComponents(param.type);
  if (arrayComponents) {
    const [length, type] = arrayComponents;
    return decodeArray(cursor, { ...param, type }, { length, staticPosition });
  }
  if (param.type === "tuple")
    return decodeTuple(cursor, param, { staticPosition });
  if (param.type === "address")
    return decodeAddress(cursor);
  if (param.type === "bool")
    return decodeBool(cursor);
  if (param.type.startsWith("bytes"))
    return decodeBytes(cursor, param, { staticPosition });
  if (param.type.startsWith("uint") || param.type.startsWith("int"))
    return decodeNumber(cursor, param);
  if (param.type === "string")
    return decodeString(cursor, { staticPosition });
  throw new InvalidAbiDecodingTypeError(param.type, {
    docsPath: "/docs/contract/decodeAbiParameters"
  });
}
var sizeOfLength = 32;
var sizeOfOffset = 32;
function decodeAddress(cursor) {
  const value = cursor.readBytes(32);
  return [checksumAddress(bytesToHex(sliceBytes(value, -20))), 32];
}
function decodeArray(cursor, param, { length, staticPosition }) {
  if (length === null) {
    const offset = bytesToNumber(cursor.readBytes(sizeOfOffset));
    const start = staticPosition + offset;
    const startOfData = start + sizeOfLength;
    cursor.setPosition(start);
    const length = bytesToNumber(cursor.readBytes(sizeOfLength));
    const dynamicChild = hasDynamicChild(param);
    let consumed = 0;
    const value = [];
    for (let i = 0;i < length; ++i) {
      cursor.setPosition(startOfData + (dynamicChild ? i * 32 : consumed));
      const [data, consumed_] = decodeParameter(cursor, param, {
        staticPosition: startOfData
      });
      consumed += consumed_;
      value.push(data);
      if (consumed_ === 0) {
        cursor.assertReadLimit();
        cursor._touch();
      }
    }
    cursor.setPosition(staticPosition + 32);
    return [value, 32];
  }
  if (hasDynamicChild(param)) {
    const offset = bytesToNumber(cursor.readBytes(sizeOfOffset));
    const start = staticPosition + offset;
    const value = [];
    for (let i = 0;i < length; ++i) {
      cursor.setPosition(start + i * 32);
      const [data] = decodeParameter(cursor, param, {
        staticPosition: start
      });
      value.push(data);
    }
    cursor.setPosition(staticPosition + 32);
    return [value, 32];
  }
  let consumed = 0;
  const value = [];
  for (let i = 0;i < length; ++i) {
    const [data, consumed_] = decodeParameter(cursor, param, {
      staticPosition: staticPosition + consumed
    });
    consumed += consumed_;
    value.push(data);
    if (consumed_ === 0) {
      cursor.assertReadLimit();
      cursor._touch();
    }
  }
  return [value, consumed];
}
function decodeBool(cursor) {
  return [bytesToBool(cursor.readBytes(32), { size: 32 }), 32];
}
function decodeBytes(cursor, param, { staticPosition }) {
  const [_, size] = param.type.split("bytes");
  if (!size) {
    const offset = bytesToNumber(cursor.readBytes(32));
    cursor.setPosition(staticPosition + offset);
    const length = bytesToNumber(cursor.readBytes(32));
    if (length === 0) {
      cursor.setPosition(staticPosition + 32);
      return ["0x", 32];
    }
    const data = cursor.readBytes(length);
    cursor.setPosition(staticPosition + 32);
    return [bytesToHex(data), 32];
  }
  const value = bytesToHex(cursor.readBytes(Number.parseInt(size, 10), 32));
  return [value, 32];
}
function decodeNumber(cursor, param) {
  const signed = param.type.startsWith("int");
  const size = Number.parseInt(param.type.split("int")[1] || "256", 10);
  const value = cursor.readBytes(32);
  return [
    size > 48 ? bytesToBigInt(value, { signed }) : bytesToNumber(value, { signed }),
    32
  ];
}
function decodeTuple(cursor, param, { staticPosition }) {
  const hasUnnamedChild = param.components.length === 0 || param.components.some(({ name }) => !name);
  const value = hasUnnamedChild ? [] : {};
  let consumed = 0;
  if (hasDynamicChild(param)) {
    const offset = bytesToNumber(cursor.readBytes(sizeOfOffset));
    const start = staticPosition + offset;
    for (let i = 0;i < param.components.length; ++i) {
      const component = param.components[i];
      cursor.setPosition(start + consumed);
      const [data, consumed_] = decodeParameter(cursor, component, {
        staticPosition: start
      });
      consumed += consumed_;
      value[hasUnnamedChild ? i : component?.name] = data;
    }
    cursor.setPosition(staticPosition + 32);
    return [value, 32];
  }
  for (let i = 0;i < param.components.length; ++i) {
    const component = param.components[i];
    const [data, consumed_] = decodeParameter(cursor, component, {
      staticPosition
    });
    value[hasUnnamedChild ? i : component?.name] = data;
    consumed += consumed_;
  }
  return [value, consumed];
}
function decodeString(cursor, { staticPosition }) {
  const offset = bytesToNumber(cursor.readBytes(32));
  const start = staticPosition + offset;
  cursor.setPosition(start);
  const length = bytesToNumber(cursor.readBytes(32));
  if (length === 0) {
    cursor.setPosition(staticPosition + 32);
    return ["", 32];
  }
  const data = cursor.readBytes(length, 32);
  const value = bytesToString(data);
  cursor.setPosition(staticPosition + 32);
  return [value, 32];
}
function hasDynamicChild(param) {
  const { type } = param;
  if (type === "string")
    return true;
  if (type === "bytes")
    return true;
  if (type.endsWith("[]"))
    return true;
  if (type === "tuple")
    return param.components?.some(hasDynamicChild);
  const arrayComponents = getArrayComponents(param.type);
  if (arrayComponents && hasDynamicChild({ ...param, type: arrayComponents[1] }))
    return true;
  return false;
}
var hash = (value) => keccak256(toBytes(value));
function hashSignature(sig) {
  return hash(sig);
}
function normalizeSignature(signature) {
  let active = true;
  let current = "";
  let level = 0;
  let result = "";
  let valid = false;
  for (let i = 0;i < signature.length; i++) {
    const char = signature[i];
    if (["(", ")", ","].includes(char))
      active = true;
    if (char === "(")
      level++;
    if (char === ")")
      level--;
    if (!active)
      continue;
    if (level === 0) {
      if (char === " " && ["event", "function", ""].includes(result))
        result = "";
      else {
        result += char;
        if (char === ")") {
          valid = true;
          break;
        }
      }
      continue;
    }
    if (char === " ") {
      if (signature[i - 1] !== "," && current !== "," && current !== ",(") {
        current = "";
        active = false;
      }
      continue;
    }
    result += char;
    current += char;
  }
  if (!valid)
    throw new BaseError3("Unable to normalize signature.");
  return result;
}
var toSignature = (def) => {
  const def_ = (() => {
    if (typeof def === "string")
      return def;
    return formatAbiItem(def);
  })();
  return normalizeSignature(def_);
};
function toSignatureHash(fn) {
  return hashSignature(toSignature(fn));
}
var toEventSelector = toSignatureHash;
var toFunctionSelector = (fn) => slice(toSignatureHash(fn), 0, 4);
function getAbiItem(parameters) {
  const { abi, args = [], name } = parameters;
  const isSelector = isHex(name, { strict: false });
  const abiItems = abi.filter((abiItem) => {
    if (isSelector) {
      if (abiItem.type === "function")
        return toFunctionSelector(abiItem) === name;
      if (abiItem.type === "event")
        return toEventSelector(abiItem) === name;
      return false;
    }
    return "name" in abiItem && abiItem.name === name;
  });
  if (abiItems.length === 0)
    return;
  if (abiItems.length === 1)
    return abiItems[0];
  let matchedAbiItem;
  for (const abiItem of abiItems) {
    if (!("inputs" in abiItem))
      continue;
    if (!args || args.length === 0) {
      if (!abiItem.inputs || abiItem.inputs.length === 0)
        return abiItem;
      continue;
    }
    if (!abiItem.inputs)
      continue;
    if (abiItem.inputs.length === 0)
      continue;
    if (abiItem.inputs.length !== args.length)
      continue;
    const matched = args.every((arg, index) => {
      const abiParameter = "inputs" in abiItem && abiItem.inputs[index];
      if (!abiParameter)
        return false;
      return isArgOfType(arg, abiParameter);
    });
    if (matched) {
      if (matchedAbiItem && "inputs" in matchedAbiItem && matchedAbiItem.inputs) {
        const ambiguousTypes = getAmbiguousTypes(abiItem.inputs, matchedAbiItem.inputs, args);
        if (ambiguousTypes)
          throw new AbiItemAmbiguityError({
            abiItem,
            type: ambiguousTypes[0]
          }, {
            abiItem: matchedAbiItem,
            type: ambiguousTypes[1]
          });
      }
      matchedAbiItem = abiItem;
    }
  }
  if (matchedAbiItem)
    return matchedAbiItem;
  return abiItems[0];
}
function isArgOfType(arg, abiParameter) {
  const argType = typeof arg;
  const abiParameterType = abiParameter.type;
  switch (abiParameterType) {
    case "address":
      return isAddress(arg, { strict: false });
    case "bool":
      return argType === "boolean";
    case "function":
      return argType === "string";
    case "string":
      return argType === "string";
    default: {
      if (abiParameterType === "tuple" && "components" in abiParameter)
        return Object.values(abiParameter.components).every((component, index) => {
          return argType === "object" && isArgOfType(Object.values(arg)[index], component);
        });
      if (/^u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?$/.test(abiParameterType))
        return argType === "number" || argType === "bigint";
      if (/^bytes([1-9]|1[0-9]|2[0-9]|3[0-2])?$/.test(abiParameterType))
        return argType === "string" || arg instanceof Uint8Array;
      if (/[a-z]+[1-9]{0,3}(\[[0-9]{0,}\])+$/.test(abiParameterType)) {
        return Array.isArray(arg) && arg.every((x) => isArgOfType(x, {
          ...abiParameter,
          type: abiParameterType.replace(/(\[[0-9]{0,}\])$/, "")
        }));
      }
      return false;
    }
  }
}
function getAmbiguousTypes(sourceParameters, targetParameters, args) {
  for (const parameterIndex in sourceParameters) {
    const sourceParameter = sourceParameters[parameterIndex];
    const targetParameter = targetParameters[parameterIndex];
    if (sourceParameter.type === "tuple" && targetParameter.type === "tuple" && "components" in sourceParameter && "components" in targetParameter)
      return getAmbiguousTypes(sourceParameter.components, targetParameter.components, args[parameterIndex]);
    const types = [sourceParameter.type, targetParameter.type];
    const ambiguous = (() => {
      if (types.includes("address") && types.includes("bytes20"))
        return true;
      if (types.includes("address") && types.includes("string"))
        return isAddress(args[parameterIndex], { strict: false });
      if (types.includes("address") && types.includes("bytes"))
        return isAddress(args[parameterIndex], { strict: false });
      return false;
    })();
    if (ambiguous)
      return types;
  }
  return;
}
var docsPath = "/docs/contract/decodeFunctionResult";
function decodeFunctionResult(parameters) {
  const { abi, args, functionName, data } = parameters;
  let abiItem = abi[0];
  if (functionName) {
    const item = getAbiItem({ abi, args, name: functionName });
    if (!item)
      throw new AbiFunctionNotFoundError(functionName, { docsPath });
    abiItem = item;
  }
  if (abiItem.type !== "function")
    throw new AbiFunctionNotFoundError(undefined, { docsPath });
  if (!abiItem.outputs)
    throw new AbiFunctionOutputsNotFoundError(abiItem.name, { docsPath });
  const values = decodeAbiParameters(abiItem.outputs, data);
  if (values && values.length > 1)
    return values;
  if (values && values.length === 1)
    return values[0];
  return;
}
var docsPath2 = "/docs/contract/encodeFunctionData";
function prepareEncodeFunctionData(parameters) {
  const { abi, args, functionName } = parameters;
  let abiItem = abi[0];
  if (functionName) {
    const item = getAbiItem({
      abi,
      args,
      name: functionName
    });
    if (!item)
      throw new AbiFunctionNotFoundError(functionName, { docsPath: docsPath2 });
    abiItem = item;
  }
  if (abiItem.type !== "function")
    throw new AbiFunctionNotFoundError(undefined, { docsPath: docsPath2 });
  return {
    abi: [abiItem],
    functionName: toFunctionSelector(formatAbiItem2(abiItem))
  };
}
function encodeFunctionData(parameters) {
  const { args } = parameters;
  const { abi, functionName } = (() => {
    if (parameters.abi.length === 1 && parameters.functionName?.startsWith("0x"))
      return parameters;
    return prepareEncodeFunctionData(parameters);
  })();
  const abiItem = abi[0];
  const signature = functionName;
  const data = "inputs" in abiItem && abiItem.inputs ? encodeAbiParameters(abiItem.inputs, args ?? []) : undefined;
  return concatHex([signature, data ?? "0x"]);
}
function publicKeyToAddress(publicKey) {
  const address = keccak256(`0x${publicKey.substring(4)}`).substring(26);
  return checksumAddress(`0x${address}`);
}
async function recoverPublicKey({ hash, signature }) {
  const hashHex = isHex(hash) ? hash : toHex(hash);
  await Promise.resolve().then(() => init_secp256k1());
  const signature_ = (() => {
    if (typeof signature === "object" && "r" in signature && "s" in signature) {
      const { r, s, v, yParity } = signature;
      const yParityOrV = Number(yParity ?? v);
      const recoveryBit = toRecoveryBit(yParityOrV);
      return new secp256k1.Signature(hexToBigInt(r), hexToBigInt(s)).addRecoveryBit(recoveryBit);
    }
    const signatureHex = isHex(signature) ? signature : toHex(signature);
    if (size(signatureHex) !== 65)
      throw new Error("invalid signature length");
    const yParityOrV = hexToNumber(`0x${signatureHex.slice(130)}`);
    const recoveryBit = toRecoveryBit(yParityOrV);
    return secp256k1.Signature.fromCompact(signatureHex.substring(2, 130)).addRecoveryBit(recoveryBit);
  })();
  const publicKey = signature_.recoverPublicKey(hashHex.substring(2)).toHex(false);
  return `0x${publicKey}`;
}
function toRecoveryBit(yParityOrV) {
  if (yParityOrV === 0 || yParityOrV === 1)
    return yParityOrV;
  if (yParityOrV === 27)
    return 0;
  if (yParityOrV === 28)
    return 1;
  throw new Error("Invalid yParityOrV value");
}
async function recoverAddress({ hash, signature }) {
  return publicKeyToAddress(await recoverPublicKey({ hash, signature }));
}
function productionEnvironment() {
  return {
    chainSelector: 5009297550715157269n,
    registryAddress: "0x76c9cf548b4179F8901cda1f8623568b58215E62"
  };
}

class CapabilityError extends Error {
  name;
  capabilityId;
  method;
  callbackId;
  constructor(message, options) {
    super(message);
    this.name = "CapabilityError";
    if (options) {
      this.capabilityId = options.capabilityId;
      this.method = options.method;
      this.callbackId = options.callbackId;
    }
  }
}

class DonModeError extends Error {
  constructor() {
    super("cannot use Runtime inside RunInNodeMode");
    this.name = "DonModeError";
  }
}

class NodeModeError extends Error {
  constructor() {
    super("cannot use NodeRuntime outside RunInNodeMode");
    this.name = "NodeModeError";
  }
}

class SecretsError extends Error {
  secretRequest;
  error;
  constructor(secretRequest, error) {
    super(`secret retrieval failed for ${secretRequest.id || "unknown"} (namespace: ${secretRequest.namespace || "default"}): ${error}. Verify the secret name is correct and that the secret has been configured for this workflow`);
    this.secretRequest = secretRequest;
    this.error = error;
    this.name = "SecretsError";
  }
}

class SecretsBatchError extends Error {
  secretRequests;
  error;
  constructor(secretRequests, error) {
    super(`batch secret retrieval failed for ${secretRequests.length} request(s):
${error}
Verify the host response is complete and that the workflow has access to the requested secrets`);
    this.secretRequests = secretRequests;
    this.error = error;
    this.name = "SecretsBatchError";
  }
}

class NullReportError extends Error {
  constructor() {
    super("null report");
    this.name = "NullReportError";
  }
}

class WrongSignatureCountError extends Error {
  constructor() {
    super("wrong number of signatures");
    this.name = "WrongSignatureCountError";
  }
}

class ParseSignatureError extends Error {
  constructor() {
    super("failed to parse signature");
    this.name = "ParseSignatureError";
  }
}

class RecoverSignerError extends Error {
  constructor() {
    super("failed to recover signer address from signature");
    this.name = "RecoverSignerError";
  }
}

class UnknownSignerError extends Error {
  constructor() {
    super("invalid signature");
    this.name = "UnknownSignerError";
  }
}

class DuplicateSignerError extends Error {
  constructor() {
    super("duplicate signer");
    this.name = "DuplicateSignerError";
  }
}

class RawReportTooShortError extends Error {
  need;
  got;
  constructor(need, got) {
    super(`raw report too short to contain metadata header: need ${need} bytes, got ${got}`);
    this.need = need;
    this.got = got;
    this.name = "RawReportTooShortError";
  }
}
var donInfoCache = new Map;
var GET_DON_SELECTOR = new Uint8Array([35, 83, 116, 5]);
var GET_NODES_BY_P2P_IDS_SELECTOR = new Uint8Array([5, 165, 25, 102]);
function cacheKey(env, donID) {
  return `${env.chainSelector.toString()}:${donID}`;
}
function normalizeRegistryHex(addr) {
  return addr.trim().replace(/^0[xX]/, "").toLowerCase();
}
function decodeRegistryAddress(registryAddress) {
  const hex = normalizeRegistryHex(registryAddress);
  if (hex.length !== 40) {
    throw new Error(`invalid registry address ${JSON.stringify(registryAddress)}`);
  }
  return hexToBytes(`0x${hex}`);
}
function padUint256(v) {
  const n = typeof v === "bigint" ? v : BigInt(v);
  const b = new Uint8Array(32);
  const view = new DataView(b.buffer);
  view.setBigUint64(24, n, false);
  return b;
}
function bytesToBigIntBE(word) {
  let x = 0n;
  for (let i = 0;i < word.length; i++) {
    x = x << 8n | BigInt(word[i]);
  }
  return x;
}
function readUint256AsInt(word) {
  const b = bytesToBigIntBE(word);
  if (b > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("ABI uint256 value too large for Number");
  }
  return Number(b);
}
function protoVarint(v) {
  const out = [];
  let n = typeof v === "bigint" ? v : BigInt(v);
  while (n >= 128n) {
    out.push(Number(n & 0x7fn) | 128);
    n >>= 7n;
  }
  out.push(Number(n));
  return out;
}
function protoTag(field, wireType) {
  return protoVarint(field << 3 | wireType);
}
function protoLenBytes(data) {
  return [...protoVarint(data.length), ...data];
}
function buildCallContractRequestBytes(registryAddr, callData) {
  const callMsg = new Uint8Array([
    ...protoTag(2, 2),
    ...protoLenBytes(registryAddr),
    ...protoTag(3, 2),
    ...protoLenBytes(callData)
  ]);
  const bigInt = new Uint8Array([
    ...protoTag(1, 2),
    ...protoLenBytes(new Uint8Array([3])),
    ...protoTag(2, 0),
    ...protoVarint(0xffffffffffffffffn)
  ]);
  return new Uint8Array([
    ...protoTag(2, 2),
    ...protoLenBytes(bigInt),
    ...protoTag(1, 2),
    ...protoLenBytes(callMsg)
  ]);
}
function decodeCallContractReplyData(bytes) {
  const reader = new BinaryReader(bytes);
  while (reader.pos < reader.len) {
    const [fieldNo, wireType] = reader.tag();
    if (fieldNo === 1 && wireType === WireType.LengthDelimited) {
      return reader.bytes();
    }
    reader.skip(wireType);
  }
  throw new Error("data field not found in CallContractReply");
}
var CALL_CONTRACT_REQUEST_TYPE_URL = "type.googleapis.com/capabilities.blockchain.evm.v1alpha.CallContractRequest";
function callContract(runtime, capID, registryAddr, callData) {
  const reqBytes = buildCallContractRequestBytes(registryAddr, callData);
  const anyPayload = create(AnySchema, {
    typeUrl: CALL_CONTRACT_REQUEST_TYPE_URL,
    value: reqBytes
  });
  const rt = runtime;
  const callbackId = rt.nextCallId++;
  const req = create(CapabilityRequestSchema, {
    id: capID,
    method: "CallContract",
    payload: anyPayload,
    callbackId
  });
  if (!rt.helpers.call(req)) {
    throw new Error(`EVM capability '${capID}' not found`);
  }
  const awaitResp = rt.helpers.await(create(AwaitCapabilitiesRequestSchema, { ids: [callbackId] }), rt.maxResponseSize);
  const capResp = awaitResp?.responses?.[callbackId];
  if (!capResp) {
    throw new Error(`no response from EVM capability '${capID}'`);
  }
  const response = capResp.response;
  if (response.case === "error") {
    throw new Error(response.value);
  }
  if (response.case !== "payload") {
    throw new Error(`unexpected response '${response.case}' from EVM capability '${capID}'`);
  }
  return decodeCallContractReplyData(response.value.value);
}
function encodeGetDONCalldata(donID) {
  const padded = new Uint8Array(32);
  const view = new DataView(padded.buffer);
  view.setUint32(28, donID >>> 0, false);
  const out = new Uint8Array(4 + 32);
  out.set(GET_DON_SELECTOR, 0);
  out.set(padded, 4);
  return out;
}
function concatBytes4(parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const r = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    r.set(p, o);
    o += p.length;
  }
  return r;
}
function encodeGetNodesByP2PIdsCalldata(p2pIds) {
  const chunks = [
    GET_NODES_BY_P2P_IDS_SELECTOR,
    padUint256(32),
    padUint256(p2pIds.length)
  ];
  for (const id of p2pIds) {
    if (id.length !== 32) {
      throw new Error("p2p id must be 32 bytes");
    }
    chunks.push(new Uint8Array(id));
  }
  return concatBytes4(chunks);
}
var NODE_TUPLE_HEAD_SIZE = 288;
function fetchDONInfo(runtime, env, donID) {
  const key = cacheKey(env, donID);
  const hit = donInfoCache.get(key);
  if (hit) {
    return hit;
  }
  const registryAddr = decodeRegistryAddress(env.registryAddress);
  const capID = `evm:ChainSelector:${env.chainSelector.toString()}@1.0.0`;
  const getDONABI = callContract(runtime, capID, registryAddr, encodeGetDONCalldata(donID));
  if (getDONABI.length < 224) {
    throw new Error(`getDON ABI response too short: ${getDONABI.length} bytes`);
  }
  const f = readUint256AsInt(getDONABI.subarray(96, 128));
  const tupleStart = 32;
  const nodeP2PIdsPtr = readUint256AsInt(getDONABI.subarray(192, 224));
  const nodeCountOff = tupleStart + nodeP2PIdsPtr;
  if (nodeCountOff + 32 > getDONABI.length) {
    throw new Error("getDON ABI: nodeP2PIds pointer out of range");
  }
  const nodeCount = readUint256AsInt(getDONABI.subarray(nodeCountOff, nodeCountOff + 32));
  if (nodeCountOff + 32 + nodeCount * 32 > getDONABI.length) {
    throw new Error("getDON ABI: nodeP2PIds data out of range");
  }
  const nodeP2PIds = [];
  for (let i = 0;i < nodeCount; i++) {
    const start = nodeCountOff + 32 + i * 32;
    nodeP2PIds.push(getDONABI.subarray(start, start + 32));
  }
  if (nodeCount === 0) {
    const info = { f, signers: new Map };
    donInfoCache.set(key, info);
    return info;
  }
  const getNodesABI = callContract(runtime, capID, registryAddr, encodeGetNodesByP2PIdsCalldata(nodeP2PIds));
  if (getNodesABI.length < 64) {
    throw new Error(`getNodesByP2PIds ABI response too short: ${getNodesABI.length} bytes`);
  }
  const outerPtr = readUint256AsInt(getNodesABI.subarray(0, 32));
  if (outerPtr + 32 > getNodesABI.length) {
    throw new Error("getNodesByP2PIds ABI: outer pointer out of range");
  }
  const returnedCount = readUint256AsInt(getNodesABI.subarray(outerPtr, outerPtr + 32));
  const signers = new Map;
  for (let i = 0;i < returnedCount; i++) {
    const elemPtrOff = outerPtr + 32 + i * 32;
    if (elemPtrOff + 32 > getNodesABI.length) {
      break;
    }
    const elemPtr = readUint256AsInt(getNodesABI.subarray(elemPtrOff, elemPtrOff + 32));
    const tupleBase = outerPtr + 32 + elemPtr;
    if (tupleBase + NODE_TUPLE_HEAD_SIZE > getNodesABI.length) {
      break;
    }
    const nodeOperatorId = Number(bytesToBigIntBE(getNodesABI.subarray(tupleBase, tupleBase + 32)) & 0xffffffffn);
    const signerSlot = tupleBase + 3 * 32;
    const addrBytes = getNodesABI.subarray(signerSlot, signerSlot + 20);
    const addr = getAddress(toHex(addrBytes));
    signers.set(addr, nodeOperatorId);
  }
  const info = { f, signers };
  donInfoCache.set(key, info);
  return info;
}
function computeReportHash(rawReport, reportContext) {
  const innerHash = keccak256(toHex(rawReport));
  return keccak256(concatHex([innerHash, toHex(reportContext)]));
}
function addressKeyNo0x(addr) {
  return addr.slice(2).toLowerCase();
}
async function verifySigs(report, f, signers) {
  const required = f + 1;
  const sigs = report.sigs;
  if (sigs.length < required) {
    throw new WrongSignatureCountError;
  }
  const reportHash = computeReportHash(report.rawReport, report.reportContext);
  const seen = new Set;
  const accepted = [];
  const skipErrs = [];
  for (let i = 0;i < sigs.length; i++) {
    if (accepted.length === required) {
      break;
    }
    const attrSig = sigs[i];
    const sigBytes = new Uint8Array(attrSig.signature);
    if (sigBytes.length !== 65) {
      skipErrs.push(new ParseSignatureError);
      continue;
    }
    const normalized = new Uint8Array(sigBytes);
    if (normalized[64] === 27 || normalized[64] === 28) {
      normalized[64] -= 27;
    }
    let recovered;
    try {
      recovered = await recoverAddress({
        hash: reportHash,
        signature: toHex(normalized)
      });
    } catch {
      skipErrs.push(new RecoverSignerError);
      continue;
    }
    const key = addressKeyNo0x(recovered);
    if (seen.has(key)) {
      skipErrs.push(new DuplicateSignerError);
      continue;
    }
    seen.add(key);
    const nodeOperatorId = signers.get(key);
    if (nodeOperatorId === undefined) {
      skipErrs.push(new UnknownSignerError);
      continue;
    }
    attrSig.signerId = nodeOperatorId;
    accepted.push(attrSig);
  }
  if (accepted.length < required) {
    if (skipErrs.length > 0) {
      throw new AggregateError(skipErrs);
    }
    throw new WrongSignatureCountError;
  }
  report.sigs = accepted;
}
function mergeReportParseConfig(overrides) {
  return {
    acceptedZones: overrides?.acceptedZones ?? [],
    acceptedEnvironments: overrides !== undefined ? overrides.acceptedEnvironments ?? [] : [productionEnvironment()],
    skipSignatureVerification: overrides?.skipSignatureVerification ?? false
  };
}
function normalizeDonSigners(signers) {
  const out = new Map;
  for (const [addr, id] of signers) {
    out.set(addr.slice(2).toLowerCase(), id);
  }
  return out;
}
var REPORT_METADATA_HEADER_LENGTH = 109;
var REPORT_METADATA_OFFSETS = {
  version: 0,
  versionSize: 1,
  executionId: 1,
  executionIdSize: 32,
  timestamp: 33,
  timestampSize: 4,
  donId: 37,
  donIdSize: 4,
  donConfigVersion: 41,
  donConfigVersionSize: 4,
  workflowId: 45,
  workflowIdSize: 32,
  workflowName: 77,
  workflowNameSize: 10,
  workflowOwner: 87,
  workflowOwnerSize: 20,
  reportId: 107,
  reportIdSize: 2,
  bodyStart: 109
};
function encodeHexLower(bytes) {
  let out = "";
  for (let i = 0;i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}
function readUint32BE(raw, offset) {
  return new DataView(raw.buffer, raw.byteOffset + offset, 4).getUint32(0, false);
}
function parseReportMetadataHeader(raw) {
  if (raw === undefined || raw === null) {
    throw new NullReportError;
  }
  if (raw.length < REPORT_METADATA_HEADER_LENGTH) {
    throw new RawReportTooShortError(REPORT_METADATA_HEADER_LENGTH, raw.length);
  }
  const o = REPORT_METADATA_OFFSETS;
  const workflowNameBytes = raw.subarray(o.workflowName, o.workflowName + o.workflowNameSize);
  return {
    version: raw[o.version],
    executionId: encodeHexLower(raw.subarray(o.executionId, o.executionId + o.executionIdSize)),
    timestamp: readUint32BE(raw, o.timestamp),
    donId: readUint32BE(raw, o.donId),
    donConfigVersion: readUint32BE(raw, o.donConfigVersion),
    workflowId: encodeHexLower(raw.subarray(o.workflowId, o.workflowId + o.workflowIdSize)),
    workflowName: new TextDecoder("utf-8", { fatal: false }).decode(workflowNameBytes),
    workflowOwner: encodeHexLower(raw.subarray(o.workflowOwner, o.workflowOwner + o.workflowOwnerSize)),
    reportId: encodeHexLower(raw.subarray(o.reportId, o.reportId + o.reportIdSize)),
    body: raw.subarray(REPORT_METADATA_HEADER_LENGTH)
  };
}

class Report {
  report;
  cachedHeader;
  constructor(report) {
    this.report = report.$typeName ? report : fromJson(ReportResponseSchema, report);
  }
  static async parse(runtime, rawReport, signatures, reportContext, config) {
    const configDigest = reportContext.length >= 32 ? reportContext.slice(0, 32) : new Uint8Array(32);
    const seqNr = reportContext.length >= 40 ? new DataView(reportContext.buffer, reportContext.byteOffset + 32, 8).getBigUint64(0, false) : 0n;
    const reportResponse = create(ReportResponseSchema, {
      configDigest,
      seqNr,
      reportContext,
      rawReport,
      sigs: signatures.map((signature) => create(AttributedSignatureSchema, { signature, signerId: 0 }))
    });
    const merged = mergeReportParseConfig(config);
    const report = new Report(reportResponse);
    if (merged.skipSignatureVerification) {
      report.donId();
      return report;
    }
    await report.verifySignaturesWithConfig(runtime, merged);
    return report;
  }
  parseHeader() {
    if (this.cachedHeader !== undefined) {
      return this.cachedHeader;
    }
    this.cachedHeader = parseReportMetadataHeader(this.report.rawReport);
    return this.cachedHeader;
  }
  async verifySignaturesWithConfig(runtime, config) {
    const donId = this.donId();
    const candidates = [];
    for (const z of config.acceptedZones) {
      if (z.donID === donId) {
        candidates.push(z.environment);
      }
    }
    candidates.push(...config.acceptedEnvironments);
    if (candidates.length === 0) {
      throw new Error(`DON ID ${donId} is not in accepted zones`);
    }
    const fetchFailures = [];
    let lastVerifyErr = null;
    for (const env of candidates) {
      let info;
      try {
        info = fetchDONInfo(runtime, env, donId);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        fetchFailures.push(new Error(`could not read from chain ${env.chainSelector} contract ${env.registryAddress}: ${msg}`));
        continue;
      }
      try {
        await verifySigs(this.report, info.f, normalizeDonSigners(info.signers));
        return;
      } catch (err) {
        lastVerifyErr = err instanceof Error ? err : new Error(String(err));
      }
    }
    if (fetchFailures.length > 0) {
      throw new AggregateError(fetchFailures, fetchFailures.map((e) => e.message).join(`
`));
    }
    if (lastVerifyErr !== null) {
      throw lastVerifyErr;
    }
  }
  seqNr() {
    return this.report.seqNr;
  }
  configDigest() {
    return this.report.configDigest;
  }
  reportContext() {
    return this.report.reportContext;
  }
  rawReport() {
    return this.report.rawReport;
  }
  version() {
    return this.parseHeader().version;
  }
  executionId() {
    return this.parseHeader().executionId;
  }
  timestamp() {
    return this.parseHeader().timestamp;
  }
  donId() {
    return this.parseHeader().donId;
  }
  donConfigVersion() {
    return this.parseHeader().donConfigVersion;
  }
  workflowId() {
    return this.parseHeader().workflowId;
  }
  workflowName() {
    return this.parseHeader().workflowName;
  }
  workflowOwner() {
    return this.parseHeader().workflowOwner;
  }
  reportId() {
    return this.parseHeader().reportId;
  }
  body() {
    return this.parseHeader().body;
  }
  x_generatedCodeOnly_unwrap() {
    return this.report;
  }
}
var hexToBytes3 = (hexStr) => {
  if (!hexStr.startsWith("0x")) {
    throw new Error(`Invalid hex string: ${hexStr}`);
  }
  if (!/^0x[0-9a-fA-F]*$/.test(hexStr)) {
    throw new Error(`Invalid hex string: ${hexStr}`);
  }
  if ((hexStr.length - 2) % 2 !== 0) {
    throw new Error(`Hex string must have an even number of characters: ${hexStr}`);
  }
  const hex = hexStr.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0;i < hex.length; i += 2) {
    bytes[i / 2] = Number.parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
};
var bytesToHex3 = (bytes) => {
  return `0x${Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("")}`;
};
var bytesToBase64 = (bytes) => {
  return Buffer.from(bytes).toString("base64");
};
var hexToBase64 = (hex) => {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (cleanHex.length === 0) {
    return "";
  }
  if (cleanHex.length % 2 !== 0) {
    throw new Error(`Hex string must have an even number of characters: ${hex}`);
  }
  if (!/^[0-9a-fA-F]*$/.test(cleanHex)) {
    throw new Error(`Invalid hex string: ${hex}`);
  }
  return Buffer.from(cleanHex, "hex").toString("base64");
};
function createWriteCreReportRequest(input) {
  return {
    receiver: hexToBytes3(input.receiver),
    report: input.report,
    gasConfig: input.gasConfig !== undefined ? fromJson(GasConfigSchema, input.gasConfig) : undefined,
    $report: true
  };
}
function x_generatedCodeOnly_unwrap_WriteCreReportRequest(input) {
  return create(WriteReportRequestSchema, {
    receiver: input.receiver,
    report: input.report !== undefined ? input.report.x_generatedCodeOnly_unwrap() : undefined,
    gasConfig: input.gasConfig
  });
}

class ClientCapability {
  ChainSelector;
  static CAPABILITY_ID = "evm@1.0.0";
  static CAPABILITY_NAME = "evm";
  static CAPABILITY_VERSION = "1.0.0";
  static SUPPORTED_CHAIN_SELECTORS = {
    "adi-mainnet": 4059281736450291836n,
    "adi-testnet": 9418205736192840573n,
    "apechain-testnet-curtis": 9900119385908781505n,
    "arc-testnet": 3034092155422581607n,
    "avalanche-mainnet": 6433500567565415381n,
    "avalanche-testnet-fuji": 14767482510784806043n,
    "binance_smart_chain-mainnet": 11344663589394136015n,
    "binance_smart_chain-testnet": 13264668187771770619n,
    "celo-mainnet": 1346049177634351622n,
    "celo-sepolia": 3761762704474186180n,
    "cronos-testnet": 2995292832068775165n,
    "dtcc-mainnet-appchain": 13879014182901017172n,
    "dtcc-testnet-andesite": 15513093881969820114n,
    "ethereum-mainnet": 5009297550715157269n,
    "ethereum-mainnet-arbitrum-1": 4949039107694359620n,
    "ethereum-mainnet-base-1": 15971525489660198786n,
    "ethereum-mainnet-ink-1": 3461204551265785888n,
    "ethereum-mainnet-linea-1": 4627098889531055414n,
    "ethereum-mainnet-mantle-1": 1556008542357238666n,
    "ethereum-mainnet-optimism-1": 3734403246176062136n,
    "ethereum-mainnet-scroll-1": 13204309965629103672n,
    "ethereum-mainnet-worldchain-1": 2049429975587534727n,
    "ethereum-mainnet-xlayer-1": 3016212468291539606n,
    "ethereum-mainnet-zksync-1": 1562403441176082196n,
    "ethereum-testnet-hoodi": 10380998176179737091n,
    "ethereum-testnet-sepolia": 16015286601757825753n,
    "ethereum-testnet-sepolia-arbitrum-1": 3478487238524512106n,
    "ethereum-testnet-sepolia-base-1": 10344971235874465080n,
    "ethereum-testnet-sepolia-linea-1": 5719461335882077547n,
    "ethereum-testnet-sepolia-mantle-1": 8236463271206331221n,
    "ethereum-testnet-sepolia-optimism-1": 5224473277236331295n,
    "ethereum-testnet-sepolia-scroll-1": 2279865765895943307n,
    "ethereum-testnet-sepolia-unichain-1": 14135854469784514356n,
    "ethereum-testnet-sepolia-worldchain-1": 5299555114858065850n,
    "ethereum-testnet-sepolia-zksync-1": 6898391096552792247n,
    "gnosis_chain-mainnet": 465200170687744372n,
    "gnosis_chain-testnet-chiado": 8871595565390010547n,
    "hyperliquid-mainnet": 2442541497099098535n,
    "hyperliquid-testnet": 4286062357653186312n,
    "ink-testnet-sepolia": 9763904284804119144n,
    "jovay-mainnet": 1523760397290643893n,
    "jovay-testnet": 945045181441419236n,
    "megaeth-mainnet": 6093540873831549674n,
    "megaeth-testnet-2": 18241817625092392675n,
    "monad-mainnet": 8481857512324358265n,
    "monad-testnet": 2183018362218727504n,
    "pharos-atlantic-testnet": 16098325658947243212n,
    "pharos-mainnet": 7801139999541420232n,
    "plasma-mainnet": 9335212494177455608n,
    "plasma-testnet": 3967220077692964309n,
    "polygon-mainnet": 4051577828743386545n,
    "polygon-testnet-amoy": 16281711391670634445n,
    "private-testnet-andesite": 6915682381028791124n,
    "private-testnet-basalt": 18362000170840307455n,
    "private-testnet-pumice": 1564738277398880633n,
    "private-testnet-quartzite": 4175996748267305081n,
    "private-testnet-rhyolite": 604447335222770945n,
    "robinhood-testnet": 2032988798112970440n,
    "sonic-mainnet": 1673871237479749969n,
    "sonic-testnet": 1763698235108410440n,
    "stable-testnet": 11793402411494852765n,
    "t-rex-testnet": 17611928792452358269n,
    "tac-testnet": 9488606126177218005n,
    "tempo-testnet-moderato": 8457817439310187923n,
    "xlayer-testnet": 10212741611335999305n
  };
  constructor(ChainSelector) {
    this.ChainSelector = ChainSelector;
  }
  callContract(runtime, input) {
    let payload;
    if (input.$typeName) {
      payload = input;
    } else {
      payload = fromJson(CallContractRequestSchema, input);
    }
    const capabilityId = `${ClientCapability.CAPABILITY_NAME}:ChainSelector:${this.ChainSelector}@${ClientCapability.CAPABILITY_VERSION}`;
    const capabilityResponse = runtime.callCapability({
      capabilityId,
      method: "CallContract",
      payload,
      inputSchema: CallContractRequestSchema,
      outputSchema: CallContractReplySchema
    });
    return {
      result: () => {
        const result = capabilityResponse.result();
        return result;
      }
    };
  }
  filterLogs(runtime, input) {
    let payload;
    if (input.$typeName) {
      payload = input;
    } else {
      payload = fromJson(FilterLogsRequestSchema, input);
    }
    const capabilityId = `${ClientCapability.CAPABILITY_NAME}:ChainSelector:${this.ChainSelector}@${ClientCapability.CAPABILITY_VERSION}`;
    const capabilityResponse = runtime.callCapability({
      capabilityId,
      method: "FilterLogs",
      payload,
      inputSchema: FilterLogsRequestSchema,
      outputSchema: FilterLogsReplySchema
    });
    return {
      result: () => {
        const result = capabilityResponse.result();
        return result;
      }
    };
  }
  balanceAt(runtime, input) {
    let payload;
    if (input.$typeName) {
      payload = input;
    } else {
      payload = fromJson(BalanceAtRequestSchema, input);
    }
    const capabilityId = `${ClientCapability.CAPABILITY_NAME}:ChainSelector:${this.ChainSelector}@${ClientCapability.CAPABILITY_VERSION}`;
    const capabilityResponse = runtime.callCapability({
      capabilityId,
      method: "BalanceAt",
      payload,
      inputSchema: BalanceAtRequestSchema,
      outputSchema: BalanceAtReplySchema
    });
    return {
      result: () => {
        const result = capabilityResponse.result();
        return result;
      }
    };
  }
  estimateGas(runtime, input) {
    let payload;
    if (input.$typeName) {
      payload = input;
    } else {
      payload = fromJson(EstimateGasRequestSchema, input);
    }
    const capabilityId = `${ClientCapability.CAPABILITY_NAME}:ChainSelector:${this.ChainSelector}@${ClientCapability.CAPABILITY_VERSION}`;
    const capabilityResponse = runtime.callCapability({
      capabilityId,
      method: "EstimateGas",
      payload,
      inputSchema: EstimateGasRequestSchema,
      outputSchema: EstimateGasReplySchema
    });
    return {
      result: () => {
        const result = capabilityResponse.result();
        return result;
      }
    };
  }
  getTransactionByHash(runtime, input) {
    let payload;
    if (input.$typeName) {
      payload = input;
    } else {
      payload = fromJson(GetTransactionByHashRequestSchema, input);
    }
    const capabilityId = `${ClientCapability.CAPABILITY_NAME}:ChainSelector:${this.ChainSelector}@${ClientCapability.CAPABILITY_VERSION}`;
    const capabilityResponse = runtime.callCapability({
      capabilityId,
      method: "GetTransactionByHash",
      payload,
      inputSchema: GetTransactionByHashRequestSchema,
      outputSchema: GetTransactionByHashReplySchema
    });
    return {
      result: () => {
        const result = capabilityResponse.result();
        return result;
      }
    };
  }
  getTransactionReceipt(runtime, input) {
    let payload;
    if (input.$typeName) {
      payload = input;
    } else {
      payload = fromJson(GetTransactionReceiptRequestSchema, input);
    }
    const capabilityId = `${ClientCapability.CAPABILITY_NAME}:ChainSelector:${this.ChainSelector}@${ClientCapability.CAPABILITY_VERSION}`;
    const capabilityResponse = runtime.callCapability({
      capabilityId,
      method: "GetTransactionReceipt",
      payload,
      inputSchema: GetTransactionReceiptRequestSchema,
      outputSchema: GetTransactionReceiptReplySchema
    });
    return {
      result: () => {
        const result = capabilityResponse.result();
        return result;
      }
    };
  }
  headerByNumber(runtime, input) {
    let payload;
    if (input.$typeName) {
      payload = input;
    } else {
      payload = fromJson(HeaderByNumberRequestSchema, input);
    }
    const capabilityId = `${ClientCapability.CAPABILITY_NAME}:ChainSelector:${this.ChainSelector}@${ClientCapability.CAPABILITY_VERSION}`;
    const capabilityResponse = runtime.callCapability({
      capabilityId,
      method: "HeaderByNumber",
      payload,
      inputSchema: HeaderByNumberRequestSchema,
      outputSchema: HeaderByNumberReplySchema
    });
    return {
      result: () => {
        const result = capabilityResponse.result();
        return result;
      }
    };
  }
  logTrigger(config) {
    const capabilityId = `${ClientCapability.CAPABILITY_NAME}:ChainSelector:${this.ChainSelector}@${ClientCapability.CAPABILITY_VERSION}`;
    return new ClientLogTrigger(config, capabilityId, "LogTrigger", this.ChainSelector);
  }
  writeReport(runtime, input) {
    let payload;
    if (input.$report) {
      payload = x_generatedCodeOnly_unwrap_WriteCreReportRequest(input);
    } else {
      payload = x_generatedCodeOnly_unwrap_WriteCreReportRequest(createWriteCreReportRequest(input));
    }
    const capabilityId = `${ClientCapability.CAPABILITY_NAME}:ChainSelector:${this.ChainSelector}@${ClientCapability.CAPABILITY_VERSION}`;
    const capabilityResponse = runtime.callCapability({
      capabilityId,
      method: "WriteReport",
      payload,
      inputSchema: WriteReportRequestSchema,
      outputSchema: WriteReportReplySchema
    });
    return {
      result: () => {
        const result = capabilityResponse.result();
        return result;
      }
    };
  }
}

class ClientLogTrigger {
  _capabilityId;
  _method;
  ChainSelector;
  config;
  constructor(config, _capabilityId, _method, ChainSelector) {
    this._capabilityId = _capabilityId;
    this._method = _method;
    this.ChainSelector = ChainSelector;
    this.config = config.$typeName ? config : fromJson(FilterLogTriggerRequestSchema, config);
  }
  capabilityId() {
    return this._capabilityId;
  }
  method() {
    return this._method;
  }
  outputSchema() {
    return LogSchema;
  }
  configAsAny() {
    return anyPack(FilterLogTriggerRequestSchema, this.config);
  }
  adapt(rawOutput) {
    return rawOutput;
  }
}
var EncodingType;
(function(EncodingType) {
  EncodingType[EncodingType["NONE"] = 0] = "NONE";
  EncodingType[EncodingType["BASE58"] = 1] = "BASE58";
  EncodingType[EncodingType["BASE64"] = 2] = "BASE64";
  EncodingType[EncodingType["BASE64_ZSTD"] = 3] = "BASE64_ZSTD";
  EncodingType[EncodingType["JSON_PARSED"] = 4] = "JSON_PARSED";
  EncodingType[EncodingType["JSON"] = 5] = "JSON";
})(EncodingType || (EncodingType = {}));
var CommitmentType;
(function(CommitmentType) {
  CommitmentType[CommitmentType["NONE"] = 0] = "NONE";
  CommitmentType[CommitmentType["FINALIZED"] = 1] = "FINALIZED";
  CommitmentType[CommitmentType["CONFIRMED"] = 2] = "CONFIRMED";
  CommitmentType[CommitmentType["PROCESSED"] = 3] = "PROCESSED";
})(CommitmentType || (CommitmentType = {}));
var ConfirmationStatusType;
(function(ConfirmationStatusType) {
  ConfirmationStatusType[ConfirmationStatusType["NONE"] = 0] = "NONE";
  ConfirmationStatusType[ConfirmationStatusType["PROCESSED"] = 1] = "PROCESSED";
  ConfirmationStatusType[ConfirmationStatusType["CONFIRMED"] = 2] = "CONFIRMED";
  ConfirmationStatusType[ConfirmationStatusType["FINALIZED"] = 3] = "FINALIZED";
})(ConfirmationStatusType || (ConfirmationStatusType = {}));
var TxStatus2;
(function(TxStatus) {
  TxStatus[TxStatus["FATAL"] = 0] = "FATAL";
  TxStatus[TxStatus["ABORTED"] = 1] = "ABORTED";
  TxStatus[TxStatus["SUCCESS"] = 2] = "SUCCESS";
})(TxStatus2 || (TxStatus2 = {}));
var ComparisonOperator;
(function(ComparisonOperator) {
  ComparisonOperator[ComparisonOperator["EQ"] = 0] = "EQ";
  ComparisonOperator[ComparisonOperator["NEQ"] = 1] = "NEQ";
  ComparisonOperator[ComparisonOperator["GT"] = 2] = "GT";
  ComparisonOperator[ComparisonOperator["LT"] = 3] = "LT";
  ComparisonOperator[ComparisonOperator["GTE"] = 4] = "GTE";
  ComparisonOperator[ComparisonOperator["LTE"] = 5] = "LTE";
})(ComparisonOperator || (ComparisonOperator = {}));
var ReceiverContractExecutionStatus2;
(function(ReceiverContractExecutionStatus) {
  ReceiverContractExecutionStatus[ReceiverContractExecutionStatus["SUCCESS"] = 0] = "SUCCESS";
  ReceiverContractExecutionStatus[ReceiverContractExecutionStatus["REVERTED"] = 1] = "REVERTED";
})(ReceiverContractExecutionStatus2 || (ReceiverContractExecutionStatus2 = {}));
var file_capabilities_networking_confidentialhttp_v1alpha_client = /* @__PURE__ */ fileDesc("Cj1jYXBhYmlsaXRpZXMvbmV0d29ya2luZy9jb25maWRlbnRpYWxodHRwL3YxYWxwaGEvY2xpZW50LnByb3RvEjBjYXBhYmlsaXRpZXMubmV0d29ya2luZy5jb25maWRlbnRpYWxodHRwLnYxYWxwaGEiUAoQU2VjcmV0SWRlbnRpZmllchILCgNrZXkYASABKAkSEQoJbmFtZXNwYWNlGAIgASgJEhIKBW93bmVyGAMgASgJSACIAQFCCAoGX293bmVyIh4KDEhlYWRlclZhbHVlcxIOCgZ2YWx1ZXMYASADKAki1wQKC0hUVFBSZXF1ZXN0EgsKA3VybBgBIAEoCRIOCgZtZXRob2QYAiABKAkSFQoLYm9keV9zdHJpbmcYAyABKAlIABIUCgpib2R5X2J5dGVzGAggASgMSAASZgoNbXVsdGlfaGVhZGVycxgEIAMoCzJPLmNhcGFiaWxpdGllcy5uZXR3b3JraW5nLmNvbmZpZGVudGlhbGh0dHAudjFhbHBoYS5IVFRQUmVxdWVzdC5NdWx0aUhlYWRlcnNFbnRyeRJ3ChZ0ZW1wbGF0ZV9wdWJsaWNfdmFsdWVzGAUgAygLMlcuY2FwYWJpbGl0aWVzLm5ldHdvcmtpbmcuY29uZmlkZW50aWFsaHR0cC52MWFscGhhLkhUVFBSZXF1ZXN0LlRlbXBsYXRlUHVibGljVmFsdWVzRW50cnkSHwoXY3VzdG9tX3Jvb3RfY2FfY2VydF9wZW0YBiABKAwSKgoHdGltZW91dBgHIAEoCzIZLmdvb2dsZS5wcm90b2J1Zi5EdXJhdGlvbhIWCg5lbmNyeXB0X291dHB1dBgJIAEoCBpzChFNdWx0aUhlYWRlcnNFbnRyeRILCgNrZXkYASABKAkSTQoFdmFsdWUYAiABKAsyPi5jYXBhYmlsaXRpZXMubmV0d29ya2luZy5jb25maWRlbnRpYWxodHRwLnYxYWxwaGEuSGVhZGVyVmFsdWVzOgI4ARo7ChlUZW1wbGF0ZVB1YmxpY1ZhbHVlc0VudHJ5EgsKA2tleRgBIAEoCRINCgV2YWx1ZRgCIAEoCToCOAFCBgoEYm9keSKPAgoMSFRUUFJlc3BvbnNlEhMKC3N0YXR1c19jb2RlGAEgASgNEgwKBGJvZHkYAiABKAwSZwoNbXVsdGlfaGVhZGVycxgDIAMoCzJQLmNhcGFiaWxpdGllcy5uZXR3b3JraW5nLmNvbmZpZGVudGlhbGh0dHAudjFhbHBoYS5IVFRQUmVzcG9uc2UuTXVsdGlIZWFkZXJzRW50cnkacwoRTXVsdGlIZWFkZXJzRW50cnkSCwoDa2V5GAEgASgJEk0KBXZhbHVlGAIgASgLMj4uY2FwYWJpbGl0aWVzLm5ldHdvcmtpbmcuY29uZmlkZW50aWFsaHR0cC52MWFscGhhLkhlYWRlclZhbHVlczoCOAEiyAEKF0NvbmZpZGVudGlhbEhUVFBSZXF1ZXN0El0KEXZhdWx0X2Rvbl9zZWNyZXRzGAEgAygLMkIuY2FwYWJpbGl0aWVzLm5ldHdvcmtpbmcuY29uZmlkZW50aWFsaHR0cC52MWFscGhhLlNlY3JldElkZW50aWZpZXISTgoHcmVxdWVzdBgCIAEoCzI9LmNhcGFiaWxpdGllcy5uZXR3b3JraW5nLmNvbmZpZGVudGlhbGh0dHAudjFhbHBoYS5IVFRQUmVxdWVzdDLKAQoGQ2xpZW50EpgBCgtTZW5kUmVxdWVzdBJJLmNhcGFiaWxpdGllcy5uZXR3b3JraW5nLmNvbmZpZGVudGlhbGh0dHAudjFhbHBoYS5Db25maWRlbnRpYWxIVFRQUmVxdWVzdBo+LmNhcGFiaWxpdGllcy5uZXR3b3JraW5nLmNvbmZpZGVudGlhbGh0dHAudjFhbHBoYS5IVFRQUmVzcG9uc2UaJYK1GCEIARIdY29uZmlkZW50aWFsLWh0dHBAMS4wLjAtYWxwaGFCpgIKNGNvbS5jYXBhYmlsaXRpZXMubmV0d29ya2luZy5jb25maWRlbnRpYWxodHRwLnYxYWxwaGFCC0NsaWVudFByb3RvUAGiAgNDTkOqAjBDYXBhYmlsaXRpZXMuTmV0d29ya2luZy5Db25maWRlbnRpYWxodHRwLlYxYWxwaGHKAjBDYXBhYmlsaXRpZXNcTmV0d29ya2luZ1xDb25maWRlbnRpYWxodHRwXFYxYWxwaGHiAjxDYXBhYmlsaXRpZXNcTmV0d29ya2luZ1xDb25maWRlbnRpYWxodHRwXFYxYWxwaGFcR1BCTWV0YWRhdGHqAjNDYXBhYmlsaXRpZXM6Ok5ldHdvcmtpbmc6OkNvbmZpZGVudGlhbGh0dHA6OlYxYWxwaGFiBnByb3RvMw", [file_google_protobuf_duration, file_tools_generator_v1alpha_cre_metadata]);
var HTTPResponseSchema = /* @__PURE__ */ messageDesc(file_capabilities_networking_confidentialhttp_v1alpha_client, 3);
var ConfidentialHTTPRequestSchema = /* @__PURE__ */ messageDesc(file_capabilities_networking_confidentialhttp_v1alpha_client, 4);

class ClientCapability2 {
  static CAPABILITY_ID = "confidential-http@1.0.0-alpha";
  static CAPABILITY_NAME = "confidential-http";
  static CAPABILITY_VERSION = "1.0.0-alpha";
  sendRequest(runtime, input) {
    let payload;
    if (input.$typeName) {
      payload = input;
    } else {
      payload = fromJson(ConfidentialHTTPRequestSchema, input);
    }
    const capabilityId = ClientCapability2.CAPABILITY_ID;
    const capabilityResponse = runtime.callCapability({
      capabilityId,
      method: "SendRequest",
      payload,
      inputSchema: ConfidentialHTTPRequestSchema,
      outputSchema: HTTPResponseSchema
    });
    return {
      result: () => {
        const result = capabilityResponse.result();
        return result;
      }
    };
  }
}
var file_capabilities_networking_http_v1alpha_client = /* @__PURE__ */ fileDesc("CjFjYXBhYmlsaXRpZXMvbmV0d29ya2luZy9odHRwL3YxYWxwaGEvY2xpZW50LnByb3RvEiRjYXBhYmlsaXRpZXMubmV0d29ya2luZy5odHRwLnYxYWxwaGEiSgoNQ2FjaGVTZXR0aW5ncxINCgVzdG9yZRgBIAEoCBIqCgdtYXhfYWdlGAIgASgLMhkuZ29vZ2xlLnByb3RvYnVmLkR1cmF0aW9uIh4KDEhlYWRlclZhbHVlcxIOCgZ2YWx1ZXMYASADKAkiNAoITXRsc0F1dGgSEwoLcHJpdmF0ZV9rZXkYASABKAwSEwoLY2VydGlmaWNhdGUYAiABKAwiuwQKB1JlcXVlc3QSCwoDdXJsGAEgASgJEg4KBm1ldGhvZBgCIAEoCRJPCgdoZWFkZXJzGAMgAygLMjouY2FwYWJpbGl0aWVzLm5ldHdvcmtpbmcuaHR0cC52MWFscGhhLlJlcXVlc3QuSGVhZGVyc0VudHJ5QgIYARIMCgRib2R5GAQgASgMEioKB3RpbWVvdXQYBSABKAsyGS5nb29nbGUucHJvdG9idWYuRHVyYXRpb24SSwoOY2FjaGVfc2V0dGluZ3MYBiABKAsyMy5jYXBhYmlsaXRpZXMubmV0d29ya2luZy5odHRwLnYxYWxwaGEuQ2FjaGVTZXR0aW5ncxJWCg1tdWx0aV9oZWFkZXJzGAcgAygLMj8uY2FwYWJpbGl0aWVzLm5ldHdvcmtpbmcuaHR0cC52MWFscGhhLlJlcXVlc3QuTXVsdGlIZWFkZXJzRW50cnkSQQoEbXRscxgIIAEoCzIuLmNhcGFiaWxpdGllcy5uZXR3b3JraW5nLmh0dHAudjFhbHBoYS5NdGxzQXV0aEgAiAEBGi4KDEhlYWRlcnNFbnRyeRILCgNrZXkYASABKAkSDQoFdmFsdWUYAiABKAk6AjgBGmcKEU11bHRpSGVhZGVyc0VudHJ5EgsKA2tleRgBIAEoCRJBCgV2YWx1ZRgCIAEoCzIyLmNhcGFiaWxpdGllcy5uZXR3b3JraW5nLmh0dHAudjFhbHBoYS5IZWFkZXJWYWx1ZXM6AjgBQgcKBV9tdGxzIvECCghSZXNwb25zZRITCgtzdGF0dXNfY29kZRgBIAEoDRJQCgdoZWFkZXJzGAIgAygLMjsuY2FwYWJpbGl0aWVzLm5ldHdvcmtpbmcuaHR0cC52MWFscGhhLlJlc3BvbnNlLkhlYWRlcnNFbnRyeUICGAESDAoEYm9keRgDIAEoDBJXCg1tdWx0aV9oZWFkZXJzGAQgAygLMkAuY2FwYWJpbGl0aWVzLm5ldHdvcmtpbmcuaHR0cC52MWFscGhhLlJlc3BvbnNlLk11bHRpSGVhZGVyc0VudHJ5Gi4KDEhlYWRlcnNFbnRyeRILCgNrZXkYASABKAkSDQoFdmFsdWUYAiABKAk6AjgBGmcKEU11bHRpSGVhZGVyc0VudHJ5EgsKA2tleRgBIAEoCRJBCgV2YWx1ZRgCIAEoCzIyLmNhcGFiaWxpdGllcy5uZXR3b3JraW5nLmh0dHAudjFhbHBoYS5IZWFkZXJWYWx1ZXM6AjgBMpsBCgZDbGllbnQSbAoLU2VuZFJlcXVlc3QSLS5jYXBhYmlsaXRpZXMubmV0d29ya2luZy5odHRwLnYxYWxwaGEuUmVxdWVzdBouLmNhcGFiaWxpdGllcy5uZXR3b3JraW5nLmh0dHAudjFhbHBoYS5SZXNwb25zZRojgrUYHwgCEhhodHRwLWFjdGlvbnNAMS4wLjAtYWxwaGEiAQFC6gEKKGNvbS5jYXBhYmlsaXRpZXMubmV0d29ya2luZy5odHRwLnYxYWxwaGFCC0NsaWVudFByb3RvUAGiAgNDTkiqAiRDYXBhYmlsaXRpZXMuTmV0d29ya2luZy5IdHRwLlYxYWxwaGHKAiRDYXBhYmlsaXRpZXNcTmV0d29ya2luZ1xIdHRwXFYxYWxwaGHiAjBDYXBhYmlsaXRpZXNcTmV0d29ya2luZ1xIdHRwXFYxYWxwaGFcR1BCTWV0YWRhdGHqAidDYXBhYmlsaXRpZXM6Ok5ldHdvcmtpbmc6Okh0dHA6OlYxYWxwaGFiBnByb3RvMw", [file_google_protobuf_duration, file_tools_generator_v1alpha_cre_metadata]);
var RequestSchema = /* @__PURE__ */ messageDesc(file_capabilities_networking_http_v1alpha_client, 3);
var ResponseSchema = /* @__PURE__ */ messageDesc(file_capabilities_networking_http_v1alpha_client, 4);

class SendRequester {
  runtime;
  client;
  constructor(runtime, client) {
    this.runtime = runtime;
    this.client = client;
  }
  sendRequest(input) {
    return this.client.sendRequest(this.runtime, input);
  }
}

class ClientCapability3 {
  static CAPABILITY_ID = "http-actions@1.0.0-alpha";
  static CAPABILITY_NAME = "http-actions";
  static CAPABILITY_VERSION = "1.0.0-alpha";
  sendRequest(...args) {
    if (typeof args[1] === "function") {
      const [runtime, fn, consensusAggregation, unwrapOptions] = args;
      return this.sendRequestSugarHelper(runtime, fn, consensusAggregation, unwrapOptions);
    }
    const [runtime, input] = args;
    return this.sendRequestCallHelper(runtime, input);
  }
  sendRequestCallHelper(runtime, input) {
    let payload;
    if (input.$typeName) {
      payload = input;
    } else {
      payload = fromJson(RequestSchema, input);
    }
    const capabilityId = ClientCapability3.CAPABILITY_ID;
    const capabilityResponse = runtime.callCapability({
      capabilityId,
      method: "SendRequest",
      payload,
      inputSchema: RequestSchema,
      outputSchema: ResponseSchema
    });
    return {
      result: () => {
        const result = capabilityResponse.result();
        return result;
      }
    };
  }
  sendRequestSugarHelper(runtime, fn, consensusAggregation, unwrapOptions) {
    const wrappedFn = (runtime, ...args) => {
      const sendRequester = new SendRequester(runtime, this);
      return fn(sendRequester, ...args);
    };
    return runtime.runInNodeMode(wrappedFn, consensusAggregation, unwrapOptions);
  }
}
var file_capabilities_networking_http_v1alpha_trigger = /* @__PURE__ */ fileDesc("CjJjYXBhYmlsaXRpZXMvbmV0d29ya2luZy9odHRwL3YxYWxwaGEvdHJpZ2dlci5wcm90bxIkY2FwYWJpbGl0aWVzLm5ldHdvcmtpbmcuaHR0cC52MWFscGhhIlYKBkNvbmZpZxJMCg9hdXRob3JpemVkX2tleXMYASADKAsyMy5jYXBhYmlsaXRpZXMubmV0d29ya2luZy5odHRwLnYxYWxwaGEuQXV0aG9yaXplZEtleSJaCgdQYXlsb2FkEg0KBWlucHV0GAEgASgMEkAKA2tleRgCIAEoCzIzLmNhcGFiaWxpdGllcy5uZXR3b3JraW5nLmh0dHAudjFhbHBoYS5BdXRob3JpemVkS2V5ImAKDUF1dGhvcml6ZWRLZXkSOwoEdHlwZRgBIAEoDjItLmNhcGFiaWxpdGllcy5uZXR3b3JraW5nLmh0dHAudjFhbHBoYS5LZXlUeXBlEhIKCnB1YmxpY19rZXkYAiABKAkqOwoHS2V5VHlwZRIYChRLRVlfVFlQRV9VTlNQRUNJRklFRBAAEhYKEktFWV9UWVBFX0VDRFNBX0VWTRABMpIBCgRIVFRQEmgKB1RyaWdnZXISLC5jYXBhYmlsaXRpZXMubmV0d29ya2luZy5odHRwLnYxYWxwaGEuQ29uZmlnGi0uY2FwYWJpbGl0aWVzLm5ldHdvcmtpbmcuaHR0cC52MWFscGhhLlBheWxvYWQwARoggrUYHAgBEhhodHRwLXRyaWdnZXJAMS4wLjAtYWxwaGFC6wEKKGNvbS5jYXBhYmlsaXRpZXMubmV0d29ya2luZy5odHRwLnYxYWxwaGFCDFRyaWdnZXJQcm90b1ABogIDQ05IqgIkQ2FwYWJpbGl0aWVzLk5ldHdvcmtpbmcuSHR0cC5WMWFscGhhygIkQ2FwYWJpbGl0aWVzXE5ldHdvcmtpbmdcSHR0cFxWMWFscGhh4gIwQ2FwYWJpbGl0aWVzXE5ldHdvcmtpbmdcSHR0cFxWMWFscGhhXEdQQk1ldGFkYXRh6gInQ2FwYWJpbGl0aWVzOjpOZXR3b3JraW5nOjpIdHRwOjpWMWFscGhhYgZwcm90bzM", [file_tools_generator_v1alpha_cre_metadata]);
var ConfigSchema = /* @__PURE__ */ messageDesc(file_capabilities_networking_http_v1alpha_trigger, 0);
var PayloadSchema = /* @__PURE__ */ messageDesc(file_capabilities_networking_http_v1alpha_trigger, 1);
var KeyType;
(function(KeyType) {
  KeyType[KeyType["UNSPECIFIED"] = 0] = "UNSPECIFIED";
  KeyType[KeyType["ECDSA_EVM"] = 1] = "ECDSA_EVM";
})(KeyType || (KeyType = {}));

class HTTPCapability {
  static CAPABILITY_ID = "http-trigger@1.0.0-alpha";
  static CAPABILITY_NAME = "http-trigger";
  static CAPABILITY_VERSION = "1.0.0-alpha";
  trigger(config) {
    const capabilityId = HTTPCapability.CAPABILITY_ID;
    return new HTTPTrigger(config, capabilityId, "Trigger");
  }
}

class HTTPTrigger {
  _capabilityId;
  _method;
  config;
  constructor(config, _capabilityId, _method) {
    this._capabilityId = _capabilityId;
    this._method = _method;
    this.config = config.$typeName ? config : fromJson(ConfigSchema, config);
  }
  capabilityId() {
    return this._capabilityId;
  }
  method() {
    return this._method;
  }
  outputSchema() {
    return PayloadSchema;
  }
  configAsAny() {
    return anyPack(ConfigSchema, this.config);
  }
  adapt(rawOutput) {
    return rawOutput;
  }
}
var lookup = [];
var revLookup = [];
var code = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
for (i = 0, len = code.length;i < len; ++i)
  lookup[i] = code[i], revLookup[code.charCodeAt(i)] = i;
var i;
var len;
revLookup[45] = 62;
revLookup[95] = 63;
function getLens(b64) {
  var len2 = b64.length;
  if (len2 % 4 > 0)
    throw Error("Invalid string. Length must be a multiple of 4");
  var validLen = b64.indexOf("=");
  if (validLen === -1)
    validLen = len2;
  var placeHoldersLen = validLen === len2 ? 0 : 4 - validLen % 4;
  return [validLen, placeHoldersLen];
}
function _byteLength(validLen, placeHoldersLen) {
  return (validLen + placeHoldersLen) * 3 / 4 - placeHoldersLen;
}
function toByteArray(b64) {
  var tmp, lens = getLens(b64), validLen = lens[0], placeHoldersLen = lens[1], arr = new Uint8Array(_byteLength(validLen, placeHoldersLen)), curByte = 0, len2 = placeHoldersLen > 0 ? validLen - 4 : validLen, i2;
  for (i2 = 0;i2 < len2; i2 += 4)
    tmp = revLookup[b64.charCodeAt(i2)] << 18 | revLookup[b64.charCodeAt(i2 + 1)] << 12 | revLookup[b64.charCodeAt(i2 + 2)] << 6 | revLookup[b64.charCodeAt(i2 + 3)], arr[curByte++] = tmp >> 16 & 255, arr[curByte++] = tmp >> 8 & 255, arr[curByte++] = tmp & 255;
  if (placeHoldersLen === 2)
    tmp = revLookup[b64.charCodeAt(i2)] << 2 | revLookup[b64.charCodeAt(i2 + 1)] >> 4, arr[curByte++] = tmp & 255;
  if (placeHoldersLen === 1)
    tmp = revLookup[b64.charCodeAt(i2)] << 10 | revLookup[b64.charCodeAt(i2 + 1)] << 4 | revLookup[b64.charCodeAt(i2 + 2)] >> 2, arr[curByte++] = tmp >> 8 & 255, arr[curByte++] = tmp & 255;
  return arr;
}
function tripletToBase64(num) {
  return lookup[num >> 18 & 63] + lookup[num >> 12 & 63] + lookup[num >> 6 & 63] + lookup[num & 63];
}
function encodeChunk(uint8, start, end) {
  var tmp, output = [];
  for (var i2 = start;i2 < end; i2 += 3)
    tmp = (uint8[i2] << 16 & 16711680) + (uint8[i2 + 1] << 8 & 65280) + (uint8[i2 + 2] & 255), output.push(tripletToBase64(tmp));
  return output.join("");
}
function fromByteArray(uint8) {
  var tmp, len2 = uint8.length, extraBytes = len2 % 3, parts = [], maxChunkLength = 16383;
  for (var i2 = 0, len22 = len2 - extraBytes;i2 < len22; i2 += maxChunkLength)
    parts.push(encodeChunk(uint8, i2, i2 + maxChunkLength > len22 ? len22 : i2 + maxChunkLength));
  if (extraBytes === 1)
    tmp = uint8[len2 - 1], parts.push(lookup[tmp >> 2] + lookup[tmp << 4 & 63] + "==");
  else if (extraBytes === 2)
    tmp = (uint8[len2 - 2] << 8) + uint8[len2 - 1], parts.push(lookup[tmp >> 10] + lookup[tmp >> 4 & 63] + lookup[tmp << 2 & 63] + "=");
  return parts.join("");
}
function read(buffer, offset, isLE, mLen, nBytes) {
  var e, m, eLen = nBytes * 8 - mLen - 1, eMax = (1 << eLen) - 1, eBias = eMax >> 1, nBits = -7, i2 = isLE ? nBytes - 1 : 0, d = isLE ? -1 : 1, s = buffer[offset + i2];
  i2 += d, e = s & (1 << -nBits) - 1, s >>= -nBits, nBits += eLen;
  for (;nBits > 0; e = e * 256 + buffer[offset + i2], i2 += d, nBits -= 8)
    ;
  m = e & (1 << -nBits) - 1, e >>= -nBits, nBits += mLen;
  for (;nBits > 0; m = m * 256 + buffer[offset + i2], i2 += d, nBits -= 8)
    ;
  if (e === 0)
    e = 1 - eBias;
  else if (e === eMax)
    return m ? NaN : (s ? -1 : 1) * (1 / 0);
  else
    m = m + Math.pow(2, mLen), e = e - eBias;
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen);
}
function write(buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c, eLen = nBytes * 8 - mLen - 1, eMax = (1 << eLen) - 1, eBias = eMax >> 1, rt = mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0, i2 = isLE ? 0 : nBytes - 1, d = isLE ? 1 : -1, s = value < 0 || value === 0 && 1 / value < 0 ? 1 : 0;
  if (value = Math.abs(value), isNaN(value) || value === 1 / 0)
    m = isNaN(value) ? 1 : 0, e = eMax;
  else {
    if (e = Math.floor(Math.log(value) / Math.LN2), value * (c = Math.pow(2, -e)) < 1)
      e--, c *= 2;
    if (e + eBias >= 1)
      value += rt / c;
    else
      value += rt * Math.pow(2, 1 - eBias);
    if (value * c >= 2)
      e++, c /= 2;
    if (e + eBias >= eMax)
      m = 0, e = eMax;
    else if (e + eBias >= 1)
      m = (value * c - 1) * Math.pow(2, mLen), e = e + eBias;
    else
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen), e = 0;
  }
  for (;mLen >= 8; buffer[offset + i2] = m & 255, i2 += d, m /= 256, mLen -= 8)
    ;
  e = e << mLen | m, eLen += mLen;
  for (;eLen > 0; buffer[offset + i2] = e & 255, i2 += d, e /= 256, eLen -= 8)
    ;
  buffer[offset + i2 - d] |= s * 128;
}
var customInspectSymbol = typeof Symbol === "function" && typeof Symbol.for === "function" ? Symbol.for("nodejs.util.inspect.custom") : null;
var INSPECT_MAX_BYTES = 50;
var kMaxLength = 2147483647;
var btoa2 = globalThis.btoa;
var atob2 = globalThis.atob;
var File2 = globalThis.File;
var Blob = globalThis.Blob;
function createBuffer(length) {
  if (length > kMaxLength)
    throw RangeError('The value "' + length + '" is invalid for option "size"');
  let buf = new Uint8Array(length);
  return Object.setPrototypeOf(buf, Buffer2.prototype), buf;
}
function E(sym, getMessage, Base) {
  return class extends Base {
    constructor() {
      super();
      Object.defineProperty(this, "message", { value: getMessage.apply(this, arguments), writable: true, configurable: true }), this.name = `${this.name} [${sym}]`, this.stack, delete this.name;
    }
    get code() {
      return sym;
    }
    set code(value) {
      Object.defineProperty(this, "code", { configurable: true, enumerable: true, value, writable: true });
    }
    toString() {
      return `${this.name} [${sym}]: ${this.message}`;
    }
  };
}
var ERR_BUFFER_OUT_OF_BOUNDS = E("ERR_BUFFER_OUT_OF_BOUNDS", function(name) {
  if (name)
    return `${name} is outside of buffer bounds`;
  return "Attempt to access memory outside buffer bounds";
}, RangeError);
var ERR_INVALID_ARG_TYPE = E("ERR_INVALID_ARG_TYPE", function(name, actual) {
  return `The "${name}" argument must be of type number. Received type ${typeof actual}`;
}, TypeError);
var ERR_OUT_OF_RANGE = E("ERR_OUT_OF_RANGE", function(str, range, input) {
  let msg = `The value of "${str}" is out of range.`, received = input;
  if (Number.isInteger(input) && Math.abs(input) > 4294967296)
    received = addNumericalSeparator(String(input));
  else if (typeof input === "bigint") {
    if (received = String(input), input > BigInt(2) ** BigInt(32) || input < -(BigInt(2) ** BigInt(32)))
      received = addNumericalSeparator(received);
    received += "n";
  }
  return msg += ` It must be ${range}. Received ${received}`, msg;
}, RangeError);
function Buffer2(arg, encodingOrOffset, length) {
  if (typeof arg === "number") {
    if (typeof encodingOrOffset === "string")
      throw TypeError('The "string" argument must be of type string. Received type number');
    return allocUnsafe(arg);
  }
  return from(arg, encodingOrOffset, length);
}
Object.defineProperty(Buffer2.prototype, "parent", { enumerable: true, get: function() {
  if (!Buffer2.isBuffer(this))
    return;
  return this.buffer;
} });
Object.defineProperty(Buffer2.prototype, "offset", { enumerable: true, get: function() {
  if (!Buffer2.isBuffer(this))
    return;
  return this.byteOffset;
} });
Buffer2.poolSize = 8192;
function from(value, encodingOrOffset, length) {
  if (typeof value === "string")
    return fromString(value, encodingOrOffset);
  if (ArrayBuffer.isView(value))
    return fromArrayView(value);
  if (value == null)
    throw TypeError("The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof value);
  if (isInstance(value, ArrayBuffer) || value && isInstance(value.buffer, ArrayBuffer))
    return fromArrayBuffer(value, encodingOrOffset, length);
  if (typeof SharedArrayBuffer < "u" && (isInstance(value, SharedArrayBuffer) || value && isInstance(value.buffer, SharedArrayBuffer)))
    return fromArrayBuffer(value, encodingOrOffset, length);
  if (typeof value === "number")
    throw TypeError('The "value" argument must not be of type number. Received type number');
  let valueOf = value.valueOf && value.valueOf();
  if (valueOf != null && valueOf !== value)
    return Buffer2.from(valueOf, encodingOrOffset, length);
  let b = fromObject(value);
  if (b)
    return b;
  if (typeof Symbol < "u" && Symbol.toPrimitive != null && typeof value[Symbol.toPrimitive] === "function")
    return Buffer2.from(value[Symbol.toPrimitive]("string"), encodingOrOffset, length);
  throw TypeError("The first argument must be one of type string, Buffer, ArrayBuffer, Array, or Array-like Object. Received type " + typeof value);
}
Buffer2.from = function(value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length);
};
Object.setPrototypeOf(Buffer2.prototype, Uint8Array.prototype);
Object.setPrototypeOf(Buffer2, Uint8Array);
function assertSize2(size) {
  if (typeof size !== "number")
    throw TypeError('"size" argument must be of type number');
  else if (size < 0)
    throw RangeError('The value "' + size + '" is invalid for option "size"');
}
function alloc(size, fill, encoding) {
  if (assertSize2(size), size <= 0)
    return createBuffer(size);
  if (fill !== undefined)
    return typeof encoding === "string" ? createBuffer(size).fill(fill, encoding) : createBuffer(size).fill(fill);
  return createBuffer(size);
}
Buffer2.alloc = function(size, fill, encoding) {
  return alloc(size, fill, encoding);
};
function allocUnsafe(size) {
  return assertSize2(size), createBuffer(size < 0 ? 0 : checked(size) | 0);
}
Buffer2.allocUnsafe = function(size) {
  return allocUnsafe(size);
};
Buffer2.allocUnsafeSlow = function(size) {
  return allocUnsafe(size);
};
function fromString(string, encoding) {
  if (typeof encoding !== "string" || encoding === "")
    encoding = "utf8";
  if (!Buffer2.isEncoding(encoding))
    throw TypeError("Unknown encoding: " + encoding);
  let length = byteLength(string, encoding) | 0, buf = createBuffer(length), actual = buf.write(string, encoding);
  if (actual !== length)
    buf = buf.slice(0, actual);
  return buf;
}
function fromArrayLike(array) {
  let length = array.length < 0 ? 0 : checked(array.length) | 0, buf = createBuffer(length);
  for (let i2 = 0;i2 < length; i2 += 1)
    buf[i2] = array[i2] & 255;
  return buf;
}
function fromArrayView(arrayView) {
  if (isInstance(arrayView, Uint8Array)) {
    let copy = new Uint8Array(arrayView);
    return fromArrayBuffer(copy.buffer, copy.byteOffset, copy.byteLength);
  }
  return fromArrayLike(arrayView);
}
function fromArrayBuffer(array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset)
    throw RangeError('"offset" is outside of buffer bounds');
  if (array.byteLength < byteOffset + (length || 0))
    throw RangeError('"length" is outside of buffer bounds');
  let buf;
  if (byteOffset === undefined && length === undefined)
    buf = new Uint8Array(array);
  else if (length === undefined)
    buf = new Uint8Array(array, byteOffset);
  else
    buf = new Uint8Array(array, byteOffset, length);
  return Object.setPrototypeOf(buf, Buffer2.prototype), buf;
}
function fromObject(obj) {
  if (Buffer2.isBuffer(obj)) {
    let len2 = checked(obj.length) | 0, buf = createBuffer(len2);
    if (buf.length === 0)
      return buf;
    return obj.copy(buf, 0, 0, len2), buf;
  }
  if (obj.length !== undefined) {
    if (typeof obj.length !== "number" || Number.isNaN(obj.length))
      return createBuffer(0);
    return fromArrayLike(obj);
  }
  if (obj.type === "Buffer" && Array.isArray(obj.data))
    return fromArrayLike(obj.data);
}
function checked(length) {
  if (length >= kMaxLength)
    throw RangeError("Attempt to allocate Buffer larger than maximum size: 0x" + kMaxLength.toString(16) + " bytes");
  return length | 0;
}
Buffer2.isBuffer = function(b) {
  return b != null && b._isBuffer === true && b !== Buffer2.prototype;
};
Buffer2.compare = function(a, b) {
  if (isInstance(a, Uint8Array))
    a = Buffer2.from(a, a.offset, a.byteLength);
  if (isInstance(b, Uint8Array))
    b = Buffer2.from(b, b.offset, b.byteLength);
  if (!Buffer2.isBuffer(a) || !Buffer2.isBuffer(b))
    throw TypeError('The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array');
  if (a === b)
    return 0;
  let x = a.length, y = b.length;
  for (let i2 = 0, len2 = Math.min(x, y);i2 < len2; ++i2)
    if (a[i2] !== b[i2]) {
      x = a[i2], y = b[i2];
      break;
    }
  if (x < y)
    return -1;
  if (y < x)
    return 1;
  return 0;
};
Buffer2.isEncoding = function(encoding) {
  switch (String(encoding).toLowerCase()) {
    case "hex":
    case "utf8":
    case "utf-8":
    case "ascii":
    case "latin1":
    case "binary":
    case "base64":
    case "ucs2":
    case "ucs-2":
    case "utf16le":
    case "utf-16le":
      return true;
    default:
      return false;
  }
};
Buffer2.concat = function(list, length) {
  if (!Array.isArray(list))
    throw TypeError('"list" argument must be an Array of Buffers');
  if (list.length === 0)
    return Buffer2.alloc(0);
  let i2;
  if (length === undefined) {
    length = 0;
    for (i2 = 0;i2 < list.length; ++i2)
      length += list[i2].length;
  }
  let buffer = Buffer2.allocUnsafe(length), pos = 0;
  for (i2 = 0;i2 < list.length; ++i2) {
    let buf = list[i2];
    if (isInstance(buf, Uint8Array))
      if (pos + buf.length > buffer.length) {
        if (!Buffer2.isBuffer(buf))
          buf = Buffer2.from(buf);
        buf.copy(buffer, pos);
      } else
        Uint8Array.prototype.set.call(buffer, buf, pos);
    else if (!Buffer2.isBuffer(buf))
      throw TypeError('"list" argument must be an Array of Buffers');
    else
      buf.copy(buffer, pos);
    pos += buf.length;
  }
  return buffer;
};
function byteLength(string, encoding) {
  if (Buffer2.isBuffer(string))
    return string.length;
  if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer))
    return string.byteLength;
  if (typeof string !== "string")
    throw TypeError('The "string" argument must be one of type string, Buffer, or ArrayBuffer. Received type ' + typeof string);
  let len2 = string.length, mustMatch = arguments.length > 2 && arguments[2] === true;
  if (!mustMatch && len2 === 0)
    return 0;
  let loweredCase = false;
  for (;; )
    switch (encoding) {
      case "ascii":
      case "latin1":
      case "binary":
        return len2;
      case "utf8":
      case "utf-8":
        return utf8ToBytes3(string).length;
      case "ucs2":
      case "ucs-2":
      case "utf16le":
      case "utf-16le":
        return len2 * 2;
      case "hex":
        return len2 >>> 1;
      case "base64":
        return base64ToBytes(string).length;
      default:
        if (loweredCase)
          return mustMatch ? -1 : utf8ToBytes3(string).length;
        encoding = ("" + encoding).toLowerCase(), loweredCase = true;
    }
}
Buffer2.byteLength = byteLength;
function slowToString(encoding, start, end) {
  let loweredCase = false;
  if (start === undefined || start < 0)
    start = 0;
  if (start > this.length)
    return "";
  if (end === undefined || end > this.length)
    end = this.length;
  if (end <= 0)
    return "";
  if (end >>>= 0, start >>>= 0, end <= start)
    return "";
  if (!encoding)
    encoding = "utf8";
  while (true)
    switch (encoding) {
      case "hex":
        return hexSlice(this, start, end);
      case "utf8":
      case "utf-8":
        return utf8Slice(this, start, end);
      case "ascii":
        return asciiSlice(this, start, end);
      case "latin1":
      case "binary":
        return latin1Slice(this, start, end);
      case "base64":
        return base64Slice(this, start, end);
      case "ucs2":
      case "ucs-2":
      case "utf16le":
      case "utf-16le":
        return utf16leSlice(this, start, end);
      default:
        if (loweredCase)
          throw TypeError("Unknown encoding: " + encoding);
        encoding = (encoding + "").toLowerCase(), loweredCase = true;
    }
}
Buffer2.prototype._isBuffer = true;
function swap(b, n, m) {
  let i2 = b[n];
  b[n] = b[m], b[m] = i2;
}
Buffer2.prototype.swap16 = function() {
  let len2 = this.length;
  if (len2 % 2 !== 0)
    throw RangeError("Buffer size must be a multiple of 16-bits");
  for (let i2 = 0;i2 < len2; i2 += 2)
    swap(this, i2, i2 + 1);
  return this;
};
Buffer2.prototype.swap32 = function() {
  let len2 = this.length;
  if (len2 % 4 !== 0)
    throw RangeError("Buffer size must be a multiple of 32-bits");
  for (let i2 = 0;i2 < len2; i2 += 4)
    swap(this, i2, i2 + 3), swap(this, i2 + 1, i2 + 2);
  return this;
};
Buffer2.prototype.swap64 = function() {
  let len2 = this.length;
  if (len2 % 8 !== 0)
    throw RangeError("Buffer size must be a multiple of 64-bits");
  for (let i2 = 0;i2 < len2; i2 += 8)
    swap(this, i2, i2 + 7), swap(this, i2 + 1, i2 + 6), swap(this, i2 + 2, i2 + 5), swap(this, i2 + 3, i2 + 4);
  return this;
};
Buffer2.prototype.toString = function() {
  let length = this.length;
  if (length === 0)
    return "";
  if (arguments.length === 0)
    return utf8Slice(this, 0, length);
  return slowToString.apply(this, arguments);
};
Buffer2.prototype.toLocaleString = Buffer2.prototype.toString;
Buffer2.prototype.equals = function(b) {
  if (!Buffer2.isBuffer(b))
    throw TypeError("Argument must be a Buffer");
  if (this === b)
    return true;
  return Buffer2.compare(this, b) === 0;
};
Buffer2.prototype.inspect = function() {
  let str = "", max = INSPECT_MAX_BYTES;
  if (str = this.toString("hex", 0, max).replace(/(.{2})/g, "$1 ").trim(), this.length > max)
    str += " ... ";
  return "<Buffer " + str + ">";
};
if (customInspectSymbol)
  Buffer2.prototype[customInspectSymbol] = Buffer2.prototype.inspect;
Buffer2.prototype.compare = function(target, start, end, thisStart, thisEnd) {
  if (isInstance(target, Uint8Array))
    target = Buffer2.from(target, target.offset, target.byteLength);
  if (!Buffer2.isBuffer(target))
    throw TypeError('The "target" argument must be one of type Buffer or Uint8Array. Received type ' + typeof target);
  if (start === undefined)
    start = 0;
  if (end === undefined)
    end = target ? target.length : 0;
  if (thisStart === undefined)
    thisStart = 0;
  if (thisEnd === undefined)
    thisEnd = this.length;
  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length)
    throw RangeError("out of range index");
  if (thisStart >= thisEnd && start >= end)
    return 0;
  if (thisStart >= thisEnd)
    return -1;
  if (start >= end)
    return 1;
  if (start >>>= 0, end >>>= 0, thisStart >>>= 0, thisEnd >>>= 0, this === target)
    return 0;
  let x = thisEnd - thisStart, y = end - start, len2 = Math.min(x, y), thisCopy = this.slice(thisStart, thisEnd), targetCopy = target.slice(start, end);
  for (let i2 = 0;i2 < len2; ++i2)
    if (thisCopy[i2] !== targetCopy[i2]) {
      x = thisCopy[i2], y = targetCopy[i2];
      break;
    }
  if (x < y)
    return -1;
  if (y < x)
    return 1;
  return 0;
};
function bidirectionalIndexOf(buffer, val, byteOffset, encoding, dir) {
  if (buffer.length === 0)
    return -1;
  if (typeof byteOffset === "string")
    encoding = byteOffset, byteOffset = 0;
  else if (byteOffset > 2147483647)
    byteOffset = 2147483647;
  else if (byteOffset < -2147483648)
    byteOffset = -2147483648;
  if (byteOffset = +byteOffset, Number.isNaN(byteOffset))
    byteOffset = dir ? 0 : buffer.length - 1;
  if (byteOffset < 0)
    byteOffset = buffer.length + byteOffset;
  if (byteOffset >= buffer.length)
    if (dir)
      return -1;
    else
      byteOffset = buffer.length - 1;
  else if (byteOffset < 0)
    if (dir)
      byteOffset = 0;
    else
      return -1;
  if (typeof val === "string")
    val = Buffer2.from(val, encoding);
  if (Buffer2.isBuffer(val)) {
    if (val.length === 0)
      return -1;
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir);
  } else if (typeof val === "number") {
    if (val = val & 255, typeof Uint8Array.prototype.indexOf === "function")
      if (dir)
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset);
      else
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset);
    return arrayIndexOf(buffer, [val], byteOffset, encoding, dir);
  }
  throw TypeError("val must be string, number or Buffer");
}
function arrayIndexOf(arr, val, byteOffset, encoding, dir) {
  let indexSize = 1, arrLength = arr.length, valLength = val.length;
  if (encoding !== undefined) {
    if (encoding = String(encoding).toLowerCase(), encoding === "ucs2" || encoding === "ucs-2" || encoding === "utf16le" || encoding === "utf-16le") {
      if (arr.length < 2 || val.length < 2)
        return -1;
      indexSize = 2, arrLength /= 2, valLength /= 2, byteOffset /= 2;
    }
  }
  function read2(buf, i3) {
    if (indexSize === 1)
      return buf[i3];
    else
      return buf.readUInt16BE(i3 * indexSize);
  }
  let i2;
  if (dir) {
    let foundIndex = -1;
    for (i2 = byteOffset;i2 < arrLength; i2++)
      if (read2(arr, i2) === read2(val, foundIndex === -1 ? 0 : i2 - foundIndex)) {
        if (foundIndex === -1)
          foundIndex = i2;
        if (i2 - foundIndex + 1 === valLength)
          return foundIndex * indexSize;
      } else {
        if (foundIndex !== -1)
          i2 -= i2 - foundIndex;
        foundIndex = -1;
      }
  } else {
    if (byteOffset + valLength > arrLength)
      byteOffset = arrLength - valLength;
    for (i2 = byteOffset;i2 >= 0; i2--) {
      let found = true;
      for (let j = 0;j < valLength; j++)
        if (read2(arr, i2 + j) !== read2(val, j)) {
          found = false;
          break;
        }
      if (found)
        return i2;
    }
  }
  return -1;
}
Buffer2.prototype.includes = function(val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1;
};
Buffer2.prototype.indexOf = function(val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true);
};
Buffer2.prototype.lastIndexOf = function(val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false);
};
function hexWrite(buf, string, offset, length) {
  offset = Number(offset) || 0;
  let remaining = buf.length - offset;
  if (!length)
    length = remaining;
  else if (length = Number(length), length > remaining)
    length = remaining;
  let strLen = string.length;
  if (length > strLen / 2)
    length = strLen / 2;
  let i2;
  for (i2 = 0;i2 < length; ++i2) {
    let parsed = parseInt(string.substr(i2 * 2, 2), 16);
    if (Number.isNaN(parsed))
      return i2;
    buf[offset + i2] = parsed;
  }
  return i2;
}
function utf8Write(buf, string, offset, length) {
  return blitBuffer(utf8ToBytes3(string, buf.length - offset), buf, offset, length);
}
function asciiWrite(buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length);
}
function base64Write(buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length);
}
function ucs2Write(buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length);
}
Buffer2.prototype.write = function(string, offset, length, encoding) {
  if (offset === undefined)
    encoding = "utf8", length = this.length, offset = 0;
  else if (length === undefined && typeof offset === "string")
    encoding = offset, length = this.length, offset = 0;
  else if (isFinite(offset))
    if (offset = offset >>> 0, isFinite(length)) {
      if (length = length >>> 0, encoding === undefined)
        encoding = "utf8";
    } else
      encoding = length, length = undefined;
  else
    throw Error("Buffer.write(string, encoding, offset[, length]) is no longer supported");
  let remaining = this.length - offset;
  if (length === undefined || length > remaining)
    length = remaining;
  if (string.length > 0 && (length < 0 || offset < 0) || offset > this.length)
    throw RangeError("Attempt to write outside buffer bounds");
  if (!encoding)
    encoding = "utf8";
  let loweredCase = false;
  for (;; )
    switch (encoding) {
      case "hex":
        return hexWrite(this, string, offset, length);
      case "utf8":
      case "utf-8":
        return utf8Write(this, string, offset, length);
      case "ascii":
      case "latin1":
      case "binary":
        return asciiWrite(this, string, offset, length);
      case "base64":
        return base64Write(this, string, offset, length);
      case "ucs2":
      case "ucs-2":
      case "utf16le":
      case "utf-16le":
        return ucs2Write(this, string, offset, length);
      default:
        if (loweredCase)
          throw TypeError("Unknown encoding: " + encoding);
        encoding = ("" + encoding).toLowerCase(), loweredCase = true;
    }
};
Buffer2.prototype.toJSON = function() {
  return { type: "Buffer", data: Array.prototype.slice.call(this._arr || this, 0) };
};
function base64Slice(buf, start, end) {
  if (start === 0 && end === buf.length)
    return fromByteArray(buf);
  else
    return fromByteArray(buf.slice(start, end));
}
function utf8Slice(buf, start, end) {
  end = Math.min(buf.length, end);
  let res = [], i2 = start;
  while (i2 < end) {
    let firstByte = buf[i2], codePoint = null, bytesPerSequence = firstByte > 239 ? 4 : firstByte > 223 ? 3 : firstByte > 191 ? 2 : 1;
    if (i2 + bytesPerSequence <= end) {
      let secondByte, thirdByte, fourthByte, tempCodePoint;
      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 128)
            codePoint = firstByte;
          break;
        case 2:
          if (secondByte = buf[i2 + 1], (secondByte & 192) === 128) {
            if (tempCodePoint = (firstByte & 31) << 6 | secondByte & 63, tempCodePoint > 127)
              codePoint = tempCodePoint;
          }
          break;
        case 3:
          if (secondByte = buf[i2 + 1], thirdByte = buf[i2 + 2], (secondByte & 192) === 128 && (thirdByte & 192) === 128) {
            if (tempCodePoint = (firstByte & 15) << 12 | (secondByte & 63) << 6 | thirdByte & 63, tempCodePoint > 2047 && (tempCodePoint < 55296 || tempCodePoint > 57343))
              codePoint = tempCodePoint;
          }
          break;
        case 4:
          if (secondByte = buf[i2 + 1], thirdByte = buf[i2 + 2], fourthByte = buf[i2 + 3], (secondByte & 192) === 128 && (thirdByte & 192) === 128 && (fourthByte & 192) === 128) {
            if (tempCodePoint = (firstByte & 15) << 18 | (secondByte & 63) << 12 | (thirdByte & 63) << 6 | fourthByte & 63, tempCodePoint > 65535 && tempCodePoint < 1114112)
              codePoint = tempCodePoint;
          }
      }
    }
    if (codePoint === null)
      codePoint = 65533, bytesPerSequence = 1;
    else if (codePoint > 65535)
      codePoint -= 65536, res.push(codePoint >>> 10 & 1023 | 55296), codePoint = 56320 | codePoint & 1023;
    res.push(codePoint), i2 += bytesPerSequence;
  }
  return decodeCodePointsArray(res);
}
var MAX_ARGUMENTS_LENGTH = 4096;
function decodeCodePointsArray(codePoints) {
  let len2 = codePoints.length;
  if (len2 <= MAX_ARGUMENTS_LENGTH)
    return String.fromCharCode.apply(String, codePoints);
  let res = "", i2 = 0;
  while (i2 < len2)
    res += String.fromCharCode.apply(String, codePoints.slice(i2, i2 += MAX_ARGUMENTS_LENGTH));
  return res;
}
function asciiSlice(buf, start, end) {
  let ret = "";
  end = Math.min(buf.length, end);
  for (let i2 = start;i2 < end; ++i2)
    ret += String.fromCharCode(buf[i2] & 127);
  return ret;
}
function latin1Slice(buf, start, end) {
  let ret = "";
  end = Math.min(buf.length, end);
  for (let i2 = start;i2 < end; ++i2)
    ret += String.fromCharCode(buf[i2]);
  return ret;
}
function hexSlice(buf, start, end) {
  let len2 = buf.length;
  if (!start || start < 0)
    start = 0;
  if (!end || end < 0 || end > len2)
    end = len2;
  let out = "";
  for (let i2 = start;i2 < end; ++i2)
    out += hexSliceLookupTable[buf[i2]];
  return out;
}
function utf16leSlice(buf, start, end) {
  let bytes = buf.slice(start, end), res = "";
  for (let i2 = 0;i2 < bytes.length - 1; i2 += 2)
    res += String.fromCharCode(bytes[i2] + bytes[i2 + 1] * 256);
  return res;
}
Buffer2.prototype.slice = function(start, end) {
  let len2 = this.length;
  if (start = ~~start, end = end === undefined ? len2 : ~~end, start < 0) {
    if (start += len2, start < 0)
      start = 0;
  } else if (start > len2)
    start = len2;
  if (end < 0) {
    if (end += len2, end < 0)
      end = 0;
  } else if (end > len2)
    end = len2;
  if (end < start)
    end = start;
  let newBuf = this.subarray(start, end);
  return Object.setPrototypeOf(newBuf, Buffer2.prototype), newBuf;
};
function checkOffset(offset, ext, length) {
  if (offset % 1 !== 0 || offset < 0)
    throw RangeError("offset is not uint");
  if (offset + ext > length)
    throw RangeError("Trying to access beyond buffer length");
}
Buffer2.prototype.readUintLE = Buffer2.prototype.readUIntLE = function(offset, byteLength2, noAssert) {
  if (offset = offset >>> 0, byteLength2 = byteLength2 >>> 0, !noAssert)
    checkOffset(offset, byteLength2, this.length);
  let val = this[offset], mul = 1, i2 = 0;
  while (++i2 < byteLength2 && (mul *= 256))
    val += this[offset + i2] * mul;
  return val;
};
Buffer2.prototype.readUintBE = Buffer2.prototype.readUIntBE = function(offset, byteLength2, noAssert) {
  if (offset = offset >>> 0, byteLength2 = byteLength2 >>> 0, !noAssert)
    checkOffset(offset, byteLength2, this.length);
  let val = this[offset + --byteLength2], mul = 1;
  while (byteLength2 > 0 && (mul *= 256))
    val += this[offset + --byteLength2] * mul;
  return val;
};
Buffer2.prototype.readUint8 = Buffer2.prototype.readUInt8 = function(offset, noAssert) {
  if (offset = offset >>> 0, !noAssert)
    checkOffset(offset, 1, this.length);
  return this[offset];
};
Buffer2.prototype.readUint16LE = Buffer2.prototype.readUInt16LE = function(offset, noAssert) {
  if (offset = offset >>> 0, !noAssert)
    checkOffset(offset, 2, this.length);
  return this[offset] | this[offset + 1] << 8;
};
Buffer2.prototype.readUint16BE = Buffer2.prototype.readUInt16BE = function(offset, noAssert) {
  if (offset = offset >>> 0, !noAssert)
    checkOffset(offset, 2, this.length);
  return this[offset] << 8 | this[offset + 1];
};
Buffer2.prototype.readUint32LE = Buffer2.prototype.readUInt32LE = function(offset, noAssert) {
  if (offset = offset >>> 0, !noAssert)
    checkOffset(offset, 4, this.length);
  return (this[offset] | this[offset + 1] << 8 | this[offset + 2] << 16) + this[offset + 3] * 16777216;
};
Buffer2.prototype.readUint32BE = Buffer2.prototype.readUInt32BE = function(offset, noAssert) {
  if (offset = offset >>> 0, !noAssert)
    checkOffset(offset, 4, this.length);
  return this[offset] * 16777216 + (this[offset + 1] << 16 | this[offset + 2] << 8 | this[offset + 3]);
};
Buffer2.prototype.readBigUInt64LE = defineBigIntMethod(function(offset) {
  offset = offset >>> 0, validateNumber(offset, "offset");
  let first = this[offset], last = this[offset + 7];
  if (first === undefined || last === undefined)
    boundsError(offset, this.length - 8);
  let lo = first + this[++offset] * 256 + this[++offset] * 65536 + this[++offset] * 16777216, hi = this[++offset] + this[++offset] * 256 + this[++offset] * 65536 + last * 16777216;
  return BigInt(lo) + (BigInt(hi) << BigInt(32));
});
Buffer2.prototype.readBigUInt64BE = defineBigIntMethod(function(offset) {
  offset = offset >>> 0, validateNumber(offset, "offset");
  let first = this[offset], last = this[offset + 7];
  if (first === undefined || last === undefined)
    boundsError(offset, this.length - 8);
  let hi = first * 16777216 + this[++offset] * 65536 + this[++offset] * 256 + this[++offset], lo = this[++offset] * 16777216 + this[++offset] * 65536 + this[++offset] * 256 + last;
  return (BigInt(hi) << BigInt(32)) + BigInt(lo);
});
Buffer2.prototype.readIntLE = function(offset, byteLength2, noAssert) {
  if (offset = offset >>> 0, byteLength2 = byteLength2 >>> 0, !noAssert)
    checkOffset(offset, byteLength2, this.length);
  let val = this[offset], mul = 1, i2 = 0;
  while (++i2 < byteLength2 && (mul *= 256))
    val += this[offset + i2] * mul;
  if (mul *= 128, val >= mul)
    val -= Math.pow(2, 8 * byteLength2);
  return val;
};
Buffer2.prototype.readIntBE = function(offset, byteLength2, noAssert) {
  if (offset = offset >>> 0, byteLength2 = byteLength2 >>> 0, !noAssert)
    checkOffset(offset, byteLength2, this.length);
  let i2 = byteLength2, mul = 1, val = this[offset + --i2];
  while (i2 > 0 && (mul *= 256))
    val += this[offset + --i2] * mul;
  if (mul *= 128, val >= mul)
    val -= Math.pow(2, 8 * byteLength2);
  return val;
};
Buffer2.prototype.readInt8 = function(offset, noAssert) {
  if (offset = offset >>> 0, !noAssert)
    checkOffset(offset, 1, this.length);
  if (!(this[offset] & 128))
    return this[offset];
  return (255 - this[offset] + 1) * -1;
};
Buffer2.prototype.readInt16LE = function(offset, noAssert) {
  if (offset = offset >>> 0, !noAssert)
    checkOffset(offset, 2, this.length);
  let val = this[offset] | this[offset + 1] << 8;
  return val & 32768 ? val | 4294901760 : val;
};
Buffer2.prototype.readInt16BE = function(offset, noAssert) {
  if (offset = offset >>> 0, !noAssert)
    checkOffset(offset, 2, this.length);
  let val = this[offset + 1] | this[offset] << 8;
  return val & 32768 ? val | 4294901760 : val;
};
Buffer2.prototype.readInt32LE = function(offset, noAssert) {
  if (offset = offset >>> 0, !noAssert)
    checkOffset(offset, 4, this.length);
  return this[offset] | this[offset + 1] << 8 | this[offset + 2] << 16 | this[offset + 3] << 24;
};
Buffer2.prototype.readInt32BE = function(offset, noAssert) {
  if (offset = offset >>> 0, !noAssert)
    checkOffset(offset, 4, this.length);
  return this[offset] << 24 | this[offset + 1] << 16 | this[offset + 2] << 8 | this[offset + 3];
};
Buffer2.prototype.readBigInt64LE = defineBigIntMethod(function(offset) {
  offset = offset >>> 0, validateNumber(offset, "offset");
  let first = this[offset], last = this[offset + 7];
  if (first === undefined || last === undefined)
    boundsError(offset, this.length - 8);
  let val = this[offset + 4] + this[offset + 5] * 256 + this[offset + 6] * 65536 + (last << 24);
  return (BigInt(val) << BigInt(32)) + BigInt(first + this[++offset] * 256 + this[++offset] * 65536 + this[++offset] * 16777216);
});
Buffer2.prototype.readBigInt64BE = defineBigIntMethod(function(offset) {
  offset = offset >>> 0, validateNumber(offset, "offset");
  let first = this[offset], last = this[offset + 7];
  if (first === undefined || last === undefined)
    boundsError(offset, this.length - 8);
  let val = (first << 24) + this[++offset] * 65536 + this[++offset] * 256 + this[++offset];
  return (BigInt(val) << BigInt(32)) + BigInt(this[++offset] * 16777216 + this[++offset] * 65536 + this[++offset] * 256 + last);
});
Buffer2.prototype.readFloatLE = function(offset, noAssert) {
  if (offset = offset >>> 0, !noAssert)
    checkOffset(offset, 4, this.length);
  return read(this, offset, true, 23, 4);
};
Buffer2.prototype.readFloatBE = function(offset, noAssert) {
  if (offset = offset >>> 0, !noAssert)
    checkOffset(offset, 4, this.length);
  return read(this, offset, false, 23, 4);
};
Buffer2.prototype.readDoubleLE = function(offset, noAssert) {
  if (offset = offset >>> 0, !noAssert)
    checkOffset(offset, 8, this.length);
  return read(this, offset, true, 52, 8);
};
Buffer2.prototype.readDoubleBE = function(offset, noAssert) {
  if (offset = offset >>> 0, !noAssert)
    checkOffset(offset, 8, this.length);
  return read(this, offset, false, 52, 8);
};
function checkInt(buf, value, offset, ext, max, min) {
  if (!Buffer2.isBuffer(buf))
    throw TypeError('"buffer" argument must be a Buffer instance');
  if (value > max || value < min)
    throw RangeError('"value" argument is out of bounds');
  if (offset + ext > buf.length)
    throw RangeError("Index out of range");
}
Buffer2.prototype.writeUintLE = Buffer2.prototype.writeUIntLE = function(value, offset, byteLength2, noAssert) {
  if (value = +value, offset = offset >>> 0, byteLength2 = byteLength2 >>> 0, !noAssert) {
    let maxBytes = Math.pow(2, 8 * byteLength2) - 1;
    checkInt(this, value, offset, byteLength2, maxBytes, 0);
  }
  let mul = 1, i2 = 0;
  this[offset] = value & 255;
  while (++i2 < byteLength2 && (mul *= 256))
    this[offset + i2] = value / mul & 255;
  return offset + byteLength2;
};
Buffer2.prototype.writeUintBE = Buffer2.prototype.writeUIntBE = function(value, offset, byteLength2, noAssert) {
  if (value = +value, offset = offset >>> 0, byteLength2 = byteLength2 >>> 0, !noAssert) {
    let maxBytes = Math.pow(2, 8 * byteLength2) - 1;
    checkInt(this, value, offset, byteLength2, maxBytes, 0);
  }
  let i2 = byteLength2 - 1, mul = 1;
  this[offset + i2] = value & 255;
  while (--i2 >= 0 && (mul *= 256))
    this[offset + i2] = value / mul & 255;
  return offset + byteLength2;
};
Buffer2.prototype.writeUint8 = Buffer2.prototype.writeUInt8 = function(value, offset, noAssert) {
  if (value = +value, offset = offset >>> 0, !noAssert)
    checkInt(this, value, offset, 1, 255, 0);
  return this[offset] = value & 255, offset + 1;
};
Buffer2.prototype.writeUint16LE = Buffer2.prototype.writeUInt16LE = function(value, offset, noAssert) {
  if (value = +value, offset = offset >>> 0, !noAssert)
    checkInt(this, value, offset, 2, 65535, 0);
  return this[offset] = value & 255, this[offset + 1] = value >>> 8, offset + 2;
};
Buffer2.prototype.writeUint16BE = Buffer2.prototype.writeUInt16BE = function(value, offset, noAssert) {
  if (value = +value, offset = offset >>> 0, !noAssert)
    checkInt(this, value, offset, 2, 65535, 0);
  return this[offset] = value >>> 8, this[offset + 1] = value & 255, offset + 2;
};
Buffer2.prototype.writeUint32LE = Buffer2.prototype.writeUInt32LE = function(value, offset, noAssert) {
  if (value = +value, offset = offset >>> 0, !noAssert)
    checkInt(this, value, offset, 4, 4294967295, 0);
  return this[offset + 3] = value >>> 24, this[offset + 2] = value >>> 16, this[offset + 1] = value >>> 8, this[offset] = value & 255, offset + 4;
};
Buffer2.prototype.writeUint32BE = Buffer2.prototype.writeUInt32BE = function(value, offset, noAssert) {
  if (value = +value, offset = offset >>> 0, !noAssert)
    checkInt(this, value, offset, 4, 4294967295, 0);
  return this[offset] = value >>> 24, this[offset + 1] = value >>> 16, this[offset + 2] = value >>> 8, this[offset + 3] = value & 255, offset + 4;
};
function wrtBigUInt64LE(buf, value, offset, min, max) {
  checkIntBI(value, min, max, buf, offset, 7);
  let lo = Number(value & BigInt(4294967295));
  buf[offset++] = lo, lo = lo >> 8, buf[offset++] = lo, lo = lo >> 8, buf[offset++] = lo, lo = lo >> 8, buf[offset++] = lo;
  let hi = Number(value >> BigInt(32) & BigInt(4294967295));
  return buf[offset++] = hi, hi = hi >> 8, buf[offset++] = hi, hi = hi >> 8, buf[offset++] = hi, hi = hi >> 8, buf[offset++] = hi, offset;
}
function wrtBigUInt64BE(buf, value, offset, min, max) {
  checkIntBI(value, min, max, buf, offset, 7);
  let lo = Number(value & BigInt(4294967295));
  buf[offset + 7] = lo, lo = lo >> 8, buf[offset + 6] = lo, lo = lo >> 8, buf[offset + 5] = lo, lo = lo >> 8, buf[offset + 4] = lo;
  let hi = Number(value >> BigInt(32) & BigInt(4294967295));
  return buf[offset + 3] = hi, hi = hi >> 8, buf[offset + 2] = hi, hi = hi >> 8, buf[offset + 1] = hi, hi = hi >> 8, buf[offset] = hi, offset + 8;
}
Buffer2.prototype.writeBigUInt64LE = defineBigIntMethod(function(value, offset = 0) {
  return wrtBigUInt64LE(this, value, offset, BigInt(0), BigInt("0xffffffffffffffff"));
});
Buffer2.prototype.writeBigUInt64BE = defineBigIntMethod(function(value, offset = 0) {
  return wrtBigUInt64BE(this, value, offset, BigInt(0), BigInt("0xffffffffffffffff"));
});
Buffer2.prototype.writeIntLE = function(value, offset, byteLength2, noAssert) {
  if (value = +value, offset = offset >>> 0, !noAssert) {
    let limit = Math.pow(2, 8 * byteLength2 - 1);
    checkInt(this, value, offset, byteLength2, limit - 1, -limit);
  }
  let i2 = 0, mul = 1, sub = 0;
  this[offset] = value & 255;
  while (++i2 < byteLength2 && (mul *= 256)) {
    if (value < 0 && sub === 0 && this[offset + i2 - 1] !== 0)
      sub = 1;
    this[offset + i2] = (value / mul >> 0) - sub & 255;
  }
  return offset + byteLength2;
};
Buffer2.prototype.writeIntBE = function(value, offset, byteLength2, noAssert) {
  if (value = +value, offset = offset >>> 0, !noAssert) {
    let limit = Math.pow(2, 8 * byteLength2 - 1);
    checkInt(this, value, offset, byteLength2, limit - 1, -limit);
  }
  let i2 = byteLength2 - 1, mul = 1, sub = 0;
  this[offset + i2] = value & 255;
  while (--i2 >= 0 && (mul *= 256)) {
    if (value < 0 && sub === 0 && this[offset + i2 + 1] !== 0)
      sub = 1;
    this[offset + i2] = (value / mul >> 0) - sub & 255;
  }
  return offset + byteLength2;
};
Buffer2.prototype.writeInt8 = function(value, offset, noAssert) {
  if (value = +value, offset = offset >>> 0, !noAssert)
    checkInt(this, value, offset, 1, 127, -128);
  if (value < 0)
    value = 255 + value + 1;
  return this[offset] = value & 255, offset + 1;
};
Buffer2.prototype.writeInt16LE = function(value, offset, noAssert) {
  if (value = +value, offset = offset >>> 0, !noAssert)
    checkInt(this, value, offset, 2, 32767, -32768);
  return this[offset] = value & 255, this[offset + 1] = value >>> 8, offset + 2;
};
Buffer2.prototype.writeInt16BE = function(value, offset, noAssert) {
  if (value = +value, offset = offset >>> 0, !noAssert)
    checkInt(this, value, offset, 2, 32767, -32768);
  return this[offset] = value >>> 8, this[offset + 1] = value & 255, offset + 2;
};
Buffer2.prototype.writeInt32LE = function(value, offset, noAssert) {
  if (value = +value, offset = offset >>> 0, !noAssert)
    checkInt(this, value, offset, 4, 2147483647, -2147483648);
  return this[offset] = value & 255, this[offset + 1] = value >>> 8, this[offset + 2] = value >>> 16, this[offset + 3] = value >>> 24, offset + 4;
};
Buffer2.prototype.writeInt32BE = function(value, offset, noAssert) {
  if (value = +value, offset = offset >>> 0, !noAssert)
    checkInt(this, value, offset, 4, 2147483647, -2147483648);
  if (value < 0)
    value = 4294967295 + value + 1;
  return this[offset] = value >>> 24, this[offset + 1] = value >>> 16, this[offset + 2] = value >>> 8, this[offset + 3] = value & 255, offset + 4;
};
Buffer2.prototype.writeBigInt64LE = defineBigIntMethod(function(value, offset = 0) {
  return wrtBigUInt64LE(this, value, offset, -BigInt("0x8000000000000000"), BigInt("0x7fffffffffffffff"));
});
Buffer2.prototype.writeBigInt64BE = defineBigIntMethod(function(value, offset = 0) {
  return wrtBigUInt64BE(this, value, offset, -BigInt("0x8000000000000000"), BigInt("0x7fffffffffffffff"));
});
function checkIEEE754(buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length)
    throw RangeError("Index out of range");
  if (offset < 0)
    throw RangeError("Index out of range");
}
function writeFloat(buf, value, offset, littleEndian, noAssert) {
  if (value = +value, offset = offset >>> 0, !noAssert)
    checkIEEE754(buf, value, offset, 4, 340282346638528860000000000000000000000, -340282346638528860000000000000000000000);
  return write(buf, value, offset, littleEndian, 23, 4), offset + 4;
}
Buffer2.prototype.writeFloatLE = function(value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert);
};
Buffer2.prototype.writeFloatBE = function(value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert);
};
function writeDouble(buf, value, offset, littleEndian, noAssert) {
  if (value = +value, offset = offset >>> 0, !noAssert)
    checkIEEE754(buf, value, offset, 8, 179769313486231570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000, -179769313486231570000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000);
  return write(buf, value, offset, littleEndian, 52, 8), offset + 8;
}
Buffer2.prototype.writeDoubleLE = function(value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert);
};
Buffer2.prototype.writeDoubleBE = function(value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert);
};
Buffer2.prototype.copy = function(target, targetStart, start, end) {
  if (!Buffer2.isBuffer(target))
    throw TypeError("argument should be a Buffer");
  if (!start)
    start = 0;
  if (!end && end !== 0)
    end = this.length;
  if (targetStart >= target.length)
    targetStart = target.length;
  if (!targetStart)
    targetStart = 0;
  if (end > 0 && end < start)
    end = start;
  if (end === start)
    return 0;
  if (target.length === 0 || this.length === 0)
    return 0;
  if (targetStart < 0)
    throw RangeError("targetStart out of bounds");
  if (start < 0 || start >= this.length)
    throw RangeError("Index out of range");
  if (end < 0)
    throw RangeError("sourceEnd out of bounds");
  if (end > this.length)
    end = this.length;
  if (target.length - targetStart < end - start)
    end = target.length - targetStart + start;
  let len2 = end - start;
  if (this === target && typeof Uint8Array.prototype.copyWithin === "function")
    this.copyWithin(targetStart, start, end);
  else
    Uint8Array.prototype.set.call(target, this.subarray(start, end), targetStart);
  return len2;
};
Buffer2.prototype.fill = function(val, start, end, encoding) {
  if (typeof val === "string") {
    if (typeof start === "string")
      encoding = start, start = 0, end = this.length;
    else if (typeof end === "string")
      encoding = end, end = this.length;
    if (encoding !== undefined && typeof encoding !== "string")
      throw TypeError("encoding must be a string");
    if (typeof encoding === "string" && !Buffer2.isEncoding(encoding))
      throw TypeError("Unknown encoding: " + encoding);
    if (val.length === 1) {
      let code2 = val.charCodeAt(0);
      if (encoding === "utf8" && code2 < 128 || encoding === "latin1")
        val = code2;
    }
  } else if (typeof val === "number")
    val = val & 255;
  else if (typeof val === "boolean")
    val = Number(val);
  if (start < 0 || this.length < start || this.length < end)
    throw RangeError("Out of range index");
  if (end <= start)
    return this;
  if (start = start >>> 0, end = end === undefined ? this.length : end >>> 0, !val)
    val = 0;
  let i2;
  if (typeof val === "number")
    for (i2 = start;i2 < end; ++i2)
      this[i2] = val;
  else {
    let bytes = Buffer2.isBuffer(val) ? val : Buffer2.from(val, encoding), len2 = bytes.length;
    if (len2 === 0)
      throw TypeError('The value "' + val + '" is invalid for argument "value"');
    for (i2 = 0;i2 < end - start; ++i2)
      this[i2 + start] = bytes[i2 % len2];
  }
  return this;
};
function addNumericalSeparator(val) {
  let res = "", i2 = val.length, start = val[0] === "-" ? 1 : 0;
  for (;i2 >= start + 4; i2 -= 3)
    res = `_${val.slice(i2 - 3, i2)}${res}`;
  return `${val.slice(0, i2)}${res}`;
}
function checkBounds(buf, offset, byteLength2) {
  if (validateNumber(offset, "offset"), buf[offset] === undefined || buf[offset + byteLength2] === undefined)
    boundsError(offset, buf.length - (byteLength2 + 1));
}
function checkIntBI(value, min, max, buf, offset, byteLength2) {
  if (value > max || value < min) {
    let n = typeof min === "bigint" ? "n" : "", range;
    if (byteLength2 > 3)
      if (min === 0 || min === BigInt(0))
        range = `>= 0${n} and < 2${n} ** ${(byteLength2 + 1) * 8}${n}`;
      else
        range = `>= -(2${n} ** ${(byteLength2 + 1) * 8 - 1}${n}) and < 2 ** ${(byteLength2 + 1) * 8 - 1}${n}`;
    else
      range = `>= ${min}${n} and <= ${max}${n}`;
    throw new ERR_OUT_OF_RANGE("value", range, value);
  }
  checkBounds(buf, offset, byteLength2);
}
function validateNumber(value, name) {
  if (typeof value !== "number")
    throw new ERR_INVALID_ARG_TYPE(name, "number", value);
}
function boundsError(value, length, type) {
  if (Math.floor(value) !== value)
    throw validateNumber(value, type), new ERR_OUT_OF_RANGE(type || "offset", "an integer", value);
  if (length < 0)
    throw new ERR_BUFFER_OUT_OF_BOUNDS;
  throw new ERR_OUT_OF_RANGE(type || "offset", `>= ${type ? 1 : 0} and <= ${length}`, value);
}
var INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g;
function base64clean(str) {
  if (str = str.split("=")[0], str = str.trim().replace(INVALID_BASE64_RE, ""), str.length < 2)
    return "";
  while (str.length % 4 !== 0)
    str = str + "=";
  return str;
}
function utf8ToBytes3(string, units) {
  units = units || 1 / 0;
  let codePoint, length = string.length, leadSurrogate = null, bytes = [];
  for (let i2 = 0;i2 < length; ++i2) {
    if (codePoint = string.charCodeAt(i2), codePoint > 55295 && codePoint < 57344) {
      if (!leadSurrogate) {
        if (codePoint > 56319) {
          if ((units -= 3) > -1)
            bytes.push(239, 191, 189);
          continue;
        } else if (i2 + 1 === length) {
          if ((units -= 3) > -1)
            bytes.push(239, 191, 189);
          continue;
        }
        leadSurrogate = codePoint;
        continue;
      }
      if (codePoint < 56320) {
        if ((units -= 3) > -1)
          bytes.push(239, 191, 189);
        leadSurrogate = codePoint;
        continue;
      }
      codePoint = (leadSurrogate - 55296 << 10 | codePoint - 56320) + 65536;
    } else if (leadSurrogate) {
      if ((units -= 3) > -1)
        bytes.push(239, 191, 189);
    }
    if (leadSurrogate = null, codePoint < 128) {
      if ((units -= 1) < 0)
        break;
      bytes.push(codePoint);
    } else if (codePoint < 2048) {
      if ((units -= 2) < 0)
        break;
      bytes.push(codePoint >> 6 | 192, codePoint & 63 | 128);
    } else if (codePoint < 65536) {
      if ((units -= 3) < 0)
        break;
      bytes.push(codePoint >> 12 | 224, codePoint >> 6 & 63 | 128, codePoint & 63 | 128);
    } else if (codePoint < 1114112) {
      if ((units -= 4) < 0)
        break;
      bytes.push(codePoint >> 18 | 240, codePoint >> 12 & 63 | 128, codePoint >> 6 & 63 | 128, codePoint & 63 | 128);
    } else
      throw Error("Invalid code point");
  }
  return bytes;
}
function asciiToBytes(str) {
  let byteArray = [];
  for (let i2 = 0;i2 < str.length; ++i2)
    byteArray.push(str.charCodeAt(i2) & 255);
  return byteArray;
}
function utf16leToBytes(str, units) {
  let c, hi, lo, byteArray = [];
  for (let i2 = 0;i2 < str.length; ++i2) {
    if ((units -= 2) < 0)
      break;
    c = str.charCodeAt(i2), hi = c >> 8, lo = c % 256, byteArray.push(lo), byteArray.push(hi);
  }
  return byteArray;
}
function base64ToBytes(str) {
  return toByteArray(base64clean(str));
}
function blitBuffer(src, dst, offset, length) {
  let i2;
  for (i2 = 0;i2 < length; ++i2) {
    if (i2 + offset >= dst.length || i2 >= src.length)
      break;
    dst[i2 + offset] = src[i2];
  }
  return i2;
}
function isInstance(obj, type) {
  return obj instanceof type || obj != null && obj.constructor != null && obj.constructor.name != null && obj.constructor.name === type.name;
}
var hexSliceLookupTable = function() {
  let table = Array(256);
  for (let i2 = 0;i2 < 16; ++i2) {
    let i16 = i2 * 16;
    for (let j = 0;j < 16; ++j)
      table[i16 + j] = "0123456789abcdef"[i2] + "0123456789abcdef"[j];
  }
  return table;
}();
function defineBigIntMethod(fn) {
  return typeof BigInt > "u" ? BufferBigIntNotDefined : fn;
}
function BufferBigIntNotDefined() {
  throw Error("BigInt not supported");
}
function notimpl(name) {
  return () => {
    throw Error(name + " is not implemented for node:buffer browser polyfill");
  };
}
var resolveObjectURL = notimpl("resolveObjectURL");
var isUtf8 = notimpl("isUtf8");
var transcode = notimpl("transcode");
var { URL: URL2, URLSearchParams } = globalThis;
function util_isString(arg) {
  return typeof arg === "string";
}
function util_isObject(arg) {
  return typeof arg === "object" && arg !== null;
}
function util_isNull(arg) {
  return arg === null;
}
function util_isNullOrUndefined(arg) {
  return arg == null;
}
function Url() {
  this.protocol = null, this.slashes = null, this.auth = null, this.host = null, this.port = null, this.hostname = null, this.hash = null, this.search = null, this.query = null, this.pathname = null, this.path = null, this.href = null;
}
var protocolPattern = /^([a-z0-9.+-]+:)/i;
var portPattern = /:[0-9]*$/;
var simplePathPattern = /^(\/\/?(?!\/)[^\?\s]*)(\?[^\s]*)?$/;
var delims = ["<", ">", '"', "`", " ", "\r", `
`, "\t"];
var unwise = ["{", "}", "|", "\\", "^", "`"].concat(delims);
var autoEscape = ["'"].concat(unwise);
var nonHostChars = ["%", "/", "?", ";", "#"].concat(autoEscape);
var hostEndingChars = ["/", "?", "#"];
var hostnameMaxLen = 255;
var hostnamePartPattern = /^[+a-z0-9A-Z_-]{0,63}$/;
var hostnamePartStart = /^([+a-z0-9A-Z_-]{0,63})(.*)$/;
var unsafeProtocol = { __proto__: null, javascript: true, "javascript:": true };
var hostlessProtocol = { __proto__: null, javascript: true, "javascript:": true };
var slashedProtocol = { __proto__: null, http: true, https: true, ftp: true, gopher: true, file: true, "http:": true, "https:": true, "ftp:": true, "gopher:": true, "file:": true };
var querystring = { parse(str) {
  var decode = decodeURIComponent;
  return (str + "").replace(/\+/g, " ").split("&").filter(Boolean).reduce(function(obj, item, index) {
    var ref = item.split("="), key = decode(ref[0] || ""), val = decode(ref[1] || ""), prev = obj[key];
    return obj[key] = prev === undefined ? val : [].concat(prev, val), obj;
  }, {});
}, stringify(obj) {
  var encode = encodeURIComponent;
  return Object.keys(obj || {}).reduce(function(arr, key) {
    return [].concat(obj[key]).forEach(function(v) {
      arr.push(encode(key) + "=" + encode(v));
    }), arr;
  }, []).join("&").replace(/\s/g, "+");
} };
function urlParse(url, parseQueryString, slashesDenoteHost) {
  if (url && util_isObject(url) && url instanceof Url)
    return url;
  var u = new Url;
  return u.parse(url, parseQueryString, slashesDenoteHost), u;
}
Url.prototype.parse = function(url, parseQueryString, slashesDenoteHost) {
  if (!util_isString(url))
    throw TypeError("Parameter 'url' must be a string, not " + typeof url);
  var queryIndex = url.indexOf("?"), splitter = queryIndex !== -1 && queryIndex < url.indexOf("#") ? "?" : "#", uSplit = url.split(splitter), slashRegex = /\\/g;
  uSplit[0] = uSplit[0].replace(slashRegex, "/"), url = uSplit.join(splitter);
  var rest = url;
  if (rest = rest.trim(), !slashesDenoteHost && url.split("#").length === 1) {
    var simplePath = simplePathPattern.exec(rest);
    if (simplePath) {
      if (this.path = rest, this.href = rest, this.pathname = simplePath[1], simplePath[2])
        if (this.search = simplePath[2], parseQueryString)
          this.query = querystring.parse(this.search.substr(1));
        else
          this.query = this.search.substr(1);
      else if (parseQueryString)
        this.search = "", this.query = {};
      return this;
    }
  }
  var proto = protocolPattern.exec(rest);
  if (proto) {
    proto = proto[0];
    var lowerProto = proto.toLowerCase();
    this.protocol = lowerProto, rest = rest.substr(proto.length);
  }
  if (slashesDenoteHost || proto || rest.match(/^\/\/[^@\/]+@[^@\/]+/)) {
    var slashes = rest.substr(0, 2) === "//";
    if (slashes && !(proto && hostlessProtocol[lowerProto]))
      rest = rest.substr(2), this.slashes = true;
  }
  if (!hostlessProtocol[lowerProto] && (slashes || lowerProto && !slashedProtocol[lowerProto])) {
    var hostEnd = -1;
    for (var i = 0;i < hostEndingChars.length; i++) {
      var hec = rest.indexOf(hostEndingChars[i]);
      if (hec !== -1 && (hostEnd === -1 || hec < hostEnd))
        hostEnd = hec;
    }
    var auth, atSign;
    if (hostEnd === -1)
      atSign = rest.lastIndexOf("@");
    else
      atSign = rest.lastIndexOf("@", hostEnd);
    if (atSign !== -1)
      auth = rest.slice(0, atSign), rest = rest.slice(atSign + 1), this.auth = decodeURIComponent(auth);
    hostEnd = -1;
    for (var i = 0;i < nonHostChars.length; i++) {
      var hec = rest.indexOf(nonHostChars[i]);
      if (hec !== -1 && (hostEnd === -1 || hec < hostEnd))
        hostEnd = hec;
    }
    if (hostEnd === -1)
      hostEnd = rest.length;
    this.host = rest.slice(0, hostEnd), rest = rest.slice(hostEnd), this.parseHost(), this.hostname = this.hostname || "";
    var ipv6Hostname = this.hostname[0] === "[" && this.hostname[this.hostname.length - 1] === "]";
    if (!ipv6Hostname) {
      var hostparts = this.hostname.split(/\./);
      for (var i = 0, l = hostparts.length;i < l; i++) {
        var part = hostparts[i];
        if (!part)
          continue;
        if (!part.match(hostnamePartPattern)) {
          var newpart = "";
          for (var j = 0, k = part.length;j < k; j++)
            if (part.charCodeAt(j) > 127)
              newpart += "x";
            else
              newpart += part[j];
          if (!newpart.match(hostnamePartPattern)) {
            var validParts = hostparts.slice(0, i), notHost = hostparts.slice(i + 1), bit = part.match(hostnamePartStart);
            if (bit)
              validParts.push(bit[1]), notHost.unshift(bit[2]);
            if (notHost.length)
              rest = "/" + notHost.join(".") + rest;
            this.hostname = validParts.join(".");
            break;
          }
        }
      }
    }
    if (this.hostname.length > hostnameMaxLen)
      this.hostname = "";
    else
      this.hostname = this.hostname.toLowerCase();
    if (!ipv6Hostname)
      this.hostname = new URL2(`https://${this.hostname}`).hostname;
    var p = this.port ? ":" + this.port : "", h = this.hostname || "";
    if (this.host = h + p, this.href += this.host, ipv6Hostname) {
      if (this.hostname = this.hostname.substr(1, this.hostname.length - 2), rest[0] !== "/")
        rest = "/" + rest;
    }
  }
  if (!unsafeProtocol[lowerProto])
    for (var i = 0, l = autoEscape.length;i < l; i++) {
      var ae = autoEscape[i];
      if (rest.indexOf(ae) === -1)
        continue;
      var esc = encodeURIComponent(ae);
      if (esc === ae)
        esc = escape(ae);
      rest = rest.split(ae).join(esc);
    }
  var hash = rest.indexOf("#");
  if (hash !== -1)
    this.hash = rest.substr(hash), rest = rest.slice(0, hash);
  var qm = rest.indexOf("?");
  if (qm !== -1) {
    if (this.search = rest.substr(qm), this.query = rest.substr(qm + 1), parseQueryString)
      this.query = querystring.parse(this.query);
    rest = rest.slice(0, qm);
  } else if (parseQueryString)
    this.search = "", this.query = {};
  if (rest)
    this.pathname = rest;
  if (slashedProtocol[lowerProto] && this.hostname && !this.pathname)
    this.pathname = "/";
  if (this.pathname || this.search) {
    var p = this.pathname || "", s = this.search || "";
    this.path = p + s;
  }
  return this.href = this.format(), this;
};
Url.prototype.format = function() {
  var auth = this.auth || "";
  if (auth)
    auth = encodeURIComponent(auth), auth = auth.replace(/%3A/i, ":"), auth += "@";
  var protocol = this.protocol || "", pathname = this.pathname || "", hash = this.hash || "", host = false, query = "";
  if (this.host)
    host = auth + this.host;
  else if (this.hostname) {
    if (host = auth + (this.hostname.indexOf(":") === -1 ? this.hostname : "[" + this.hostname + "]"), this.port)
      host += ":" + this.port;
  }
  if (this.query && util_isObject(this.query) && Object.keys(this.query).length)
    query = querystring.stringify(this.query);
  var search = this.search || query && "?" + query || "";
  if (protocol && protocol.substr(-1) !== ":")
    protocol += ":";
  if (this.slashes || (!protocol || slashedProtocol[protocol]) && host !== false) {
    if (host = "//" + (host || ""), pathname && pathname.charAt(0) !== "/")
      pathname = "/" + pathname;
  } else if (!host)
    host = "";
  if (hash && hash.charAt(0) !== "#")
    hash = "#" + hash;
  if (search && search.charAt(0) !== "?")
    search = "?" + search;
  return pathname = pathname.replace(/[?#]/g, function(match) {
    return encodeURIComponent(match);
  }), search = search.replace("#", "%23"), protocol + host + pathname + search + hash;
};
Url.prototype.resolve = function(relative) {
  return this.resolveObject(urlParse(relative, false, true)).format();
};
Url.prototype.resolveObject = function(relative) {
  if (util_isString(relative)) {
    var rel = new Url;
    rel.parse(relative, false, true), relative = rel;
  }
  var result = new Url, tkeys = Object.keys(this);
  for (var tk = 0;tk < tkeys.length; tk++) {
    var tkey = tkeys[tk];
    result[tkey] = this[tkey];
  }
  if (result.hash = relative.hash, relative.href === "")
    return result.href = result.format(), result;
  if (relative.slashes && !relative.protocol) {
    var rkeys = Object.keys(relative);
    for (var rk = 0;rk < rkeys.length; rk++) {
      var rkey = rkeys[rk];
      if (rkey !== "protocol")
        result[rkey] = relative[rkey];
    }
    if (slashedProtocol[result.protocol] && result.hostname && !result.pathname)
      result.path = result.pathname = "/";
    return result.href = result.format(), result;
  }
  if (relative.protocol && relative.protocol !== result.protocol) {
    if (!slashedProtocol[relative.protocol]) {
      var keys = Object.keys(relative);
      for (var v = 0;v < keys.length; v++) {
        var k = keys[v];
        result[k] = relative[k];
      }
      return result.href = result.format(), result;
    }
    if (result.protocol = relative.protocol, !relative.host && !hostlessProtocol[relative.protocol]) {
      var relPath = (relative.pathname || "").split("/");
      while (relPath.length && !(relative.host = relPath.shift()))
        ;
      if (!relative.host)
        relative.host = "";
      if (!relative.hostname)
        relative.hostname = "";
      if (relPath[0] !== "")
        relPath.unshift("");
      if (relPath.length < 2)
        relPath.unshift("");
      result.pathname = relPath.join("/");
    } else
      result.pathname = relative.pathname;
    if (result.search = relative.search, result.query = relative.query, result.host = relative.host || "", result.auth = relative.auth, result.hostname = relative.hostname || relative.host, result.port = relative.port, result.pathname || result.search) {
      var p = result.pathname || "", s = result.search || "";
      result.path = p + s;
    }
    return result.slashes = result.slashes || relative.slashes, result.href = result.format(), result;
  }
  var isSourceAbs = result.pathname && result.pathname.charAt(0) === "/", isRelAbs = relative.host || relative.pathname && relative.pathname.charAt(0) === "/", mustEndAbs = isRelAbs || isSourceAbs || result.host && relative.pathname, removeAllDots = mustEndAbs, srcPath = result.pathname && result.pathname.split("/") || [], relPath = relative.pathname && relative.pathname.split("/") || [], psychotic = result.protocol && !slashedProtocol[result.protocol];
  if (psychotic) {
    if (result.hostname = "", result.port = null, result.host)
      if (srcPath[0] === "")
        srcPath[0] = result.host;
      else
        srcPath.unshift(result.host);
    if (result.host = "", relative.protocol) {
      if (relative.hostname = null, relative.port = null, relative.host)
        if (relPath[0] === "")
          relPath[0] = relative.host;
        else
          relPath.unshift(relative.host);
      relative.host = null;
    }
    mustEndAbs = mustEndAbs && (relPath[0] === "" || srcPath[0] === "");
  }
  if (isRelAbs)
    result.host = relative.host || relative.host === "" ? relative.host : result.host, result.hostname = relative.hostname || relative.hostname === "" ? relative.hostname : result.hostname, result.search = relative.search, result.query = relative.query, srcPath = relPath;
  else if (relPath.length) {
    if (!srcPath)
      srcPath = [];
    srcPath.pop(), srcPath = srcPath.concat(relPath), result.search = relative.search, result.query = relative.query;
  } else if (!util_isNullOrUndefined(relative.search)) {
    if (psychotic) {
      result.hostname = result.host = srcPath.shift();
      var authInHost = result.host && result.host.indexOf("@") > 0 ? result.host.split("@") : false;
      if (authInHost)
        result.auth = authInHost.shift(), result.host = result.hostname = authInHost.shift();
    }
    if (result.search = relative.search, result.query = relative.query, !util_isNull(result.pathname) || !util_isNull(result.search))
      result.path = (result.pathname ? result.pathname : "") + (result.search ? result.search : "");
    return result.href = result.format(), result;
  }
  if (!srcPath.length) {
    if (result.pathname = null, result.search)
      result.path = "/" + result.search;
    else
      result.path = null;
    return result.href = result.format(), result;
  }
  var last = srcPath.slice(-1)[0], hasTrailingSlash = (result.host || relative.host || srcPath.length > 1) && (last === "." || last === "..") || last === "", up = 0;
  for (var i = srcPath.length;i >= 0; i--)
    if (last = srcPath[i], last === ".")
      srcPath.splice(i, 1);
    else if (last === "..")
      srcPath.splice(i, 1), up++;
    else if (up)
      srcPath.splice(i, 1), up--;
  if (!mustEndAbs && !removeAllDots)
    for (;up--; up)
      srcPath.unshift("..");
  if (mustEndAbs && srcPath[0] !== "" && (!srcPath[0] || srcPath[0].charAt(0) !== "/"))
    srcPath.unshift("");
  if (hasTrailingSlash && srcPath.join("/").substr(-1) !== "/")
    srcPath.push("");
  var isAbsolute = srcPath[0] === "" || srcPath[0] && srcPath[0].charAt(0) === "/";
  if (psychotic) {
    result.hostname = result.host = isAbsolute ? "" : srcPath.length ? srcPath.shift() : "";
    var authInHost = result.host && result.host.indexOf("@") > 0 ? result.host.split("@") : false;
    if (authInHost)
      result.auth = authInHost.shift(), result.host = result.hostname = authInHost.shift();
  }
  if (mustEndAbs = mustEndAbs || result.host && srcPath.length, mustEndAbs && !isAbsolute)
    srcPath.unshift("");
  if (!srcPath.length)
    result.pathname = null, result.path = null;
  else
    result.pathname = srcPath.join("/");
  if (!util_isNull(result.pathname) || !util_isNull(result.search))
    result.path = (result.pathname ? result.pathname : "") + (result.search ? result.search : "");
  return result.auth = relative.auth || result.auth, result.slashes = result.slashes || relative.slashes, result.href = result.format(), result;
};
Url.prototype.parseHost = function() {
  var host = this.host, port = portPattern.exec(host);
  if (port) {
    if (port = port[0], port !== ":")
      this.port = port.substr(1);
    host = host.substr(0, host.length - port.length);
  }
  if (host)
    this.hostname = host;
};
var prepareRuntime = () => {
  globalThis.Buffer = Buffer2;
  globalThis.atob = atob2;
  globalThis.btoa = btoa2;
  globalThis.URL = URL2;
  globalThis.URLSearchParams = URLSearchParams;
};
var util;
(function(util) {
  util.assertEqual = (_) => {};
  function assertIs(_arg) {}
  util.assertIs = assertIs;
  function assertNever(_x) {
    throw new Error;
  }
  util.assertNever = assertNever;
  util.arrayToEnum = (items) => {
    const obj = {};
    for (const item of items) {
      obj[item] = item;
    }
    return obj;
  };
  util.getValidEnumValues = (obj) => {
    const validKeys = util.objectKeys(obj).filter((k) => typeof obj[obj[k]] !== "number");
    const filtered = {};
    for (const k of validKeys) {
      filtered[k] = obj[k];
    }
    return util.objectValues(filtered);
  };
  util.objectValues = (obj) => {
    return util.objectKeys(obj).map(function(e) {
      return obj[e];
    });
  };
  util.objectKeys = typeof Object.keys === "function" ? (obj) => Object.keys(obj) : (object) => {
    const keys = [];
    for (const key in object) {
      if (Object.prototype.hasOwnProperty.call(object, key)) {
        keys.push(key);
      }
    }
    return keys;
  };
  util.find = (arr, checker) => {
    for (const item of arr) {
      if (checker(item))
        return item;
    }
    return;
  };
  util.isInteger = typeof Number.isInteger === "function" ? (val) => Number.isInteger(val) : (val) => typeof val === "number" && Number.isFinite(val) && Math.floor(val) === val;
  function joinValues(array, separator = " | ") {
    return array.map((val) => typeof val === "string" ? `'${val}'` : val).join(separator);
  }
  util.joinValues = joinValues;
  util.jsonStringifyReplacer = (_, value) => {
    if (typeof value === "bigint") {
      return value.toString();
    }
    return value;
  };
})(util || (util = {}));
var objectUtil;
(function(objectUtil) {
  objectUtil.mergeShapes = (first, second) => {
    return {
      ...first,
      ...second
    };
  };
})(objectUtil || (objectUtil = {}));
var ZodParsedType = util.arrayToEnum([
  "string",
  "nan",
  "number",
  "integer",
  "float",
  "boolean",
  "date",
  "bigint",
  "symbol",
  "function",
  "undefined",
  "null",
  "array",
  "object",
  "unknown",
  "promise",
  "void",
  "never",
  "map",
  "set"
]);
var getParsedType = (data) => {
  const t = typeof data;
  switch (t) {
    case "undefined":
      return ZodParsedType.undefined;
    case "string":
      return ZodParsedType.string;
    case "number":
      return Number.isNaN(data) ? ZodParsedType.nan : ZodParsedType.number;
    case "boolean":
      return ZodParsedType.boolean;
    case "function":
      return ZodParsedType.function;
    case "bigint":
      return ZodParsedType.bigint;
    case "symbol":
      return ZodParsedType.symbol;
    case "object":
      if (Array.isArray(data)) {
        return ZodParsedType.array;
      }
      if (data === null) {
        return ZodParsedType.null;
      }
      if (data.then && typeof data.then === "function" && data.catch && typeof data.catch === "function") {
        return ZodParsedType.promise;
      }
      if (typeof Map !== "undefined" && data instanceof Map) {
        return ZodParsedType.map;
      }
      if (typeof Set !== "undefined" && data instanceof Set) {
        return ZodParsedType.set;
      }
      if (typeof Date !== "undefined" && data instanceof Date) {
        return ZodParsedType.date;
      }
      return ZodParsedType.object;
    default:
      return ZodParsedType.unknown;
  }
};
var ZodIssueCode = util.arrayToEnum([
  "invalid_type",
  "invalid_literal",
  "custom",
  "invalid_union",
  "invalid_union_discriminator",
  "invalid_enum_value",
  "unrecognized_keys",
  "invalid_arguments",
  "invalid_return_type",
  "invalid_date",
  "invalid_string",
  "too_small",
  "too_big",
  "invalid_intersection_types",
  "not_multiple_of",
  "not_finite"
]);

class ZodError extends Error {
  get errors() {
    return this.issues;
  }
  constructor(issues) {
    super();
    this.issues = [];
    this.addIssue = (sub) => {
      this.issues = [...this.issues, sub];
    };
    this.addIssues = (subs = []) => {
      this.issues = [...this.issues, ...subs];
    };
    const actualProto = new.target.prototype;
    if (Object.setPrototypeOf) {
      Object.setPrototypeOf(this, actualProto);
    } else {
      this.__proto__ = actualProto;
    }
    this.name = "ZodError";
    this.issues = issues;
  }
  format(_mapper) {
    const mapper = _mapper || function(issue) {
      return issue.message;
    };
    const fieldErrors = { _errors: [] };
    const processError = (error) => {
      for (const issue of error.issues) {
        if (issue.code === "invalid_union") {
          issue.unionErrors.map(processError);
        } else if (issue.code === "invalid_return_type") {
          processError(issue.returnTypeError);
        } else if (issue.code === "invalid_arguments") {
          processError(issue.argumentsError);
        } else if (issue.path.length === 0) {
          fieldErrors._errors.push(mapper(issue));
        } else {
          let curr = fieldErrors;
          let i = 0;
          while (i < issue.path.length) {
            const el = issue.path[i];
            const terminal = i === issue.path.length - 1;
            if (!terminal) {
              curr[el] = curr[el] || { _errors: [] };
            } else {
              curr[el] = curr[el] || { _errors: [] };
              curr[el]._errors.push(mapper(issue));
            }
            curr = curr[el];
            i++;
          }
        }
      }
    };
    processError(this);
    return fieldErrors;
  }
  static assert(value) {
    if (!(value instanceof ZodError)) {
      throw new Error(`Not a ZodError: ${value}`);
    }
  }
  toString() {
    return this.message;
  }
  get message() {
    return JSON.stringify(this.issues, util.jsonStringifyReplacer, 2);
  }
  get isEmpty() {
    return this.issues.length === 0;
  }
  flatten(mapper = (issue) => issue.message) {
    const fieldErrors = {};
    const formErrors = [];
    for (const sub of this.issues) {
      if (sub.path.length > 0) {
        const firstEl = sub.path[0];
        fieldErrors[firstEl] = fieldErrors[firstEl] || [];
        fieldErrors[firstEl].push(mapper(sub));
      } else {
        formErrors.push(mapper(sub));
      }
    }
    return { formErrors, fieldErrors };
  }
  get formErrors() {
    return this.flatten();
  }
}
ZodError.create = (issues) => {
  const error = new ZodError(issues);
  return error;
};
var errorMap = (issue, _ctx) => {
  let message;
  switch (issue.code) {
    case ZodIssueCode.invalid_type:
      if (issue.received === ZodParsedType.undefined) {
        message = "Required";
      } else {
        message = `Expected ${issue.expected}, received ${issue.received}`;
      }
      break;
    case ZodIssueCode.invalid_literal:
      message = `Invalid literal value, expected ${JSON.stringify(issue.expected, util.jsonStringifyReplacer)}`;
      break;
    case ZodIssueCode.unrecognized_keys:
      message = `Unrecognized key(s) in object: ${util.joinValues(issue.keys, ", ")}`;
      break;
    case ZodIssueCode.invalid_union:
      message = `Invalid input`;
      break;
    case ZodIssueCode.invalid_union_discriminator:
      message = `Invalid discriminator value. Expected ${util.joinValues(issue.options)}`;
      break;
    case ZodIssueCode.invalid_enum_value:
      message = `Invalid enum value. Expected ${util.joinValues(issue.options)}, received '${issue.received}'`;
      break;
    case ZodIssueCode.invalid_arguments:
      message = `Invalid function arguments`;
      break;
    case ZodIssueCode.invalid_return_type:
      message = `Invalid function return type`;
      break;
    case ZodIssueCode.invalid_date:
      message = `Invalid date`;
      break;
    case ZodIssueCode.invalid_string:
      if (typeof issue.validation === "object") {
        if ("includes" in issue.validation) {
          message = `Invalid input: must include "${issue.validation.includes}"`;
          if (typeof issue.validation.position === "number") {
            message = `${message} at one or more positions greater than or equal to ${issue.validation.position}`;
          }
        } else if ("startsWith" in issue.validation) {
          message = `Invalid input: must start with "${issue.validation.startsWith}"`;
        } else if ("endsWith" in issue.validation) {
          message = `Invalid input: must end with "${issue.validation.endsWith}"`;
        } else {
          util.assertNever(issue.validation);
        }
      } else if (issue.validation !== "regex") {
        message = `Invalid ${issue.validation}`;
      } else {
        message = "Invalid";
      }
      break;
    case ZodIssueCode.too_small:
      if (issue.type === "array")
        message = `Array must contain ${issue.exact ? "exactly" : issue.inclusive ? `at least` : `more than`} ${issue.minimum} element(s)`;
      else if (issue.type === "string")
        message = `String must contain ${issue.exact ? "exactly" : issue.inclusive ? `at least` : `over`} ${issue.minimum} character(s)`;
      else if (issue.type === "number")
        message = `Number must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${issue.minimum}`;
      else if (issue.type === "bigint")
        message = `Number must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${issue.minimum}`;
      else if (issue.type === "date")
        message = `Date must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${new Date(Number(issue.minimum))}`;
      else
        message = "Invalid input";
      break;
    case ZodIssueCode.too_big:
      if (issue.type === "array")
        message = `Array must contain ${issue.exact ? `exactly` : issue.inclusive ? `at most` : `less than`} ${issue.maximum} element(s)`;
      else if (issue.type === "string")
        message = `String must contain ${issue.exact ? `exactly` : issue.inclusive ? `at most` : `under`} ${issue.maximum} character(s)`;
      else if (issue.type === "number")
        message = `Number must be ${issue.exact ? `exactly` : issue.inclusive ? `less than or equal to` : `less than`} ${issue.maximum}`;
      else if (issue.type === "bigint")
        message = `BigInt must be ${issue.exact ? `exactly` : issue.inclusive ? `less than or equal to` : `less than`} ${issue.maximum}`;
      else if (issue.type === "date")
        message = `Date must be ${issue.exact ? `exactly` : issue.inclusive ? `smaller than or equal to` : `smaller than`} ${new Date(Number(issue.maximum))}`;
      else
        message = "Invalid input";
      break;
    case ZodIssueCode.custom:
      message = `Invalid input`;
      break;
    case ZodIssueCode.invalid_intersection_types:
      message = `Intersection results could not be merged`;
      break;
    case ZodIssueCode.not_multiple_of:
      message = `Number must be a multiple of ${issue.multipleOf}`;
      break;
    case ZodIssueCode.not_finite:
      message = "Number must be finite";
      break;
    default:
      message = _ctx.defaultError;
      util.assertNever(issue);
  }
  return { message };
};
var en_default = errorMap;
var overrideErrorMap = en_default;
function getErrorMap() {
  return overrideErrorMap;
}
var makeIssue = (params) => {
  const { data, path, errorMaps, issueData } = params;
  const fullPath = [...path, ...issueData.path || []];
  const fullIssue = {
    ...issueData,
    path: fullPath
  };
  if (issueData.message !== undefined) {
    return {
      ...issueData,
      path: fullPath,
      message: issueData.message
    };
  }
  let errorMessage = "";
  const maps = errorMaps.filter((m) => !!m).slice().reverse();
  for (const map of maps) {
    errorMessage = map(fullIssue, { data, defaultError: errorMessage }).message;
  }
  return {
    ...issueData,
    path: fullPath,
    message: errorMessage
  };
};
function addIssueToContext(ctx, issueData) {
  const overrideMap = getErrorMap();
  const issue = makeIssue({
    issueData,
    data: ctx.data,
    path: ctx.path,
    errorMaps: [
      ctx.common.contextualErrorMap,
      ctx.schemaErrorMap,
      overrideMap,
      overrideMap === en_default ? undefined : en_default
    ].filter((x) => !!x)
  });
  ctx.common.issues.push(issue);
}

class ParseStatus {
  constructor() {
    this.value = "valid";
  }
  dirty() {
    if (this.value === "valid")
      this.value = "dirty";
  }
  abort() {
    if (this.value !== "aborted")
      this.value = "aborted";
  }
  static mergeArray(status, results) {
    const arrayValue = [];
    for (const s of results) {
      if (s.status === "aborted")
        return INVALID;
      if (s.status === "dirty")
        status.dirty();
      arrayValue.push(s.value);
    }
    return { status: status.value, value: arrayValue };
  }
  static async mergeObjectAsync(status, pairs) {
    const syncPairs = [];
    for (const pair of pairs) {
      const key = await pair.key;
      const value = await pair.value;
      syncPairs.push({
        key,
        value
      });
    }
    return ParseStatus.mergeObjectSync(status, syncPairs);
  }
  static mergeObjectSync(status, pairs) {
    const finalObject = {};
    for (const pair of pairs) {
      const { key, value } = pair;
      if (key.status === "aborted")
        return INVALID;
      if (value.status === "aborted")
        return INVALID;
      if (key.status === "dirty")
        status.dirty();
      if (value.status === "dirty")
        status.dirty();
      if (key.value !== "__proto__" && (typeof value.value !== "undefined" || pair.alwaysSet)) {
        finalObject[key.value] = value.value;
      }
    }
    return { status: status.value, value: finalObject };
  }
}
var INVALID = Object.freeze({
  status: "aborted"
});
var DIRTY = (value) => ({ status: "dirty", value });
var OK = (value) => ({ status: "valid", value });
var isAborted = (x) => x.status === "aborted";
var isDirty = (x) => x.status === "dirty";
var isValid = (x) => x.status === "valid";
var isAsync = (x) => typeof Promise !== "undefined" && x instanceof Promise;
var errorUtil;
(function(errorUtil) {
  errorUtil.errToObj = (message) => typeof message === "string" ? { message } : message || {};
  errorUtil.toString = (message) => typeof message === "string" ? message : message?.message;
})(errorUtil || (errorUtil = {}));

class ParseInputLazyPath {
  constructor(parent, value, path, key) {
    this._cachedPath = [];
    this.parent = parent;
    this.data = value;
    this._path = path;
    this._key = key;
  }
  get path() {
    if (!this._cachedPath.length) {
      if (Array.isArray(this._key)) {
        this._cachedPath.push(...this._path, ...this._key);
      } else {
        this._cachedPath.push(...this._path, this._key);
      }
    }
    return this._cachedPath;
  }
}
var handleResult = (ctx, result) => {
  if (isValid(result)) {
    return { success: true, data: result.value };
  } else {
    if (!ctx.common.issues.length) {
      throw new Error("Validation failed but no issues detected.");
    }
    return {
      success: false,
      get error() {
        if (this._error)
          return this._error;
        const error = new ZodError(ctx.common.issues);
        this._error = error;
        return this._error;
      }
    };
  }
};
function processCreateParams(params) {
  if (!params)
    return {};
  const { errorMap, invalid_type_error, required_error, description } = params;
  if (errorMap && (invalid_type_error || required_error)) {
    throw new Error(`Can't use "invalid_type_error" or "required_error" in conjunction with custom error map.`);
  }
  if (errorMap)
    return { errorMap, description };
  const customMap = (iss, ctx) => {
    const { message } = params;
    if (iss.code === "invalid_enum_value") {
      return { message: message ?? ctx.defaultError };
    }
    if (typeof ctx.data === "undefined") {
      return { message: message ?? required_error ?? ctx.defaultError };
    }
    if (iss.code !== "invalid_type")
      return { message: ctx.defaultError };
    return { message: message ?? invalid_type_error ?? ctx.defaultError };
  };
  return { errorMap: customMap, description };
}

class ZodType {
  get description() {
    return this._def.description;
  }
  _getType(input) {
    return getParsedType(input.data);
  }
  _getOrReturnCtx(input, ctx) {
    return ctx || {
      common: input.parent.common,
      data: input.data,
      parsedType: getParsedType(input.data),
      schemaErrorMap: this._def.errorMap,
      path: input.path,
      parent: input.parent
    };
  }
  _processInputParams(input) {
    return {
      status: new ParseStatus,
      ctx: {
        common: input.parent.common,
        data: input.data,
        parsedType: getParsedType(input.data),
        schemaErrorMap: this._def.errorMap,
        path: input.path,
        parent: input.parent
      }
    };
  }
  _parseSync(input) {
    const result = this._parse(input);
    if (isAsync(result)) {
      throw new Error("Synchronous parse encountered promise.");
    }
    return result;
  }
  _parseAsync(input) {
    const result = this._parse(input);
    return Promise.resolve(result);
  }
  parse(data, params) {
    const result = this.safeParse(data, params);
    if (result.success)
      return result.data;
    throw result.error;
  }
  safeParse(data, params) {
    const ctx = {
      common: {
        issues: [],
        async: params?.async ?? false,
        contextualErrorMap: params?.errorMap
      },
      path: params?.path || [],
      schemaErrorMap: this._def.errorMap,
      parent: null,
      data,
      parsedType: getParsedType(data)
    };
    const result = this._parseSync({ data, path: ctx.path, parent: ctx });
    return handleResult(ctx, result);
  }
  "~validate"(data) {
    const ctx = {
      common: {
        issues: [],
        async: !!this["~standard"].async
      },
      path: [],
      schemaErrorMap: this._def.errorMap,
      parent: null,
      data,
      parsedType: getParsedType(data)
    };
    if (!this["~standard"].async) {
      try {
        const result = this._parseSync({ data, path: [], parent: ctx });
        return isValid(result) ? {
          value: result.value
        } : {
          issues: ctx.common.issues
        };
      } catch (err) {
        if (err?.message?.toLowerCase()?.includes("encountered")) {
          this["~standard"].async = true;
        }
        ctx.common = {
          issues: [],
          async: true
        };
      }
    }
    return this._parseAsync({ data, path: [], parent: ctx }).then((result) => isValid(result) ? {
      value: result.value
    } : {
      issues: ctx.common.issues
    });
  }
  async parseAsync(data, params) {
    const result = await this.safeParseAsync(data, params);
    if (result.success)
      return result.data;
    throw result.error;
  }
  async safeParseAsync(data, params) {
    const ctx = {
      common: {
        issues: [],
        contextualErrorMap: params?.errorMap,
        async: true
      },
      path: params?.path || [],
      schemaErrorMap: this._def.errorMap,
      parent: null,
      data,
      parsedType: getParsedType(data)
    };
    const maybeAsyncResult = this._parse({ data, path: ctx.path, parent: ctx });
    const result = await (isAsync(maybeAsyncResult) ? maybeAsyncResult : Promise.resolve(maybeAsyncResult));
    return handleResult(ctx, result);
  }
  refine(check, message) {
    const getIssueProperties = (val) => {
      if (typeof message === "string" || typeof message === "undefined") {
        return { message };
      } else if (typeof message === "function") {
        return message(val);
      } else {
        return message;
      }
    };
    return this._refinement((val, ctx) => {
      const result = check(val);
      const setError = () => ctx.addIssue({
        code: ZodIssueCode.custom,
        ...getIssueProperties(val)
      });
      if (typeof Promise !== "undefined" && result instanceof Promise) {
        return result.then((data) => {
          if (!data) {
            setError();
            return false;
          } else {
            return true;
          }
        });
      }
      if (!result) {
        setError();
        return false;
      } else {
        return true;
      }
    });
  }
  refinement(check, refinementData) {
    return this._refinement((val, ctx) => {
      if (!check(val)) {
        ctx.addIssue(typeof refinementData === "function" ? refinementData(val, ctx) : refinementData);
        return false;
      } else {
        return true;
      }
    });
  }
  _refinement(refinement) {
    return new ZodEffects({
      schema: this,
      typeName: ZodFirstPartyTypeKind.ZodEffects,
      effect: { type: "refinement", refinement }
    });
  }
  superRefine(refinement) {
    return this._refinement(refinement);
  }
  constructor(def) {
    this.spa = this.safeParseAsync;
    this._def = def;
    this.parse = this.parse.bind(this);
    this.safeParse = this.safeParse.bind(this);
    this.parseAsync = this.parseAsync.bind(this);
    this.safeParseAsync = this.safeParseAsync.bind(this);
    this.spa = this.spa.bind(this);
    this.refine = this.refine.bind(this);
    this.refinement = this.refinement.bind(this);
    this.superRefine = this.superRefine.bind(this);
    this.optional = this.optional.bind(this);
    this.nullable = this.nullable.bind(this);
    this.nullish = this.nullish.bind(this);
    this.array = this.array.bind(this);
    this.promise = this.promise.bind(this);
    this.or = this.or.bind(this);
    this.and = this.and.bind(this);
    this.transform = this.transform.bind(this);
    this.brand = this.brand.bind(this);
    this.default = this.default.bind(this);
    this.catch = this.catch.bind(this);
    this.describe = this.describe.bind(this);
    this.pipe = this.pipe.bind(this);
    this.readonly = this.readonly.bind(this);
    this.isNullable = this.isNullable.bind(this);
    this.isOptional = this.isOptional.bind(this);
    this["~standard"] = {
      version: 1,
      vendor: "zod",
      validate: (data) => this["~validate"](data)
    };
  }
  optional() {
    return ZodOptional.create(this, this._def);
  }
  nullable() {
    return ZodNullable.create(this, this._def);
  }
  nullish() {
    return this.nullable().optional();
  }
  array() {
    return ZodArray.create(this);
  }
  promise() {
    return ZodPromise.create(this, this._def);
  }
  or(option) {
    return ZodUnion.create([this, option], this._def);
  }
  and(incoming) {
    return ZodIntersection.create(this, incoming, this._def);
  }
  transform(transform) {
    return new ZodEffects({
      ...processCreateParams(this._def),
      schema: this,
      typeName: ZodFirstPartyTypeKind.ZodEffects,
      effect: { type: "transform", transform }
    });
  }
  default(def) {
    const defaultValueFunc = typeof def === "function" ? def : () => def;
    return new ZodDefault({
      ...processCreateParams(this._def),
      innerType: this,
      defaultValue: defaultValueFunc,
      typeName: ZodFirstPartyTypeKind.ZodDefault
    });
  }
  brand() {
    return new ZodBranded({
      typeName: ZodFirstPartyTypeKind.ZodBranded,
      type: this,
      ...processCreateParams(this._def)
    });
  }
  catch(def) {
    const catchValueFunc = typeof def === "function" ? def : () => def;
    return new ZodCatch({
      ...processCreateParams(this._def),
      innerType: this,
      catchValue: catchValueFunc,
      typeName: ZodFirstPartyTypeKind.ZodCatch
    });
  }
  describe(description) {
    const This = this.constructor;
    return new This({
      ...this._def,
      description
    });
  }
  pipe(target) {
    return ZodPipeline.create(this, target);
  }
  readonly() {
    return ZodReadonly.create(this);
  }
  isOptional() {
    return this.safeParse(undefined).success;
  }
  isNullable() {
    return this.safeParse(null).success;
  }
}
var cuidRegex = /^c[^\s-]{8,}$/i;
var cuid2Regex = /^[0-9a-z]+$/;
var ulidRegex = /^[0-9A-HJKMNP-TV-Z]{26}$/i;
var uuidRegex = /^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$/i;
var nanoidRegex = /^[a-z0-9_-]{21}$/i;
var jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/;
var durationRegex = /^[-+]?P(?!$)(?:(?:[-+]?\d+Y)|(?:[-+]?\d+[.,]\d+Y$))?(?:(?:[-+]?\d+M)|(?:[-+]?\d+[.,]\d+M$))?(?:(?:[-+]?\d+W)|(?:[-+]?\d+[.,]\d+W$))?(?:(?:[-+]?\d+D)|(?:[-+]?\d+[.,]\d+D$))?(?:T(?=[\d+-])(?:(?:[-+]?\d+H)|(?:[-+]?\d+[.,]\d+H$))?(?:(?:[-+]?\d+M)|(?:[-+]?\d+[.,]\d+M$))?(?:[-+]?\d+(?:[.,]\d+)?S)?)??$/;
var emailRegex = /^(?!\.)(?!.*\.\.)([A-Z0-9_'+\-\.]*)[A-Z0-9_+-]@([A-Z0-9][A-Z0-9\-]*\.)+[A-Z]{2,}$/i;
var _emojiRegex = `^(\\p{Extended_Pictographic}|\\p{Emoji_Component})+$`;
var emojiRegex;
var ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/;
var ipv4CidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\/(3[0-2]|[12]?[0-9])$/;
var ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
var ipv6CidrRegex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\/(12[0-8]|1[01][0-9]|[1-9]?[0-9])$/;
var base64Regex = /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/;
var base64urlRegex = /^([0-9a-zA-Z-_]{4})*(([0-9a-zA-Z-_]{2}(==)?)|([0-9a-zA-Z-_]{3}(=)?))?$/;
var dateRegexSource = `((\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-((0[13578]|1[02])-(0[1-9]|[12]\\d|3[01])|(0[469]|11)-(0[1-9]|[12]\\d|30)|(02)-(0[1-9]|1\\d|2[0-8])))`;
var dateRegex = new RegExp(`^${dateRegexSource}$`);
function timeRegexSource(args) {
  let secondsRegexSource = `[0-5]\\d`;
  if (args.precision) {
    secondsRegexSource = `${secondsRegexSource}\\.\\d{${args.precision}}`;
  } else if (args.precision == null) {
    secondsRegexSource = `${secondsRegexSource}(\\.\\d+)?`;
  }
  const secondsQuantifier = args.precision ? "+" : "?";
  return `([01]\\d|2[0-3]):[0-5]\\d(:${secondsRegexSource})${secondsQuantifier}`;
}
function timeRegex(args) {
  return new RegExp(`^${timeRegexSource(args)}$`);
}
function datetimeRegex(args) {
  let regex = `${dateRegexSource}T${timeRegexSource(args)}`;
  const opts = [];
  opts.push(args.local ? `Z?` : `Z`);
  if (args.offset)
    opts.push(`([+-]\\d{2}:?\\d{2})`);
  regex = `${regex}(${opts.join("|")})`;
  return new RegExp(`^${regex}$`);
}
function isValidIP(ip, version) {
  if ((version === "v4" || !version) && ipv4Regex.test(ip)) {
    return true;
  }
  if ((version === "v6" || !version) && ipv6Regex.test(ip)) {
    return true;
  }
  return false;
}
function isValidJWT(jwt, alg) {
  if (!jwtRegex.test(jwt))
    return false;
  try {
    const [header] = jwt.split(".");
    if (!header)
      return false;
    const base64 = header.replace(/-/g, "+").replace(/_/g, "/").padEnd(header.length + (4 - header.length % 4) % 4, "=");
    const decoded = JSON.parse(atob(base64));
    if (typeof decoded !== "object" || decoded === null)
      return false;
    if ("typ" in decoded && decoded?.typ !== "JWT")
      return false;
    if (!decoded.alg)
      return false;
    if (alg && decoded.alg !== alg)
      return false;
    return true;
  } catch {
    return false;
  }
}
function isValidCidr(ip, version) {
  if ((version === "v4" || !version) && ipv4CidrRegex.test(ip)) {
    return true;
  }
  if ((version === "v6" || !version) && ipv6CidrRegex.test(ip)) {
    return true;
  }
  return false;
}

class ZodString extends ZodType {
  _parse(input) {
    if (this._def.coerce) {
      input.data = String(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.string) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.string,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const status = new ParseStatus;
    let ctx = undefined;
    for (const check of this._def.checks) {
      if (check.kind === "min") {
        if (input.data.length < check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            minimum: check.value,
            type: "string",
            inclusive: true,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        if (input.data.length > check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            maximum: check.value,
            type: "string",
            inclusive: true,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "length") {
        const tooBig = input.data.length > check.value;
        const tooSmall = input.data.length < check.value;
        if (tooBig || tooSmall) {
          ctx = this._getOrReturnCtx(input, ctx);
          if (tooBig) {
            addIssueToContext(ctx, {
              code: ZodIssueCode.too_big,
              maximum: check.value,
              type: "string",
              inclusive: true,
              exact: true,
              message: check.message
            });
          } else if (tooSmall) {
            addIssueToContext(ctx, {
              code: ZodIssueCode.too_small,
              minimum: check.value,
              type: "string",
              inclusive: true,
              exact: true,
              message: check.message
            });
          }
          status.dirty();
        }
      } else if (check.kind === "email") {
        if (!emailRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "email",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "emoji") {
        if (!emojiRegex) {
          emojiRegex = new RegExp(_emojiRegex, "u");
        }
        if (!emojiRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "emoji",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "uuid") {
        if (!uuidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "uuid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "nanoid") {
        if (!nanoidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "nanoid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "cuid") {
        if (!cuidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "cuid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "cuid2") {
        if (!cuid2Regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "cuid2",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "ulid") {
        if (!ulidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "ulid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "url") {
        try {
          new URL(input.data);
        } catch {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "url",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "regex") {
        check.regex.lastIndex = 0;
        const testResult = check.regex.test(input.data);
        if (!testResult) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "regex",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "trim") {
        input.data = input.data.trim();
      } else if (check.kind === "includes") {
        if (!input.data.includes(check.value, check.position)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: { includes: check.value, position: check.position },
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "toLowerCase") {
        input.data = input.data.toLowerCase();
      } else if (check.kind === "toUpperCase") {
        input.data = input.data.toUpperCase();
      } else if (check.kind === "startsWith") {
        if (!input.data.startsWith(check.value)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: { startsWith: check.value },
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "endsWith") {
        if (!input.data.endsWith(check.value)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: { endsWith: check.value },
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "datetime") {
        const regex = datetimeRegex(check);
        if (!regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: "datetime",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "date") {
        const regex = dateRegex;
        if (!regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: "date",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "time") {
        const regex = timeRegex(check);
        if (!regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: "time",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "duration") {
        if (!durationRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "duration",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "ip") {
        if (!isValidIP(input.data, check.version)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "ip",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "jwt") {
        if (!isValidJWT(input.data, check.alg)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "jwt",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "cidr") {
        if (!isValidCidr(input.data, check.version)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "cidr",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "base64") {
        if (!base64Regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "base64",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "base64url") {
        if (!base64urlRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "base64url",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return { status: status.value, value: input.data };
  }
  _regex(regex, validation, message) {
    return this.refinement((data) => regex.test(data), {
      validation,
      code: ZodIssueCode.invalid_string,
      ...errorUtil.errToObj(message)
    });
  }
  _addCheck(check) {
    return new ZodString({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  email(message) {
    return this._addCheck({ kind: "email", ...errorUtil.errToObj(message) });
  }
  url(message) {
    return this._addCheck({ kind: "url", ...errorUtil.errToObj(message) });
  }
  emoji(message) {
    return this._addCheck({ kind: "emoji", ...errorUtil.errToObj(message) });
  }
  uuid(message) {
    return this._addCheck({ kind: "uuid", ...errorUtil.errToObj(message) });
  }
  nanoid(message) {
    return this._addCheck({ kind: "nanoid", ...errorUtil.errToObj(message) });
  }
  cuid(message) {
    return this._addCheck({ kind: "cuid", ...errorUtil.errToObj(message) });
  }
  cuid2(message) {
    return this._addCheck({ kind: "cuid2", ...errorUtil.errToObj(message) });
  }
  ulid(message) {
    return this._addCheck({ kind: "ulid", ...errorUtil.errToObj(message) });
  }
  base64(message) {
    return this._addCheck({ kind: "base64", ...errorUtil.errToObj(message) });
  }
  base64url(message) {
    return this._addCheck({
      kind: "base64url",
      ...errorUtil.errToObj(message)
    });
  }
  jwt(options) {
    return this._addCheck({ kind: "jwt", ...errorUtil.errToObj(options) });
  }
  ip(options) {
    return this._addCheck({ kind: "ip", ...errorUtil.errToObj(options) });
  }
  cidr(options) {
    return this._addCheck({ kind: "cidr", ...errorUtil.errToObj(options) });
  }
  datetime(options) {
    if (typeof options === "string") {
      return this._addCheck({
        kind: "datetime",
        precision: null,
        offset: false,
        local: false,
        message: options
      });
    }
    return this._addCheck({
      kind: "datetime",
      precision: typeof options?.precision === "undefined" ? null : options?.precision,
      offset: options?.offset ?? false,
      local: options?.local ?? false,
      ...errorUtil.errToObj(options?.message)
    });
  }
  date(message) {
    return this._addCheck({ kind: "date", message });
  }
  time(options) {
    if (typeof options === "string") {
      return this._addCheck({
        kind: "time",
        precision: null,
        message: options
      });
    }
    return this._addCheck({
      kind: "time",
      precision: typeof options?.precision === "undefined" ? null : options?.precision,
      ...errorUtil.errToObj(options?.message)
    });
  }
  duration(message) {
    return this._addCheck({ kind: "duration", ...errorUtil.errToObj(message) });
  }
  regex(regex, message) {
    return this._addCheck({
      kind: "regex",
      regex,
      ...errorUtil.errToObj(message)
    });
  }
  includes(value, options) {
    return this._addCheck({
      kind: "includes",
      value,
      position: options?.position,
      ...errorUtil.errToObj(options?.message)
    });
  }
  startsWith(value, message) {
    return this._addCheck({
      kind: "startsWith",
      value,
      ...errorUtil.errToObj(message)
    });
  }
  endsWith(value, message) {
    return this._addCheck({
      kind: "endsWith",
      value,
      ...errorUtil.errToObj(message)
    });
  }
  min(minLength, message) {
    return this._addCheck({
      kind: "min",
      value: minLength,
      ...errorUtil.errToObj(message)
    });
  }
  max(maxLength, message) {
    return this._addCheck({
      kind: "max",
      value: maxLength,
      ...errorUtil.errToObj(message)
    });
  }
  length(len, message) {
    return this._addCheck({
      kind: "length",
      value: len,
      ...errorUtil.errToObj(message)
    });
  }
  nonempty(message) {
    return this.min(1, errorUtil.errToObj(message));
  }
  trim() {
    return new ZodString({
      ...this._def,
      checks: [...this._def.checks, { kind: "trim" }]
    });
  }
  toLowerCase() {
    return new ZodString({
      ...this._def,
      checks: [...this._def.checks, { kind: "toLowerCase" }]
    });
  }
  toUpperCase() {
    return new ZodString({
      ...this._def,
      checks: [...this._def.checks, { kind: "toUpperCase" }]
    });
  }
  get isDatetime() {
    return !!this._def.checks.find((ch) => ch.kind === "datetime");
  }
  get isDate() {
    return !!this._def.checks.find((ch) => ch.kind === "date");
  }
  get isTime() {
    return !!this._def.checks.find((ch) => ch.kind === "time");
  }
  get isDuration() {
    return !!this._def.checks.find((ch) => ch.kind === "duration");
  }
  get isEmail() {
    return !!this._def.checks.find((ch) => ch.kind === "email");
  }
  get isURL() {
    return !!this._def.checks.find((ch) => ch.kind === "url");
  }
  get isEmoji() {
    return !!this._def.checks.find((ch) => ch.kind === "emoji");
  }
  get isUUID() {
    return !!this._def.checks.find((ch) => ch.kind === "uuid");
  }
  get isNANOID() {
    return !!this._def.checks.find((ch) => ch.kind === "nanoid");
  }
  get isCUID() {
    return !!this._def.checks.find((ch) => ch.kind === "cuid");
  }
  get isCUID2() {
    return !!this._def.checks.find((ch) => ch.kind === "cuid2");
  }
  get isULID() {
    return !!this._def.checks.find((ch) => ch.kind === "ulid");
  }
  get isIP() {
    return !!this._def.checks.find((ch) => ch.kind === "ip");
  }
  get isCIDR() {
    return !!this._def.checks.find((ch) => ch.kind === "cidr");
  }
  get isBase64() {
    return !!this._def.checks.find((ch) => ch.kind === "base64");
  }
  get isBase64url() {
    return !!this._def.checks.find((ch) => ch.kind === "base64url");
  }
  get minLength() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min;
  }
  get maxLength() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max;
  }
}
ZodString.create = (params) => {
  return new ZodString({
    checks: [],
    typeName: ZodFirstPartyTypeKind.ZodString,
    coerce: params?.coerce ?? false,
    ...processCreateParams(params)
  });
};
function floatSafeRemainder(val, step) {
  const valDecCount = (val.toString().split(".")[1] || "").length;
  const stepDecCount = (step.toString().split(".")[1] || "").length;
  const decCount = valDecCount > stepDecCount ? valDecCount : stepDecCount;
  const valInt = Number.parseInt(val.toFixed(decCount).replace(".", ""));
  const stepInt = Number.parseInt(step.toFixed(decCount).replace(".", ""));
  return valInt % stepInt / 10 ** decCount;
}

class ZodNumber extends ZodType {
  constructor() {
    super(...arguments);
    this.min = this.gte;
    this.max = this.lte;
    this.step = this.multipleOf;
  }
  _parse(input) {
    if (this._def.coerce) {
      input.data = Number(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.number) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.number,
        received: ctx.parsedType
      });
      return INVALID;
    }
    let ctx = undefined;
    const status = new ParseStatus;
    for (const check of this._def.checks) {
      if (check.kind === "int") {
        if (!util.isInteger(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: "integer",
            received: "float",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "min") {
        const tooSmall = check.inclusive ? input.data < check.value : input.data <= check.value;
        if (tooSmall) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            minimum: check.value,
            type: "number",
            inclusive: check.inclusive,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        const tooBig = check.inclusive ? input.data > check.value : input.data >= check.value;
        if (tooBig) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            maximum: check.value,
            type: "number",
            inclusive: check.inclusive,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "multipleOf") {
        if (floatSafeRemainder(input.data, check.value) !== 0) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.not_multiple_of,
            multipleOf: check.value,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "finite") {
        if (!Number.isFinite(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.not_finite,
            message: check.message
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return { status: status.value, value: input.data };
  }
  gte(value, message) {
    return this.setLimit("min", value, true, errorUtil.toString(message));
  }
  gt(value, message) {
    return this.setLimit("min", value, false, errorUtil.toString(message));
  }
  lte(value, message) {
    return this.setLimit("max", value, true, errorUtil.toString(message));
  }
  lt(value, message) {
    return this.setLimit("max", value, false, errorUtil.toString(message));
  }
  setLimit(kind, value, inclusive, message) {
    return new ZodNumber({
      ...this._def,
      checks: [
        ...this._def.checks,
        {
          kind,
          value,
          inclusive,
          message: errorUtil.toString(message)
        }
      ]
    });
  }
  _addCheck(check) {
    return new ZodNumber({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  int(message) {
    return this._addCheck({
      kind: "int",
      message: errorUtil.toString(message)
    });
  }
  positive(message) {
    return this._addCheck({
      kind: "min",
      value: 0,
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  negative(message) {
    return this._addCheck({
      kind: "max",
      value: 0,
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  nonpositive(message) {
    return this._addCheck({
      kind: "max",
      value: 0,
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  nonnegative(message) {
    return this._addCheck({
      kind: "min",
      value: 0,
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  multipleOf(value, message) {
    return this._addCheck({
      kind: "multipleOf",
      value,
      message: errorUtil.toString(message)
    });
  }
  finite(message) {
    return this._addCheck({
      kind: "finite",
      message: errorUtil.toString(message)
    });
  }
  safe(message) {
    return this._addCheck({
      kind: "min",
      inclusive: true,
      value: Number.MIN_SAFE_INTEGER,
      message: errorUtil.toString(message)
    })._addCheck({
      kind: "max",
      inclusive: true,
      value: Number.MAX_SAFE_INTEGER,
      message: errorUtil.toString(message)
    });
  }
  get minValue() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min;
  }
  get maxValue() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max;
  }
  get isInt() {
    return !!this._def.checks.find((ch) => ch.kind === "int" || ch.kind === "multipleOf" && util.isInteger(ch.value));
  }
  get isFinite() {
    let max = null;
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "finite" || ch.kind === "int" || ch.kind === "multipleOf") {
        return true;
      } else if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      } else if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return Number.isFinite(min) && Number.isFinite(max);
  }
}
ZodNumber.create = (params) => {
  return new ZodNumber({
    checks: [],
    typeName: ZodFirstPartyTypeKind.ZodNumber,
    coerce: params?.coerce || false,
    ...processCreateParams(params)
  });
};

class ZodBigInt extends ZodType {
  constructor() {
    super(...arguments);
    this.min = this.gte;
    this.max = this.lte;
  }
  _parse(input) {
    if (this._def.coerce) {
      try {
        input.data = BigInt(input.data);
      } catch {
        return this._getInvalidInput(input);
      }
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.bigint) {
      return this._getInvalidInput(input);
    }
    let ctx = undefined;
    const status = new ParseStatus;
    for (const check of this._def.checks) {
      if (check.kind === "min") {
        const tooSmall = check.inclusive ? input.data < check.value : input.data <= check.value;
        if (tooSmall) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            type: "bigint",
            minimum: check.value,
            inclusive: check.inclusive,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        const tooBig = check.inclusive ? input.data > check.value : input.data >= check.value;
        if (tooBig) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            type: "bigint",
            maximum: check.value,
            inclusive: check.inclusive,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "multipleOf") {
        if (input.data % check.value !== BigInt(0)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.not_multiple_of,
            multipleOf: check.value,
            message: check.message
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return { status: status.value, value: input.data };
  }
  _getInvalidInput(input) {
    const ctx = this._getOrReturnCtx(input);
    addIssueToContext(ctx, {
      code: ZodIssueCode.invalid_type,
      expected: ZodParsedType.bigint,
      received: ctx.parsedType
    });
    return INVALID;
  }
  gte(value, message) {
    return this.setLimit("min", value, true, errorUtil.toString(message));
  }
  gt(value, message) {
    return this.setLimit("min", value, false, errorUtil.toString(message));
  }
  lte(value, message) {
    return this.setLimit("max", value, true, errorUtil.toString(message));
  }
  lt(value, message) {
    return this.setLimit("max", value, false, errorUtil.toString(message));
  }
  setLimit(kind, value, inclusive, message) {
    return new ZodBigInt({
      ...this._def,
      checks: [
        ...this._def.checks,
        {
          kind,
          value,
          inclusive,
          message: errorUtil.toString(message)
        }
      ]
    });
  }
  _addCheck(check) {
    return new ZodBigInt({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  positive(message) {
    return this._addCheck({
      kind: "min",
      value: BigInt(0),
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  negative(message) {
    return this._addCheck({
      kind: "max",
      value: BigInt(0),
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  nonpositive(message) {
    return this._addCheck({
      kind: "max",
      value: BigInt(0),
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  nonnegative(message) {
    return this._addCheck({
      kind: "min",
      value: BigInt(0),
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  multipleOf(value, message) {
    return this._addCheck({
      kind: "multipleOf",
      value,
      message: errorUtil.toString(message)
    });
  }
  get minValue() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min;
  }
  get maxValue() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max;
  }
}
ZodBigInt.create = (params) => {
  return new ZodBigInt({
    checks: [],
    typeName: ZodFirstPartyTypeKind.ZodBigInt,
    coerce: params?.coerce ?? false,
    ...processCreateParams(params)
  });
};

class ZodBoolean extends ZodType {
  _parse(input) {
    if (this._def.coerce) {
      input.data = Boolean(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.boolean) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.boolean,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
}
ZodBoolean.create = (params) => {
  return new ZodBoolean({
    typeName: ZodFirstPartyTypeKind.ZodBoolean,
    coerce: params?.coerce || false,
    ...processCreateParams(params)
  });
};

class ZodDate extends ZodType {
  _parse(input) {
    if (this._def.coerce) {
      input.data = new Date(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.date) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.date,
        received: ctx.parsedType
      });
      return INVALID;
    }
    if (Number.isNaN(input.data.getTime())) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_date
      });
      return INVALID;
    }
    const status = new ParseStatus;
    let ctx = undefined;
    for (const check of this._def.checks) {
      if (check.kind === "min") {
        if (input.data.getTime() < check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            message: check.message,
            inclusive: true,
            exact: false,
            minimum: check.value,
            type: "date"
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        if (input.data.getTime() > check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            message: check.message,
            inclusive: true,
            exact: false,
            maximum: check.value,
            type: "date"
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return {
      status: status.value,
      value: new Date(input.data.getTime())
    };
  }
  _addCheck(check) {
    return new ZodDate({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  min(minDate, message) {
    return this._addCheck({
      kind: "min",
      value: minDate.getTime(),
      message: errorUtil.toString(message)
    });
  }
  max(maxDate, message) {
    return this._addCheck({
      kind: "max",
      value: maxDate.getTime(),
      message: errorUtil.toString(message)
    });
  }
  get minDate() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min != null ? new Date(min) : null;
  }
  get maxDate() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max != null ? new Date(max) : null;
  }
}
ZodDate.create = (params) => {
  return new ZodDate({
    checks: [],
    coerce: params?.coerce || false,
    typeName: ZodFirstPartyTypeKind.ZodDate,
    ...processCreateParams(params)
  });
};

class ZodSymbol extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.symbol) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.symbol,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
}
ZodSymbol.create = (params) => {
  return new ZodSymbol({
    typeName: ZodFirstPartyTypeKind.ZodSymbol,
    ...processCreateParams(params)
  });
};

class ZodUndefined extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.undefined) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.undefined,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
}
ZodUndefined.create = (params) => {
  return new ZodUndefined({
    typeName: ZodFirstPartyTypeKind.ZodUndefined,
    ...processCreateParams(params)
  });
};

class ZodNull extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.null) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.null,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
}
ZodNull.create = (params) => {
  return new ZodNull({
    typeName: ZodFirstPartyTypeKind.ZodNull,
    ...processCreateParams(params)
  });
};

class ZodAny extends ZodType {
  constructor() {
    super(...arguments);
    this._any = true;
  }
  _parse(input) {
    return OK(input.data);
  }
}
ZodAny.create = (params) => {
  return new ZodAny({
    typeName: ZodFirstPartyTypeKind.ZodAny,
    ...processCreateParams(params)
  });
};

class ZodUnknown extends ZodType {
  constructor() {
    super(...arguments);
    this._unknown = true;
  }
  _parse(input) {
    return OK(input.data);
  }
}
ZodUnknown.create = (params) => {
  return new ZodUnknown({
    typeName: ZodFirstPartyTypeKind.ZodUnknown,
    ...processCreateParams(params)
  });
};

class ZodNever extends ZodType {
  _parse(input) {
    const ctx = this._getOrReturnCtx(input);
    addIssueToContext(ctx, {
      code: ZodIssueCode.invalid_type,
      expected: ZodParsedType.never,
      received: ctx.parsedType
    });
    return INVALID;
  }
}
ZodNever.create = (params) => {
  return new ZodNever({
    typeName: ZodFirstPartyTypeKind.ZodNever,
    ...processCreateParams(params)
  });
};

class ZodVoid extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.undefined) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.void,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
}
ZodVoid.create = (params) => {
  return new ZodVoid({
    typeName: ZodFirstPartyTypeKind.ZodVoid,
    ...processCreateParams(params)
  });
};

class ZodArray extends ZodType {
  _parse(input) {
    const { ctx, status } = this._processInputParams(input);
    const def = this._def;
    if (ctx.parsedType !== ZodParsedType.array) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.array,
        received: ctx.parsedType
      });
      return INVALID;
    }
    if (def.exactLength !== null) {
      const tooBig = ctx.data.length > def.exactLength.value;
      const tooSmall = ctx.data.length < def.exactLength.value;
      if (tooBig || tooSmall) {
        addIssueToContext(ctx, {
          code: tooBig ? ZodIssueCode.too_big : ZodIssueCode.too_small,
          minimum: tooSmall ? def.exactLength.value : undefined,
          maximum: tooBig ? def.exactLength.value : undefined,
          type: "array",
          inclusive: true,
          exact: true,
          message: def.exactLength.message
        });
        status.dirty();
      }
    }
    if (def.minLength !== null) {
      if (ctx.data.length < def.minLength.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_small,
          minimum: def.minLength.value,
          type: "array",
          inclusive: true,
          exact: false,
          message: def.minLength.message
        });
        status.dirty();
      }
    }
    if (def.maxLength !== null) {
      if (ctx.data.length > def.maxLength.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_big,
          maximum: def.maxLength.value,
          type: "array",
          inclusive: true,
          exact: false,
          message: def.maxLength.message
        });
        status.dirty();
      }
    }
    if (ctx.common.async) {
      return Promise.all([...ctx.data].map((item, i) => {
        return def.type._parseAsync(new ParseInputLazyPath(ctx, item, ctx.path, i));
      })).then((result) => {
        return ParseStatus.mergeArray(status, result);
      });
    }
    const result = [...ctx.data].map((item, i) => {
      return def.type._parseSync(new ParseInputLazyPath(ctx, item, ctx.path, i));
    });
    return ParseStatus.mergeArray(status, result);
  }
  get element() {
    return this._def.type;
  }
  min(minLength, message) {
    return new ZodArray({
      ...this._def,
      minLength: { value: minLength, message: errorUtil.toString(message) }
    });
  }
  max(maxLength, message) {
    return new ZodArray({
      ...this._def,
      maxLength: { value: maxLength, message: errorUtil.toString(message) }
    });
  }
  length(len, message) {
    return new ZodArray({
      ...this._def,
      exactLength: { value: len, message: errorUtil.toString(message) }
    });
  }
  nonempty(message) {
    return this.min(1, message);
  }
}
ZodArray.create = (schema, params) => {
  return new ZodArray({
    type: schema,
    minLength: null,
    maxLength: null,
    exactLength: null,
    typeName: ZodFirstPartyTypeKind.ZodArray,
    ...processCreateParams(params)
  });
};
function deepPartialify(schema) {
  if (schema instanceof ZodObject) {
    const newShape = {};
    for (const key in schema.shape) {
      const fieldSchema = schema.shape[key];
      newShape[key] = ZodOptional.create(deepPartialify(fieldSchema));
    }
    return new ZodObject({
      ...schema._def,
      shape: () => newShape
    });
  } else if (schema instanceof ZodArray) {
    return new ZodArray({
      ...schema._def,
      type: deepPartialify(schema.element)
    });
  } else if (schema instanceof ZodOptional) {
    return ZodOptional.create(deepPartialify(schema.unwrap()));
  } else if (schema instanceof ZodNullable) {
    return ZodNullable.create(deepPartialify(schema.unwrap()));
  } else if (schema instanceof ZodTuple) {
    return ZodTuple.create(schema.items.map((item) => deepPartialify(item)));
  } else {
    return schema;
  }
}

class ZodObject extends ZodType {
  constructor() {
    super(...arguments);
    this._cached = null;
    this.nonstrict = this.passthrough;
    this.augment = this.extend;
  }
  _getCached() {
    if (this._cached !== null)
      return this._cached;
    const shape = this._def.shape();
    const keys = util.objectKeys(shape);
    this._cached = { shape, keys };
    return this._cached;
  }
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.object) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.object,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const { status, ctx } = this._processInputParams(input);
    const { shape, keys: shapeKeys } = this._getCached();
    const extraKeys = [];
    if (!(this._def.catchall instanceof ZodNever && this._def.unknownKeys === "strip")) {
      for (const key in ctx.data) {
        if (!shapeKeys.includes(key)) {
          extraKeys.push(key);
        }
      }
    }
    const pairs = [];
    for (const key of shapeKeys) {
      const keyValidator = shape[key];
      const value = ctx.data[key];
      pairs.push({
        key: { status: "valid", value: key },
        value: keyValidator._parse(new ParseInputLazyPath(ctx, value, ctx.path, key)),
        alwaysSet: key in ctx.data
      });
    }
    if (this._def.catchall instanceof ZodNever) {
      const unknownKeys = this._def.unknownKeys;
      if (unknownKeys === "passthrough") {
        for (const key of extraKeys) {
          pairs.push({
            key: { status: "valid", value: key },
            value: { status: "valid", value: ctx.data[key] }
          });
        }
      } else if (unknownKeys === "strict") {
        if (extraKeys.length > 0) {
          addIssueToContext(ctx, {
            code: ZodIssueCode.unrecognized_keys,
            keys: extraKeys
          });
          status.dirty();
        }
      } else if (unknownKeys === "strip") {} else {
        throw new Error(`Internal ZodObject error: invalid unknownKeys value.`);
      }
    } else {
      const catchall = this._def.catchall;
      for (const key of extraKeys) {
        const value = ctx.data[key];
        pairs.push({
          key: { status: "valid", value: key },
          value: catchall._parse(new ParseInputLazyPath(ctx, value, ctx.path, key)),
          alwaysSet: key in ctx.data
        });
      }
    }
    if (ctx.common.async) {
      return Promise.resolve().then(async () => {
        const syncPairs = [];
        for (const pair of pairs) {
          const key = await pair.key;
          const value = await pair.value;
          syncPairs.push({
            key,
            value,
            alwaysSet: pair.alwaysSet
          });
        }
        return syncPairs;
      }).then((syncPairs) => {
        return ParseStatus.mergeObjectSync(status, syncPairs);
      });
    } else {
      return ParseStatus.mergeObjectSync(status, pairs);
    }
  }
  get shape() {
    return this._def.shape();
  }
  strict(message) {
    errorUtil.errToObj;
    return new ZodObject({
      ...this._def,
      unknownKeys: "strict",
      ...message !== undefined ? {
        errorMap: (issue, ctx) => {
          const defaultError = this._def.errorMap?.(issue, ctx).message ?? ctx.defaultError;
          if (issue.code === "unrecognized_keys")
            return {
              message: errorUtil.errToObj(message).message ?? defaultError
            };
          return {
            message: defaultError
          };
        }
      } : {}
    });
  }
  strip() {
    return new ZodObject({
      ...this._def,
      unknownKeys: "strip"
    });
  }
  passthrough() {
    return new ZodObject({
      ...this._def,
      unknownKeys: "passthrough"
    });
  }
  extend(augmentation) {
    return new ZodObject({
      ...this._def,
      shape: () => ({
        ...this._def.shape(),
        ...augmentation
      })
    });
  }
  merge(merging) {
    const merged = new ZodObject({
      unknownKeys: merging._def.unknownKeys,
      catchall: merging._def.catchall,
      shape: () => ({
        ...this._def.shape(),
        ...merging._def.shape()
      }),
      typeName: ZodFirstPartyTypeKind.ZodObject
    });
    return merged;
  }
  setKey(key, schema) {
    return this.augment({ [key]: schema });
  }
  catchall(index) {
    return new ZodObject({
      ...this._def,
      catchall: index
    });
  }
  pick(mask) {
    const shape = {};
    for (const key of util.objectKeys(mask)) {
      if (mask[key] && this.shape[key]) {
        shape[key] = this.shape[key];
      }
    }
    return new ZodObject({
      ...this._def,
      shape: () => shape
    });
  }
  omit(mask) {
    const shape = {};
    for (const key of util.objectKeys(this.shape)) {
      if (!mask[key]) {
        shape[key] = this.shape[key];
      }
    }
    return new ZodObject({
      ...this._def,
      shape: () => shape
    });
  }
  deepPartial() {
    return deepPartialify(this);
  }
  partial(mask) {
    const newShape = {};
    for (const key of util.objectKeys(this.shape)) {
      const fieldSchema = this.shape[key];
      if (mask && !mask[key]) {
        newShape[key] = fieldSchema;
      } else {
        newShape[key] = fieldSchema.optional();
      }
    }
    return new ZodObject({
      ...this._def,
      shape: () => newShape
    });
  }
  required(mask) {
    const newShape = {};
    for (const key of util.objectKeys(this.shape)) {
      if (mask && !mask[key]) {
        newShape[key] = this.shape[key];
      } else {
        const fieldSchema = this.shape[key];
        let newField = fieldSchema;
        while (newField instanceof ZodOptional) {
          newField = newField._def.innerType;
        }
        newShape[key] = newField;
      }
    }
    return new ZodObject({
      ...this._def,
      shape: () => newShape
    });
  }
  keyof() {
    return createZodEnum(util.objectKeys(this.shape));
  }
}
ZodObject.create = (shape, params) => {
  return new ZodObject({
    shape: () => shape,
    unknownKeys: "strip",
    catchall: ZodNever.create(),
    typeName: ZodFirstPartyTypeKind.ZodObject,
    ...processCreateParams(params)
  });
};
ZodObject.strictCreate = (shape, params) => {
  return new ZodObject({
    shape: () => shape,
    unknownKeys: "strict",
    catchall: ZodNever.create(),
    typeName: ZodFirstPartyTypeKind.ZodObject,
    ...processCreateParams(params)
  });
};
ZodObject.lazycreate = (shape, params) => {
  return new ZodObject({
    shape,
    unknownKeys: "strip",
    catchall: ZodNever.create(),
    typeName: ZodFirstPartyTypeKind.ZodObject,
    ...processCreateParams(params)
  });
};

class ZodUnion extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const options = this._def.options;
    function handleResults(results) {
      for (const result of results) {
        if (result.result.status === "valid") {
          return result.result;
        }
      }
      for (const result of results) {
        if (result.result.status === "dirty") {
          ctx.common.issues.push(...result.ctx.common.issues);
          return result.result;
        }
      }
      const unionErrors = results.map((result) => new ZodError(result.ctx.common.issues));
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_union,
        unionErrors
      });
      return INVALID;
    }
    if (ctx.common.async) {
      return Promise.all(options.map(async (option) => {
        const childCtx = {
          ...ctx,
          common: {
            ...ctx.common,
            issues: []
          },
          parent: null
        };
        return {
          result: await option._parseAsync({
            data: ctx.data,
            path: ctx.path,
            parent: childCtx
          }),
          ctx: childCtx
        };
      })).then(handleResults);
    } else {
      let dirty = undefined;
      const issues = [];
      for (const option of options) {
        const childCtx = {
          ...ctx,
          common: {
            ...ctx.common,
            issues: []
          },
          parent: null
        };
        const result = option._parseSync({
          data: ctx.data,
          path: ctx.path,
          parent: childCtx
        });
        if (result.status === "valid") {
          return result;
        } else if (result.status === "dirty" && !dirty) {
          dirty = { result, ctx: childCtx };
        }
        if (childCtx.common.issues.length) {
          issues.push(childCtx.common.issues);
        }
      }
      if (dirty) {
        ctx.common.issues.push(...dirty.ctx.common.issues);
        return dirty.result;
      }
      const unionErrors = issues.map((issues) => new ZodError(issues));
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_union,
        unionErrors
      });
      return INVALID;
    }
  }
  get options() {
    return this._def.options;
  }
}
ZodUnion.create = (types, params) => {
  return new ZodUnion({
    options: types,
    typeName: ZodFirstPartyTypeKind.ZodUnion,
    ...processCreateParams(params)
  });
};
var getDiscriminator = (type) => {
  if (type instanceof ZodLazy) {
    return getDiscriminator(type.schema);
  } else if (type instanceof ZodEffects) {
    return getDiscriminator(type.innerType());
  } else if (type instanceof ZodLiteral) {
    return [type.value];
  } else if (type instanceof ZodEnum) {
    return type.options;
  } else if (type instanceof ZodNativeEnum) {
    return util.objectValues(type.enum);
  } else if (type instanceof ZodDefault) {
    return getDiscriminator(type._def.innerType);
  } else if (type instanceof ZodUndefined) {
    return [undefined];
  } else if (type instanceof ZodNull) {
    return [null];
  } else if (type instanceof ZodOptional) {
    return [undefined, ...getDiscriminator(type.unwrap())];
  } else if (type instanceof ZodNullable) {
    return [null, ...getDiscriminator(type.unwrap())];
  } else if (type instanceof ZodBranded) {
    return getDiscriminator(type.unwrap());
  } else if (type instanceof ZodReadonly) {
    return getDiscriminator(type.unwrap());
  } else if (type instanceof ZodCatch) {
    return getDiscriminator(type._def.innerType);
  } else {
    return [];
  }
};

class ZodDiscriminatedUnion extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.object) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.object,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const discriminator = this.discriminator;
    const discriminatorValue = ctx.data[discriminator];
    const option = this.optionsMap.get(discriminatorValue);
    if (!option) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_union_discriminator,
        options: Array.from(this.optionsMap.keys()),
        path: [discriminator]
      });
      return INVALID;
    }
    if (ctx.common.async) {
      return option._parseAsync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      });
    } else {
      return option._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      });
    }
  }
  get discriminator() {
    return this._def.discriminator;
  }
  get options() {
    return this._def.options;
  }
  get optionsMap() {
    return this._def.optionsMap;
  }
  static create(discriminator, options, params) {
    const optionsMap = new Map;
    for (const type of options) {
      const discriminatorValues = getDiscriminator(type.shape[discriminator]);
      if (!discriminatorValues.length) {
        throw new Error(`A discriminator value for key \`${discriminator}\` could not be extracted from all schema options`);
      }
      for (const value of discriminatorValues) {
        if (optionsMap.has(value)) {
          throw new Error(`Discriminator property ${String(discriminator)} has duplicate value ${String(value)}`);
        }
        optionsMap.set(value, type);
      }
    }
    return new ZodDiscriminatedUnion({
      typeName: ZodFirstPartyTypeKind.ZodDiscriminatedUnion,
      discriminator,
      options,
      optionsMap,
      ...processCreateParams(params)
    });
  }
}
function mergeValues(a, b) {
  const aType = getParsedType(a);
  const bType = getParsedType(b);
  if (a === b) {
    return { valid: true, data: a };
  } else if (aType === ZodParsedType.object && bType === ZodParsedType.object) {
    const bKeys = util.objectKeys(b);
    const sharedKeys = util.objectKeys(a).filter((key) => bKeys.indexOf(key) !== -1);
    const newObj = { ...a, ...b };
    for (const key of sharedKeys) {
      const sharedValue = mergeValues(a[key], b[key]);
      if (!sharedValue.valid) {
        return { valid: false };
      }
      newObj[key] = sharedValue.data;
    }
    return { valid: true, data: newObj };
  } else if (aType === ZodParsedType.array && bType === ZodParsedType.array) {
    if (a.length !== b.length) {
      return { valid: false };
    }
    const newArray = [];
    for (let index = 0;index < a.length; index++) {
      const itemA = a[index];
      const itemB = b[index];
      const sharedValue = mergeValues(itemA, itemB);
      if (!sharedValue.valid) {
        return { valid: false };
      }
      newArray.push(sharedValue.data);
    }
    return { valid: true, data: newArray };
  } else if (aType === ZodParsedType.date && bType === ZodParsedType.date && +a === +b) {
    return { valid: true, data: a };
  } else {
    return { valid: false };
  }
}

class ZodIntersection extends ZodType {
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    const handleParsed = (parsedLeft, parsedRight) => {
      if (isAborted(parsedLeft) || isAborted(parsedRight)) {
        return INVALID;
      }
      const merged = mergeValues(parsedLeft.value, parsedRight.value);
      if (!merged.valid) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.invalid_intersection_types
        });
        return INVALID;
      }
      if (isDirty(parsedLeft) || isDirty(parsedRight)) {
        status.dirty();
      }
      return { status: status.value, value: merged.data };
    };
    if (ctx.common.async) {
      return Promise.all([
        this._def.left._parseAsync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        }),
        this._def.right._parseAsync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        })
      ]).then(([left, right]) => handleParsed(left, right));
    } else {
      return handleParsed(this._def.left._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      }), this._def.right._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      }));
    }
  }
}
ZodIntersection.create = (left, right, params) => {
  return new ZodIntersection({
    left,
    right,
    typeName: ZodFirstPartyTypeKind.ZodIntersection,
    ...processCreateParams(params)
  });
};

class ZodTuple extends ZodType {
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.array) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.array,
        received: ctx.parsedType
      });
      return INVALID;
    }
    if (ctx.data.length < this._def.items.length) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.too_small,
        minimum: this._def.items.length,
        inclusive: true,
        exact: false,
        type: "array"
      });
      return INVALID;
    }
    const rest = this._def.rest;
    if (!rest && ctx.data.length > this._def.items.length) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.too_big,
        maximum: this._def.items.length,
        inclusive: true,
        exact: false,
        type: "array"
      });
      status.dirty();
    }
    const items = [...ctx.data].map((item, itemIndex) => {
      const schema = this._def.items[itemIndex] || this._def.rest;
      if (!schema)
        return null;
      return schema._parse(new ParseInputLazyPath(ctx, item, ctx.path, itemIndex));
    }).filter((x) => !!x);
    if (ctx.common.async) {
      return Promise.all(items).then((results) => {
        return ParseStatus.mergeArray(status, results);
      });
    } else {
      return ParseStatus.mergeArray(status, items);
    }
  }
  get items() {
    return this._def.items;
  }
  rest(rest) {
    return new ZodTuple({
      ...this._def,
      rest
    });
  }
}
ZodTuple.create = (schemas, params) => {
  if (!Array.isArray(schemas)) {
    throw new Error("You must pass an array of schemas to z.tuple([ ... ])");
  }
  return new ZodTuple({
    items: schemas,
    typeName: ZodFirstPartyTypeKind.ZodTuple,
    rest: null,
    ...processCreateParams(params)
  });
};

class ZodRecord extends ZodType {
  get keySchema() {
    return this._def.keyType;
  }
  get valueSchema() {
    return this._def.valueType;
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.object) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.object,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const pairs = [];
    const keyType = this._def.keyType;
    const valueType = this._def.valueType;
    for (const key in ctx.data) {
      pairs.push({
        key: keyType._parse(new ParseInputLazyPath(ctx, key, ctx.path, key)),
        value: valueType._parse(new ParseInputLazyPath(ctx, ctx.data[key], ctx.path, key)),
        alwaysSet: key in ctx.data
      });
    }
    if (ctx.common.async) {
      return ParseStatus.mergeObjectAsync(status, pairs);
    } else {
      return ParseStatus.mergeObjectSync(status, pairs);
    }
  }
  get element() {
    return this._def.valueType;
  }
  static create(first, second, third) {
    if (second instanceof ZodType) {
      return new ZodRecord({
        keyType: first,
        valueType: second,
        typeName: ZodFirstPartyTypeKind.ZodRecord,
        ...processCreateParams(third)
      });
    }
    return new ZodRecord({
      keyType: ZodString.create(),
      valueType: first,
      typeName: ZodFirstPartyTypeKind.ZodRecord,
      ...processCreateParams(second)
    });
  }
}

class ZodMap extends ZodType {
  get keySchema() {
    return this._def.keyType;
  }
  get valueSchema() {
    return this._def.valueType;
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.map) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.map,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const keyType = this._def.keyType;
    const valueType = this._def.valueType;
    const pairs = [...ctx.data.entries()].map(([key, value], index) => {
      return {
        key: keyType._parse(new ParseInputLazyPath(ctx, key, ctx.path, [index, "key"])),
        value: valueType._parse(new ParseInputLazyPath(ctx, value, ctx.path, [index, "value"]))
      };
    });
    if (ctx.common.async) {
      const finalMap = new Map;
      return Promise.resolve().then(async () => {
        for (const pair of pairs) {
          const key = await pair.key;
          const value = await pair.value;
          if (key.status === "aborted" || value.status === "aborted") {
            return INVALID;
          }
          if (key.status === "dirty" || value.status === "dirty") {
            status.dirty();
          }
          finalMap.set(key.value, value.value);
        }
        return { status: status.value, value: finalMap };
      });
    } else {
      const finalMap = new Map;
      for (const pair of pairs) {
        const key = pair.key;
        const value = pair.value;
        if (key.status === "aborted" || value.status === "aborted") {
          return INVALID;
        }
        if (key.status === "dirty" || value.status === "dirty") {
          status.dirty();
        }
        finalMap.set(key.value, value.value);
      }
      return { status: status.value, value: finalMap };
    }
  }
}
ZodMap.create = (keyType, valueType, params) => {
  return new ZodMap({
    valueType,
    keyType,
    typeName: ZodFirstPartyTypeKind.ZodMap,
    ...processCreateParams(params)
  });
};

class ZodSet extends ZodType {
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.set) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.set,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const def = this._def;
    if (def.minSize !== null) {
      if (ctx.data.size < def.minSize.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_small,
          minimum: def.minSize.value,
          type: "set",
          inclusive: true,
          exact: false,
          message: def.minSize.message
        });
        status.dirty();
      }
    }
    if (def.maxSize !== null) {
      if (ctx.data.size > def.maxSize.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_big,
          maximum: def.maxSize.value,
          type: "set",
          inclusive: true,
          exact: false,
          message: def.maxSize.message
        });
        status.dirty();
      }
    }
    const valueType = this._def.valueType;
    function finalizeSet(elements) {
      const parsedSet = new Set;
      for (const element of elements) {
        if (element.status === "aborted")
          return INVALID;
        if (element.status === "dirty")
          status.dirty();
        parsedSet.add(element.value);
      }
      return { status: status.value, value: parsedSet };
    }
    const elements = [...ctx.data.values()].map((item, i) => valueType._parse(new ParseInputLazyPath(ctx, item, ctx.path, i)));
    if (ctx.common.async) {
      return Promise.all(elements).then((elements) => finalizeSet(elements));
    } else {
      return finalizeSet(elements);
    }
  }
  min(minSize, message) {
    return new ZodSet({
      ...this._def,
      minSize: { value: minSize, message: errorUtil.toString(message) }
    });
  }
  max(maxSize, message) {
    return new ZodSet({
      ...this._def,
      maxSize: { value: maxSize, message: errorUtil.toString(message) }
    });
  }
  size(size, message) {
    return this.min(size, message).max(size, message);
  }
  nonempty(message) {
    return this.min(1, message);
  }
}
ZodSet.create = (valueType, params) => {
  return new ZodSet({
    valueType,
    minSize: null,
    maxSize: null,
    typeName: ZodFirstPartyTypeKind.ZodSet,
    ...processCreateParams(params)
  });
};
class ZodFunction extends ZodType {
  constructor() {
    super(...arguments);
    this.validate = this.implement;
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.function) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.function,
        received: ctx.parsedType
      });
      return INVALID;
    }
    function makeArgsIssue(args, error) {
      return makeIssue({
        data: args,
        path: ctx.path,
        errorMaps: [ctx.common.contextualErrorMap, ctx.schemaErrorMap, getErrorMap(), en_default].filter((x) => !!x),
        issueData: {
          code: ZodIssueCode.invalid_arguments,
          argumentsError: error
        }
      });
    }
    function makeReturnsIssue(returns, error) {
      return makeIssue({
        data: returns,
        path: ctx.path,
        errorMaps: [ctx.common.contextualErrorMap, ctx.schemaErrorMap, getErrorMap(), en_default].filter((x) => !!x),
        issueData: {
          code: ZodIssueCode.invalid_return_type,
          returnTypeError: error
        }
      });
    }
    const params = { errorMap: ctx.common.contextualErrorMap };
    const fn = ctx.data;
    if (this._def.returns instanceof ZodPromise) {
      const me = this;
      return OK(async function(...args) {
        const error = new ZodError([]);
        const parsedArgs = await me._def.args.parseAsync(args, params).catch((e) => {
          error.addIssue(makeArgsIssue(args, e));
          throw error;
        });
        const result = await Reflect.apply(fn, this, parsedArgs);
        const parsedReturns = await me._def.returns._def.type.parseAsync(result, params).catch((e) => {
          error.addIssue(makeReturnsIssue(result, e));
          throw error;
        });
        return parsedReturns;
      });
    } else {
      const me = this;
      return OK(function(...args) {
        const parsedArgs = me._def.args.safeParse(args, params);
        if (!parsedArgs.success) {
          throw new ZodError([makeArgsIssue(args, parsedArgs.error)]);
        }
        const result = Reflect.apply(fn, this, parsedArgs.data);
        const parsedReturns = me._def.returns.safeParse(result, params);
        if (!parsedReturns.success) {
          throw new ZodError([makeReturnsIssue(result, parsedReturns.error)]);
        }
        return parsedReturns.data;
      });
    }
  }
  parameters() {
    return this._def.args;
  }
  returnType() {
    return this._def.returns;
  }
  args(...items) {
    return new ZodFunction({
      ...this._def,
      args: ZodTuple.create(items).rest(ZodUnknown.create())
    });
  }
  returns(returnType) {
    return new ZodFunction({
      ...this._def,
      returns: returnType
    });
  }
  implement(func) {
    const validatedFunc = this.parse(func);
    return validatedFunc;
  }
  strictImplement(func) {
    const validatedFunc = this.parse(func);
    return validatedFunc;
  }
  static create(args, returns, params) {
    return new ZodFunction({
      args: args ? args : ZodTuple.create([]).rest(ZodUnknown.create()),
      returns: returns || ZodUnknown.create(),
      typeName: ZodFirstPartyTypeKind.ZodFunction,
      ...processCreateParams(params)
    });
  }
}

class ZodLazy extends ZodType {
  get schema() {
    return this._def.getter();
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const lazySchema = this._def.getter();
    return lazySchema._parse({ data: ctx.data, path: ctx.path, parent: ctx });
  }
}
ZodLazy.create = (getter, params) => {
  return new ZodLazy({
    getter,
    typeName: ZodFirstPartyTypeKind.ZodLazy,
    ...processCreateParams(params)
  });
};

class ZodLiteral extends ZodType {
  _parse(input) {
    if (input.data !== this._def.value) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        received: ctx.data,
        code: ZodIssueCode.invalid_literal,
        expected: this._def.value
      });
      return INVALID;
    }
    return { status: "valid", value: input.data };
  }
  get value() {
    return this._def.value;
  }
}
ZodLiteral.create = (value, params) => {
  return new ZodLiteral({
    value,
    typeName: ZodFirstPartyTypeKind.ZodLiteral,
    ...processCreateParams(params)
  });
};
function createZodEnum(values, params) {
  return new ZodEnum({
    values,
    typeName: ZodFirstPartyTypeKind.ZodEnum,
    ...processCreateParams(params)
  });
}

class ZodEnum extends ZodType {
  _parse(input) {
    if (typeof input.data !== "string") {
      const ctx = this._getOrReturnCtx(input);
      const expectedValues = this._def.values;
      addIssueToContext(ctx, {
        expected: util.joinValues(expectedValues),
        received: ctx.parsedType,
        code: ZodIssueCode.invalid_type
      });
      return INVALID;
    }
    if (!this._cache) {
      this._cache = new Set(this._def.values);
    }
    if (!this._cache.has(input.data)) {
      const ctx = this._getOrReturnCtx(input);
      const expectedValues = this._def.values;
      addIssueToContext(ctx, {
        received: ctx.data,
        code: ZodIssueCode.invalid_enum_value,
        options: expectedValues
      });
      return INVALID;
    }
    return OK(input.data);
  }
  get options() {
    return this._def.values;
  }
  get enum() {
    const enumValues = {};
    for (const val of this._def.values) {
      enumValues[val] = val;
    }
    return enumValues;
  }
  get Values() {
    const enumValues = {};
    for (const val of this._def.values) {
      enumValues[val] = val;
    }
    return enumValues;
  }
  get Enum() {
    const enumValues = {};
    for (const val of this._def.values) {
      enumValues[val] = val;
    }
    return enumValues;
  }
  extract(values, newDef = this._def) {
    return ZodEnum.create(values, {
      ...this._def,
      ...newDef
    });
  }
  exclude(values, newDef = this._def) {
    return ZodEnum.create(this.options.filter((opt) => !values.includes(opt)), {
      ...this._def,
      ...newDef
    });
  }
}
ZodEnum.create = createZodEnum;

class ZodNativeEnum extends ZodType {
  _parse(input) {
    const nativeEnumValues = util.getValidEnumValues(this._def.values);
    const ctx = this._getOrReturnCtx(input);
    if (ctx.parsedType !== ZodParsedType.string && ctx.parsedType !== ZodParsedType.number) {
      const expectedValues = util.objectValues(nativeEnumValues);
      addIssueToContext(ctx, {
        expected: util.joinValues(expectedValues),
        received: ctx.parsedType,
        code: ZodIssueCode.invalid_type
      });
      return INVALID;
    }
    if (!this._cache) {
      this._cache = new Set(util.getValidEnumValues(this._def.values));
    }
    if (!this._cache.has(input.data)) {
      const expectedValues = util.objectValues(nativeEnumValues);
      addIssueToContext(ctx, {
        received: ctx.data,
        code: ZodIssueCode.invalid_enum_value,
        options: expectedValues
      });
      return INVALID;
    }
    return OK(input.data);
  }
  get enum() {
    return this._def.values;
  }
}
ZodNativeEnum.create = (values, params) => {
  return new ZodNativeEnum({
    values,
    typeName: ZodFirstPartyTypeKind.ZodNativeEnum,
    ...processCreateParams(params)
  });
};

class ZodPromise extends ZodType {
  unwrap() {
    return this._def.type;
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.promise && ctx.common.async === false) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.promise,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const promisified = ctx.parsedType === ZodParsedType.promise ? ctx.data : Promise.resolve(ctx.data);
    return OK(promisified.then((data) => {
      return this._def.type.parseAsync(data, {
        path: ctx.path,
        errorMap: ctx.common.contextualErrorMap
      });
    }));
  }
}
ZodPromise.create = (schema, params) => {
  return new ZodPromise({
    type: schema,
    typeName: ZodFirstPartyTypeKind.ZodPromise,
    ...processCreateParams(params)
  });
};

class ZodEffects extends ZodType {
  innerType() {
    return this._def.schema;
  }
  sourceType() {
    return this._def.schema._def.typeName === ZodFirstPartyTypeKind.ZodEffects ? this._def.schema.sourceType() : this._def.schema;
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    const effect = this._def.effect || null;
    const checkCtx = {
      addIssue: (arg) => {
        addIssueToContext(ctx, arg);
        if (arg.fatal) {
          status.abort();
        } else {
          status.dirty();
        }
      },
      get path() {
        return ctx.path;
      }
    };
    checkCtx.addIssue = checkCtx.addIssue.bind(checkCtx);
    if (effect.type === "preprocess") {
      const processed = effect.transform(ctx.data, checkCtx);
      if (ctx.common.async) {
        return Promise.resolve(processed).then(async (processed) => {
          if (status.value === "aborted")
            return INVALID;
          const result = await this._def.schema._parseAsync({
            data: processed,
            path: ctx.path,
            parent: ctx
          });
          if (result.status === "aborted")
            return INVALID;
          if (result.status === "dirty")
            return DIRTY(result.value);
          if (status.value === "dirty")
            return DIRTY(result.value);
          return result;
        });
      } else {
        if (status.value === "aborted")
          return INVALID;
        const result = this._def.schema._parseSync({
          data: processed,
          path: ctx.path,
          parent: ctx
        });
        if (result.status === "aborted")
          return INVALID;
        if (result.status === "dirty")
          return DIRTY(result.value);
        if (status.value === "dirty")
          return DIRTY(result.value);
        return result;
      }
    }
    if (effect.type === "refinement") {
      const executeRefinement = (acc) => {
        const result = effect.refinement(acc, checkCtx);
        if (ctx.common.async) {
          return Promise.resolve(result);
        }
        if (result instanceof Promise) {
          throw new Error("Async refinement encountered during synchronous parse operation. Use .parseAsync instead.");
        }
        return acc;
      };
      if (ctx.common.async === false) {
        const inner = this._def.schema._parseSync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        });
        if (inner.status === "aborted")
          return INVALID;
        if (inner.status === "dirty")
          status.dirty();
        executeRefinement(inner.value);
        return { status: status.value, value: inner.value };
      } else {
        return this._def.schema._parseAsync({ data: ctx.data, path: ctx.path, parent: ctx }).then((inner) => {
          if (inner.status === "aborted")
            return INVALID;
          if (inner.status === "dirty")
            status.dirty();
          return executeRefinement(inner.value).then(() => {
            return { status: status.value, value: inner.value };
          });
        });
      }
    }
    if (effect.type === "transform") {
      if (ctx.common.async === false) {
        const base = this._def.schema._parseSync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        });
        if (!isValid(base))
          return INVALID;
        const result = effect.transform(base.value, checkCtx);
        if (result instanceof Promise) {
          throw new Error(`Asynchronous transform encountered during synchronous parse operation. Use .parseAsync instead.`);
        }
        return { status: status.value, value: result };
      } else {
        return this._def.schema._parseAsync({ data: ctx.data, path: ctx.path, parent: ctx }).then((base) => {
          if (!isValid(base))
            return INVALID;
          return Promise.resolve(effect.transform(base.value, checkCtx)).then((result) => ({
            status: status.value,
            value: result
          }));
        });
      }
    }
    util.assertNever(effect);
  }
}
ZodEffects.create = (schema, effect, params) => {
  return new ZodEffects({
    schema,
    typeName: ZodFirstPartyTypeKind.ZodEffects,
    effect,
    ...processCreateParams(params)
  });
};
ZodEffects.createWithPreprocess = (preprocess, schema, params) => {
  return new ZodEffects({
    schema,
    effect: { type: "preprocess", transform: preprocess },
    typeName: ZodFirstPartyTypeKind.ZodEffects,
    ...processCreateParams(params)
  });
};

class ZodOptional extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType === ZodParsedType.undefined) {
      return OK(undefined);
    }
    return this._def.innerType._parse(input);
  }
  unwrap() {
    return this._def.innerType;
  }
}
ZodOptional.create = (type, params) => {
  return new ZodOptional({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodOptional,
    ...processCreateParams(params)
  });
};

class ZodNullable extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType === ZodParsedType.null) {
      return OK(null);
    }
    return this._def.innerType._parse(input);
  }
  unwrap() {
    return this._def.innerType;
  }
}
ZodNullable.create = (type, params) => {
  return new ZodNullable({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodNullable,
    ...processCreateParams(params)
  });
};

class ZodDefault extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    let data = ctx.data;
    if (ctx.parsedType === ZodParsedType.undefined) {
      data = this._def.defaultValue();
    }
    return this._def.innerType._parse({
      data,
      path: ctx.path,
      parent: ctx
    });
  }
  removeDefault() {
    return this._def.innerType;
  }
}
ZodDefault.create = (type, params) => {
  return new ZodDefault({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodDefault,
    defaultValue: typeof params.default === "function" ? params.default : () => params.default,
    ...processCreateParams(params)
  });
};

class ZodCatch extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const newCtx = {
      ...ctx,
      common: {
        ...ctx.common,
        issues: []
      }
    };
    const result = this._def.innerType._parse({
      data: newCtx.data,
      path: newCtx.path,
      parent: {
        ...newCtx
      }
    });
    if (isAsync(result)) {
      return result.then((result) => {
        return {
          status: "valid",
          value: result.status === "valid" ? result.value : this._def.catchValue({
            get error() {
              return new ZodError(newCtx.common.issues);
            },
            input: newCtx.data
          })
        };
      });
    } else {
      return {
        status: "valid",
        value: result.status === "valid" ? result.value : this._def.catchValue({
          get error() {
            return new ZodError(newCtx.common.issues);
          },
          input: newCtx.data
        })
      };
    }
  }
  removeCatch() {
    return this._def.innerType;
  }
}
ZodCatch.create = (type, params) => {
  return new ZodCatch({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodCatch,
    catchValue: typeof params.catch === "function" ? params.catch : () => params.catch,
    ...processCreateParams(params)
  });
};

class ZodNaN extends ZodType {
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.nan) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.nan,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return { status: "valid", value: input.data };
  }
}
ZodNaN.create = (params) => {
  return new ZodNaN({
    typeName: ZodFirstPartyTypeKind.ZodNaN,
    ...processCreateParams(params)
  });
};
var BRAND = Symbol("zod_brand");

class ZodBranded extends ZodType {
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const data = ctx.data;
    return this._def.type._parse({
      data,
      path: ctx.path,
      parent: ctx
    });
  }
  unwrap() {
    return this._def.type;
  }
}

class ZodPipeline extends ZodType {
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.common.async) {
      const handleAsync = async () => {
        const inResult = await this._def.in._parseAsync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        });
        if (inResult.status === "aborted")
          return INVALID;
        if (inResult.status === "dirty") {
          status.dirty();
          return DIRTY(inResult.value);
        } else {
          return this._def.out._parseAsync({
            data: inResult.value,
            path: ctx.path,
            parent: ctx
          });
        }
      };
      return handleAsync();
    } else {
      const inResult = this._def.in._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      });
      if (inResult.status === "aborted")
        return INVALID;
      if (inResult.status === "dirty") {
        status.dirty();
        return {
          status: "dirty",
          value: inResult.value
        };
      } else {
        return this._def.out._parseSync({
          data: inResult.value,
          path: ctx.path,
          parent: ctx
        });
      }
    }
  }
  static create(a, b) {
    return new ZodPipeline({
      in: a,
      out: b,
      typeName: ZodFirstPartyTypeKind.ZodPipeline
    });
  }
}

class ZodReadonly extends ZodType {
  _parse(input) {
    const result = this._def.innerType._parse(input);
    const freeze = (data) => {
      if (isValid(data)) {
        data.value = Object.freeze(data.value);
      }
      return data;
    };
    return isAsync(result) ? result.then((data) => freeze(data)) : freeze(result);
  }
  unwrap() {
    return this._def.innerType;
  }
}
ZodReadonly.create = (type, params) => {
  return new ZodReadonly({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodReadonly,
    ...processCreateParams(params)
  });
};
function cleanParams(params, data) {
  const p = typeof params === "function" ? params(data) : typeof params === "string" ? { message: params } : params;
  const p2 = typeof p === "string" ? { message: p } : p;
  return p2;
}
function custom2(check, _params = {}, fatal) {
  if (check)
    return ZodAny.create().superRefine((data, ctx) => {
      const r = check(data);
      if (r instanceof Promise) {
        return r.then((r) => {
          if (!r) {
            const params = cleanParams(_params, data);
            const _fatal = params.fatal ?? fatal ?? true;
            ctx.addIssue({ code: "custom", ...params, fatal: _fatal });
          }
        });
      }
      if (!r) {
        const params = cleanParams(_params, data);
        const _fatal = params.fatal ?? fatal ?? true;
        ctx.addIssue({ code: "custom", ...params, fatal: _fatal });
      }
      return;
    });
  return ZodAny.create();
}
var late = {
  object: ZodObject.lazycreate
};
var ZodFirstPartyTypeKind;
(function(ZodFirstPartyTypeKind) {
  ZodFirstPartyTypeKind["ZodString"] = "ZodString";
  ZodFirstPartyTypeKind["ZodNumber"] = "ZodNumber";
  ZodFirstPartyTypeKind["ZodNaN"] = "ZodNaN";
  ZodFirstPartyTypeKind["ZodBigInt"] = "ZodBigInt";
  ZodFirstPartyTypeKind["ZodBoolean"] = "ZodBoolean";
  ZodFirstPartyTypeKind["ZodDate"] = "ZodDate";
  ZodFirstPartyTypeKind["ZodSymbol"] = "ZodSymbol";
  ZodFirstPartyTypeKind["ZodUndefined"] = "ZodUndefined";
  ZodFirstPartyTypeKind["ZodNull"] = "ZodNull";
  ZodFirstPartyTypeKind["ZodAny"] = "ZodAny";
  ZodFirstPartyTypeKind["ZodUnknown"] = "ZodUnknown";
  ZodFirstPartyTypeKind["ZodNever"] = "ZodNever";
  ZodFirstPartyTypeKind["ZodVoid"] = "ZodVoid";
  ZodFirstPartyTypeKind["ZodArray"] = "ZodArray";
  ZodFirstPartyTypeKind["ZodObject"] = "ZodObject";
  ZodFirstPartyTypeKind["ZodUnion"] = "ZodUnion";
  ZodFirstPartyTypeKind["ZodDiscriminatedUnion"] = "ZodDiscriminatedUnion";
  ZodFirstPartyTypeKind["ZodIntersection"] = "ZodIntersection";
  ZodFirstPartyTypeKind["ZodTuple"] = "ZodTuple";
  ZodFirstPartyTypeKind["ZodRecord"] = "ZodRecord";
  ZodFirstPartyTypeKind["ZodMap"] = "ZodMap";
  ZodFirstPartyTypeKind["ZodSet"] = "ZodSet";
  ZodFirstPartyTypeKind["ZodFunction"] = "ZodFunction";
  ZodFirstPartyTypeKind["ZodLazy"] = "ZodLazy";
  ZodFirstPartyTypeKind["ZodLiteral"] = "ZodLiteral";
  ZodFirstPartyTypeKind["ZodEnum"] = "ZodEnum";
  ZodFirstPartyTypeKind["ZodEffects"] = "ZodEffects";
  ZodFirstPartyTypeKind["ZodNativeEnum"] = "ZodNativeEnum";
  ZodFirstPartyTypeKind["ZodOptional"] = "ZodOptional";
  ZodFirstPartyTypeKind["ZodNullable"] = "ZodNullable";
  ZodFirstPartyTypeKind["ZodDefault"] = "ZodDefault";
  ZodFirstPartyTypeKind["ZodCatch"] = "ZodCatch";
  ZodFirstPartyTypeKind["ZodPromise"] = "ZodPromise";
  ZodFirstPartyTypeKind["ZodBranded"] = "ZodBranded";
  ZodFirstPartyTypeKind["ZodPipeline"] = "ZodPipeline";
  ZodFirstPartyTypeKind["ZodReadonly"] = "ZodReadonly";
})(ZodFirstPartyTypeKind || (ZodFirstPartyTypeKind = {}));
var instanceOfType = (cls, params = {
  message: `Input not instance of ${cls.name}`
}) => custom2((data) => data instanceof cls, params);
var stringType = ZodString.create;
var numberType = ZodNumber.create;
var nanType = ZodNaN.create;
var bigIntType = ZodBigInt.create;
var booleanType = ZodBoolean.create;
var dateType = ZodDate.create;
var symbolType = ZodSymbol.create;
var undefinedType = ZodUndefined.create;
var nullType = ZodNull.create;
var anyType = ZodAny.create;
var unknownType = ZodUnknown.create;
var neverType = ZodNever.create;
var voidType = ZodVoid.create;
var arrayType = ZodArray.create;
var objectType = ZodObject.create;
var strictObjectType = ZodObject.strictCreate;
var unionType = ZodUnion.create;
var discriminatedUnionType = ZodDiscriminatedUnion.create;
var intersectionType = ZodIntersection.create;
var tupleType = ZodTuple.create;
var recordType = ZodRecord.create;
var mapType = ZodMap.create;
var setType = ZodSet.create;
var functionType = ZodFunction.create;
var lazyType = ZodLazy.create;
var literalType = ZodLiteral.create;
var enumType = ZodEnum.create;
var nativeEnumType = ZodNativeEnum.create;
var promiseType = ZodPromise.create;
var effectsType = ZodEffects.create;
var optionalType = ZodOptional.create;
var nullableType = ZodNullable.create;
var preprocessType = ZodEffects.createWithPreprocess;
var pipelineType = ZodPipeline.create;
var REGIONS = ["us-west-2"];
var NITRO_REGIONS = ["us-west-2"];
var regionSchema = enumType(REGIONS, {
  message: `unknown region; expected one of: ${REGIONS.join(", ")}`
});
var nitroRegionSchema = enumType(NITRO_REGIONS, {
  message: `aws nitro does not support this region; expected one of: ${NITRO_REGIONS.join(", ")}`
});
var nitroBindingSchema = objectType({
  tee: literalType("nitro"),
  regions: arrayType(nitroRegionSchema).nonempty().optional()
}).strict();
var teeBindingSchema = discriminatedUnionType("tee", [nitroBindingSchema]);
var oneOfTeesSchema = arrayType(teeBindingSchema).nonempty();
var anyTeeConstraintSchema = objectType({
  regions: arrayType(regionSchema).nonempty().optional()
}).strict();
var teeConstraintSchema = unionType([oneOfTeesSchema, anyTeeConstraintSchema]);
var handler = (trigger, fn, hooks) => ({
  trigger,
  fn,
  hooks
});
prepareRuntime();
function assertSafeIntegerNumber(value, label) {
  if (!Number.isFinite(value) || !Number.isInteger(value)) {
    throw new Error(`${label} requires an integer number, received ${value}`);
  }
  if (!Number.isSafeInteger(value)) {
    throw new Error(`${label} requires a safe integer number, received ${value}. Pass a bigint or string for larger values`);
  }
}
var prepareReportRequestFromBytes = (payload, reportEncoder) => ({
  encodedPayload: bytesToBase64(payload),
  ...reportEncoder
});
var LAST_FINALIZED_BLOCK_NUMBER = {
  absVal: Buffer.from([3]).toString("base64"),
  sign: "-1"
};
var LATEST_BLOCK_NUMBER = {
  absVal: Buffer.from([2]).toString("base64"),
  sign: "-1"
};
var encodeCallMsg = (payload) => {
  const encodeField = (fieldName, value) => {
    try {
      return hexToBase64(value);
    } catch (e) {
      throw new Error(`Invalid hex in '${fieldName}' field of CallMsg: ${e instanceof Error ? e.message : String(e)}`);
    }
  };
  return {
    from: encodeField("from", payload.from),
    to: encodeField("to", payload.to),
    data: encodeField("data", payload.data)
  };
};
var EVM_DEFAULT_REPORT_ENCODER = {
  encoderName: "evm",
  signingAlgo: "ecdsa",
  hashingAlgo: "keccak256"
};
var prepareReportRequest = (hexEncodedPayload, reportEncoder = EVM_DEFAULT_REPORT_ENCODER) => prepareReportRequestFromBytes(hexToBytes3(hexEncodedPayload), reportEncoder);
var SOLANA_ERROR__BLOCK_HEIGHT_EXCEEDED = 1;
var SOLANA_ERROR__INVALID_NONCE = 2;
var SOLANA_ERROR__NONCE_ACCOUNT_NOT_FOUND = 3;
var SOLANA_ERROR__BLOCKHASH_STRING_LENGTH_OUT_OF_RANGE = 4;
var SOLANA_ERROR__INVALID_BLOCKHASH_BYTE_LENGTH = 5;
var SOLANA_ERROR__LAMPORTS_OUT_OF_RANGE = 6;
var SOLANA_ERROR__MALFORMED_BIGINT_STRING = 7;
var SOLANA_ERROR__MALFORMED_NUMBER_STRING = 8;
var SOLANA_ERROR__TIMESTAMP_OUT_OF_RANGE = 9;
var SOLANA_ERROR__MALFORMED_JSON_RPC_ERROR = 10;
var SOLANA_ERROR__FAILED_TO_SEND_TRANSACTION = 11;
var SOLANA_ERROR__FAILED_TO_SEND_TRANSACTIONS = 12;
var SOLANA_ERROR__JSON_RPC__PARSE_ERROR = -32700;
var SOLANA_ERROR__JSON_RPC__INTERNAL_ERROR = -32603;
var SOLANA_ERROR__JSON_RPC__INVALID_PARAMS = -32602;
var SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND = -32601;
var SOLANA_ERROR__JSON_RPC__INVALID_REQUEST = -32600;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_NO_SLOT_HISTORY = -32021;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_FILTER_TRANSACTION_NOT_FOUND = -32020;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_LONG_TERM_STORAGE_UNREACHABLE = -32019;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SLOT_NOT_EPOCH_BOUNDARY = -32018;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_EPOCH_REWARDS_PERIOD_ACTIVE = -32017;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED = -32016;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_UNSUPPORTED_TRANSACTION_VERSION = -32015;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_BLOCK_STATUS_NOT_AVAILABLE_YET = -32014;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_TRANSACTION_SIGNATURE_LEN_MISMATCH = -32013;
var SOLANA_ERROR__JSON_RPC__SCAN_ERROR = -32012;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_TRANSACTION_HISTORY_NOT_AVAILABLE = -32011;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_KEY_EXCLUDED_FROM_SECONDARY_INDEX = -32010;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_LONG_TERM_STORAGE_SLOT_SKIPPED = -32009;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_NO_SNAPSHOT = -32008;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SLOT_SKIPPED = -32007;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_TRANSACTION_PRECOMPILE_VERIFICATION_FAILURE = -32006;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_NODE_UNHEALTHY = -32005;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_BLOCK_NOT_AVAILABLE = -32004;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_TRANSACTION_SIGNATURE_VERIFICATION_FAILURE = -32003;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE = -32002;
var SOLANA_ERROR__JSON_RPC__SERVER_ERROR_BLOCK_CLEANED_UP = -32001;
var SOLANA_ERROR__ADDRESSES__INVALID_BYTE_LENGTH = 2800000;
var SOLANA_ERROR__ADDRESSES__STRING_LENGTH_OUT_OF_RANGE = 2800001;
var SOLANA_ERROR__ADDRESSES__INVALID_BASE58_ENCODED_ADDRESS = 2800002;
var SOLANA_ERROR__ADDRESSES__INVALID_ED25519_PUBLIC_KEY = 2800003;
var SOLANA_ERROR__ADDRESSES__MALFORMED_PDA = 2800004;
var SOLANA_ERROR__ADDRESSES__PDA_BUMP_SEED_OUT_OF_RANGE = 2800005;
var SOLANA_ERROR__ADDRESSES__MAX_NUMBER_OF_PDA_SEEDS_EXCEEDED = 2800006;
var SOLANA_ERROR__ADDRESSES__MAX_PDA_SEED_LENGTH_EXCEEDED = 2800007;
var SOLANA_ERROR__ADDRESSES__INVALID_SEEDS_POINT_ON_CURVE = 2800008;
var SOLANA_ERROR__ADDRESSES__FAILED_TO_FIND_VIABLE_PDA_BUMP_SEED = 2800009;
var SOLANA_ERROR__ADDRESSES__PDA_ENDS_WITH_PDA_MARKER = 2800010;
var SOLANA_ERROR__ADDRESSES__INVALID_OFF_CURVE_ADDRESS = 2800011;
var SOLANA_ERROR__ACCOUNTS__ACCOUNT_NOT_FOUND = 3230000;
var SOLANA_ERROR__ACCOUNTS__ONE_OR_MORE_ACCOUNTS_NOT_FOUND = 32300001;
var SOLANA_ERROR__ACCOUNTS__FAILED_TO_DECODE_ACCOUNT = 3230002;
var SOLANA_ERROR__ACCOUNTS__EXPECTED_DECODED_ACCOUNT = 3230003;
var SOLANA_ERROR__ACCOUNTS__EXPECTED_ALL_ACCOUNTS_TO_BE_DECODED = 3230004;
var SOLANA_ERROR__SUBTLE_CRYPTO__DISALLOWED_IN_INSECURE_CONTEXT = 3610000;
var SOLANA_ERROR__SUBTLE_CRYPTO__DIGEST_UNIMPLEMENTED = 3610001;
var SOLANA_ERROR__SUBTLE_CRYPTO__ED25519_ALGORITHM_UNIMPLEMENTED = 3610002;
var SOLANA_ERROR__SUBTLE_CRYPTO__EXPORT_FUNCTION_UNIMPLEMENTED = 3610003;
var SOLANA_ERROR__SUBTLE_CRYPTO__GENERATE_FUNCTION_UNIMPLEMENTED = 3610004;
var SOLANA_ERROR__SUBTLE_CRYPTO__SIGN_FUNCTION_UNIMPLEMENTED = 3610005;
var SOLANA_ERROR__SUBTLE_CRYPTO__VERIFY_FUNCTION_UNIMPLEMENTED = 3610006;
var SOLANA_ERROR__SUBTLE_CRYPTO__CANNOT_EXPORT_NON_EXTRACTABLE_KEY = 3610007;
var SOLANA_ERROR__CRYPTO__RANDOM_VALUES_FUNCTION_UNIMPLEMENTED = 3611000;
var SOLANA_ERROR__KEYS__INVALID_KEY_PAIR_BYTE_LENGTH = 3704000;
var SOLANA_ERROR__KEYS__INVALID_PRIVATE_KEY_BYTE_LENGTH = 3704001;
var SOLANA_ERROR__KEYS__INVALID_SIGNATURE_BYTE_LENGTH = 3704002;
var SOLANA_ERROR__KEYS__SIGNATURE_STRING_LENGTH_OUT_OF_RANGE = 3704003;
var SOLANA_ERROR__KEYS__PUBLIC_KEY_MUST_MATCH_PRIVATE_KEY = 3704004;
var SOLANA_ERROR__KEYS__INVALID_BASE58_IN_GRIND_REGEX = 3704005;
var SOLANA_ERROR__KEYS__WRITE_KEY_PAIR_UNSUPPORTED_ENVIRONMENT = 3704006;
var SOLANA_ERROR__FS__UNSUPPORTED_ENVIRONMENT = 3712000;
var SOLANA_ERROR__INSTRUCTION__EXPECTED_TO_HAVE_ACCOUNTS = 4128000;
var SOLANA_ERROR__INSTRUCTION__EXPECTED_TO_HAVE_DATA = 4128001;
var SOLANA_ERROR__INSTRUCTION__PROGRAM_ID_MISMATCH = 4128002;
var SOLANA_ERROR__INSTRUCTION_ERROR__UNKNOWN = 4615000;
var SOLANA_ERROR__INSTRUCTION_ERROR__GENERIC_ERROR = 4615001;
var SOLANA_ERROR__INSTRUCTION_ERROR__INVALID_ARGUMENT = 4615002;
var SOLANA_ERROR__INSTRUCTION_ERROR__INVALID_INSTRUCTION_DATA = 4615003;
var SOLANA_ERROR__INSTRUCTION_ERROR__INVALID_ACCOUNT_DATA = 4615004;
var SOLANA_ERROR__INSTRUCTION_ERROR__ACCOUNT_DATA_TOO_SMALL = 4615005;
var SOLANA_ERROR__INSTRUCTION_ERROR__INSUFFICIENT_FUNDS = 4615006;
var SOLANA_ERROR__INSTRUCTION_ERROR__INCORRECT_PROGRAM_ID = 4615007;
var SOLANA_ERROR__INSTRUCTION_ERROR__MISSING_REQUIRED_SIGNATURE = 4615008;
var SOLANA_ERROR__INSTRUCTION_ERROR__ACCOUNT_ALREADY_INITIALIZED = 4615009;
var SOLANA_ERROR__INSTRUCTION_ERROR__UNINITIALIZED_ACCOUNT = 4615010;
var SOLANA_ERROR__INSTRUCTION_ERROR__UNBALANCED_INSTRUCTION = 4615011;
var SOLANA_ERROR__INSTRUCTION_ERROR__MODIFIED_PROGRAM_ID = 4615012;
var SOLANA_ERROR__INSTRUCTION_ERROR__EXTERNAL_ACCOUNT_LAMPORT_SPEND = 4615013;
var SOLANA_ERROR__INSTRUCTION_ERROR__EXTERNAL_ACCOUNT_DATA_MODIFIED = 4615014;
var SOLANA_ERROR__INSTRUCTION_ERROR__READONLY_LAMPORT_CHANGE = 4615015;
var SOLANA_ERROR__INSTRUCTION_ERROR__READONLY_DATA_MODIFIED = 4615016;
var SOLANA_ERROR__INSTRUCTION_ERROR__DUPLICATE_ACCOUNT_INDEX = 4615017;
var SOLANA_ERROR__INSTRUCTION_ERROR__EXECUTABLE_MODIFIED = 4615018;
var SOLANA_ERROR__INSTRUCTION_ERROR__RENT_EPOCH_MODIFIED = 4615019;
var SOLANA_ERROR__INSTRUCTION_ERROR__NOT_ENOUGH_ACCOUNT_KEYS = 4615020;
var SOLANA_ERROR__INSTRUCTION_ERROR__ACCOUNT_DATA_SIZE_CHANGED = 4615021;
var SOLANA_ERROR__INSTRUCTION_ERROR__ACCOUNT_NOT_EXECUTABLE = 4615022;
var SOLANA_ERROR__INSTRUCTION_ERROR__ACCOUNT_BORROW_FAILED = 4615023;
var SOLANA_ERROR__INSTRUCTION_ERROR__ACCOUNT_BORROW_OUTSTANDING = 4615024;
var SOLANA_ERROR__INSTRUCTION_ERROR__DUPLICATE_ACCOUNT_OUT_OF_SYNC = 4615025;
var SOLANA_ERROR__INSTRUCTION_ERROR__CUSTOM = 4615026;
var SOLANA_ERROR__INSTRUCTION_ERROR__INVALID_ERROR = 4615027;
var SOLANA_ERROR__INSTRUCTION_ERROR__EXECUTABLE_DATA_MODIFIED = 4615028;
var SOLANA_ERROR__INSTRUCTION_ERROR__EXECUTABLE_LAMPORT_CHANGE = 4615029;
var SOLANA_ERROR__INSTRUCTION_ERROR__EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT = 4615030;
var SOLANA_ERROR__INSTRUCTION_ERROR__UNSUPPORTED_PROGRAM_ID = 4615031;
var SOLANA_ERROR__INSTRUCTION_ERROR__CALL_DEPTH = 4615032;
var SOLANA_ERROR__INSTRUCTION_ERROR__MISSING_ACCOUNT = 4615033;
var SOLANA_ERROR__INSTRUCTION_ERROR__REENTRANCY_NOT_ALLOWED = 4615034;
var SOLANA_ERROR__INSTRUCTION_ERROR__MAX_SEED_LENGTH_EXCEEDED = 4615035;
var SOLANA_ERROR__INSTRUCTION_ERROR__INVALID_SEEDS = 4615036;
var SOLANA_ERROR__INSTRUCTION_ERROR__INVALID_REALLOC = 4615037;
var SOLANA_ERROR__INSTRUCTION_ERROR__COMPUTATIONAL_BUDGET_EXCEEDED = 4615038;
var SOLANA_ERROR__INSTRUCTION_ERROR__PRIVILEGE_ESCALATION = 4615039;
var SOLANA_ERROR__INSTRUCTION_ERROR__PROGRAM_ENVIRONMENT_SETUP_FAILURE = 4615040;
var SOLANA_ERROR__INSTRUCTION_ERROR__PROGRAM_FAILED_TO_COMPLETE = 4615041;
var SOLANA_ERROR__INSTRUCTION_ERROR__PROGRAM_FAILED_TO_COMPILE = 4615042;
var SOLANA_ERROR__INSTRUCTION_ERROR__IMMUTABLE = 4615043;
var SOLANA_ERROR__INSTRUCTION_ERROR__INCORRECT_AUTHORITY = 4615044;
var SOLANA_ERROR__INSTRUCTION_ERROR__BORSH_IO_ERROR = 4615045;
var SOLANA_ERROR__INSTRUCTION_ERROR__ACCOUNT_NOT_RENT_EXEMPT = 4615046;
var SOLANA_ERROR__INSTRUCTION_ERROR__INVALID_ACCOUNT_OWNER = 4615047;
var SOLANA_ERROR__INSTRUCTION_ERROR__ARITHMETIC_OVERFLOW = 4615048;
var SOLANA_ERROR__INSTRUCTION_ERROR__UNSUPPORTED_SYSVAR = 4615049;
var SOLANA_ERROR__INSTRUCTION_ERROR__ILLEGAL_OWNER = 4615050;
var SOLANA_ERROR__INSTRUCTION_ERROR__MAX_ACCOUNTS_DATA_ALLOCATIONS_EXCEEDED = 4615051;
var SOLANA_ERROR__INSTRUCTION_ERROR__MAX_ACCOUNTS_EXCEEDED = 4615052;
var SOLANA_ERROR__INSTRUCTION_ERROR__MAX_INSTRUCTION_TRACE_LENGTH_EXCEEDED = 4615053;
var SOLANA_ERROR__INSTRUCTION_ERROR__BUILTIN_PROGRAMS_MUST_CONSUME_COMPUTE_UNITS = 4615054;
var SOLANA_ERROR__SIGNER__ADDRESS_CANNOT_HAVE_MULTIPLE_SIGNERS = 5508000;
var SOLANA_ERROR__SIGNER__EXPECTED_KEY_PAIR_SIGNER = 5508001;
var SOLANA_ERROR__SIGNER__EXPECTED_MESSAGE_SIGNER = 5508002;
var SOLANA_ERROR__SIGNER__EXPECTED_MESSAGE_MODIFYING_SIGNER = 5508003;
var SOLANA_ERROR__SIGNER__EXPECTED_MESSAGE_PARTIAL_SIGNER = 5508004;
var SOLANA_ERROR__SIGNER__EXPECTED_TRANSACTION_SIGNER = 5508005;
var SOLANA_ERROR__SIGNER__EXPECTED_TRANSACTION_MODIFYING_SIGNER = 5508006;
var SOLANA_ERROR__SIGNER__EXPECTED_TRANSACTION_PARTIAL_SIGNER = 5508007;
var SOLANA_ERROR__SIGNER__EXPECTED_TRANSACTION_SENDING_SIGNER = 5508008;
var SOLANA_ERROR__SIGNER__TRANSACTION_CANNOT_HAVE_MULTIPLE_SENDING_SIGNERS = 5508009;
var SOLANA_ERROR__SIGNER__TRANSACTION_SENDING_SIGNER_MISSING = 5508010;
var SOLANA_ERROR__SIGNER__WALLET_MULTISIGN_UNIMPLEMENTED = 5508011;
var SOLANA_ERROR__SIGNER__WALLET_ACCOUNT_CANNOT_SIGN_TRANSACTION = 5508012;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__MAXIMUM_LENGTH_EXCEEDED = 5607000;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__RESTRICTED_ASCII_BODY_CHARACTER_OUT_OF_RANGE = 5607001;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__APPLICATION_DOMAIN_STRING_LENGTH_OUT_OF_RANGE = 5607002;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__INVALID_APPLICATION_DOMAIN_BYTE_LENGTH = 5607003;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__NUM_SIGNATURES_MISMATCH = 5607004;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__NUM_REQUIRED_SIGNERS_CANNOT_BE_ZERO = 5607005;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__VERSION_NUMBER_NOT_SUPPORTED = 5607006;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__MESSAGE_FORMAT_MISMATCH = 5607007;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__MESSAGE_LENGTH_MISMATCH = 5607008;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__MESSAGE_MUST_BE_NON_EMPTY = 5607009;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__NUM_ENVELOPE_SIGNATURES_CANNOT_BE_ZERO = 5607010;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__SIGNATURES_MISSING = 5607011;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__ENVELOPE_SIGNERS_MISMATCH = 5607012;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__ADDRESSES_CANNOT_SIGN_OFFCHAIN_MESSAGE = 5607013;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__UNEXPECTED_VERSION = 5607014;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__SIGNATORIES_MUST_BE_SORTED = 5607015;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__SIGNATORIES_MUST_BE_UNIQUE = 5607016;
var SOLANA_ERROR__OFFCHAIN_MESSAGE__SIGNATURE_VERIFICATION_FAILURE = 5607017;
var SOLANA_ERROR__TRANSACTION__INVOKED_PROGRAMS_CANNOT_PAY_FEES = 5663000;
var SOLANA_ERROR__TRANSACTION__INVOKED_PROGRAMS_MUST_NOT_BE_WRITABLE = 5663001;
var SOLANA_ERROR__TRANSACTION__EXPECTED_BLOCKHASH_LIFETIME = 5663002;
var SOLANA_ERROR__TRANSACTION__EXPECTED_NONCE_LIFETIME = 5663003;
var SOLANA_ERROR__TRANSACTION__VERSION_NUMBER_OUT_OF_RANGE = 5663004;
var SOLANA_ERROR__TRANSACTION__FAILED_TO_DECOMPILE_ADDRESS_LOOKUP_TABLE_CONTENTS_MISSING = 5663005;
var SOLANA_ERROR__TRANSACTION__FAILED_TO_DECOMPILE_ADDRESS_LOOKUP_TABLE_INDEX_OUT_OF_RANGE = 5663006;
var SOLANA_ERROR__TRANSACTION__FAILED_TO_DECOMPILE_INSTRUCTION_PROGRAM_ADDRESS_NOT_FOUND = 5663007;
var SOLANA_ERROR__TRANSACTION__FAILED_TO_DECOMPILE_FEE_PAYER_MISSING = 5663008;
var SOLANA_ERROR__TRANSACTION__SIGNATURES_MISSING = 5663009;
var SOLANA_ERROR__TRANSACTION__ADDRESS_MISSING = 5663010;
var SOLANA_ERROR__TRANSACTION__FEE_PAYER_MISSING = 5663011;
var SOLANA_ERROR__TRANSACTION__FEE_PAYER_SIGNATURE_MISSING = 5663012;
var SOLANA_ERROR__TRANSACTION__INVALID_NONCE_TRANSACTION_INSTRUCTIONS_MISSING = 5663013;
var SOLANA_ERROR__TRANSACTION__INVALID_NONCE_TRANSACTION_FIRST_INSTRUCTION_MUST_BE_ADVANCE_NONCE = 5663014;
var SOLANA_ERROR__TRANSACTION__ADDRESSES_CANNOT_SIGN_TRANSACTION = 5663015;
var SOLANA_ERROR__TRANSACTION__CANNOT_ENCODE_WITH_EMPTY_SIGNATURES = 5663016;
var SOLANA_ERROR__TRANSACTION__MESSAGE_SIGNATURES_MISMATCH = 5663017;
var SOLANA_ERROR__TRANSACTION__FAILED_TO_ESTIMATE_COMPUTE_LIMIT = 5663018;
var SOLANA_ERROR__TRANSACTION__FAILED_WHEN_SIMULATING_TO_ESTIMATE_COMPUTE_LIMIT = 5663019;
var SOLANA_ERROR__TRANSACTION__EXCEEDS_SIZE_LIMIT = 5663020;
var SOLANA_ERROR__TRANSACTION__VERSION_NUMBER_NOT_SUPPORTED = 5663021;
var SOLANA_ERROR__TRANSACTION__NONCE_ACCOUNT_CANNOT_BE_IN_LOOKUP_TABLE = 5663022;
var SOLANA_ERROR__TRANSACTION__MALFORMED_MESSAGE_BYTES = 5663023;
var SOLANA_ERROR__TRANSACTION__CANNOT_ENCODE_WITH_EMPTY_MESSAGE_BYTES = 5663024;
var SOLANA_ERROR__TRANSACTION__CANNOT_DECODE_EMPTY_TRANSACTION_BYTES = 5663025;
var SOLANA_ERROR__TRANSACTION__VERSION_ZERO_MUST_BE_ENCODED_WITH_SIGNATURES_FIRST = 5663026;
var SOLANA_ERROR__TRANSACTION__SIGNATURE_COUNT_TOO_HIGH_FOR_TRANSACTION_BYTES = 5663027;
var SOLANA_ERROR__TRANSACTION__INVALID_CONFIG_MASK_PRIORITY_FEE_BITS = 5663028;
var SOLANA_ERROR__TRANSACTION__INVALID_NONCE_ACCOUNT_INDEX = 5663029;
var SOLANA_ERROR__TRANSACTION__INVALID_CONFIG_VALUE_KIND = 5663030;
var SOLANA_ERROR__TRANSACTION__INSTRUCTION_HEADERS_PAYLOADS_MISMATCH = 5663031;
var SOLANA_ERROR__TRANSACTION__TOO_MANY_SIGNER_ADDRESSES = 5663032;
var SOLANA_ERROR__TRANSACTION__TOO_MANY_ACCOUNT_ADDRESSES = 5663033;
var SOLANA_ERROR__TRANSACTION__TOO_MANY_INSTRUCTIONS = 5663034;
var SOLANA_ERROR__TRANSACTION__TOO_MANY_ACCOUNTS_IN_INSTRUCTION = 5663035;
var SOLANA_ERROR__TRANSACTION__FAILED_TO_ESTIMATE_LOADED_ACCOUNTS_DATA_SIZE_LIMIT = 5663036;
var SOLANA_ERROR__TRANSACTION__FAILED_WHEN_SIMULATING_TO_ESTIMATE_RESOURCE_LIMITS = 5663037;
var SOLANA_ERROR__TRANSACTION_ERROR__UNKNOWN = 7050000;
var SOLANA_ERROR__TRANSACTION_ERROR__ACCOUNT_IN_USE = 7050001;
var SOLANA_ERROR__TRANSACTION_ERROR__ACCOUNT_LOADED_TWICE = 7050002;
var SOLANA_ERROR__TRANSACTION_ERROR__ACCOUNT_NOT_FOUND = 7050003;
var SOLANA_ERROR__TRANSACTION_ERROR__PROGRAM_ACCOUNT_NOT_FOUND = 7050004;
var SOLANA_ERROR__TRANSACTION_ERROR__INSUFFICIENT_FUNDS_FOR_FEE = 7050005;
var SOLANA_ERROR__TRANSACTION_ERROR__INVALID_ACCOUNT_FOR_FEE = 7050006;
var SOLANA_ERROR__TRANSACTION_ERROR__ALREADY_PROCESSED = 7050007;
var SOLANA_ERROR__TRANSACTION_ERROR__BLOCKHASH_NOT_FOUND = 7050008;
var SOLANA_ERROR__TRANSACTION_ERROR__CALL_CHAIN_TOO_DEEP = 7050009;
var SOLANA_ERROR__TRANSACTION_ERROR__MISSING_SIGNATURE_FOR_FEE = 7050010;
var SOLANA_ERROR__TRANSACTION_ERROR__INVALID_ACCOUNT_INDEX = 7050011;
var SOLANA_ERROR__TRANSACTION_ERROR__SIGNATURE_FAILURE = 7050012;
var SOLANA_ERROR__TRANSACTION_ERROR__INVALID_PROGRAM_FOR_EXECUTION = 7050013;
var SOLANA_ERROR__TRANSACTION_ERROR__SANITIZE_FAILURE = 7050014;
var SOLANA_ERROR__TRANSACTION_ERROR__CLUSTER_MAINTENANCE = 7050015;
var SOLANA_ERROR__TRANSACTION_ERROR__ACCOUNT_BORROW_OUTSTANDING = 7050016;
var SOLANA_ERROR__TRANSACTION_ERROR__WOULD_EXCEED_MAX_BLOCK_COST_LIMIT = 7050017;
var SOLANA_ERROR__TRANSACTION_ERROR__UNSUPPORTED_VERSION = 7050018;
var SOLANA_ERROR__TRANSACTION_ERROR__INVALID_WRITABLE_ACCOUNT = 7050019;
var SOLANA_ERROR__TRANSACTION_ERROR__WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT = 7050020;
var SOLANA_ERROR__TRANSACTION_ERROR__WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT = 7050021;
var SOLANA_ERROR__TRANSACTION_ERROR__TOO_MANY_ACCOUNT_LOCKS = 7050022;
var SOLANA_ERROR__TRANSACTION_ERROR__ADDRESS_LOOKUP_TABLE_NOT_FOUND = 7050023;
var SOLANA_ERROR__TRANSACTION_ERROR__INVALID_ADDRESS_LOOKUP_TABLE_OWNER = 7050024;
var SOLANA_ERROR__TRANSACTION_ERROR__INVALID_ADDRESS_LOOKUP_TABLE_DATA = 7050025;
var SOLANA_ERROR__TRANSACTION_ERROR__INVALID_ADDRESS_LOOKUP_TABLE_INDEX = 7050026;
var SOLANA_ERROR__TRANSACTION_ERROR__INVALID_RENT_PAYING_ACCOUNT = 7050027;
var SOLANA_ERROR__TRANSACTION_ERROR__WOULD_EXCEED_MAX_VOTE_COST_LIMIT = 7050028;
var SOLANA_ERROR__TRANSACTION_ERROR__WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT = 7050029;
var SOLANA_ERROR__TRANSACTION_ERROR__DUPLICATE_INSTRUCTION = 7050030;
var SOLANA_ERROR__TRANSACTION_ERROR__INSUFFICIENT_FUNDS_FOR_RENT = 7050031;
var SOLANA_ERROR__TRANSACTION_ERROR__MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED = 7050032;
var SOLANA_ERROR__TRANSACTION_ERROR__INVALID_LOADED_ACCOUNTS_DATA_SIZE_LIMIT = 7050033;
var SOLANA_ERROR__TRANSACTION_ERROR__RESANITIZATION_NEEDED = 7050034;
var SOLANA_ERROR__TRANSACTION_ERROR__PROGRAM_EXECUTION_TEMPORARILY_RESTRICTED = 7050035;
var SOLANA_ERROR__TRANSACTION_ERROR__UNBALANCED_TRANSACTION = 7050036;
var SOLANA_ERROR__INSTRUCTION_PLANS__MESSAGE_CANNOT_ACCOMMODATE_PLAN = 7618000;
var SOLANA_ERROR__INSTRUCTION_PLANS__MESSAGE_PACKER_ALREADY_COMPLETE = 7618001;
var SOLANA_ERROR__INSTRUCTION_PLANS__EMPTY_INSTRUCTION_PLAN = 7618002;
var SOLANA_ERROR__INSTRUCTION_PLANS__FAILED_TO_EXECUTE_TRANSACTION_PLAN = 7618003;
var SOLANA_ERROR__INSTRUCTION_PLANS__NON_DIVISIBLE_TRANSACTION_PLANS_NOT_SUPPORTED = 7618004;
var SOLANA_ERROR__INSTRUCTION_PLANS__FAILED_SINGLE_TRANSACTION_PLAN_RESULT_NOT_FOUND = 7618005;
var SOLANA_ERROR__INSTRUCTION_PLANS__UNEXPECTED_INSTRUCTION_PLAN = 7618006;
var SOLANA_ERROR__INSTRUCTION_PLANS__UNEXPECTED_TRANSACTION_PLAN = 7618007;
var SOLANA_ERROR__INSTRUCTION_PLANS__UNEXPECTED_TRANSACTION_PLAN_RESULT = 7618008;
var SOLANA_ERROR__INSTRUCTION_PLANS__EXPECTED_SUCCESSFUL_TRANSACTION_PLAN_RESULT = 7618009;
var SOLANA_ERROR__CODECS__CANNOT_DECODE_EMPTY_BYTE_ARRAY = 8078000;
var SOLANA_ERROR__CODECS__INVALID_BYTE_LENGTH = 8078001;
var SOLANA_ERROR__CODECS__EXPECTED_FIXED_LENGTH = 8078002;
var SOLANA_ERROR__CODECS__EXPECTED_VARIABLE_LENGTH = 8078003;
var SOLANA_ERROR__CODECS__ENCODER_DECODER_SIZE_COMPATIBILITY_MISMATCH = 8078004;
var SOLANA_ERROR__CODECS__ENCODER_DECODER_FIXED_SIZE_MISMATCH = 8078005;
var SOLANA_ERROR__CODECS__ENCODER_DECODER_MAX_SIZE_MISMATCH = 8078006;
var SOLANA_ERROR__CODECS__INVALID_NUMBER_OF_ITEMS = 8078007;
var SOLANA_ERROR__CODECS__ENUM_DISCRIMINATOR_OUT_OF_RANGE = 8078008;
var SOLANA_ERROR__CODECS__INVALID_DISCRIMINATED_UNION_VARIANT = 8078009;
var SOLANA_ERROR__CODECS__INVALID_ENUM_VARIANT = 8078010;
var SOLANA_ERROR__CODECS__NUMBER_OUT_OF_RANGE = 8078011;
var SOLANA_ERROR__CODECS__INVALID_STRING_FOR_BASE = 8078012;
var SOLANA_ERROR__CODECS__EXPECTED_POSITIVE_BYTE_LENGTH = 8078013;
var SOLANA_ERROR__CODECS__OFFSET_OUT_OF_RANGE = 8078014;
var SOLANA_ERROR__CODECS__INVALID_LITERAL_UNION_VARIANT = 8078015;
var SOLANA_ERROR__CODECS__LITERAL_UNION_DISCRIMINATOR_OUT_OF_RANGE = 8078016;
var SOLANA_ERROR__CODECS__UNION_VARIANT_OUT_OF_RANGE = 8078017;
var SOLANA_ERROR__CODECS__INVALID_CONSTANT = 8078018;
var SOLANA_ERROR__CODECS__EXPECTED_ZERO_VALUE_TO_MATCH_ITEM_FIXED_SIZE = 8078019;
var SOLANA_ERROR__CODECS__ENCODED_BYTES_MUST_NOT_INCLUDE_SENTINEL = 8078020;
var SOLANA_ERROR__CODECS__SENTINEL_MISSING_IN_DECODED_BYTES = 8078021;
var SOLANA_ERROR__CODECS__CANNOT_USE_LEXICAL_VALUES_AS_ENUM_DISCRIMINATORS = 8078022;
var SOLANA_ERROR__CODECS__EXPECTED_DECODER_TO_CONSUME_ENTIRE_BYTE_ARRAY = 8078023;
var SOLANA_ERROR__CODECS__INVALID_PATTERN_MATCH_VALUE = 8078024;
var SOLANA_ERROR__CODECS__INVALID_PATTERN_MATCH_BYTES = 8078025;
var SOLANA_ERROR__FIXED_POINTS__INVALID_TOTAL_BITS = 8090000;
var SOLANA_ERROR__FIXED_POINTS__INVALID_FRACTIONAL_BITS = 8090001;
var SOLANA_ERROR__FIXED_POINTS__INVALID_DECIMALS = 8090002;
var SOLANA_ERROR__FIXED_POINTS__FRACTIONAL_BITS_EXCEED_TOTAL_BITS = 8090003;
var SOLANA_ERROR__FIXED_POINTS__VALUE_OUT_OF_RANGE = 8090004;
var SOLANA_ERROR__FIXED_POINTS__INVALID_STRING = 8090005;
var SOLANA_ERROR__FIXED_POINTS__INVALID_ZERO_DENOMINATOR_RATIO = 8090006;
var SOLANA_ERROR__FIXED_POINTS__ARITHMETIC_OVERFLOW = 8090007;
var SOLANA_ERROR__FIXED_POINTS__SHAPE_MISMATCH = 8090008;
var SOLANA_ERROR__FIXED_POINTS__DIVISION_BY_ZERO = 8090009;
var SOLANA_ERROR__FIXED_POINTS__STRICT_MODE_PRECISION_LOSS = 8090010;
var SOLANA_ERROR__FIXED_POINTS__MALFORMED_RAW_VALUE = 8090011;
var SOLANA_ERROR__FIXED_POINTS__TOTAL_BITS_NOT_BYTE_ALIGNED = 8090012;
var SOLANA_ERROR__RPC__INTEGER_OVERFLOW = 8100000;
var SOLANA_ERROR__RPC__TRANSPORT_HTTP_HEADER_FORBIDDEN = 8100001;
var SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR = 8100002;
var SOLANA_ERROR__RPC__API_PLAN_MISSING_FOR_RPC_METHOD = 8100003;
var SOLANA_ERROR__RPC_SUBSCRIPTIONS__CANNOT_CREATE_SUBSCRIPTION_PLAN = 8190000;
var SOLANA_ERROR__RPC_SUBSCRIPTIONS__EXPECTED_SERVER_SUBSCRIPTION_ID = 8190001;
var SOLANA_ERROR__RPC_SUBSCRIPTIONS__CHANNEL_CLOSED_BEFORE_MESSAGE_BUFFERED = 8190002;
var SOLANA_ERROR__RPC_SUBSCRIPTIONS__CHANNEL_CONNECTION_CLOSED = 8190003;
var SOLANA_ERROR__RPC_SUBSCRIPTIONS__CHANNEL_FAILED_TO_CONNECT = 8190004;
var SOLANA_ERROR__SUBSCRIBABLE__RETRY_NOT_SUPPORTED = 8195000;
var SOLANA_ERROR__PROGRAM_CLIENTS__INSUFFICIENT_ACCOUNT_METAS = 8500000;
var SOLANA_ERROR__PROGRAM_CLIENTS__UNRECOGNIZED_INSTRUCTION_TYPE = 8500001;
var SOLANA_ERROR__PROGRAM_CLIENTS__FAILED_TO_IDENTIFY_INSTRUCTION = 8500002;
var SOLANA_ERROR__PROGRAM_CLIENTS__UNEXPECTED_RESOLVED_INSTRUCTION_INPUT_TYPE = 8500003;
var SOLANA_ERROR__PROGRAM_CLIENTS__RESOLVED_INSTRUCTION_INPUT_MUST_BE_NON_NULL = 8500004;
var SOLANA_ERROR__PROGRAM_CLIENTS__UNRECOGNIZED_ACCOUNT_TYPE = 8500005;
var SOLANA_ERROR__PROGRAM_CLIENTS__FAILED_TO_IDENTIFY_ACCOUNT = 8500006;
var SOLANA_ERROR__WALLET__NOT_CONNECTED = 8900000;
var SOLANA_ERROR__WALLET__NO_SIGNER_CONNECTED = 8900001;
var SOLANA_ERROR__WALLET__SIGNER_NOT_AVAILABLE = 8900002;
var SOLANA_ERROR__WALLET__ACCOUNT_NOT_AVAILABLE = 8900003;
var SOLANA_ERROR__INVARIANT_VIOLATION__SUBSCRIPTION_ITERATOR_STATE_MISSING = 9900000;
var SOLANA_ERROR__INVARIANT_VIOLATION__SUBSCRIPTION_ITERATOR_MUST_NOT_POLL_BEFORE_RESOLVING_EXISTING_MESSAGE_PROMISE = 9900001;
var SOLANA_ERROR__INVARIANT_VIOLATION__CACHED_ABORTABLE_ITERABLE_CACHE_ENTRY_MISSING = 9900002;
var SOLANA_ERROR__INVARIANT_VIOLATION__SWITCH_MUST_BE_EXHAUSTIVE = 9900003;
var SOLANA_ERROR__INVARIANT_VIOLATION__DATA_PUBLISHER_CHANNEL_UNIMPLEMENTED = 9900004;
var SOLANA_ERROR__INVARIANT_VIOLATION__INVALID_INSTRUCTION_PLAN_KIND = 9900005;
var SOLANA_ERROR__INVARIANT_VIOLATION__INVALID_TRANSACTION_PLAN_KIND = 9900006;
var SolanaErrorMessages = {
  [SOLANA_ERROR__ACCOUNTS__ACCOUNT_NOT_FOUND]: "Account not found at address: $address",
  [SOLANA_ERROR__ACCOUNTS__EXPECTED_ALL_ACCOUNTS_TO_BE_DECODED]: "Not all accounts were decoded. Encoded accounts found at addresses: $addresses.",
  [SOLANA_ERROR__ACCOUNTS__EXPECTED_DECODED_ACCOUNT]: "Expected decoded account at address: $address",
  [SOLANA_ERROR__ACCOUNTS__FAILED_TO_DECODE_ACCOUNT]: "Failed to decode account data at address: $address",
  [SOLANA_ERROR__ACCOUNTS__ONE_OR_MORE_ACCOUNTS_NOT_FOUND]: "Accounts not found at addresses: $addresses",
  [SOLANA_ERROR__ADDRESSES__FAILED_TO_FIND_VIABLE_PDA_BUMP_SEED]: "Unable to find a viable program address bump seed.",
  [SOLANA_ERROR__ADDRESSES__INVALID_BASE58_ENCODED_ADDRESS]: "$putativeAddress is not a base58-encoded address.",
  [SOLANA_ERROR__ADDRESSES__INVALID_BYTE_LENGTH]: "Expected base58 encoded address to decode to a byte array of length 32. Actual length: $actualLength.",
  [SOLANA_ERROR__ADDRESSES__INVALID_ED25519_PUBLIC_KEY]: "The `CryptoKey` must be an `Ed25519` public key.",
  [SOLANA_ERROR__ADDRESSES__INVALID_OFF_CURVE_ADDRESS]: "$putativeOffCurveAddress is not a base58-encoded off-curve address.",
  [SOLANA_ERROR__ADDRESSES__INVALID_SEEDS_POINT_ON_CURVE]: "Invalid seeds; point must fall off the Ed25519 curve.",
  [SOLANA_ERROR__ADDRESSES__MALFORMED_PDA]: "Expected given program derived address to have the following format: [Address, ProgramDerivedAddressBump].",
  [SOLANA_ERROR__ADDRESSES__MAX_NUMBER_OF_PDA_SEEDS_EXCEEDED]: "A maximum of $maxSeeds seeds, including the bump seed, may be supplied when creating an address. Received: $actual.",
  [SOLANA_ERROR__ADDRESSES__MAX_PDA_SEED_LENGTH_EXCEEDED]: "The seed at index $index with length $actual exceeds the maximum length of $maxSeedLength bytes.",
  [SOLANA_ERROR__ADDRESSES__PDA_BUMP_SEED_OUT_OF_RANGE]: "Expected program derived address bump to be in the range [0, 255], got: $bump.",
  [SOLANA_ERROR__ADDRESSES__PDA_ENDS_WITH_PDA_MARKER]: "Program address cannot end with PDA marker.",
  [SOLANA_ERROR__ADDRESSES__STRING_LENGTH_OUT_OF_RANGE]: "Expected base58-encoded address string of length in the range [32, 44]. Actual length: $actualLength.",
  [SOLANA_ERROR__BLOCKHASH_STRING_LENGTH_OUT_OF_RANGE]: "Expected base58-encoded blockhash string of length in the range [32, 44]. Actual length: $actualLength.",
  [SOLANA_ERROR__BLOCK_HEIGHT_EXCEEDED]: "The network has progressed past the last block for which this transaction could have been committed.",
  [SOLANA_ERROR__CODECS__CANNOT_DECODE_EMPTY_BYTE_ARRAY]: "Codec [$codecDescription] cannot decode empty byte arrays.",
  [SOLANA_ERROR__CODECS__CANNOT_USE_LEXICAL_VALUES_AS_ENUM_DISCRIMINATORS]: "Enum codec cannot use lexical values [$stringValues] as discriminators. Either remove all lexical values or set `useValuesAsDiscriminators` to `false`.",
  [SOLANA_ERROR__CODECS__ENCODED_BYTES_MUST_NOT_INCLUDE_SENTINEL]: "Sentinel [$hexSentinel] must not be present in encoded bytes [$hexEncodedBytes].",
  [SOLANA_ERROR__CODECS__ENCODER_DECODER_FIXED_SIZE_MISMATCH]: "Encoder and decoder must have the same fixed size, got [$encoderFixedSize] and [$decoderFixedSize].",
  [SOLANA_ERROR__CODECS__ENCODER_DECODER_MAX_SIZE_MISMATCH]: "Encoder and decoder must have the same max size, got [$encoderMaxSize] and [$decoderMaxSize].",
  [SOLANA_ERROR__CODECS__ENCODER_DECODER_SIZE_COMPATIBILITY_MISMATCH]: "Encoder and decoder must either both be fixed-size or variable-size.",
  [SOLANA_ERROR__CODECS__ENUM_DISCRIMINATOR_OUT_OF_RANGE]: "Enum discriminator out of range. Expected a number in [$formattedValidDiscriminators], got $discriminator.",
  [SOLANA_ERROR__CODECS__EXPECTED_FIXED_LENGTH]: "Expected a fixed-size codec, got a variable-size one.",
  [SOLANA_ERROR__CODECS__EXPECTED_POSITIVE_BYTE_LENGTH]: "Codec [$codecDescription] expected a positive byte length, got $bytesLength.",
  [SOLANA_ERROR__CODECS__EXPECTED_VARIABLE_LENGTH]: "Expected a variable-size codec, got a fixed-size one.",
  [SOLANA_ERROR__CODECS__EXPECTED_ZERO_VALUE_TO_MATCH_ITEM_FIXED_SIZE]: "Codec [$codecDescription] expected zero-value [$hexZeroValue] to have the same size as the provided fixed-size item [$expectedSize bytes].",
  [SOLANA_ERROR__CODECS__INVALID_BYTE_LENGTH]: "Codec [$codecDescription] expected $expected bytes, got $bytesLength.",
  [SOLANA_ERROR__CODECS__INVALID_CONSTANT]: "Expected byte array constant [$hexConstant] to be present in data [$hexData] at offset [$offset].",
  [SOLANA_ERROR__CODECS__INVALID_DISCRIMINATED_UNION_VARIANT]: "Invalid discriminated union variant. Expected one of [$variants], got $value.",
  [SOLANA_ERROR__CODECS__INVALID_ENUM_VARIANT]: "Invalid enum variant. Expected one of [$stringValues] or a number in [$formattedNumericalValues], got $variant.",
  [SOLANA_ERROR__CODECS__INVALID_LITERAL_UNION_VARIANT]: "Invalid literal union variant. Expected one of [$variants], got $value.",
  [SOLANA_ERROR__CODECS__INVALID_NUMBER_OF_ITEMS]: "Expected [$codecDescription] to have $expected items, got $actual.",
  [SOLANA_ERROR__CODECS__INVALID_STRING_FOR_BASE]: "Invalid value $value for base $base with alphabet $alphabet.",
  [SOLANA_ERROR__CODECS__LITERAL_UNION_DISCRIMINATOR_OUT_OF_RANGE]: "Literal union discriminator out of range. Expected a number between $minRange and $maxRange, got $discriminator.",
  [SOLANA_ERROR__CODECS__NUMBER_OUT_OF_RANGE]: "Codec [$codecDescription] expected number to be in the range [$min, $max], got $value.",
  [SOLANA_ERROR__CODECS__OFFSET_OUT_OF_RANGE]: "Codec [$codecDescription] expected offset to be in the range [0, $bytesLength], got $offset.",
  [SOLANA_ERROR__CODECS__SENTINEL_MISSING_IN_DECODED_BYTES]: "Expected sentinel [$hexSentinel] to be present in decoded bytes [$hexDecodedBytes].",
  [SOLANA_ERROR__CODECS__UNION_VARIANT_OUT_OF_RANGE]: "Union variant out of range. Expected an index between $minRange and $maxRange, got $variant.",
  [SOLANA_ERROR__CODECS__EXPECTED_DECODER_TO_CONSUME_ENTIRE_BYTE_ARRAY]: "This decoder expected a byte array of exactly $expectedLength bytes, but $numExcessBytes unexpected excess bytes remained after decoding. Are you sure that you have chosen the correct decoder for this data?",
  [SOLANA_ERROR__CODECS__INVALID_PATTERN_MATCH_VALUE]: "Invalid pattern match value. The provided value does not match any of the specified patterns.",
  [SOLANA_ERROR__CODECS__INVALID_PATTERN_MATCH_BYTES]: "Invalid pattern match bytes. The provided byte array does not match any of the specified patterns.",
  [SOLANA_ERROR__CRYPTO__RANDOM_VALUES_FUNCTION_UNIMPLEMENTED]: "No random values implementation could be found.",
  [SOLANA_ERROR__FAILED_TO_SEND_TRANSACTION]: "Failed to send transaction$causeMessage",
  [SOLANA_ERROR__FAILED_TO_SEND_TRANSACTIONS]: "Failed to send transactions$causeMessages",
  [SOLANA_ERROR__FIXED_POINTS__ARITHMETIC_OVERFLOW]: "Fixed-point operation `$operation` of kind `$kind` overflowed. Expected a raw bigint in [$min, $max], got $result.",
  [SOLANA_ERROR__FIXED_POINTS__DIVISION_BY_ZERO]: "Fixed-point division by zero for value of kind `$kind` ($signedness, $totalBits bits).",
  [SOLANA_ERROR__FIXED_POINTS__FRACTIONAL_BITS_EXCEED_TOTAL_BITS]: "`fractionalBits` ($fractionalBits) must not exceed `totalBits` ($totalBits).",
  [SOLANA_ERROR__FIXED_POINTS__INVALID_DECIMALS]: "Invalid `decimals`. Expected a non-negative integer, got $decimals.",
  [SOLANA_ERROR__FIXED_POINTS__INVALID_FRACTIONAL_BITS]: "Invalid `fractionalBits`. Expected a non-negative integer, got $fractionalBits.",
  [SOLANA_ERROR__FIXED_POINTS__INVALID_STRING]: "Invalid string `$input` for fixed-point value of kind `$kind`.",
  [SOLANA_ERROR__FIXED_POINTS__INVALID_TOTAL_BITS]: "Invalid `totalBits`. Expected a positive integer, got $totalBits.",
  [SOLANA_ERROR__FIXED_POINTS__INVALID_ZERO_DENOMINATOR_RATIO]: "Invalid ratio $numerator/$denominator for fixed-point value of kind `$kind`. Denominator must be non-zero.",
  [SOLANA_ERROR__FIXED_POINTS__MALFORMED_RAW_VALUE]: "Fixed-point value of kind `$kind` has a malformed `raw` field. Expected a bigint, got `$raw`.",
  [SOLANA_ERROR__FIXED_POINTS__SHAPE_MISMATCH]: "Fixed-point `$operation` operation expected $expectedKind ($expectedSignedness, $expectedTotalBits bits, $expectedScale $expectedScaleLabel); got $actualKind ($actualSignedness, $actualTotalBits bits, $actualScale $actualScaleLabel).",
  [SOLANA_ERROR__FIXED_POINTS__STRICT_MODE_PRECISION_LOSS]: "Fixed-point operation `$operation` of kind `$kind` cannot be performed exactly; pass a rounding mode other than `strict` to allow a rounded result.",
  [SOLANA_ERROR__FIXED_POINTS__TOTAL_BITS_NOT_BYTE_ALIGNED]: "Fixed-point codec of kind `$kind` requires `totalBits` to be a multiple of 8; got $totalBits.",
  [SOLANA_ERROR__FIXED_POINTS__VALUE_OUT_OF_RANGE]: "Fixed-point value of kind `$kind` is out of range for $signedness $totalBits-bit storage. Expected a raw bigint in [$min, $max], got $raw.",
  [SOLANA_ERROR__FS__UNSUPPORTED_ENVIRONMENT]: "Filesystem operation `$operation` is not supported in this environment.",
  [SOLANA_ERROR__INSTRUCTION_ERROR__ACCOUNT_ALREADY_INITIALIZED]: "Instruction requires an uninitialized account",
  [SOLANA_ERROR__INSTRUCTION_ERROR__ACCOUNT_BORROW_FAILED]: "Instruction tries to borrow reference for an account which is already borrowed",
  [SOLANA_ERROR__INSTRUCTION_ERROR__ACCOUNT_BORROW_OUTSTANDING]: "Instruction left account with an outstanding borrowed reference",
  [SOLANA_ERROR__INSTRUCTION_ERROR__ACCOUNT_DATA_SIZE_CHANGED]: "Program other than the account's owner changed the size of the account data",
  [SOLANA_ERROR__INSTRUCTION_ERROR__ACCOUNT_DATA_TOO_SMALL]: "Account data too small for instruction",
  [SOLANA_ERROR__INSTRUCTION_ERROR__ACCOUNT_NOT_EXECUTABLE]: "Instruction expected an executable account",
  [SOLANA_ERROR__INSTRUCTION_ERROR__ACCOUNT_NOT_RENT_EXEMPT]: "An account does not have enough lamports to be rent-exempt",
  [SOLANA_ERROR__INSTRUCTION_ERROR__ARITHMETIC_OVERFLOW]: "Program arithmetic overflowed",
  [SOLANA_ERROR__INSTRUCTION_ERROR__BORSH_IO_ERROR]: "Failed to serialize or deserialize account data",
  [SOLANA_ERROR__INSTRUCTION_ERROR__BUILTIN_PROGRAMS_MUST_CONSUME_COMPUTE_UNITS]: "Builtin programs must consume compute units",
  [SOLANA_ERROR__INSTRUCTION_ERROR__CALL_DEPTH]: "Cross-program invocation call depth too deep",
  [SOLANA_ERROR__INSTRUCTION_ERROR__COMPUTATIONAL_BUDGET_EXCEEDED]: "Computational budget exceeded",
  [SOLANA_ERROR__INSTRUCTION_ERROR__CUSTOM]: "Custom program error: #$code",
  [SOLANA_ERROR__INSTRUCTION_ERROR__DUPLICATE_ACCOUNT_INDEX]: "Instruction contains duplicate accounts",
  [SOLANA_ERROR__INSTRUCTION_ERROR__DUPLICATE_ACCOUNT_OUT_OF_SYNC]: "Instruction modifications of multiply-passed account differ",
  [SOLANA_ERROR__INSTRUCTION_ERROR__EXECUTABLE_ACCOUNT_NOT_RENT_EXEMPT]: "Executable accounts must be rent exempt",
  [SOLANA_ERROR__INSTRUCTION_ERROR__EXECUTABLE_DATA_MODIFIED]: "Instruction changed executable accounts data",
  [SOLANA_ERROR__INSTRUCTION_ERROR__EXECUTABLE_LAMPORT_CHANGE]: "Instruction changed the balance of an executable account",
  [SOLANA_ERROR__INSTRUCTION_ERROR__EXECUTABLE_MODIFIED]: "Instruction changed executable bit of an account",
  [SOLANA_ERROR__INSTRUCTION_ERROR__EXTERNAL_ACCOUNT_DATA_MODIFIED]: "Instruction modified data of an account it does not own",
  [SOLANA_ERROR__INSTRUCTION_ERROR__EXTERNAL_ACCOUNT_LAMPORT_SPEND]: "Instruction spent from the balance of an account it does not own",
  [SOLANA_ERROR__INSTRUCTION_ERROR__GENERIC_ERROR]: "Generic instruction error",
  [SOLANA_ERROR__INSTRUCTION_ERROR__ILLEGAL_OWNER]: "Provided owner is not allowed",
  [SOLANA_ERROR__INSTRUCTION_ERROR__IMMUTABLE]: "Account is immutable",
  [SOLANA_ERROR__INSTRUCTION_ERROR__INCORRECT_AUTHORITY]: "Incorrect authority provided",
  [SOLANA_ERROR__INSTRUCTION_ERROR__INCORRECT_PROGRAM_ID]: "Incorrect program id for instruction",
  [SOLANA_ERROR__INSTRUCTION_ERROR__INSUFFICIENT_FUNDS]: "Insufficient funds for instruction",
  [SOLANA_ERROR__INSTRUCTION_ERROR__INVALID_ACCOUNT_DATA]: "Invalid account data for instruction",
  [SOLANA_ERROR__INSTRUCTION_ERROR__INVALID_ACCOUNT_OWNER]: "Invalid account owner",
  [SOLANA_ERROR__INSTRUCTION_ERROR__INVALID_ARGUMENT]: "Invalid program argument",
  [SOLANA_ERROR__INSTRUCTION_ERROR__INVALID_ERROR]: "Program returned invalid error code",
  [SOLANA_ERROR__INSTRUCTION_ERROR__INVALID_INSTRUCTION_DATA]: "Invalid instruction data",
  [SOLANA_ERROR__INSTRUCTION_ERROR__INVALID_REALLOC]: "Failed to reallocate account data",
  [SOLANA_ERROR__INSTRUCTION_ERROR__INVALID_SEEDS]: "Provided seeds do not result in a valid address",
  [SOLANA_ERROR__INSTRUCTION_ERROR__MAX_ACCOUNTS_DATA_ALLOCATIONS_EXCEEDED]: "Accounts data allocations exceeded the maximum allowed per transaction",
  [SOLANA_ERROR__INSTRUCTION_ERROR__MAX_ACCOUNTS_EXCEEDED]: "Max accounts exceeded",
  [SOLANA_ERROR__INSTRUCTION_ERROR__MAX_INSTRUCTION_TRACE_LENGTH_EXCEEDED]: "Max instruction trace length exceeded",
  [SOLANA_ERROR__INSTRUCTION_ERROR__MAX_SEED_LENGTH_EXCEEDED]: "Length of the seed is too long for address generation",
  [SOLANA_ERROR__INSTRUCTION_ERROR__MISSING_ACCOUNT]: "An account required by the instruction is missing",
  [SOLANA_ERROR__INSTRUCTION_ERROR__MISSING_REQUIRED_SIGNATURE]: "Missing required signature for instruction",
  [SOLANA_ERROR__INSTRUCTION_ERROR__MODIFIED_PROGRAM_ID]: "Instruction illegally modified the program id of an account",
  [SOLANA_ERROR__INSTRUCTION_ERROR__NOT_ENOUGH_ACCOUNT_KEYS]: "Insufficient account keys for instruction",
  [SOLANA_ERROR__INSTRUCTION_ERROR__PRIVILEGE_ESCALATION]: "Cross-program invocation with unauthorized signer or writable account",
  [SOLANA_ERROR__INSTRUCTION_ERROR__PROGRAM_ENVIRONMENT_SETUP_FAILURE]: "Failed to create program execution environment",
  [SOLANA_ERROR__INSTRUCTION_ERROR__PROGRAM_FAILED_TO_COMPILE]: "Program failed to compile",
  [SOLANA_ERROR__INSTRUCTION_ERROR__PROGRAM_FAILED_TO_COMPLETE]: "Program failed to complete",
  [SOLANA_ERROR__INSTRUCTION_ERROR__READONLY_DATA_MODIFIED]: "Instruction modified data of a read-only account",
  [SOLANA_ERROR__INSTRUCTION_ERROR__READONLY_LAMPORT_CHANGE]: "Instruction changed the balance of a read-only account",
  [SOLANA_ERROR__INSTRUCTION_ERROR__REENTRANCY_NOT_ALLOWED]: "Cross-program invocation reentrancy not allowed for this instruction",
  [SOLANA_ERROR__INSTRUCTION_ERROR__RENT_EPOCH_MODIFIED]: "Instruction modified rent epoch of an account",
  [SOLANA_ERROR__INSTRUCTION_ERROR__UNBALANCED_INSTRUCTION]: "Sum of account balances before and after instruction do not match",
  [SOLANA_ERROR__INSTRUCTION_ERROR__UNINITIALIZED_ACCOUNT]: "Instruction requires an initialized account",
  [SOLANA_ERROR__INSTRUCTION_ERROR__UNKNOWN]: "The instruction failed with the error: $errorName",
  [SOLANA_ERROR__INSTRUCTION_ERROR__UNSUPPORTED_PROGRAM_ID]: "Unsupported program id",
  [SOLANA_ERROR__INSTRUCTION_ERROR__UNSUPPORTED_SYSVAR]: "Unsupported sysvar",
  [SOLANA_ERROR__INVARIANT_VIOLATION__INVALID_INSTRUCTION_PLAN_KIND]: "Invalid instruction plan kind: $kind.",
  [SOLANA_ERROR__INSTRUCTION_PLANS__EMPTY_INSTRUCTION_PLAN]: "The provided instruction plan is empty.",
  [SOLANA_ERROR__INSTRUCTION_PLANS__FAILED_SINGLE_TRANSACTION_PLAN_RESULT_NOT_FOUND]: "No failed transaction plan result was found in the provided transaction plan result.",
  [SOLANA_ERROR__INSTRUCTION_PLANS__NON_DIVISIBLE_TRANSACTION_PLANS_NOT_SUPPORTED]: "This transaction plan executor does not support non-divisible sequential plans. To support them, you may create your own executor such that multi-transaction atomicity is preserved — e.g. by targetting RPCs that support transaction bundles.",
  [SOLANA_ERROR__INSTRUCTION_PLANS__FAILED_TO_EXECUTE_TRANSACTION_PLAN]: "The provided transaction plan failed to execute. See the `transactionPlanResult` attribute for more details. Note that the `cause` property is deprecated, and a future version will not set it.",
  [SOLANA_ERROR__INSTRUCTION_PLANS__MESSAGE_CANNOT_ACCOMMODATE_PLAN]: "The provided message has insufficient capacity to accommodate the next instruction(s) in this plan. Expected at least $numBytesRequired free byte(s), got $numFreeBytes byte(s).",
  [SOLANA_ERROR__INVARIANT_VIOLATION__INVALID_TRANSACTION_PLAN_KIND]: "Invalid transaction plan kind: $kind.",
  [SOLANA_ERROR__INSTRUCTION_PLANS__MESSAGE_PACKER_ALREADY_COMPLETE]: "No more instructions to pack; the message packer has completed the instruction plan.",
  [SOLANA_ERROR__INSTRUCTION_PLANS__UNEXPECTED_INSTRUCTION_PLAN]: "Unexpected instruction plan. Expected $expectedKind plan, got $actualKind plan.",
  [SOLANA_ERROR__INSTRUCTION_PLANS__UNEXPECTED_TRANSACTION_PLAN]: "Unexpected transaction plan. Expected $expectedKind plan, got $actualKind plan.",
  [SOLANA_ERROR__INSTRUCTION_PLANS__UNEXPECTED_TRANSACTION_PLAN_RESULT]: "Unexpected transaction plan result. Expected $expectedKind plan, got $actualKind plan.",
  [SOLANA_ERROR__INSTRUCTION_PLANS__EXPECTED_SUCCESSFUL_TRANSACTION_PLAN_RESULT]: "Expected a successful transaction plan result. I.e. there is at least one failed or cancelled transaction in the plan.",
  [SOLANA_ERROR__INSTRUCTION__EXPECTED_TO_HAVE_ACCOUNTS]: "The instruction does not have any accounts.",
  [SOLANA_ERROR__INSTRUCTION__EXPECTED_TO_HAVE_DATA]: "The instruction does not have any data.",
  [SOLANA_ERROR__INSTRUCTION__PROGRAM_ID_MISMATCH]: "Expected instruction to have progress address $expectedProgramAddress, got $actualProgramAddress.",
  [SOLANA_ERROR__INVALID_BLOCKHASH_BYTE_LENGTH]: "Expected base58 encoded blockhash to decode to a byte array of length 32. Actual length: $actualLength.",
  [SOLANA_ERROR__INVALID_NONCE]: "The nonce `$expectedNonceValue` is no longer valid. It has advanced to `$actualNonceValue`",
  [SOLANA_ERROR__INVARIANT_VIOLATION__CACHED_ABORTABLE_ITERABLE_CACHE_ENTRY_MISSING]: "Invariant violation: Found no abortable iterable cache entry for key `$cacheKey`. It should be impossible to hit this error; please file an issue at https://sola.na/web3invariant",
  [SOLANA_ERROR__INVARIANT_VIOLATION__DATA_PUBLISHER_CHANNEL_UNIMPLEMENTED]: "Invariant violation: This data publisher does not publish to the channel named `$channelName`. Supported channels include $supportedChannelNames.",
  [SOLANA_ERROR__INVARIANT_VIOLATION__SUBSCRIPTION_ITERATOR_MUST_NOT_POLL_BEFORE_RESOLVING_EXISTING_MESSAGE_PROMISE]: "Invariant violation: WebSocket message iterator state is corrupt; iterated without first resolving existing message promise. It should be impossible to hit this error; please file an issue at https://sola.na/web3invariant",
  [SOLANA_ERROR__INVARIANT_VIOLATION__SUBSCRIPTION_ITERATOR_STATE_MISSING]: "Invariant violation: WebSocket message iterator is missing state storage. It should be impossible to hit this error; please file an issue at https://sola.na/web3invariant",
  [SOLANA_ERROR__INVARIANT_VIOLATION__SWITCH_MUST_BE_EXHAUSTIVE]: "Invariant violation: Switch statement non-exhaustive. Received unexpected value `$unexpectedValue`. It should be impossible to hit this error; please file an issue at https://sola.na/web3invariant",
  [SOLANA_ERROR__JSON_RPC__INTERNAL_ERROR]: "JSON-RPC error: Internal JSON-RPC error ($__serverMessage)",
  [SOLANA_ERROR__JSON_RPC__INVALID_PARAMS]: "JSON-RPC error: Invalid method parameter(s) ($__serverMessage)",
  [SOLANA_ERROR__JSON_RPC__INVALID_REQUEST]: "JSON-RPC error: The JSON sent is not a valid `Request` object ($__serverMessage)",
  [SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND]: "JSON-RPC error: The method does not exist / is not available ($__serverMessage)",
  [SOLANA_ERROR__JSON_RPC__PARSE_ERROR]: "JSON-RPC error: An error occurred on the server while parsing the JSON text ($__serverMessage)",
  [SOLANA_ERROR__JSON_RPC__SCAN_ERROR]: "$__serverMessage",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_BLOCK_CLEANED_UP]: "$__serverMessage",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_BLOCK_NOT_AVAILABLE]: "$__serverMessage",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_BLOCK_STATUS_NOT_AVAILABLE_YET]: "$__serverMessage",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_EPOCH_REWARDS_PERIOD_ACTIVE]: "Epoch rewards period still active at slot $slot",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_FILTER_TRANSACTION_NOT_FOUND]: "$__serverMessage",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_KEY_EXCLUDED_FROM_SECONDARY_INDEX]: "$__serverMessage",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_LONG_TERM_STORAGE_SLOT_SKIPPED]: "$__serverMessage",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_LONG_TERM_STORAGE_UNREACHABLE]: "Failed to query long-term storage; please try again",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_MIN_CONTEXT_SLOT_NOT_REACHED]: "Minimum context slot has not been reached",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_NODE_UNHEALTHY]: "Node is unhealthy; behind by $numSlotsBehind slots",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_NO_SLOT_HISTORY]: "No slot history",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_NO_SNAPSHOT]: "No snapshot",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SEND_TRANSACTION_PREFLIGHT_FAILURE]: "Transaction simulation failed",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SLOT_NOT_EPOCH_BOUNDARY]: "Rewards cannot be found because slot $slot is not the epoch boundary. This may be due to gap in the queried node's local ledger or long-term storage",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_SLOT_SKIPPED]: "$__serverMessage",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_TRANSACTION_HISTORY_NOT_AVAILABLE]: "Transaction history is not available from this node",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_TRANSACTION_PRECOMPILE_VERIFICATION_FAILURE]: "$__serverMessage",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_TRANSACTION_SIGNATURE_LEN_MISMATCH]: "Transaction signature length mismatch",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_TRANSACTION_SIGNATURE_VERIFICATION_FAILURE]: "Transaction signature verification failure",
  [SOLANA_ERROR__JSON_RPC__SERVER_ERROR_UNSUPPORTED_TRANSACTION_VERSION]: "$__serverMessage",
  [SOLANA_ERROR__KEYS__INVALID_BASE58_IN_GRIND_REGEX]: "The grind regex `/$source/` contains the character `$character`, which is not in the base58 alphabet and can never match a Solana address.",
  [SOLANA_ERROR__KEYS__INVALID_KEY_PAIR_BYTE_LENGTH]: "Key pair bytes must be of length 64, got $byteLength.",
  [SOLANA_ERROR__KEYS__INVALID_PRIVATE_KEY_BYTE_LENGTH]: "Expected private key bytes with length 32. Actual length: $actualLength.",
  [SOLANA_ERROR__KEYS__INVALID_SIGNATURE_BYTE_LENGTH]: "Expected base58-encoded signature to decode to a byte array of length 64. Actual length: $actualLength.",
  [SOLANA_ERROR__KEYS__PUBLIC_KEY_MUST_MATCH_PRIVATE_KEY]: "The provided private key does not match the provided public key.",
  [SOLANA_ERROR__KEYS__SIGNATURE_STRING_LENGTH_OUT_OF_RANGE]: "Expected base58-encoded signature string of length in the range [64, 88]. Actual length: $actualLength.",
  [SOLANA_ERROR__KEYS__WRITE_KEY_PAIR_UNSUPPORTED_ENVIRONMENT]: "Writing a key pair to disk is not supported in this environment.",
  [SOLANA_ERROR__LAMPORTS_OUT_OF_RANGE]: "Lamports value must be in the range [0, 2e64-1]",
  [SOLANA_ERROR__MALFORMED_BIGINT_STRING]: "`$value` cannot be parsed as a `BigInt`",
  [SOLANA_ERROR__MALFORMED_JSON_RPC_ERROR]: "$message",
  [SOLANA_ERROR__MALFORMED_NUMBER_STRING]: "`$value` cannot be parsed as a `Number`",
  [SOLANA_ERROR__NONCE_ACCOUNT_NOT_FOUND]: "No nonce account could be found at address `$nonceAccountAddress`",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__INVALID_APPLICATION_DOMAIN_BYTE_LENGTH]: "Expected base58 encoded application domain to decode to a byte array of length 32. Actual length: $actualLength.",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__ADDRESSES_CANNOT_SIGN_OFFCHAIN_MESSAGE]: "Attempted to sign an offchain message with an address that is not a signer for it",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__APPLICATION_DOMAIN_STRING_LENGTH_OUT_OF_RANGE]: "Expected base58-encoded application domain string of length in the range [32, 44]. Actual length: $actualLength.",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__ENVELOPE_SIGNERS_MISMATCH]: "The signer addresses in this offchain message envelope do not match the list of required signers in the message preamble. These unexpected signers were present in the envelope: `[$unexpectedSigners]`. These required signers were missing from the envelope `[$missingSigners]`.",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__MAXIMUM_LENGTH_EXCEEDED]: "The message body provided has a byte-length of $actualBytes. The maximum allowable byte-length is $maxBytes",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__MESSAGE_FORMAT_MISMATCH]: "Expected message format $expectedMessageFormat, got $actualMessageFormat",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__MESSAGE_LENGTH_MISMATCH]: "The message length specified in the message preamble is $specifiedLength bytes. The actual length of the message is $actualLength bytes.",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__MESSAGE_MUST_BE_NON_EMPTY]: "Offchain message content must be non-empty",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__NUM_REQUIRED_SIGNERS_CANNOT_BE_ZERO]: "Offchain message must specify the address of at least one required signer",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__NUM_ENVELOPE_SIGNATURES_CANNOT_BE_ZERO]: "Offchain message envelope must reserve space for at least one signature",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__NUM_SIGNATURES_MISMATCH]: "The offchain message preamble specifies $numRequiredSignatures required signature(s), got $signaturesLength.",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__SIGNATORIES_MUST_BE_SORTED]: "The signatories of this offchain message must be listed in lexicographical order",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__SIGNATORIES_MUST_BE_UNIQUE]: "An address must be listed no more than once among the signatories of an offchain message",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__SIGNATURES_MISSING]: "Offchain message is missing signatures for addresses: $addresses.",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__SIGNATURE_VERIFICATION_FAILURE]: "Offchain message signature verification failed. Signature mismatch for required signatories [$signatoriesWithInvalidSignatures]. Missing signatures for signatories [$signatoriesWithMissingSignatures]",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__RESTRICTED_ASCII_BODY_CHARACTER_OUT_OF_RANGE]: "The message body provided contains characters whose codes fall outside the allowed range. In order to ensure clear-signing compatiblity with hardware wallets, the message may only contain line feeds and characters in the range [\\x20-\\x7e].",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__UNEXPECTED_VERSION]: "Expected offchain message version $expectedVersion. Got $actualVersion.",
  [SOLANA_ERROR__OFFCHAIN_MESSAGE__VERSION_NUMBER_NOT_SUPPORTED]: "This version of Kit does not support decoding offchain messages with version $unsupportedVersion. The current max supported version is 0.",
  [SOLANA_ERROR__PROGRAM_CLIENTS__FAILED_TO_IDENTIFY_ACCOUNT]: "The provided account could not be identified as an account from the $programName program.",
  [SOLANA_ERROR__PROGRAM_CLIENTS__FAILED_TO_IDENTIFY_INSTRUCTION]: "The provided instruction could not be identified as an instruction from the $programName program.",
  [SOLANA_ERROR__PROGRAM_CLIENTS__INSUFFICIENT_ACCOUNT_METAS]: "The provided instruction is missing some accounts. Expected at least $expectedAccountMetas account(s), got $actualAccountMetas.",
  [SOLANA_ERROR__PROGRAM_CLIENTS__RESOLVED_INSTRUCTION_INPUT_MUST_BE_NON_NULL]: "Expected resolved instruction input '$inputName' to be non-null.",
  [SOLANA_ERROR__PROGRAM_CLIENTS__UNEXPECTED_RESOLVED_INSTRUCTION_INPUT_TYPE]: "Expected resolved instruction input '$inputName' to be of type `$expectedType`.",
  [SOLANA_ERROR__PROGRAM_CLIENTS__UNRECOGNIZED_ACCOUNT_TYPE]: "Unrecognized account type '$accountType' for the $programName program.",
  [SOLANA_ERROR__PROGRAM_CLIENTS__UNRECOGNIZED_INSTRUCTION_TYPE]: "Unrecognized instruction type '$instructionType' for the $programName program.",
  [SOLANA_ERROR__RPC_SUBSCRIPTIONS__CANNOT_CREATE_SUBSCRIPTION_PLAN]: "The notification name must end in 'Notifications' and the API must supply a subscription plan creator function for the notification '$notificationName'.",
  [SOLANA_ERROR__RPC_SUBSCRIPTIONS__CHANNEL_CLOSED_BEFORE_MESSAGE_BUFFERED]: "WebSocket was closed before payload could be added to the send buffer",
  [SOLANA_ERROR__RPC_SUBSCRIPTIONS__CHANNEL_CONNECTION_CLOSED]: "WebSocket connection closed",
  [SOLANA_ERROR__RPC_SUBSCRIPTIONS__CHANNEL_FAILED_TO_CONNECT]: "WebSocket failed to connect",
  [SOLANA_ERROR__RPC_SUBSCRIPTIONS__EXPECTED_SERVER_SUBSCRIPTION_ID]: "Failed to obtain a subscription id from the server",
  [SOLANA_ERROR__RPC__API_PLAN_MISSING_FOR_RPC_METHOD]: "Could not find an API plan for RPC method: `$method`",
  [SOLANA_ERROR__RPC__INTEGER_OVERFLOW]: "The $argumentLabel argument to the `$methodName` RPC method$optionalPathLabel was `$value`. This number is unsafe for use with the Solana JSON-RPC because it exceeds `Number.MAX_SAFE_INTEGER`.",
  [SOLANA_ERROR__RPC__TRANSPORT_HTTP_ERROR]: "HTTP error ($statusCode): $message",
  [SOLANA_ERROR__RPC__TRANSPORT_HTTP_HEADER_FORBIDDEN]: "HTTP header(s) forbidden: $headers. Learn more at https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name.",
  [SOLANA_ERROR__SIGNER__ADDRESS_CANNOT_HAVE_MULTIPLE_SIGNERS]: "Multiple distinct signers were identified for address `$address`. Please ensure that you are using the same signer instance for each address.",
  [SOLANA_ERROR__SIGNER__EXPECTED_KEY_PAIR_SIGNER]: "The provided value does not implement the `KeyPairSigner` interface",
  [SOLANA_ERROR__SIGNER__EXPECTED_MESSAGE_MODIFYING_SIGNER]: "The provided value does not implement the `MessageModifyingSigner` interface",
  [SOLANA_ERROR__SIGNER__EXPECTED_MESSAGE_PARTIAL_SIGNER]: "The provided value does not implement the `MessagePartialSigner` interface",
  [SOLANA_ERROR__SIGNER__EXPECTED_MESSAGE_SIGNER]: "The provided value does not implement any of the `MessageSigner` interfaces",
  [SOLANA_ERROR__SIGNER__EXPECTED_TRANSACTION_MODIFYING_SIGNER]: "The provided value does not implement the `TransactionModifyingSigner` interface",
  [SOLANA_ERROR__SIGNER__EXPECTED_TRANSACTION_PARTIAL_SIGNER]: "The provided value does not implement the `TransactionPartialSigner` interface",
  [SOLANA_ERROR__SIGNER__EXPECTED_TRANSACTION_SENDING_SIGNER]: "The provided value does not implement the `TransactionSendingSigner` interface",
  [SOLANA_ERROR__SIGNER__EXPECTED_TRANSACTION_SIGNER]: "The provided value does not implement any of the `TransactionSigner` interfaces",
  [SOLANA_ERROR__SIGNER__TRANSACTION_CANNOT_HAVE_MULTIPLE_SENDING_SIGNERS]: "More than one `TransactionSendingSigner` was identified.",
  [SOLANA_ERROR__SIGNER__TRANSACTION_SENDING_SIGNER_MISSING]: "No `TransactionSendingSigner` was identified. Please provide a valid `TransactionWithSingleSendingSigner` transaction.",
  [SOLANA_ERROR__SIGNER__WALLET_ACCOUNT_CANNOT_SIGN_TRANSACTION]: "The wallet account $address cannot be used to create a transaction signer because it does not implement either the `solana:signTransaction` or `solana:signAndSendTransaction` feature. At least one of these features is required. The account supports the following features: $supportedFeatures.",
  [SOLANA_ERROR__SIGNER__WALLET_MULTISIGN_UNIMPLEMENTED]: "Wallet account signers do not support signing multiple messages/transactions in a single operation",
  [SOLANA_ERROR__SUBSCRIBABLE__RETRY_NOT_SUPPORTED]: "This `ReactiveStreamStore` does not support retry. Use `createReactiveStoreFromDataPublisherFactory` to construct a retryable store.",
  [SOLANA_ERROR__SUBTLE_CRYPTO__CANNOT_EXPORT_NON_EXTRACTABLE_KEY]: "Cannot export a non-extractable key.",
  [SOLANA_ERROR__SUBTLE_CRYPTO__DIGEST_UNIMPLEMENTED]: "No digest implementation could be found.",
  [SOLANA_ERROR__SUBTLE_CRYPTO__DISALLOWED_IN_INSECURE_CONTEXT]: "Cryptographic operations are only allowed in secure browser contexts. Read more here: https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts.",
  [SOLANA_ERROR__SUBTLE_CRYPTO__ED25519_ALGORITHM_UNIMPLEMENTED]: `This runtime does not support the generation of Ed25519 key pairs.

Install @solana/webcrypto-ed25519-polyfill and call its \`install\` function before generating keys in environments that do not support Ed25519.

For a list of runtimes that currently support Ed25519 operations, visit https://github.com/WICG/webcrypto-secure-curves/issues/20.`,
  [SOLANA_ERROR__SUBTLE_CRYPTO__EXPORT_FUNCTION_UNIMPLEMENTED]: "No key export implementation could be found.",
  [SOLANA_ERROR__SUBTLE_CRYPTO__GENERATE_FUNCTION_UNIMPLEMENTED]: "No key generation implementation could be found.",
  [SOLANA_ERROR__SUBTLE_CRYPTO__SIGN_FUNCTION_UNIMPLEMENTED]: "No signing implementation could be found.",
  [SOLANA_ERROR__SUBTLE_CRYPTO__VERIFY_FUNCTION_UNIMPLEMENTED]: "No signature verification implementation could be found.",
  [SOLANA_ERROR__TIMESTAMP_OUT_OF_RANGE]: "Timestamp value must be in the range [-(2n ** 63n), (2n ** 63n) - 1]. `$value` given",
  [SOLANA_ERROR__TRANSACTION_ERROR__ACCOUNT_BORROW_OUTSTANDING]: "Transaction processing left an account with an outstanding borrowed reference",
  [SOLANA_ERROR__TRANSACTION_ERROR__ACCOUNT_IN_USE]: "Account in use",
  [SOLANA_ERROR__TRANSACTION_ERROR__ACCOUNT_LOADED_TWICE]: "Account loaded twice",
  [SOLANA_ERROR__TRANSACTION_ERROR__ACCOUNT_NOT_FOUND]: "Attempt to debit an account but found no record of a prior credit.",
  [SOLANA_ERROR__TRANSACTION_ERROR__ADDRESS_LOOKUP_TABLE_NOT_FOUND]: "Transaction loads an address table account that doesn't exist",
  [SOLANA_ERROR__TRANSACTION_ERROR__ALREADY_PROCESSED]: "This transaction has already been processed",
  [SOLANA_ERROR__TRANSACTION_ERROR__BLOCKHASH_NOT_FOUND]: "Blockhash not found",
  [SOLANA_ERROR__TRANSACTION_ERROR__CALL_CHAIN_TOO_DEEP]: "Loader call chain is too deep",
  [SOLANA_ERROR__TRANSACTION_ERROR__CLUSTER_MAINTENANCE]: "Transactions are currently disabled due to cluster maintenance",
  [SOLANA_ERROR__TRANSACTION_ERROR__DUPLICATE_INSTRUCTION]: "Transaction contains a duplicate instruction ($index) that is not allowed",
  [SOLANA_ERROR__TRANSACTION_ERROR__INSUFFICIENT_FUNDS_FOR_FEE]: "Insufficient funds for fee",
  [SOLANA_ERROR__TRANSACTION_ERROR__INSUFFICIENT_FUNDS_FOR_RENT]: "Transaction results in an account ($accountIndex) with insufficient funds for rent",
  [SOLANA_ERROR__TRANSACTION_ERROR__INVALID_ACCOUNT_FOR_FEE]: "This account may not be used to pay transaction fees",
  [SOLANA_ERROR__TRANSACTION_ERROR__INVALID_ACCOUNT_INDEX]: "Transaction contains an invalid account reference",
  [SOLANA_ERROR__TRANSACTION_ERROR__INVALID_ADDRESS_LOOKUP_TABLE_DATA]: "Transaction loads an address table account with invalid data",
  [SOLANA_ERROR__TRANSACTION_ERROR__INVALID_ADDRESS_LOOKUP_TABLE_INDEX]: "Transaction address table lookup uses an invalid index",
  [SOLANA_ERROR__TRANSACTION_ERROR__INVALID_ADDRESS_LOOKUP_TABLE_OWNER]: "Transaction loads an address table account with an invalid owner",
  [SOLANA_ERROR__TRANSACTION_ERROR__INVALID_LOADED_ACCOUNTS_DATA_SIZE_LIMIT]: "LoadedAccountsDataSizeLimit set for transaction must be greater than 0.",
  [SOLANA_ERROR__TRANSACTION_ERROR__INVALID_PROGRAM_FOR_EXECUTION]: "This program may not be used for executing instructions",
  [SOLANA_ERROR__TRANSACTION_ERROR__INVALID_RENT_PAYING_ACCOUNT]: "Transaction leaves an account with a lower balance than rent-exempt minimum",
  [SOLANA_ERROR__TRANSACTION_ERROR__INVALID_WRITABLE_ACCOUNT]: "Transaction loads a writable account that cannot be written",
  [SOLANA_ERROR__TRANSACTION_ERROR__MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED]: "Transaction exceeded max loaded accounts data size cap",
  [SOLANA_ERROR__TRANSACTION_ERROR__MISSING_SIGNATURE_FOR_FEE]: "Transaction requires a fee but has no signature present",
  [SOLANA_ERROR__TRANSACTION_ERROR__PROGRAM_ACCOUNT_NOT_FOUND]: "Attempt to load a program that does not exist",
  [SOLANA_ERROR__TRANSACTION_ERROR__PROGRAM_EXECUTION_TEMPORARILY_RESTRICTED]: "Execution of the program referenced by account at index $accountIndex is temporarily restricted.",
  [SOLANA_ERROR__TRANSACTION_ERROR__RESANITIZATION_NEEDED]: "ResanitizationNeeded",
  [SOLANA_ERROR__TRANSACTION_ERROR__SANITIZE_FAILURE]: "Transaction failed to sanitize accounts offsets correctly",
  [SOLANA_ERROR__TRANSACTION_ERROR__SIGNATURE_FAILURE]: "Transaction did not pass signature verification",
  [SOLANA_ERROR__TRANSACTION_ERROR__TOO_MANY_ACCOUNT_LOCKS]: "Transaction locked too many accounts",
  [SOLANA_ERROR__TRANSACTION_ERROR__UNBALANCED_TRANSACTION]: "Sum of account balances before and after transaction do not match",
  [SOLANA_ERROR__TRANSACTION_ERROR__UNKNOWN]: "The transaction failed with the error `$errorName`",
  [SOLANA_ERROR__TRANSACTION_ERROR__UNSUPPORTED_VERSION]: "Transaction version is unsupported",
  [SOLANA_ERROR__TRANSACTION_ERROR__WOULD_EXCEED_ACCOUNT_DATA_BLOCK_LIMIT]: "Transaction would exceed account data limit within the block",
  [SOLANA_ERROR__TRANSACTION_ERROR__WOULD_EXCEED_ACCOUNT_DATA_TOTAL_LIMIT]: "Transaction would exceed total account data limit",
  [SOLANA_ERROR__TRANSACTION_ERROR__WOULD_EXCEED_MAX_ACCOUNT_COST_LIMIT]: "Transaction would exceed max account limit within the block",
  [SOLANA_ERROR__TRANSACTION_ERROR__WOULD_EXCEED_MAX_BLOCK_COST_LIMIT]: "Transaction would exceed max Block Cost Limit",
  [SOLANA_ERROR__TRANSACTION_ERROR__WOULD_EXCEED_MAX_VOTE_COST_LIMIT]: "Transaction would exceed max Vote Cost Limit",
  [SOLANA_ERROR__TRANSACTION__ADDRESSES_CANNOT_SIGN_TRANSACTION]: "Attempted to sign a transaction with an address that is not a signer for it",
  [SOLANA_ERROR__TRANSACTION__ADDRESS_MISSING]: "Transaction is missing an address at index: $index.",
  [SOLANA_ERROR__TRANSACTION__CANNOT_ENCODE_WITH_EMPTY_SIGNATURES]: "Transaction has no expected signers therefore it cannot be encoded",
  [SOLANA_ERROR__TRANSACTION__EXCEEDS_SIZE_LIMIT]: "Transaction size $transactionSize exceeds limit of $transactionSizeLimit bytes",
  [SOLANA_ERROR__TRANSACTION__EXPECTED_BLOCKHASH_LIFETIME]: "Transaction does not have a blockhash lifetime",
  [SOLANA_ERROR__TRANSACTION__EXPECTED_NONCE_LIFETIME]: "Transaction is not a durable nonce transaction",
  [SOLANA_ERROR__TRANSACTION__FAILED_TO_DECOMPILE_ADDRESS_LOOKUP_TABLE_CONTENTS_MISSING]: "Contents of these address lookup tables unknown: $lookupTableAddresses",
  [SOLANA_ERROR__TRANSACTION__FAILED_TO_DECOMPILE_ADDRESS_LOOKUP_TABLE_INDEX_OUT_OF_RANGE]: "Lookup of address at index $highestRequestedIndex failed for lookup table `$lookupTableAddress`. Highest known index is $highestKnownIndex. The lookup table may have been extended since its contents were retrieved",
  [SOLANA_ERROR__TRANSACTION__FAILED_TO_DECOMPILE_FEE_PAYER_MISSING]: "No fee payer set in CompiledTransaction",
  [SOLANA_ERROR__TRANSACTION__FAILED_TO_DECOMPILE_INSTRUCTION_PROGRAM_ADDRESS_NOT_FOUND]: "Could not find program address at index $index",
  [SOLANA_ERROR__TRANSACTION__FAILED_TO_ESTIMATE_COMPUTE_LIMIT]: "Failed to estimate the compute unit consumption for this transaction message. This is likely because simulating the transaction failed. Inspect the `cause` property of this error to learn more",
  [SOLANA_ERROR__TRANSACTION__FAILED_TO_ESTIMATE_LOADED_ACCOUNTS_DATA_SIZE_LIMIT]: "Failed to estimate the loaded accounts data size for this transaction message. The RPC did not return a `loadedAccountsDataSize` value from simulation. This value is required for version 1 transactions",
  [SOLANA_ERROR__TRANSACTION__FAILED_WHEN_SIMULATING_TO_ESTIMATE_COMPUTE_LIMIT]: "Transaction failed when it was simulated in order to estimate the compute unit consumption. The compute unit estimate provided is for a transaction that failed when simulated and may not be representative of the compute units this transaction would consume if successful. Inspect the `cause` property of this error to learn more",
  [SOLANA_ERROR__TRANSACTION__FAILED_WHEN_SIMULATING_TO_ESTIMATE_RESOURCE_LIMITS]: "Transaction failed when it was simulated in order to estimate its resource limits. The resource limit estimates provided are for a transaction that failed when simulated and may not be representative of the resources this transaction would consume if successful. Inspect the `cause` property of this error to learn more",
  [SOLANA_ERROR__TRANSACTION__FEE_PAYER_MISSING]: "Transaction is missing a fee payer.",
  [SOLANA_ERROR__TRANSACTION__FEE_PAYER_SIGNATURE_MISSING]: "Could not determine this transaction's signature. Make sure that the transaction has been signed by its fee payer.",
  [SOLANA_ERROR__TRANSACTION__INVALID_NONCE_TRANSACTION_FIRST_INSTRUCTION_MUST_BE_ADVANCE_NONCE]: "Transaction first instruction is not advance nonce account instruction.",
  [SOLANA_ERROR__TRANSACTION__INVALID_NONCE_TRANSACTION_INSTRUCTIONS_MISSING]: "Transaction with no instructions cannot be durable nonce transaction.",
  [SOLANA_ERROR__TRANSACTION__INVOKED_PROGRAMS_CANNOT_PAY_FEES]: "This transaction includes an address (`$programAddress`) which is both invoked and set as the fee payer. Program addresses may not pay fees",
  [SOLANA_ERROR__TRANSACTION__INVOKED_PROGRAMS_MUST_NOT_BE_WRITABLE]: "This transaction includes an address (`$programAddress`) which is both invoked and marked writable. Program addresses may not be writable",
  [SOLANA_ERROR__TRANSACTION__MESSAGE_SIGNATURES_MISMATCH]: "The transaction message expected the transaction to have $numRequiredSignatures signatures, got $signaturesLength.",
  [SOLANA_ERROR__TRANSACTION__SIGNATURES_MISSING]: "Transaction is missing signatures for addresses: $addresses.",
  [SOLANA_ERROR__TRANSACTION__VERSION_NUMBER_OUT_OF_RANGE]: "Transaction version must be in the range [0, 127]. `$actualVersion` given",
  [SOLANA_ERROR__TRANSACTION__VERSION_NUMBER_NOT_SUPPORTED]: "This version of Kit does not support decoding transactions with version $unsupportedVersion. The current max supported version is 1.",
  [SOLANA_ERROR__TRANSACTION__NONCE_ACCOUNT_CANNOT_BE_IN_LOOKUP_TABLE]: "The transaction has a durable nonce lifetime (with nonce `$nonce`), but the nonce account address is in a lookup table. The lifetime constraint cannot be constructed without fetching the lookup tables for the transaction.",
  [SOLANA_ERROR__TRANSACTION__INVALID_CONFIG_MASK_PRIORITY_FEE_BITS]: "Invalid transaction config mask: $mask. Bits 0 and 1 must match (both set or both unset)",
  [SOLANA_ERROR__TRANSACTION__MALFORMED_MESSAGE_BYTES]: "Transaction message bytes are malformed: $messageBytes",
  [SOLANA_ERROR__TRANSACTION__CANNOT_ENCODE_WITH_EMPTY_MESSAGE_BYTES]: "Transaction message bytes are empty, so the transaction cannot be encoded",
  [SOLANA_ERROR__TRANSACTION__CANNOT_DECODE_EMPTY_TRANSACTION_BYTES]: "Transaction bytes are empty, so no transaction can be decoded",
  [SOLANA_ERROR__TRANSACTION__VERSION_ZERO_MUST_BE_ENCODED_WITH_SIGNATURES_FIRST]: "Transaction version 0 must be encoded with signatures first. This transaction was encoded with first byte $firstByte, which is expected to be a signature count for v0 transactions.",
  [SOLANA_ERROR__TRANSACTION__SIGNATURE_COUNT_TOO_HIGH_FOR_TRANSACTION_BYTES]: "The provided transaction bytes expect that there should be $numExpectedSignatures signatures, but the bytes are not long enough to contain a transaction message with this many signatures. The provided bytes are $transactionBytesLength bytes long.",
  [SOLANA_ERROR__TRANSACTION__INVALID_NONCE_ACCOUNT_INDEX]: "The transaction has a durable nonce lifetime, but the nonce account index is invalid. Expected a nonce account index less than $numberOfStaticAccounts, got $nonceAccountIndex.",
  [SOLANA_ERROR__TRANSACTION__INVALID_CONFIG_VALUE_KIND]: "The transaction config value for $configName has the incorrect kind. Expected $expectedKind, got $actualKind.",
  [SOLANA_ERROR__TRANSACTION__INSTRUCTION_HEADERS_PAYLOADS_MISMATCH]: "The transaction does not have the same number of instruction headers and instruction payloads. Got $numInstructionHeaders instruction headers, and $numInstructionPayloads instruction payloads.",
  [SOLANA_ERROR__TRANSACTION__TOO_MANY_SIGNER_ADDRESSES]: "Transaction has $actualCount unique signer addresses but the maximum allowed is $maxAllowed",
  [SOLANA_ERROR__TRANSACTION__TOO_MANY_ACCOUNT_ADDRESSES]: "Transaction has $actualCount unique account addresses but the maximum allowed is $maxAllowed",
  [SOLANA_ERROR__TRANSACTION__TOO_MANY_INSTRUCTIONS]: "Transaction has $actualCount instructions but the maximum allowed is $maxAllowed",
  [SOLANA_ERROR__TRANSACTION__TOO_MANY_ACCOUNTS_IN_INSTRUCTION]: "The instruction at index $instructionIndex has $actualCount account references but the maximum allowed is $maxAllowed",
  [SOLANA_ERROR__WALLET__NOT_CONNECTED]: "Cannot $operation: no wallet connected",
  [SOLANA_ERROR__WALLET__NO_SIGNER_CONNECTED]: "No signing wallet connected (status: $status)",
  [SOLANA_ERROR__WALLET__SIGNER_NOT_AVAILABLE]: "Connected wallet does not support signing",
  [SOLANA_ERROR__WALLET__ACCOUNT_NOT_AVAILABLE]: 'Account $address is not available in wallet "$walletName"'
};
var INSTRUCTION_ERROR_RANGE_SIZE = 1000;
var START_INDEX = "i";
var TYPE = "t";
function getHumanReadableErrorMessage(code, context = {}) {
  const messageFormatString = SolanaErrorMessages[code];
  if (messageFormatString.length === 0) {
    return "";
  }
  let state;
  function commitStateUpTo(endIndex) {
    if (state[TYPE] === 2) {
      const variableName = messageFormatString.slice(state[START_INDEX] + 1, endIndex);
      fragments.push(variableName in context ? `${context[variableName]}` : `$${variableName}`);
    } else if (state[TYPE] === 1) {
      fragments.push(messageFormatString.slice(state[START_INDEX], endIndex));
    }
  }
  const fragments = [];
  messageFormatString.split("").forEach((char, ii) => {
    if (ii === 0) {
      state = {
        [START_INDEX]: 0,
        [TYPE]: messageFormatString[0] === "\\" ? 0 : messageFormatString[0] === "$" ? 2 : 1
      };
      return;
    }
    let nextState;
    switch (state[TYPE]) {
      case 0:
        nextState = { [START_INDEX]: ii, [TYPE]: 1 };
        break;
      case 1:
        if (char === "\\") {
          nextState = { [START_INDEX]: ii, [TYPE]: 0 };
        } else if (char === "$") {
          nextState = { [START_INDEX]: ii, [TYPE]: 2 };
        }
        break;
      case 2:
        if (char === "\\") {
          nextState = { [START_INDEX]: ii, [TYPE]: 0 };
        } else if (char === "$") {
          nextState = { [START_INDEX]: ii, [TYPE]: 2 };
        } else if (!char.match(/\w/)) {
          nextState = { [START_INDEX]: ii, [TYPE]: 1 };
        }
        break;
    }
    if (nextState) {
      if (state !== nextState) {
        commitStateUpTo(ii);
      }
      state = nextState;
    }
  });
  commitStateUpTo();
  let message = fragments.join("");
  if (code >= SOLANA_ERROR__INSTRUCTION_ERROR__UNKNOWN && code < SOLANA_ERROR__INSTRUCTION_ERROR__UNKNOWN + INSTRUCTION_ERROR_RANGE_SIZE && "index" in context) {
    message += ` (instruction #${context.index + 1})`;
  }
  return message;
}
function getErrorMessage(code, context = {}) {
  if (true) {
    return getHumanReadableErrorMessage(code, context);
  }
}
var SolanaError = class extends Error {
  cause = this.cause;
  context;
  constructor(...[code, contextAndErrorOptions]) {
    let context;
    let errorOptions;
    if (contextAndErrorOptions) {
      Object.entries(Object.getOwnPropertyDescriptors(contextAndErrorOptions)).forEach(([name, descriptor]) => {
        if (name === "cause") {
          errorOptions = { cause: descriptor.value };
        } else {
          if (context === undefined) {
            context = {
              __code: code
            };
          }
          Object.defineProperty(context, name, descriptor);
        }
      });
    }
    const message = getErrorMessage(code, context);
    super(message, errorOptions);
    this.context = Object.freeze(context === undefined ? {
      __code: code
    } : context);
    this.name = "SolanaError";
  }
};
function getEncodedSize(value, encoder) {
  return "fixedSize" in encoder ? encoder.fixedSize : encoder.getSizeFromValue(value);
}
function createEncoder(encoder) {
  return Object.freeze({
    ...encoder,
    encode: (value) => {
      const bytes = new Uint8Array(getEncodedSize(value, encoder));
      encoder.write(value, bytes, 0);
      return bytes;
    }
  });
}
function isFixedSize(codec) {
  return "fixedSize" in codec && typeof codec.fixedSize === "number";
}
function isVariableSize(codec) {
  return !isFixedSize(codec);
}
function fixEncoderSize(encoder, fixedBytes) {
  return createEncoder({
    fixedSize: fixedBytes,
    write: (value, bytes, offset) => {
      const variableByteArray = encoder.encode(value);
      const fixedByteArray = variableByteArray.length > fixedBytes ? variableByteArray.slice(0, fixedBytes) : variableByteArray;
      bytes.set(fixedByteArray, offset);
      return offset + fixedBytes;
    }
  });
}
function transformEncoder(encoder, unmap) {
  return createEncoder({
    ...isVariableSize(encoder) ? { ...encoder, getSizeFromValue: (value) => encoder.getSizeFromValue(unmap(value)) } : encoder,
    write: (value, bytes, offset) => encoder.write(unmap(value), bytes, offset)
  });
}
function assertValidBaseString(alphabet4, testValue, givenValue = testValue) {
  if (!testValue.match(new RegExp(`^[${alphabet4}]*$`))) {
    throw new SolanaError(SOLANA_ERROR__CODECS__INVALID_STRING_FOR_BASE, {
      alphabet: alphabet4,
      base: alphabet4.length,
      value: givenValue
    });
  }
}
var getBaseXEncoder = (alphabet4) => {
  return createEncoder({
    getSizeFromValue: (value) => {
      const [leadingZeroes, tailChars] = partitionLeadingZeroes(value, alphabet4[0]);
      if (!tailChars)
        return value.length;
      const base10Number = getBigIntFromBaseX(tailChars, alphabet4);
      return leadingZeroes.length + Math.ceil(base10Number.toString(16).length / 2);
    },
    write(value, bytes, offset) {
      assertValidBaseString(alphabet4, value);
      if (value === "")
        return offset;
      const [leadingZeroes, tailChars] = partitionLeadingZeroes(value, alphabet4[0]);
      if (!tailChars) {
        bytes.set(new Uint8Array(leadingZeroes.length).fill(0), offset);
        return offset + leadingZeroes.length;
      }
      let base10Number = getBigIntFromBaseX(tailChars, alphabet4);
      const tailBytes = [];
      while (base10Number > 0n) {
        tailBytes.unshift(Number(base10Number % 256n));
        base10Number /= 256n;
      }
      const bytesToAdd = [...Array(leadingZeroes.length).fill(0), ...tailBytes];
      bytes.set(bytesToAdd, offset);
      return offset + bytesToAdd.length;
    }
  });
};
function partitionLeadingZeroes(value, zeroCharacter) {
  const [leadingZeros, tailChars] = value.split(new RegExp(`((?!${zeroCharacter}).*)`));
  return [leadingZeros, tailChars];
}
function getBigIntFromBaseX(value, alphabet4) {
  const base = BigInt(alphabet4.length);
  let sum = 0n;
  for (const char of value) {
    sum *= base;
    sum += BigInt(alphabet4.indexOf(char));
  }
  return sum;
}
var alphabet2 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
var getBase58Encoder = () => getBaseXEncoder(alphabet2);
var e = globalThis.TextDecoder;
var o = globalThis.TextEncoder;
var memoizedBase58Encoder;
function getMemoizedBase58Encoder() {
  if (!memoizedBase58Encoder)
    memoizedBase58Encoder = getBase58Encoder();
  return memoizedBase58Encoder;
}
function assertIsAddress(putativeAddress) {
  if (putativeAddress.length < 32 || putativeAddress.length > 44) {
    throw new SolanaError(SOLANA_ERROR__ADDRESSES__STRING_LENGTH_OUT_OF_RANGE, {
      actualLength: putativeAddress.length
    });
  }
  const base58Encoder = getMemoizedBase58Encoder();
  const bytes = base58Encoder.encode(putativeAddress);
  const numBytes = bytes.byteLength;
  if (numBytes !== 32) {
    throw new SolanaError(SOLANA_ERROR__ADDRESSES__INVALID_BYTE_LENGTH, {
      actualLength: numBytes
    });
  }
}
function address(putativeAddress) {
  assertIsAddress(putativeAddress);
  return putativeAddress;
}
function getAddressEncoder() {
  return transformEncoder(fixEncoderSize(getMemoizedBase58Encoder(), 32), (putativeAddress) => address(putativeAddress));
}
var ADDRESS_ENCODER = getAddressEncoder();
var U64_SIGN_BIT = 1n << 63n;
var UTF8_ENCODER = new TextEncoder;
var ANCHOR_CPI_METHOD_NAME = "anchor:event";
var ANCHOR_CPI_METHOD_NAME_B64 = bytesToBase64(UTF8_ENCODER.encode(ANCHOR_CPI_METHOD_NAME));
var decodeJson = (input) => {
  const decoder = new TextDecoder("utf-8");
  const textBody = decoder.decode(input);
  return JSON.parse(textBody);
};
function json(responseOrFn) {
  if (typeof responseOrFn === "function") {
    return {
      result: () => json(responseOrFn().result)
    };
  }
  return decodeJson(responseOrFn.body);
}
function ok(responseOrFn) {
  if (typeof responseOrFn === "function") {
    return {
      result: () => ok(responseOrFn().result)
    };
  } else {
    return responseOrFn.statusCode >= 200 && responseOrFn.statusCode < 300;
  }
}
function sendReport(runtime, report, fn) {
  const rawReport = report.x_generatedCodeOnly_unwrap();
  const request = fn(rawReport);
  return this.sendRequest(runtime, request);
}
function sendRequesterSendReport(report, fn) {
  const rawReport = report.x_generatedCodeOnly_unwrap();
  const request = fn(rawReport);
  return this.sendRequest(request);
}
ClientCapability3.prototype.sendReport = sendReport;
SendRequester.prototype.sendReport = sendRequesterSendReport;
var network = {
  chainId: "1",
  chainSelector: {
    name: "aptos-mainnet",
    selector: 4741433654826277614n
  },
  chainFamily: "aptos",
  networkType: "mainnet"
};
var aptos_mainnet_default = network;
var network2 = {
  chainId: "16661",
  chainSelector: {
    name: "0g-mainnet",
    selector: 4426351306075016396n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var _0g_mainnet_default = network2;
var network3 = {
  chainId: "36888",
  chainSelector: {
    name: "ab-mainnet",
    selector: 4829375610284793157n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ab_mainnet_default = network3;
var network4 = {
  chainId: "2741",
  chainSelector: {
    name: "abstract-mainnet",
    selector: 3577778157919314504n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var abstract_mainnet_default = network4;
var network5 = {
  chainId: "36900",
  chainSelector: {
    name: "adi-mainnet",
    selector: 4059281736450291836n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var adi_mainnet_default = network5;
var network6 = {
  chainId: "33139",
  chainSelector: {
    name: "apechain-mainnet",
    selector: 14894068710063348487n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var apechain_mainnet_default = network6;
var network7 = {
  chainId: "5042",
  chainSelector: {
    name: "arc-mainnet",
    selector: 6370580034781731079n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var arc_mainnet_default = network7;
var network8 = {
  chainId: "463",
  chainSelector: {
    name: "areon-mainnet",
    selector: 1939936305787790600n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var areon_mainnet_default = network8;
var network9 = {
  chainId: "43114",
  chainSelector: {
    name: "avalanche-mainnet",
    selector: 6433500567565415381n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var avalanche_mainnet_default = network9;
var network10 = {
  chainId: "432204",
  chainSelector: {
    name: "avalanche-subnet-dexalot-mainnet",
    selector: 5463201557265485081n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var avalanche_subnet_dexalot_mainnet_default = network10;
var network11 = {
  chainId: "80094",
  chainSelector: {
    name: "berachain-mainnet",
    selector: 1294465214383781161n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var berachain_mainnet_default = network11;
var network12 = {
  chainId: "56",
  chainSelector: {
    name: "binance_smart_chain-mainnet",
    selector: 11344663589394136015n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var binance_smart_chain_mainnet_default = network12;
var network13 = {
  chainId: "204",
  chainSelector: {
    name: "binance_smart_chain-mainnet-opbnb-1",
    selector: 465944652040885897n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var binance_smart_chain_mainnet_opbnb_1_default = network13;
var network14 = {
  chainId: "1907",
  chainSelector: {
    name: "bitcichain-mainnet",
    selector: 4874388048629246000n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var bitcichain_mainnet_default = network14;
var network15 = {
  chainId: "200901",
  chainSelector: {
    name: "bitcoin-mainnet-bitlayer-1",
    selector: 7937294810946806131n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var bitcoin_mainnet_bitlayer_1_default = network15;
var network16 = {
  chainId: "60808",
  chainSelector: {
    name: "bitcoin-mainnet-bob-1",
    selector: 3849287863852499584n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var bitcoin_mainnet_bob_1_default = network16;
var network17 = {
  chainId: "3637",
  chainSelector: {
    name: "bitcoin-mainnet-botanix",
    selector: 4560701533377838164n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var bitcoin_mainnet_botanix_default = network17;
var network18 = {
  chainId: "223",
  chainSelector: {
    name: "bitcoin-mainnet-bsquared-1",
    selector: 5406759801798337480n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var bitcoin_mainnet_bsquared_1_default = network18;
var network19 = {
  chainId: "4200",
  chainSelector: {
    name: "bitcoin-merlin-mainnet",
    selector: 241851231317828981n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var bitcoin_merlin_mainnet_default = network19;
var network20 = {
  chainId: "964",
  chainSelector: {
    name: "bittensor-mainnet",
    selector: 2135107236357186872n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var bittensor_mainnet_default = network20;
var network21 = {
  chainId: "199",
  chainSelector: {
    name: "bittorrent_chain-mainnet",
    selector: 3776006016387883143n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var bittorrent_chain_mainnet_default = network21;
var network22 = {
  chainId: "42220",
  chainSelector: {
    name: "celo-mainnet",
    selector: 1346049177634351622n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var celo_mainnet_default = network22;
var network23 = {
  chainId: "81224",
  chainSelector: {
    name: "codex-mainnet",
    selector: 9478124434908827753n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var codex_mainnet_default = network23;
var network24 = {
  chainId: "52",
  chainSelector: {
    name: "coinex_smart_chain-mainnet",
    selector: 1761333065194157300n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var coinex_smart_chain_mainnet_default = network24;
var network25 = {
  chainId: "1030",
  chainSelector: {
    name: "conflux-mainnet",
    selector: 3358365939762719202n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var conflux_mainnet_default = network25;
var network26 = {
  chainId: "1116",
  chainSelector: {
    name: "core-mainnet",
    selector: 1224752112135636129n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var core_mainnet_default = network26;
var network27 = {
  chainId: "21000000",
  chainSelector: {
    name: "corn-mainnet",
    selector: 9043146809313071210n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var corn_mainnet_default = network27;
var network28 = {
  chainId: "102030",
  chainSelector: {
    name: "creditcoin-mainnet",
    selector: 18240105181246962294n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var creditcoin_mainnet_default = network28;
var network29 = {
  chainId: "25",
  chainSelector: {
    name: "cronos-mainnet",
    selector: 1456215246176062136n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var cronos_mainnet_default = network29;
var network30 = {
  chainId: "388",
  chainSelector: {
    name: "cronos-zkevm-mainnet",
    selector: 8788096068760390840n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var cronos_zkevm_mainnet_default = network30;
var network31 = {
  chainId: "2026041005",
  chainSelector: {
    name: "dtcc-mainnet-appchain",
    selector: 13879014182901017172n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var dtcc_mainnet_appchain_default = network31;
var network32 = {
  chainId: "3343",
  chainSelector: {
    name: "edge-mainnet",
    selector: 6325494908023253251n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var edge_mainnet_default = network32;
var network33 = {
  chainId: "1",
  chainSelector: {
    name: "ethereum-mainnet",
    selector: 5009297550715157269n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_default = network33;
var network34 = {
  chainId: "42161",
  chainSelector: {
    name: "ethereum-mainnet-arbitrum-1",
    selector: 4949039107694359620n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_arbitrum_1_default = network34;
var network35 = {
  chainId: "12324",
  chainSelector: {
    name: "ethereum-mainnet-arbitrum-1-l3x-1",
    selector: 3162193654116181371n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_arbitrum_1_l3x_1_default = network35;
var network36 = {
  chainId: "978670",
  chainSelector: {
    name: "ethereum-mainnet-arbitrum-1-treasure-1",
    selector: 1010349088906777999n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_arbitrum_1_treasure_1_default = network36;
var network37 = {
  chainId: "3776",
  chainSelector: {
    name: "ethereum-mainnet-astar-zkevm-1",
    selector: 1540201334317828111n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_astar_zkevm_1_default = network37;
var network38 = {
  chainId: "8453",
  chainSelector: {
    name: "ethereum-mainnet-base-1",
    selector: 15971525489660198786n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_base_1_default = network38;
var network39 = {
  chainId: "81457",
  chainSelector: {
    name: "ethereum-mainnet-blast-1",
    selector: 4411394078118774322n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_blast_1_default = network39;
var network40 = {
  chainId: "177",
  chainSelector: {
    name: "ethereum-mainnet-hashkey-1",
    selector: 7613811247471741961n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_hashkey_1_default = network40;
var network41 = {
  chainId: "13371",
  chainSelector: {
    name: "ethereum-mainnet-immutable-zkevm-1",
    selector: 1237925231416731909n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_immutable_zkevm_1_default = network41;
var network42 = {
  chainId: "57073",
  chainSelector: {
    name: "ethereum-mainnet-ink-1",
    selector: 3461204551265785888n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_ink_1_default = network42;
var network43 = {
  chainId: "255",
  chainSelector: {
    name: "ethereum-mainnet-kroma-1",
    selector: 3719320017875267166n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_kroma_1_default = network43;
var network44 = {
  chainId: "59144",
  chainSelector: {
    name: "ethereum-mainnet-linea-1",
    selector: 4627098889531055414n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_linea_1_default = network44;
var network45 = {
  chainId: "5000",
  chainSelector: {
    name: "ethereum-mainnet-mantle-1",
    selector: 1556008542357238666n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_mantle_1_default = network45;
var network46 = {
  chainId: "1088",
  chainSelector: {
    name: "ethereum-mainnet-metis-1",
    selector: 8805746078405598895n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_metis_1_default = network46;
var network47 = {
  chainId: "34443",
  chainSelector: {
    name: "ethereum-mainnet-mode-1",
    selector: 7264351850409363825n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_mode_1_default = network47;
var network48 = {
  chainId: "10",
  chainSelector: {
    name: "ethereum-mainnet-optimism-1",
    selector: 3734403246176062136n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_optimism_1_default = network48;
var network49 = {
  chainId: "1101",
  chainSelector: {
    name: "ethereum-mainnet-polygon-zkevm-1",
    selector: 4348158687435793198n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_polygon_zkevm_1_default = network49;
var network50 = {
  chainId: "534352",
  chainSelector: {
    name: "ethereum-mainnet-scroll-1",
    selector: 13204309965629103672n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_scroll_1_default = network50;
var network51 = {
  chainId: "167000",
  chainSelector: {
    name: "ethereum-mainnet-taiko-1",
    selector: 16468599424800719238n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_taiko_1_default = network51;
var network52 = {
  chainId: "130",
  chainSelector: {
    name: "ethereum-mainnet-unichain-1",
    selector: 1923510103922296319n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_unichain_1_default = network52;
var network53 = {
  chainId: "480",
  chainSelector: {
    name: "ethereum-mainnet-worldchain-1",
    selector: 2049429975587534727n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_worldchain_1_default = network53;
var network54 = {
  chainId: "196",
  chainSelector: {
    name: "ethereum-mainnet-xlayer-1",
    selector: 3016212468291539606n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_xlayer_1_default = network54;
var network55 = {
  chainId: "48900",
  chainSelector: {
    name: "ethereum-mainnet-zircuit-1",
    selector: 17198166215261833993n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_zircuit_1_default = network55;
var network56 = {
  chainId: "324",
  chainSelector: {
    name: "ethereum-mainnet-zksync-1",
    selector: 1562403441176082196n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ethereum_mainnet_zksync_1_default = network56;
var network57 = {
  chainId: "42793",
  chainSelector: {
    name: "etherlink-mainnet",
    selector: 13624601974233774587n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var etherlink_mainnet_default = network57;
var network58 = {
  chainId: "25327",
  chainSelector: {
    name: "everclear-mainnet",
    selector: 9723842205701363942n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var everclear_mainnet_default = network58;
var network59 = {
  chainId: "250",
  chainSelector: {
    name: "fantom-mainnet",
    selector: 3768048213127883732n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var fantom_mainnet_default = network59;
var network60 = {
  chainId: "314",
  chainSelector: {
    name: "filecoin-mainnet",
    selector: 4561443241176882990n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var filecoin_mainnet_default = network60;
var network61 = {
  chainId: "252",
  chainSelector: {
    name: "fraxtal-mainnet",
    selector: 1462016016387883143n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var fraxtal_mainnet_default = network61;
var network62 = {
  chainId: "86",
  chainSelector: {
    name: "gate-chain-mainnet",
    selector: 9688382747979139404n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var gate_chain_mainnet_default = network62;
var network63 = {
  chainId: "10088",
  chainSelector: {
    name: "gate-layer-mainnet",
    selector: 9373518659714509671n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var gate_layer_mainnet_default = network63;
var network64 = {
  chainId: "100",
  chainSelector: {
    name: "gnosis_chain-mainnet",
    selector: 465200170687744372n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var gnosis_chain_mainnet_default = network64;
var network65 = {
  chainId: "127001",
  chainSelector: {
    name: "gravity-mainnet",
    selector: 2988178761202034333n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var gravity_mainnet_default = network65;
var network66 = {
  chainId: "295",
  chainSelector: {
    name: "hedera-mainnet",
    selector: 3229138320728879060n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var hedera_mainnet_default = network66;
var network67 = {
  chainId: "43111",
  chainSelector: {
    name: "hemi-mainnet",
    selector: 1804312132722180201n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var hemi_mainnet_default = network67;
var network68 = {
  chainId: "999",
  chainSelector: {
    name: "hyperliquid-mainnet",
    selector: 2442541497099098535n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var hyperliquid_mainnet_default = network68;
var network69 = {
  chainId: "678",
  chainSelector: {
    name: "janction-mainnet",
    selector: 9107126442626377432n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var janction_mainnet_default = network69;
var network70 = {
  chainId: "5734951",
  chainSelector: {
    name: "jovay-mainnet",
    selector: 1523760397290643893n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var jovay_mainnet_default = network70;
var network71 = {
  chainId: "8217",
  chainSelector: {
    name: "kaia-mainnet",
    selector: 9813823125703490621n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var kaia_mainnet_default = network71;
var network72 = {
  chainId: "2222",
  chainSelector: {
    name: "kava-mainnet",
    selector: 7550000543357438061n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var kava_mainnet_default = network72;
var network73 = {
  chainId: "1285",
  chainSelector: {
    name: "kusama-mainnet-moonriver",
    selector: 1355020143337428062n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var kusama_mainnet_moonriver_default = network73;
var network74 = {
  chainId: "232",
  chainSelector: {
    name: "lens-mainnet",
    selector: 5608378062013572713n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var lens_mainnet_default = network74;
var network75 = {
  chainId: "1135",
  chainSelector: {
    name: "lisk-mainnet",
    selector: 15293031020466096408n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var lisk_mainnet_default = network75;
var network76 = {
  chainId: "4326",
  chainSelector: {
    name: "megaeth-mainnet",
    selector: 6093540873831549674n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var megaeth_mainnet_default = network76;
var network77 = {
  chainId: "51888",
  chainSelector: {
    name: "memento-mainnet",
    selector: 6473245816409426016n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var memento_mainnet_default = network77;
var network78 = {
  chainId: "1750",
  chainSelector: {
    name: "metal-mainnet",
    selector: 13447077090413146373n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var metal_mainnet_default = network78;
var network79 = {
  chainId: "228",
  chainSelector: {
    name: "mind-mainnet",
    selector: 11690709103138290329n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var mind_mainnet_default = network79;
var network80 = {
  chainId: "185",
  chainSelector: {
    name: "mint-mainnet",
    selector: 17164792800244661392n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var mint_mainnet_default = network80;
var network81 = {
  chainId: "143",
  chainSelector: {
    name: "monad-mainnet",
    selector: 8481857512324358265n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var monad_mainnet_default = network81;
var network82 = {
  chainId: "2818",
  chainSelector: {
    name: "morph-mainnet",
    selector: 18164309074156128038n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var morph_mainnet_default = network82;
var network83 = {
  chainId: "61900",
  chainSelector: {
    name: "mova-mainnet",
    selector: 3314641565992046393n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var mova_mainnet_default = network83;
var network84 = {
  chainId: "61901",
  chainSelector: {
    name: "mova-mainnet-2",
    selector: 4215185756725900654n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var mova_mainnet_2_default = network84;
var network85 = {
  chainId: "397",
  chainSelector: {
    name: "near-mainnet",
    selector: 2039744413822257700n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var near_mainnet_default = network85;
var network86 = {
  chainId: "259",
  chainSelector: {
    name: "neonlink-mainnet",
    selector: 8239338020728974000n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var neonlink_mainnet_default = network86;
var network87 = {
  chainId: "47763",
  chainSelector: {
    name: "neox-mainnet",
    selector: 7222032299962346917n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var neox_mainnet_default = network87;
var network88 = {
  chainId: "68414",
  chainSelector: {
    name: "nexon-mainnet-henesys",
    selector: 12657445206920369324n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var nexon_mainnet_henesys_default = network88;
var network89 = {
  chainId: "60118",
  chainSelector: {
    name: "nexon-mainnet-lith",
    selector: 15758750456714168963n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var nexon_mainnet_lith_default = network89;
var network90 = {
  chainId: "807424",
  chainSelector: {
    name: "nexon-qa",
    selector: 14632960069656270105n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var nexon_qa_default = network90;
var network91 = {
  chainId: "847799",
  chainSelector: {
    name: "nexon-stage",
    selector: 5556806327594153475n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var nexon_stage_default = network91;
var network92 = {
  chainId: "6900",
  chainSelector: {
    name: "nibiru-mainnet",
    selector: 17349189558768828726n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var nibiru_mainnet_default = network92;
var network93 = {
  chainId: "1672",
  chainSelector: {
    name: "pharos-mainnet",
    selector: 7801139999541420232n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var pharos_mainnet_default = network93;
var network94 = {
  chainId: "9745",
  chainSelector: {
    name: "plasma-mainnet",
    selector: 9335212494177455608n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var plasma_mainnet_default = network94;
var network95 = {
  chainId: "98866",
  chainSelector: {
    name: "plume-mainnet",
    selector: 17912061998839310979n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var plume_mainnet_default = network95;
var network96 = {
  chainId: "592",
  chainSelector: {
    name: "polkadot-mainnet-astar",
    selector: 6422105447186081193n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var polkadot_mainnet_astar_default = network96;
var network97 = {
  chainId: "2031",
  chainSelector: {
    name: "polkadot-mainnet-centrifuge",
    selector: 8175830712062617656n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var polkadot_mainnet_centrifuge_default = network97;
var network98 = {
  chainId: "46",
  chainSelector: {
    name: "polkadot-mainnet-darwinia",
    selector: 8866418665544333000n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var polkadot_mainnet_darwinia_default = network98;
var network99 = {
  chainId: "1284",
  chainSelector: {
    name: "polkadot-mainnet-moonbeam",
    selector: 1252863800116739621n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var polkadot_mainnet_moonbeam_default = network99;
var network100 = {
  chainId: "137",
  chainSelector: {
    name: "polygon-mainnet",
    selector: 4051577828743386545n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var polygon_mainnet_default = network100;
var network101 = {
  chainId: "747474",
  chainSelector: {
    name: "polygon-mainnet-katana",
    selector: 2459028469735686113n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var polygon_mainnet_katana_default = network101;
var network102 = {
  chainId: "4663",
  chainSelector: {
    name: "robinhood-mainnet",
    selector: 6180753054346818345n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var robinhood_mainnet_default = network102;
var network103 = {
  chainId: "2020",
  chainSelector: {
    name: "ronin-mainnet",
    selector: 6916147374840168594n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var ronin_mainnet_default = network103;
var network104 = {
  chainId: "30",
  chainSelector: {
    name: "rootstock-mainnet",
    selector: 11964252391146578476n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var rootstock_mainnet_default = network104;
var network105 = {
  chainId: "1329",
  chainSelector: {
    name: "sei-mainnet",
    selector: 9027416829622342829n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var sei_mainnet_default = network105;
var network106 = {
  chainId: "109",
  chainSelector: {
    name: "shibarium-mainnet",
    selector: 3993510008929295315n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var shibarium_mainnet_default = network106;
var network107 = {
  chainId: "1868",
  chainSelector: {
    name: "soneium-mainnet",
    selector: 12505351618335765396n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var soneium_mainnet_default = network107;
var network108 = {
  chainId: "146",
  chainSelector: {
    name: "sonic-mainnet",
    selector: 1673871237479749969n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var sonic_mainnet_default = network108;
var network109 = {
  chainId: "988",
  chainSelector: {
    name: "stable-mainnet",
    selector: 16978377838628290997n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var stable_mainnet_default = network109;
var network110 = {
  chainId: "5330",
  chainSelector: {
    name: "superseed-mainnet",
    selector: 470401360549526817n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var superseed_mainnet_default = network110;
var network111 = {
  chainId: "239",
  chainSelector: {
    name: "tac-mainnet",
    selector: 5936861837188149645n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var tac_mainnet_default = network111;
var network112 = {
  chainId: "40",
  chainSelector: {
    name: "telos-evm-mainnet",
    selector: 1477345371608778000n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var telos_evm_mainnet_default = network112;
var network113 = {
  chainId: "4217",
  chainSelector: {
    name: "tempo-mainnet",
    selector: 7281642695469137430n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var tempo_mainnet_default = network113;
var network114 = {
  chainId: "61166",
  chainSelector: {
    name: "treasure-mainnet",
    selector: 5214452172935136222n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var treasure_mainnet_default = network114;
var network115 = {
  chainId: "728126428",
  chainSelector: {
    name: "tron-mainnet-evm",
    selector: 1546563616611573946n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var tron_mainnet_evm_default = network115;
var network116 = {
  chainId: "106",
  chainSelector: {
    name: "velas-mainnet",
    selector: 374210358663784372n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var velas_mainnet_default = network116;
var network117 = {
  chainId: "1111",
  chainSelector: {
    name: "wemix-mainnet",
    selector: 5142893604156789321n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var wemix_mainnet_default = network117;
var network118 = {
  chainId: "50",
  chainSelector: {
    name: "xdc-mainnet",
    selector: 17673274061779414707n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var xdc_mainnet_default = network118;
var network119 = {
  chainId: "7000",
  chainSelector: {
    name: "zetachain-mainnet",
    selector: 10817664450262215148n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var zetachain_mainnet_default = network119;
var network120 = {
  chainId: "810180",
  chainSelector: {
    name: "zklink_nova-mainnet",
    selector: 4350319965322101699n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var zklink_nova_mainnet_default = network120;
var network121 = {
  chainId: "7777777",
  chainSelector: {
    name: "zora-mainnet",
    selector: 3555797439612589184n
  },
  chainFamily: "evm",
  networkType: "mainnet"
};
var zora_mainnet_default = network121;
var network122 = {
  chainId: "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d",
  chainSelector: {
    name: "solana-mainnet",
    selector: 124615329519749607n
  },
  chainFamily: "solana",
  networkType: "mainnet"
};
var solana_mainnet_default = network122;
var network123 = {
  chainId: "1",
  chainSelector: {
    name: "sui-mainnet",
    selector: 17529533435026248318n
  },
  chainFamily: "sui",
  networkType: "mainnet"
};
var sui_mainnet_default = network123;
var network124 = {
  chainId: "-239",
  chainSelector: {
    name: "ton-mainnet",
    selector: 16448340667252469081n
  },
  chainFamily: "ton",
  networkType: "mainnet"
};
var ton_mainnet_default = network124;
var network125 = {
  chainId: "728126428",
  chainSelector: {
    name: "tron-mainnet",
    selector: 1546563616611573945n
  },
  chainFamily: "tron",
  networkType: "mainnet"
};
var tron_mainnet_default = network125;
var network126 = {
  chainId: "4",
  chainSelector: {
    name: "aptos-localnet",
    selector: 4457093679053095497n
  },
  chainFamily: "aptos",
  networkType: "testnet"
};
var aptos_localnet_default = network126;
var network127 = {
  chainId: "2",
  chainSelector: {
    name: "aptos-testnet",
    selector: 743186221051783445n
  },
  chainFamily: "aptos",
  networkType: "testnet"
};
var aptos_testnet_default = network127;
var network128 = {
  chainId: "16601",
  chainSelector: {
    name: "0g-testnet-galileo",
    selector: 2131427466778448014n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var _0g_testnet_galileo_default = network128;
var network129 = {
  chainId: "16602",
  chainSelector: {
    name: "0g-testnet-galileo-1",
    selector: 6892437333620424805n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var _0g_testnet_galileo_1_default = network129;
var network130 = {
  chainId: "16600",
  chainSelector: {
    name: "0g-testnet-newton",
    selector: 16088006396410204581n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var _0g_testnet_newton_default = network130;
var network131 = {
  chainId: "26888",
  chainSelector: {
    name: "ab-testnet",
    selector: 7051849327615092843n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ab_testnet_default = network131;
var network132 = {
  chainId: "11124",
  chainSelector: {
    name: "abstract-testnet",
    selector: 16235373811196386733n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var abstract_testnet_default = network132;
var network133 = {
  chainId: "99999",
  chainSelector: {
    name: "adi-testnet",
    selector: 9418205736192840573n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var adi_testnet_default = network133;
var network134 = {
  chainId: "31337",
  chainSelector: {
    name: "anvil-devnet",
    selector: 7759470850252068959n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var anvil_devnet_default = network134;
var network135 = {
  chainId: "33111",
  chainSelector: {
    name: "apechain-testnet-curtis",
    selector: 9900119385908781505n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var apechain_testnet_curtis_default = network135;
var network136 = {
  chainId: "5042002",
  chainSelector: {
    name: "arc-testnet",
    selector: 3034092155422581607n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var arc_testnet_default = network136;
var network137 = {
  chainId: "462",
  chainSelector: {
    name: "areon-testnet",
    selector: 7317911323415911000n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var areon_testnet_default = network137;
var network138 = {
  chainId: "432201",
  chainSelector: {
    name: "avalanche-subnet-dexalot-testnet",
    selector: 1458281248224512906n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var avalanche_subnet_dexalot_testnet_default = network138;
var network139 = {
  chainId: "43113",
  chainSelector: {
    name: "avalanche-testnet-fuji",
    selector: 14767482510784806043n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var avalanche_testnet_fuji_default = network139;
var network140 = {
  chainId: "595581",
  chainSelector: {
    name: "avalanche-testnet-nexon",
    selector: 7837562506228496256n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var avalanche_testnet_nexon_default = network140;
var network141 = {
  chainId: "80085",
  chainSelector: {
    name: "berachain-testnet-artio",
    selector: 12336603543561911511n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var berachain_testnet_artio_default = network141;
var network142 = {
  chainId: "80084",
  chainSelector: {
    name: "berachain-testnet-bartio",
    selector: 8999465244383784164n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var berachain_testnet_bartio_default = network142;
var network143 = {
  chainId: "80069",
  chainSelector: {
    name: "berachain-testnet-bepolia",
    selector: 7728255861635209484n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var berachain_testnet_bepolia_default = network143;
var network144 = {
  chainId: "97",
  chainSelector: {
    name: "binance_smart_chain-testnet",
    selector: 13264668187771770619n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var binance_smart_chain_testnet_default = network144;
var network145 = {
  chainId: "5611",
  chainSelector: {
    name: "binance_smart_chain-testnet-opbnb-1",
    selector: 13274425992935471758n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var binance_smart_chain_testnet_opbnb_1_default = network145;
var network146 = {
  chainId: "1908",
  chainSelector: {
    name: "bitcichain-testnet",
    selector: 4888058894222120000n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var bitcichain_testnet_default = network146;
var network147 = {
  chainId: "200810",
  chainSelector: {
    name: "bitcoin-testnet-bitlayer-1",
    selector: 3789623672476206327n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var bitcoin_testnet_bitlayer_1_default = network147;
var network148 = {
  chainId: "3636",
  chainSelector: {
    name: "bitcoin-testnet-botanix",
    selector: 1467223411771711614n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var bitcoin_testnet_botanix_default = network148;
var network149 = {
  chainId: "1123",
  chainSelector: {
    name: "bitcoin-testnet-bsquared-1",
    selector: 1948510578179542068n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var bitcoin_testnet_bsquared_1_default = network149;
var network150 = {
  chainId: "686868",
  chainSelector: {
    name: "bitcoin-testnet-merlin",
    selector: 5269261765892944301n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var bitcoin_testnet_merlin_default = network150;
var network151 = {
  chainId: "31",
  chainSelector: {
    name: "bitcoin-testnet-rootstock",
    selector: 8953668971247136127n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var bitcoin_testnet_rootstock_default = network151;
var network152 = {
  chainId: "808813",
  chainSelector: {
    name: "bitcoin-testnet-sepolia-bob-1",
    selector: 5535534526963509396n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var bitcoin_testnet_sepolia_bob_1_default = network152;
var network153 = {
  chainId: "945",
  chainSelector: {
    name: "bittensor-testnet",
    selector: 2177900824115119161n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var bittensor_testnet_default = network153;
var network154 = {
  chainId: "1029",
  chainSelector: {
    name: "bittorrent_chain-testnet",
    selector: 4459371029167934217n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var bittorrent_chain_testnet_default = network154;
var network155 = {
  chainId: "11142220",
  chainSelector: {
    name: "celo-sepolia",
    selector: 3761762704474186180n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var celo_sepolia_default = network155;
var network156 = {
  chainId: "44787",
  chainSelector: {
    name: "celo-testnet-alfajores",
    selector: 3552045678561919002n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var celo_testnet_alfajores_default = network156;
var network157 = {
  chainId: "812242",
  chainSelector: {
    name: "codex-testnet",
    selector: 7225665875429174318n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var codex_testnet_default = network157;
var network158 = {
  chainId: "53",
  chainSelector: {
    name: "coinex_smart_chain-testnet",
    selector: 8955032871639343000n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var coinex_smart_chain_testnet_default = network158;
var network159 = {
  chainId: "1114",
  chainSelector: {
    name: "core-testnet",
    selector: 4264732132125536123n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var core_testnet_default = network159;
var network160 = {
  chainId: "102031",
  chainSelector: {
    name: "creditcoin-testnet",
    selector: 16960985330067274105n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var creditcoin_testnet_default = network160;
var network161 = {
  chainId: "338",
  chainSelector: {
    name: "cronos-testnet",
    selector: 2995292832068775165n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var cronos_testnet_default = network161;
var network162 = {
  chainId: "282",
  chainSelector: {
    name: "cronos-testnet-zkevm-1",
    selector: 3842103497652714138n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var cronos_testnet_zkevm_1_default = network162;
var network163 = {
  chainId: "240",
  chainSelector: {
    name: "cronos-zkevm-testnet-sepolia",
    selector: 16487132492576884721n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var cronos_zkevm_testnet_sepolia_default = network163;
var network164 = {
  chainId: "6281971",
  chainSelector: {
    name: "dogeos-testnet-chikyu",
    selector: 7254999290874773717n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var dogeos_testnet_chikyu_default = network164;
var network165 = {
  chainId: "2025",
  chainSelector: {
    name: "dtcc-testnet-andesite",
    selector: 15513093881969820114n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var dtcc_testnet_andesite_default = network165;
var network166 = {
  chainId: "33431",
  chainSelector: {
    name: "edge-testnet",
    selector: 13222148116102326311n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var edge_testnet_default = network166;
var network167 = {
  chainId: "421613",
  chainSelector: {
    name: "ethereum-testnet-goerli-arbitrum-1",
    selector: 6101244977088475029n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_goerli_arbitrum_1_default = network167;
var network168 = {
  chainId: "84531",
  chainSelector: {
    name: "ethereum-testnet-goerli-base-1",
    selector: 5790810961207155433n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_goerli_base_1_default = network168;
var network169 = {
  chainId: "59140",
  chainSelector: {
    name: "ethereum-testnet-goerli-linea-1",
    selector: 1355246678561316402n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_goerli_linea_1_default = network169;
var network170 = {
  chainId: "5001",
  chainSelector: {
    name: "ethereum-testnet-goerli-mantle-1",
    selector: 4168263376276232250n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_goerli_mantle_1_default = network170;
var network171 = {
  chainId: "420",
  chainSelector: {
    name: "ethereum-testnet-goerli-optimism-1",
    selector: 2664363617261496610n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_goerli_optimism_1_default = network171;
var network172 = {
  chainId: "1442",
  chainSelector: {
    name: "ethereum-testnet-goerli-polygon-zkevm-1",
    selector: 11059667695644972511n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_goerli_polygon_zkevm_1_default = network172;
var network173 = {
  chainId: "280",
  chainSelector: {
    name: "ethereum-testnet-goerli-zksync-1",
    selector: 6802309497652714138n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_goerli_zksync_1_default = network173;
var network174 = {
  chainId: "17000",
  chainSelector: {
    name: "ethereum-testnet-holesky",
    selector: 7717148896336251131n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_holesky_default = network174;
var network175 = {
  chainId: "2522",
  chainSelector: {
    name: "ethereum-testnet-holesky-fraxtal-1",
    selector: 8901520481741771655n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_holesky_fraxtal_1_default = network175;
var network176 = {
  chainId: "2810",
  chainSelector: {
    name: "ethereum-testnet-holesky-morph-1",
    selector: 8304510386741731151n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_holesky_morph_1_default = network176;
var network177 = {
  chainId: "167009",
  chainSelector: {
    name: "ethereum-testnet-holesky-taiko-1",
    selector: 7248756420937879088n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_holesky_taiko_1_default = network177;
var network178 = {
  chainId: "560048",
  chainSelector: {
    name: "ethereum-testnet-hoodi",
    selector: 10380998176179737091n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_hoodi_default = network178;
var network179 = {
  chainId: "2910",
  chainSelector: {
    name: "ethereum-testnet-hoodi-morph",
    selector: 1064004874793747259n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_hoodi_morph_default = network179;
var network180 = {
  chainId: "167012",
  chainSelector: {
    name: "ethereum-testnet-hoodi-taiko",
    selector: 9873759436596923887n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_hoodi_taiko_default = network180;
var network181 = {
  chainId: "167013",
  chainSelector: {
    name: "ethereum-testnet-hoodi-taiko-1",
    selector: 15858691699034549072n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_hoodi_taiko_1_default = network181;
var network182 = {
  chainId: "7091047534",
  chainSelector: {
    name: "ethereum-testnet-plataberget",
    selector: 12540949017250913122n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_plataberget_default = network182;
var network183 = {
  chainId: "11155111",
  chainSelector: {
    name: "ethereum-testnet-sepolia",
    selector: 16015286601757825753n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_default = network183;
var network184 = {
  chainId: "421614",
  chainSelector: {
    name: "ethereum-testnet-sepolia-arbitrum-1",
    selector: 3478487238524512106n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_arbitrum_1_default = network184;
var network185 = {
  chainId: "12325",
  chainSelector: {
    name: "ethereum-testnet-sepolia-arbitrum-1-l3x-1",
    selector: 3486622437121596122n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_arbitrum_1_l3x_1_default = network185;
var network186 = {
  chainId: "978657",
  chainSelector: {
    name: "ethereum-testnet-sepolia-arbitrum-1-treasure-1",
    selector: 10443705513486043421n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_arbitrum_1_treasure_1_default = network186;
var network187 = {
  chainId: "84532",
  chainSelector: {
    name: "ethereum-testnet-sepolia-base-1",
    selector: 10344971235874465080n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_base_1_default = network187;
var network188 = {
  chainId: "168587773",
  chainSelector: {
    name: "ethereum-testnet-sepolia-blast-1",
    selector: 2027362563942762617n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_blast_1_default = network188;
var network189 = {
  chainId: "21000001",
  chainSelector: {
    name: "ethereum-testnet-sepolia-corn-1",
    selector: 1467427327723633929n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_corn_1_default = network189;
var network190 = {
  chainId: "133",
  chainSelector: {
    name: "ethereum-testnet-sepolia-hashkey-1",
    selector: 4356164186791070119n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_hashkey_1_default = network190;
var network191 = {
  chainId: "13473",
  chainSelector: {
    name: "ethereum-testnet-sepolia-immutable-zkevm-1",
    selector: 4526165231216331901n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_immutable_zkevm_1_default = network191;
var network192 = {
  chainId: "2358",
  chainSelector: {
    name: "ethereum-testnet-sepolia-kroma-1",
    selector: 5990477251245693094n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_kroma_1_default = network192;
var network193 = {
  chainId: "37111",
  chainSelector: {
    name: "ethereum-testnet-sepolia-lens-1",
    selector: 6827576821754315911n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_lens_1_default = network193;
var network194 = {
  chainId: "59141",
  chainSelector: {
    name: "ethereum-testnet-sepolia-linea-1",
    selector: 5719461335882077547n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_linea_1_default = network194;
var network195 = {
  chainId: "4202",
  chainSelector: {
    name: "ethereum-testnet-sepolia-lisk-1",
    selector: 5298399861320400553n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_lisk_1_default = network195;
var network196 = {
  chainId: "5003",
  chainSelector: {
    name: "ethereum-testnet-sepolia-mantle-1",
    selector: 8236463271206331221n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_mantle_1_default = network196;
var network197 = {
  chainId: "59902",
  chainSelector: {
    name: "ethereum-testnet-sepolia-metis-1",
    selector: 3777822886988675105n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_metis_1_default = network197;
var network198 = {
  chainId: "919",
  chainSelector: {
    name: "ethereum-testnet-sepolia-mode-1",
    selector: 829525985033418733n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_mode_1_default = network198;
var network199 = {
  chainId: "11155420",
  chainSelector: {
    name: "ethereum-testnet-sepolia-optimism-1",
    selector: 5224473277236331295n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_optimism_1_default = network199;
var network200 = {
  chainId: "717160",
  chainSelector: {
    name: "ethereum-testnet-sepolia-polygon-validium-1",
    selector: 4418231248214522936n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_polygon_validium_1_default = network200;
var network201 = {
  chainId: "2442",
  chainSelector: {
    name: "ethereum-testnet-sepolia-polygon-zkevm-1",
    selector: 1654667687261492630n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_polygon_zkevm_1_default = network201;
var network202 = {
  chainId: "202601",
  chainSelector: {
    name: "ethereum-testnet-sepolia-ronin-1",
    selector: 1091131740251125869n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_ronin_1_default = network202;
var network203 = {
  chainId: "534351",
  chainSelector: {
    name: "ethereum-testnet-sepolia-scroll-1",
    selector: 2279865765895943307n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_scroll_1_default = network203;
var network204 = {
  chainId: "1946",
  chainSelector: {
    name: "ethereum-testnet-sepolia-soneium-1",
    selector: 686603546605904534n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_soneium_1_default = network204;
var network205 = {
  chainId: "1301",
  chainSelector: {
    name: "ethereum-testnet-sepolia-unichain-1",
    selector: 14135854469784514356n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_unichain_1_default = network205;
var network206 = {
  chainId: "4801",
  chainSelector: {
    name: "ethereum-testnet-sepolia-worldchain-1",
    selector: 5299555114858065850n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_worldchain_1_default = network206;
var network207 = {
  chainId: "195",
  chainSelector: {
    name: "ethereum-testnet-sepolia-xlayer-1",
    selector: 2066098519157881736n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_xlayer_1_default = network207;
var network208 = {
  chainId: "48899",
  chainSelector: {
    name: "ethereum-testnet-sepolia-zircuit-1",
    selector: 4562743618362911021n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_zircuit_1_default = network208;
var network209 = {
  chainId: "300",
  chainSelector: {
    name: "ethereum-testnet-sepolia-zksync-1",
    selector: 6898391096552792247n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ethereum_testnet_sepolia_zksync_1_default = network209;
var network210 = {
  chainId: "128123",
  chainSelector: {
    name: "etherlink-testnet",
    selector: 1910019406958449359n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var etherlink_testnet_default = network210;
var network211 = {
  chainId: "6398",
  chainSelector: {
    name: "everclear-testnet-sepolia",
    selector: 379340054879810246n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var everclear_testnet_sepolia_default = network211;
var network212 = {
  chainId: "4002",
  chainSelector: {
    name: "fantom-testnet",
    selector: 4905564228793744293n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var fantom_testnet_default = network212;
var network213 = {
  chainId: "31415926",
  chainSelector: {
    name: "filecoin-testnet",
    selector: 7060342227814389000n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var filecoin_testnet_default = network213;
var network214 = {
  chainId: "85",
  chainSelector: {
    name: "gate-chain-testnet-meteora",
    selector: 3558960680482140165n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var gate_chain_testnet_meteora_default = network214;
var network215 = {
  chainId: "10087",
  chainSelector: {
    name: "gate-layer-testnet",
    selector: 3667207123485082040n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var gate_layer_testnet_default = network215;
var network216 = {
  chainId: "1337",
  chainSelector: {
    name: "geth-testnet",
    selector: 3379446385462418246n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var geth_testnet_default = network216;
var network217 = {
  chainId: "7095321190",
  chainSelector: {
    name: "glamsterdam-devnet-5",
    selector: 10073034426865795585n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var glamsterdam_devnet_5_default = network217;
var network218 = {
  chainId: "7052886157",
  chainSelector: {
    name: "glamsterdam-devnet-6",
    selector: 410896468069059699n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var glamsterdam_devnet_6_default = network218;
var network219 = {
  chainId: "10200",
  chainSelector: {
    name: "gnosis_chain-testnet-chiado",
    selector: 8871595565390010547n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var gnosis_chain_testnet_chiado_default = network219;
var network220 = {
  chainId: "7771625",
  chainSelector: {
    name: "gravity-testnet-longevity",
    selector: 9181335567442030426n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var gravity_testnet_longevity_default = network220;
var network221 = {
  chainId: "296",
  chainSelector: {
    name: "hedera-testnet",
    selector: 222782988166878823n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var hedera_testnet_default = network221;
var network222 = {
  chainId: "743111",
  chainSelector: {
    name: "hemi-testnet-sepolia",
    selector: 16126893759944359622n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var hemi_testnet_sepolia_default = network222;
var network223 = {
  chainId: "998",
  chainSelector: {
    name: "hyperliquid-testnet",
    selector: 4286062357653186312n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var hyperliquid_testnet_default = network223;
var network224 = {
  chainId: "763373",
  chainSelector: {
    name: "ink-testnet-sepolia",
    selector: 9763904284804119144n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ink_testnet_sepolia_default = network224;
var network225 = {
  chainId: "679",
  chainSelector: {
    name: "janction-testnet-sepolia",
    selector: 5059197667603797935n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var janction_testnet_sepolia_default = network225;
var network226 = {
  chainId: "2019775",
  chainSelector: {
    name: "jovay-testnet",
    selector: 945045181441419236n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var jovay_testnet_default = network226;
var network227 = {
  chainId: "1001",
  chainSelector: {
    name: "kaia-testnet-kairos",
    selector: 2624132734533621656n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var kaia_testnet_kairos_default = network227;
var network228 = {
  chainId: "2221",
  chainSelector: {
    name: "kava-testnet",
    selector: 2110537777356199208n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var kava_testnet_default = network228;
var network229 = {
  chainId: "6342",
  chainSelector: {
    name: "megaeth-testnet",
    selector: 2443239559770384419n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var megaeth_testnet_default = network229;
var network230 = {
  chainId: "6343",
  chainSelector: {
    name: "megaeth-testnet-2",
    selector: 18241817625092392675n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var megaeth_testnet_2_default = network230;
var network231 = {
  chainId: "2129",
  chainSelector: {
    name: "memento-testnet",
    selector: 12168171414969487009n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var memento_testnet_default = network231;
var network232 = {
  chainId: "1740",
  chainSelector: {
    name: "metal-testnet",
    selector: 6286293440461807648n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var metal_testnet_default = network232;
var network233 = {
  chainId: "192940",
  chainSelector: {
    name: "mind-testnet",
    selector: 7189150270347329685n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var mind_testnet_default = network233;
var network234 = {
  chainId: "1687",
  chainSelector: {
    name: "mint-testnet",
    selector: 10749384167430721561n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var mint_testnet_default = network234;
var network235 = {
  chainId: "10143",
  chainSelector: {
    name: "monad-testnet",
    selector: 2183018362218727504n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var monad_testnet_default = network235;
var network236 = {
  chainId: "10323",
  chainSelector: {
    name: "mova-testnet",
    selector: 9211758560309513668n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var mova_testnet_default = network236;
var network237 = {
  chainId: "398",
  chainSelector: {
    name: "near-testnet",
    selector: 5061593697262339000n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var near_testnet_default = network237;
var network238 = {
  chainId: "9559",
  chainSelector: {
    name: "neonlink-testnet",
    selector: 1113014352258747600n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var neonlink_testnet_default = network238;
var network239 = {
  chainId: "12227332",
  chainSelector: {
    name: "neox-testnet-t4",
    selector: 2217764097022649312n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var neox_testnet_t4_default = network239;
var network240 = {
  chainId: "5668",
  chainSelector: {
    name: "nexon-dev",
    selector: 8911150974185440581n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var nexon_dev_default = network240;
var network241 = {
  chainId: "6930",
  chainSelector: {
    name: "nibiru-testnet",
    selector: 305104239123120457n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var nibiru_testnet_default = network241;
var network242 = {
  chainId: "9000",
  chainSelector: {
    name: "ondo-testnet",
    selector: 344208382356656551n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ondo_testnet_default = network242;
var network243 = {
  chainId: "688689",
  chainSelector: {
    name: "pharos-atlantic-testnet",
    selector: 16098325658947243212n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var pharos_atlantic_testnet_default = network243;
var network244 = {
  chainId: "688688",
  chainSelector: {
    name: "pharos-testnet",
    selector: 4012524741200567430n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var pharos_testnet_default = network244;
var network245 = {
  chainId: "9746",
  chainSelector: {
    name: "plasma-testnet",
    selector: 3967220077692964309n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var plasma_testnet_default = network245;
var network246 = {
  chainId: "98864",
  chainSelector: {
    name: "plume-devnet",
    selector: 3743020999916460931n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var plume_devnet_default = network246;
var network247 = {
  chainId: "161221135",
  chainSelector: {
    name: "plume-testnet",
    selector: 14684575664602284776n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var plume_testnet_default = network247;
var network248 = {
  chainId: "98867",
  chainSelector: {
    name: "plume-testnet-sepolia",
    selector: 13874588925447303949n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var plume_testnet_sepolia_default = network248;
var network249 = {
  chainId: "81",
  chainSelector: {
    name: "polkadot-testnet-astar-shibuya",
    selector: 6955638871347136141n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var polkadot_testnet_astar_shibuya_default = network249;
var network250 = {
  chainId: "2088",
  chainSelector: {
    name: "polkadot-testnet-centrifuge-altair",
    selector: 2333097300889804761n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var polkadot_testnet_centrifuge_altair_default = network250;
var network251 = {
  chainId: "45",
  chainSelector: {
    name: "polkadot-testnet-darwinia-pangoro",
    selector: 4340886533089894000n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var polkadot_testnet_darwinia_pangoro_default = network251;
var network252 = {
  chainId: "1287",
  chainSelector: {
    name: "polkadot-testnet-moonbeam-moonbase",
    selector: 5361632739113536121n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var polkadot_testnet_moonbeam_moonbase_default = network252;
var network253 = {
  chainId: "80002",
  chainSelector: {
    name: "polygon-testnet-amoy",
    selector: 16281711391670634445n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var polygon_testnet_amoy_default = network253;
var network254 = {
  chainId: "80001",
  chainSelector: {
    name: "polygon-testnet-mumbai",
    selector: 12532609583862916517n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var polygon_testnet_mumbai_default = network254;
var network255 = {
  chainId: "129399",
  chainSelector: {
    name: "polygon-testnet-tatara",
    selector: 9090863410735740267n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var polygon_testnet_tatara_default = network255;
var network256 = {
  chainId: "2024",
  chainSelector: {
    name: "private-testnet-andesite",
    selector: 6915682381028791124n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var private_testnet_andesite_default = network256;
var network257 = {
  chainId: "4103882950",
  chainSelector: {
    name: "private-testnet-basalt",
    selector: 18362000170840307455n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var private_testnet_basalt_default = network257;
var network258 = {
  chainId: "2023",
  chainSelector: {
    name: "private-testnet-granite",
    selector: 3260900564719373474n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var private_testnet_granite_default = network258;
var network259 = {
  chainId: "424242",
  chainSelector: {
    name: "private-testnet-mica",
    selector: 4489326297382772450n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var private_testnet_mica_default = network259;
var network260 = {
  chainId: "682",
  chainSelector: {
    name: "private-testnet-obsidian",
    selector: 6260932437388305511n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var private_testnet_obsidian_default = network260;
var network261 = {
  chainId: "45439",
  chainSelector: {
    name: "private-testnet-opala",
    selector: 8446413392851542429n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var private_testnet_opala_default = network261;
var network262 = {
  chainId: "2026041004",
  chainSelector: {
    name: "private-testnet-pumice",
    selector: 1564738277398880633n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var private_testnet_pumice_default = network262;
var network263 = {
  chainId: "2026041002",
  chainSelector: {
    name: "private-testnet-quartzite",
    selector: 4175996748267305081n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var private_testnet_quartzite_default = network263;
var network264 = {
  chainId: "2026041003",
  chainSelector: {
    name: "private-testnet-rhyolite",
    selector: 604447335222770945n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var private_testnet_rhyolite_default = network264;
var network265 = {
  chainId: "46630",
  chainSelector: {
    name: "robinhood-testnet",
    selector: 2032988798112970440n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var robinhood_testnet_default = network265;
var network266 = {
  chainId: "2021",
  chainSelector: {
    name: "ronin-testnet-saigon",
    selector: 13116810400804392105n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var ronin_testnet_saigon_default = network266;
var network267 = {
  chainId: "1328",
  chainSelector: {
    name: "sei-testnet-atlantic",
    selector: 1216300075444106652n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var sei_testnet_atlantic_default = network267;
var network268 = {
  chainId: "157",
  chainSelector: {
    name: "shibarium-testnet-puppynet",
    selector: 17833296867764334567n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var shibarium_testnet_puppynet_default = network268;
var network269 = {
  chainId: "14601",
  chainSelector: {
    name: "sonic-testnet",
    selector: 1763698235108410440n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var sonic_testnet_default = network269;
var network270 = {
  chainId: "57054",
  chainSelector: {
    name: "sonic-testnet-blaze",
    selector: 3676871237479449268n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var sonic_testnet_blaze_default = network270;
var network271 = {
  chainId: "2201",
  chainSelector: {
    name: "stable-testnet",
    selector: 11793402411494852765n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var stable_testnet_default = network271;
var network272 = {
  chainId: "1513",
  chainSelector: {
    name: "story-testnet",
    selector: 4237030917318060427n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var story_testnet_default = network272;
var network273 = {
  chainId: "53302",
  chainSelector: {
    name: "superseed-testnet",
    selector: 13694007683517087973n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var superseed_testnet_default = network273;
var network274 = {
  chainId: "364301",
  chainSelector: {
    name: "t-rex-testnet",
    selector: 17611928792452358269n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var t_rex_testnet_default = network274;
var network275 = {
  chainId: "2391",
  chainSelector: {
    name: "tac-testnet",
    selector: 9488606126177218005n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var tac_testnet_default = network275;
var network276 = {
  chainId: "41",
  chainSelector: {
    name: "telos-evm-testnet",
    selector: 729797994450396300n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var telos_evm_testnet_default = network276;
var network277 = {
  chainId: "42429",
  chainSelector: {
    name: "tempo-testnet",
    selector: 3963528237232804922n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var tempo_testnet_default = network277;
var network278 = {
  chainId: "42431",
  chainSelector: {
    name: "tempo-testnet-moderato",
    selector: 8457817439310187923n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var tempo_testnet_moderato_default = network278;
var network279 = {
  chainId: "978658",
  chainSelector: {
    name: "treasure-testnet-topaz",
    selector: 3676916124122457866n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var treasure_testnet_topaz_default = network279;
var network280 = {
  chainId: "3360022319",
  chainSelector: {
    name: "tron-devnet-evm",
    selector: 13231703482326770600n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var tron_devnet_evm_default = network280;
var network281 = {
  chainId: "3448148188",
  chainSelector: {
    name: "tron-testnet-nile-evm",
    selector: 2052925811360307749n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var tron_testnet_nile_evm_default = network281;
var network282 = {
  chainId: "2494104990",
  chainSelector: {
    name: "tron-testnet-shasta-evm",
    selector: 13231703482326770598n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var tron_testnet_shasta_evm_default = network282;
var network283 = {
  chainId: "111",
  chainSelector: {
    name: "velas-testnet",
    selector: 572210378683744374n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var velas_testnet_default = network283;
var network284 = {
  chainId: "1112",
  chainSelector: {
    name: "wemix-testnet",
    selector: 9284632837123596123n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var wemix_testnet_default = network284;
var network285 = {
  chainId: "51",
  chainSelector: {
    name: "xdc-testnet",
    selector: 3017758115101368649n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var xdc_testnet_default = network285;
var network286 = {
  chainId: "1952",
  chainSelector: {
    name: "xlayer-testnet",
    selector: 10212741611335999305n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var xlayer_testnet_default = network286;
var network287 = {
  chainId: "80087",
  chainSelector: {
    name: "zero-g-testnet-galileo",
    selector: 2285225387454015855n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var zero_g_testnet_galileo_default = network287;
var network288 = {
  chainId: "48898",
  chainSelector: {
    name: "zircuit-testnet-garfield",
    selector: 13781831279385219069n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var zircuit_testnet_garfield_default = network288;
var network289 = {
  chainId: "810181",
  chainSelector: {
    name: "zklink_nova-testnet",
    selector: 5837261596322416298n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var zklink_nova_testnet_default = network289;
var network290 = {
  chainId: "999999999",
  chainSelector: {
    name: "zora-testnet",
    selector: 16244020411108056671n
  },
  chainFamily: "evm",
  networkType: "testnet"
};
var zora_testnet_default = network290;
var network291 = {
  chainId: "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
  chainSelector: {
    name: "solana-devnet",
    selector: 16423721717087811551n
  },
  chainFamily: "solana",
  networkType: "testnet"
};
var solana_devnet_default = network291;
var network292 = {
  chainId: "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY",
  chainSelector: {
    name: "solana-testnet",
    selector: 6302590918974934319n
  },
  chainFamily: "solana",
  networkType: "testnet"
};
var solana_testnet_default = network292;
var network293 = {
  chainId: "4",
  chainSelector: {
    name: "sui-localnet",
    selector: 18395503381733958356n
  },
  chainFamily: "sui",
  networkType: "testnet"
};
var sui_localnet_default = network293;
var network294 = {
  chainId: "2",
  chainSelector: {
    name: "sui-testnet",
    selector: 9762610643973837292n
  },
  chainFamily: "sui",
  networkType: "testnet"
};
var sui_testnet_default = network294;
var network295 = {
  chainId: "-217",
  chainSelector: {
    name: "ton-localnet",
    selector: 13879075125137744094n
  },
  chainFamily: "ton",
  networkType: "testnet"
};
var ton_localnet_default = network295;
var network296 = {
  chainId: "-3",
  chainSelector: {
    name: "ton-testnet",
    selector: 1399300952838017768n
  },
  chainFamily: "ton",
  networkType: "testnet"
};
var ton_testnet_default = network296;
var network297 = {
  chainId: "3360022319",
  chainSelector: {
    name: "tron-devnet",
    selector: 13231703482326770599n
  },
  chainFamily: "tron",
  networkType: "testnet"
};
var tron_devnet_default = network297;
var network298 = {
  chainId: "3448148188",
  chainSelector: {
    name: "tron-testnet-nile",
    selector: 2052925811360307740n
  },
  chainFamily: "tron",
  networkType: "testnet"
};
var tron_testnet_nile_default = network298;
var network299 = {
  chainId: "2494104990",
  chainSelector: {
    name: "tron-testnet-shasta",
    selector: 13231703482326770597n
  },
  chainFamily: "tron",
  networkType: "testnet"
};
var tron_testnet_shasta_default = network299;
var mainnetBySelector = new Map([
  [5009297550715157269n, ethereum_mainnet_default],
  [3734403246176062136n, ethereum_mainnet_optimism_1_default],
  [1456215246176062136n, cronos_mainnet_default],
  [11964252391146578476n, rootstock_mainnet_default],
  [1477345371608778000n, telos_evm_mainnet_default],
  [8866418665544333000n, polkadot_mainnet_darwinia_default],
  [17673274061779414707n, xdc_mainnet_default],
  [1761333065194157300n, coinex_smart_chain_mainnet_default],
  [11344663589394136015n, binance_smart_chain_mainnet_default],
  [9688382747979139404n, gate_chain_mainnet_default],
  [465200170687744372n, gnosis_chain_mainnet_default],
  [374210358663784372n, velas_mainnet_default],
  [3993510008929295315n, shibarium_mainnet_default],
  [1923510103922296319n, ethereum_mainnet_unichain_1_default],
  [4051577828743386545n, polygon_mainnet_default],
  [8481857512324358265n, monad_mainnet_default],
  [1673871237479749969n, sonic_mainnet_default],
  [7613811247471741961n, ethereum_mainnet_hashkey_1_default],
  [17164792800244661392n, mint_mainnet_default],
  [3016212468291539606n, ethereum_mainnet_xlayer_1_default],
  [3776006016387883143n, bittorrent_chain_mainnet_default],
  [465944652040885897n, binance_smart_chain_mainnet_opbnb_1_default],
  [5406759801798337480n, bitcoin_mainnet_bsquared_1_default],
  [11690709103138290329n, mind_mainnet_default],
  [5608378062013572713n, lens_mainnet_default],
  [5936861837188149645n, tac_mainnet_default],
  [3768048213127883732n, fantom_mainnet_default],
  [1462016016387883143n, fraxtal_mainnet_default],
  [3719320017875267166n, ethereum_mainnet_kroma_1_default],
  [8239338020728974000n, neonlink_mainnet_default],
  [3229138320728879060n, hedera_mainnet_default],
  [4561443241176882990n, filecoin_mainnet_default],
  [1562403441176082196n, ethereum_mainnet_zksync_1_default],
  [8788096068760390840n, cronos_zkevm_mainnet_default],
  [2039744413822257700n, near_mainnet_default],
  [1939936305787790600n, areon_mainnet_default],
  [2049429975587534727n, ethereum_mainnet_worldchain_1_default],
  [6422105447186081193n, polkadot_mainnet_astar_default],
  [9107126442626377432n, janction_mainnet_default],
  [2135107236357186872n, bittensor_mainnet_default],
  [16978377838628290997n, stable_mainnet_default],
  [2442541497099098535n, hyperliquid_mainnet_default],
  [3358365939762719202n, conflux_mainnet_default],
  [8805746078405598895n, ethereum_mainnet_metis_1_default],
  [4348158687435793198n, ethereum_mainnet_polygon_zkevm_1_default],
  [5142893604156789321n, wemix_mainnet_default],
  [1224752112135636129n, core_mainnet_default],
  [15293031020466096408n, lisk_mainnet_default],
  [1252863800116739621n, polkadot_mainnet_moonbeam_default],
  [1355020143337428062n, kusama_mainnet_moonriver_default],
  [9027416829622342829n, sei_mainnet_default],
  [7801139999541420232n, pharos_mainnet_default],
  [13447077090413146373n, metal_mainnet_default],
  [12505351618335765396n, soneium_mainnet_default],
  [4874388048629246000n, bitcichain_mainnet_default],
  [6916147374840168594n, ronin_mainnet_default],
  [8175830712062617656n, polkadot_mainnet_centrifuge_default],
  [7550000543357438061n, kava_mainnet_default],
  [3577778157919314504n, abstract_mainnet_default],
  [18164309074156128038n, morph_mainnet_default],
  [6325494908023253251n, edge_mainnet_default],
  [4560701533377838164n, bitcoin_mainnet_botanix_default],
  [1540201334317828111n, ethereum_mainnet_astar_zkevm_1_default],
  [241851231317828981n, bitcoin_merlin_mainnet_default],
  [7281642695469137430n, tempo_mainnet_default],
  [6093540873831549674n, megaeth_mainnet_default],
  [6180753054346818345n, robinhood_mainnet_default],
  [1556008542357238666n, ethereum_mainnet_mantle_1_default],
  [6370580034781731079n, arc_mainnet_default],
  [470401360549526817n, superseed_mainnet_default],
  [17349189558768828726n, nibiru_mainnet_default],
  [10817664450262215148n, zetachain_mainnet_default],
  [9813823125703490621n, kaia_mainnet_default],
  [15971525489660198786n, ethereum_mainnet_base_1_default],
  [9335212494177455608n, plasma_mainnet_default],
  [9373518659714509671n, gate_layer_mainnet_default],
  [3162193654116181371n, ethereum_mainnet_arbitrum_1_l3x_1_default],
  [1237925231416731909n, ethereum_mainnet_immutable_zkevm_1_default],
  [4426351306075016396n, _0g_mainnet_default],
  [9723842205701363942n, everclear_mainnet_default],
  [14894068710063348487n, apechain_mainnet_default],
  [7264351850409363825n, ethereum_mainnet_mode_1_default],
  [4829375610284793157n, ab_mainnet_default],
  [4059281736450291836n, adi_mainnet_default],
  [4949039107694359620n, ethereum_mainnet_arbitrum_1_default],
  [1346049177634351622n, celo_mainnet_default],
  [13624601974233774587n, etherlink_mainnet_default],
  [1804312132722180201n, hemi_mainnet_default],
  [6433500567565415381n, avalanche_mainnet_default],
  [7222032299962346917n, neox_mainnet_default],
  [17198166215261833993n, ethereum_mainnet_zircuit_1_default],
  [6473245816409426016n, memento_mainnet_default],
  [3461204551265785888n, ethereum_mainnet_ink_1_default],
  [4627098889531055414n, ethereum_mainnet_linea_1_default],
  [15758750456714168963n, nexon_mainnet_lith_default],
  [3849287863852499584n, bitcoin_mainnet_bob_1_default],
  [5214452172935136222n, treasure_mainnet_default],
  [3314641565992046393n, mova_mainnet_default],
  [4215185756725900654n, mova_mainnet_2_default],
  [12657445206920369324n, nexon_mainnet_henesys_default],
  [1294465214383781161n, berachain_mainnet_default],
  [9478124434908827753n, codex_mainnet_default],
  [4411394078118774322n, ethereum_mainnet_blast_1_default],
  [17912061998839310979n, plume_mainnet_default],
  [18240105181246962294n, creditcoin_mainnet_default],
  [2988178761202034333n, gravity_mainnet_default],
  [16468599424800719238n, ethereum_mainnet_taiko_1_default],
  [7937294810946806131n, bitcoin_mainnet_bitlayer_1_default],
  [5463201557265485081n, avalanche_subnet_dexalot_mainnet_default],
  [13204309965629103672n, ethereum_mainnet_scroll_1_default],
  [2459028469735686113n, polygon_mainnet_katana_default],
  [14632960069656270105n, nexon_qa_default],
  [4350319965322101699n, zklink_nova_mainnet_default],
  [5556806327594153475n, nexon_stage_default],
  [1010349088906777999n, ethereum_mainnet_arbitrum_1_treasure_1_default],
  [1523760397290643893n, jovay_mainnet_default],
  [3555797439612589184n, zora_mainnet_default],
  [9043146809313071210n, corn_mainnet_default],
  [1546563616611573946n, tron_mainnet_evm_default],
  [13879014182901017172n, dtcc_mainnet_appchain_default],
  [124615329519749607n, solana_mainnet_default],
  [4741433654826277614n, aptos_mainnet_default],
  [17529533435026248318n, sui_mainnet_default],
  [16448340667252469081n, ton_mainnet_default],
  [1546563616611573945n, tron_mainnet_default]
]);
var testnetBySelector = new Map([
  [8953668971247136127n, bitcoin_testnet_rootstock_default],
  [729797994450396300n, telos_evm_testnet_default],
  [4340886533089894000n, polkadot_testnet_darwinia_pangoro_default],
  [3017758115101368649n, xdc_testnet_default],
  [8955032871639343000n, coinex_smart_chain_testnet_default],
  [6955638871347136141n, polkadot_testnet_astar_shibuya_default],
  [3558960680482140165n, gate_chain_testnet_meteora_default],
  [13264668187771770619n, binance_smart_chain_testnet_default],
  [572210378683744374n, velas_testnet_default],
  [4356164186791070119n, ethereum_testnet_sepolia_hashkey_1_default],
  [17833296867764334567n, shibarium_testnet_puppynet_default],
  [2066098519157881736n, ethereum_testnet_sepolia_xlayer_1_default],
  [16487132492576884721n, cronos_zkevm_testnet_sepolia_default],
  [6802309497652714138n, ethereum_testnet_goerli_zksync_1_default],
  [3842103497652714138n, cronos_testnet_zkevm_1_default],
  [222782988166878823n, hedera_testnet_default],
  [6898391096552792247n, ethereum_testnet_sepolia_zksync_1_default],
  [2995292832068775165n, cronos_testnet_default],
  [5061593697262339000n, near_testnet_default],
  [2664363617261496610n, ethereum_testnet_goerli_optimism_1_default],
  [7317911323415911000n, areon_testnet_default],
  [5059197667603797935n, janction_testnet_sepolia_default],
  [6260932437388305511n, private_testnet_obsidian_default],
  [829525985033418733n, ethereum_testnet_sepolia_mode_1_default],
  [2177900824115119161n, bittensor_testnet_default],
  [4286062357653186312n, hyperliquid_testnet_default],
  [2624132734533621656n, kaia_testnet_kairos_default],
  [4459371029167934217n, bittorrent_chain_testnet_default],
  [9284632837123596123n, wemix_testnet_default],
  [4264732132125536123n, core_testnet_default],
  [1948510578179542068n, bitcoin_testnet_bsquared_1_default],
  [5361632739113536121n, polkadot_testnet_moonbeam_moonbase_default],
  [14135854469784514356n, ethereum_testnet_sepolia_unichain_1_default],
  [1216300075444106652n, sei_testnet_atlantic_default],
  [3379446385462418246n, geth_testnet_default],
  [11059667695644972511n, ethereum_testnet_goerli_polygon_zkevm_1_default],
  [4237030917318060427n, story_testnet_default],
  [10749384167430721561n, mint_testnet_default],
  [6286293440461807648n, metal_testnet_default],
  [4888058894222120000n, bitcichain_testnet_default],
  [686603546605904534n, ethereum_testnet_sepolia_soneium_1_default],
  [10212741611335999305n, xlayer_testnet_default],
  [13116810400804392105n, ronin_testnet_saigon_default],
  [3260900564719373474n, private_testnet_granite_default],
  [6915682381028791124n, private_testnet_andesite_default],
  [15513093881969820114n, dtcc_testnet_andesite_default],
  [2333097300889804761n, polkadot_testnet_centrifuge_altair_default],
  [12168171414969487009n, memento_testnet_default],
  [11793402411494852765n, stable_testnet_default],
  [2110537777356199208n, kava_testnet_default],
  [5990477251245693094n, ethereum_testnet_sepolia_kroma_1_default],
  [9488606126177218005n, tac_testnet_default],
  [1654667687261492630n, ethereum_testnet_sepolia_polygon_zkevm_1_default],
  [8901520481741771655n, ethereum_testnet_holesky_fraxtal_1_default],
  [8304510386741731151n, ethereum_testnet_holesky_morph_1_default],
  [1064004874793747259n, ethereum_testnet_hoodi_morph_default],
  [1467223411771711614n, bitcoin_testnet_botanix_default],
  [4905564228793744293n, fantom_testnet_default],
  [5298399861320400553n, ethereum_testnet_sepolia_lisk_1_default],
  [5299555114858065850n, ethereum_testnet_sepolia_worldchain_1_default],
  [4168263376276232250n, ethereum_testnet_goerli_mantle_1_default],
  [8236463271206331221n, ethereum_testnet_sepolia_mantle_1_default],
  [13274425992935471758n, binance_smart_chain_testnet_opbnb_1_default],
  [8911150974185440581n, nexon_dev_default],
  [2443239559770384419n, megaeth_testnet_default],
  [18241817625092392675n, megaeth_testnet_2_default],
  [379340054879810246n, everclear_testnet_sepolia_default],
  [305104239123120457n, nibiru_testnet_default],
  [344208382356656551n, ondo_testnet_default],
  [1113014352258747600n, neonlink_testnet_default],
  [3967220077692964309n, plasma_testnet_default],
  [3667207123485082040n, gate_layer_testnet_default],
  [2183018362218727504n, monad_testnet_default],
  [8871595565390010547n, gnosis_chain_testnet_chiado_default],
  [9211758560309513668n, mova_testnet_default],
  [16235373811196386733n, abstract_testnet_default],
  [3486622437121596122n, ethereum_testnet_sepolia_arbitrum_1_l3x_1_default],
  [4526165231216331901n, ethereum_testnet_sepolia_immutable_zkevm_1_default],
  [1763698235108410440n, sonic_testnet_default],
  [16088006396410204581n, _0g_testnet_newton_default],
  [2131427466778448014n, _0g_testnet_galileo_default],
  [6892437333620424805n, _0g_testnet_galileo_1_default],
  [7717148896336251131n, ethereum_testnet_holesky_default],
  [7051849327615092843n, ab_testnet_default],
  [7759470850252068959n, anvil_devnet_default],
  [9900119385908781505n, apechain_testnet_curtis_default],
  [13222148116102326311n, edge_testnet_default],
  [6827576821754315911n, ethereum_testnet_sepolia_lens_1_default],
  [3963528237232804922n, tempo_testnet_default],
  [8457817439310187923n, tempo_testnet_moderato_default],
  [14767482510784806043n, avalanche_testnet_fuji_default],
  [3552045678561919002n, celo_testnet_alfajores_default],
  [8446413392851542429n, private_testnet_opala_default],
  [2032988798112970440n, robinhood_testnet_default],
  [13781831279385219069n, zircuit_testnet_garfield_default],
  [4562743618362911021n, ethereum_testnet_sepolia_zircuit_1_default],
  [13694007683517087973n, superseed_testnet_default],
  [3676871237479449268n, sonic_testnet_blaze_default],
  [1355246678561316402n, ethereum_testnet_goerli_linea_1_default],
  [5719461335882077547n, ethereum_testnet_sepolia_linea_1_default],
  [3777822886988675105n, ethereum_testnet_sepolia_metis_1_default],
  [12532609583862916517n, polygon_testnet_mumbai_default],
  [16281711391670634445n, polygon_testnet_amoy_default],
  [7728255861635209484n, berachain_testnet_bepolia_default],
  [8999465244383784164n, berachain_testnet_bartio_default],
  [12336603543561911511n, berachain_testnet_artio_default],
  [2285225387454015855n, zero_g_testnet_galileo_default],
  [5790810961207155433n, ethereum_testnet_goerli_base_1_default],
  [10344971235874465080n, ethereum_testnet_sepolia_base_1_default],
  [3743020999916460931n, plume_devnet_default],
  [13874588925447303949n, plume_testnet_sepolia_default],
  [9418205736192840573n, adi_testnet_default],
  [16960985330067274105n, creditcoin_testnet_default],
  [1910019406958449359n, etherlink_testnet_default],
  [9090863410735740267n, polygon_testnet_tatara_default],
  [7248756420937879088n, ethereum_testnet_holesky_taiko_1_default],
  [9873759436596923887n, ethereum_testnet_hoodi_taiko_default],
  [15858691699034549072n, ethereum_testnet_hoodi_taiko_1_default],
  [7189150270347329685n, mind_testnet_default],
  [3789623672476206327n, bitcoin_testnet_bitlayer_1_default],
  [1091131740251125869n, ethereum_testnet_sepolia_ronin_1_default],
  [17611928792452358269n, t_rex_testnet_default],
  [6101244977088475029n, ethereum_testnet_goerli_arbitrum_1_default],
  [3478487238524512106n, ethereum_testnet_sepolia_arbitrum_1_default],
  [4489326297382772450n, private_testnet_mica_default],
  [1458281248224512906n, avalanche_subnet_dexalot_testnet_default],
  [2279865765895943307n, ethereum_testnet_sepolia_scroll_1_default],
  [10380998176179737091n, ethereum_testnet_hoodi_default],
  [7837562506228496256n, avalanche_testnet_nexon_default],
  [5269261765892944301n, bitcoin_testnet_merlin_default],
  [4012524741200567430n, pharos_testnet_default],
  [16098325658947243212n, pharos_atlantic_testnet_default],
  [4418231248214522936n, ethereum_testnet_sepolia_polygon_validium_1_default],
  [16126893759944359622n, hemi_testnet_sepolia_default],
  [9763904284804119144n, ink_testnet_sepolia_default],
  [5535534526963509396n, bitcoin_testnet_sepolia_bob_1_default],
  [5837261596322416298n, zklink_nova_testnet_default],
  [7225665875429174318n, codex_testnet_default],
  [10443705513486043421n, ethereum_testnet_sepolia_arbitrum_1_treasure_1_default],
  [3676916124122457866n, treasure_testnet_topaz_default],
  [945045181441419236n, jovay_testnet_default],
  [3034092155422581607n, arc_testnet_default],
  [7254999290874773717n, dogeos_testnet_chikyu_default],
  [9181335567442030426n, gravity_testnet_longevity_default],
  [3761762704474186180n, celo_sepolia_default],
  [16015286601757825753n, ethereum_testnet_sepolia_default],
  [5224473277236331295n, ethereum_testnet_sepolia_optimism_1_default],
  [2217764097022649312n, neox_testnet_t4_default],
  [1467427327723633929n, ethereum_testnet_sepolia_corn_1_default],
  [7060342227814389000n, filecoin_testnet_default],
  [14684575664602284776n, plume_testnet_default],
  [2027362563942762617n, ethereum_testnet_sepolia_blast_1_default],
  [16244020411108056671n, zora_testnet_default],
  [4175996748267305081n, private_testnet_quartzite_default],
  [604447335222770945n, private_testnet_rhyolite_default],
  [1564738277398880633n, private_testnet_pumice_default],
  [13231703482326770598n, tron_testnet_shasta_evm_default],
  [13231703482326770600n, tron_devnet_evm_default],
  [2052925811360307749n, tron_testnet_nile_evm_default],
  [18362000170840307455n, private_testnet_basalt_default],
  [410896468069059699n, glamsterdam_devnet_6_default],
  [10073034426865795585n, glamsterdam_devnet_5_default],
  [12540949017250913122n, ethereum_testnet_plataberget_default],
  [6302590918974934319n, solana_testnet_default],
  [16423721717087811551n, solana_devnet_default],
  [743186221051783445n, aptos_testnet_default],
  [4457093679053095497n, aptos_localnet_default],
  [9762610643973837292n, sui_testnet_default],
  [18395503381733958356n, sui_localnet_default],
  [1399300952838017768n, ton_testnet_default],
  [13879075125137744094n, ton_localnet_default],
  [13231703482326770597n, tron_testnet_shasta_default],
  [13231703482326770599n, tron_devnet_default],
  [2052925811360307740n, tron_testnet_nile_default]
]);
var mainnetByName = new Map([
  ["ethereum-mainnet", ethereum_mainnet_default],
  ["ethereum-mainnet-optimism-1", ethereum_mainnet_optimism_1_default],
  ["cronos-mainnet", cronos_mainnet_default],
  ["rootstock-mainnet", rootstock_mainnet_default],
  ["telos-evm-mainnet", telos_evm_mainnet_default],
  ["polkadot-mainnet-darwinia", polkadot_mainnet_darwinia_default],
  ["xdc-mainnet", xdc_mainnet_default],
  ["coinex_smart_chain-mainnet", coinex_smart_chain_mainnet_default],
  ["binance_smart_chain-mainnet", binance_smart_chain_mainnet_default],
  ["gate-chain-mainnet", gate_chain_mainnet_default],
  ["gnosis_chain-mainnet", gnosis_chain_mainnet_default],
  ["velas-mainnet", velas_mainnet_default],
  ["shibarium-mainnet", shibarium_mainnet_default],
  ["ethereum-mainnet-unichain-1", ethereum_mainnet_unichain_1_default],
  ["polygon-mainnet", polygon_mainnet_default],
  ["monad-mainnet", monad_mainnet_default],
  ["sonic-mainnet", sonic_mainnet_default],
  ["ethereum-mainnet-hashkey-1", ethereum_mainnet_hashkey_1_default],
  ["mint-mainnet", mint_mainnet_default],
  ["ethereum-mainnet-xlayer-1", ethereum_mainnet_xlayer_1_default],
  ["bittorrent_chain-mainnet", bittorrent_chain_mainnet_default],
  ["binance_smart_chain-mainnet-opbnb-1", binance_smart_chain_mainnet_opbnb_1_default],
  ["bitcoin-mainnet-bsquared-1", bitcoin_mainnet_bsquared_1_default],
  ["mind-mainnet", mind_mainnet_default],
  ["lens-mainnet", lens_mainnet_default],
  ["tac-mainnet", tac_mainnet_default],
  ["fantom-mainnet", fantom_mainnet_default],
  ["fraxtal-mainnet", fraxtal_mainnet_default],
  ["ethereum-mainnet-kroma-1", ethereum_mainnet_kroma_1_default],
  ["neonlink-mainnet", neonlink_mainnet_default],
  ["hedera-mainnet", hedera_mainnet_default],
  ["filecoin-mainnet", filecoin_mainnet_default],
  ["ethereum-mainnet-zksync-1", ethereum_mainnet_zksync_1_default],
  ["cronos-zkevm-mainnet", cronos_zkevm_mainnet_default],
  ["near-mainnet", near_mainnet_default],
  ["areon-mainnet", areon_mainnet_default],
  ["ethereum-mainnet-worldchain-1", ethereum_mainnet_worldchain_1_default],
  ["polkadot-mainnet-astar", polkadot_mainnet_astar_default],
  ["janction-mainnet", janction_mainnet_default],
  ["bittensor-mainnet", bittensor_mainnet_default],
  ["stable-mainnet", stable_mainnet_default],
  ["hyperliquid-mainnet", hyperliquid_mainnet_default],
  ["conflux-mainnet", conflux_mainnet_default],
  ["ethereum-mainnet-metis-1", ethereum_mainnet_metis_1_default],
  ["ethereum-mainnet-polygon-zkevm-1", ethereum_mainnet_polygon_zkevm_1_default],
  ["wemix-mainnet", wemix_mainnet_default],
  ["core-mainnet", core_mainnet_default],
  ["lisk-mainnet", lisk_mainnet_default],
  ["polkadot-mainnet-moonbeam", polkadot_mainnet_moonbeam_default],
  ["kusama-mainnet-moonriver", kusama_mainnet_moonriver_default],
  ["sei-mainnet", sei_mainnet_default],
  ["pharos-mainnet", pharos_mainnet_default],
  ["metal-mainnet", metal_mainnet_default],
  ["soneium-mainnet", soneium_mainnet_default],
  ["bitcichain-mainnet", bitcichain_mainnet_default],
  ["ronin-mainnet", ronin_mainnet_default],
  ["polkadot-mainnet-centrifuge", polkadot_mainnet_centrifuge_default],
  ["kava-mainnet", kava_mainnet_default],
  ["abstract-mainnet", abstract_mainnet_default],
  ["morph-mainnet", morph_mainnet_default],
  ["edge-mainnet", edge_mainnet_default],
  ["bitcoin-mainnet-botanix", bitcoin_mainnet_botanix_default],
  ["ethereum-mainnet-astar-zkevm-1", ethereum_mainnet_astar_zkevm_1_default],
  ["bitcoin-merlin-mainnet", bitcoin_merlin_mainnet_default],
  ["tempo-mainnet", tempo_mainnet_default],
  ["megaeth-mainnet", megaeth_mainnet_default],
  ["robinhood-mainnet", robinhood_mainnet_default],
  ["ethereum-mainnet-mantle-1", ethereum_mainnet_mantle_1_default],
  ["arc-mainnet", arc_mainnet_default],
  ["superseed-mainnet", superseed_mainnet_default],
  ["nibiru-mainnet", nibiru_mainnet_default],
  ["zetachain-mainnet", zetachain_mainnet_default],
  ["kaia-mainnet", kaia_mainnet_default],
  ["ethereum-mainnet-base-1", ethereum_mainnet_base_1_default],
  ["plasma-mainnet", plasma_mainnet_default],
  ["gate-layer-mainnet", gate_layer_mainnet_default],
  ["ethereum-mainnet-arbitrum-1-l3x-1", ethereum_mainnet_arbitrum_1_l3x_1_default],
  ["ethereum-mainnet-immutable-zkevm-1", ethereum_mainnet_immutable_zkevm_1_default],
  ["0g-mainnet", _0g_mainnet_default],
  ["everclear-mainnet", everclear_mainnet_default],
  ["apechain-mainnet", apechain_mainnet_default],
  ["ethereum-mainnet-mode-1", ethereum_mainnet_mode_1_default],
  ["ab-mainnet", ab_mainnet_default],
  ["adi-mainnet", adi_mainnet_default],
  ["ethereum-mainnet-arbitrum-1", ethereum_mainnet_arbitrum_1_default],
  ["celo-mainnet", celo_mainnet_default],
  ["etherlink-mainnet", etherlink_mainnet_default],
  ["hemi-mainnet", hemi_mainnet_default],
  ["avalanche-mainnet", avalanche_mainnet_default],
  ["neox-mainnet", neox_mainnet_default],
  ["ethereum-mainnet-zircuit-1", ethereum_mainnet_zircuit_1_default],
  ["memento-mainnet", memento_mainnet_default],
  ["ethereum-mainnet-ink-1", ethereum_mainnet_ink_1_default],
  ["ethereum-mainnet-linea-1", ethereum_mainnet_linea_1_default],
  ["nexon-mainnet-lith", nexon_mainnet_lith_default],
  ["bitcoin-mainnet-bob-1", bitcoin_mainnet_bob_1_default],
  ["treasure-mainnet", treasure_mainnet_default],
  ["mova-mainnet", mova_mainnet_default],
  ["mova-mainnet-2", mova_mainnet_2_default],
  ["nexon-mainnet-henesys", nexon_mainnet_henesys_default],
  ["berachain-mainnet", berachain_mainnet_default],
  ["codex-mainnet", codex_mainnet_default],
  ["ethereum-mainnet-blast-1", ethereum_mainnet_blast_1_default],
  ["plume-mainnet", plume_mainnet_default],
  ["creditcoin-mainnet", creditcoin_mainnet_default],
  ["gravity-mainnet", gravity_mainnet_default],
  ["ethereum-mainnet-taiko-1", ethereum_mainnet_taiko_1_default],
  ["bitcoin-mainnet-bitlayer-1", bitcoin_mainnet_bitlayer_1_default],
  ["avalanche-subnet-dexalot-mainnet", avalanche_subnet_dexalot_mainnet_default],
  ["ethereum-mainnet-scroll-1", ethereum_mainnet_scroll_1_default],
  ["polygon-mainnet-katana", polygon_mainnet_katana_default],
  ["nexon-qa", nexon_qa_default],
  ["zklink_nova-mainnet", zklink_nova_mainnet_default],
  ["nexon-stage", nexon_stage_default],
  ["ethereum-mainnet-arbitrum-1-treasure-1", ethereum_mainnet_arbitrum_1_treasure_1_default],
  ["jovay-mainnet", jovay_mainnet_default],
  ["zora-mainnet", zora_mainnet_default],
  ["corn-mainnet", corn_mainnet_default],
  ["tron-mainnet-evm", tron_mainnet_evm_default],
  ["dtcc-mainnet-appchain", dtcc_mainnet_appchain_default],
  ["solana-mainnet", solana_mainnet_default],
  ["aptos-mainnet", aptos_mainnet_default],
  ["sui-mainnet", sui_mainnet_default],
  ["ton-mainnet", ton_mainnet_default],
  ["tron-mainnet", tron_mainnet_default]
]);
var testnetByName = new Map([
  ["bitcoin-testnet-rootstock", bitcoin_testnet_rootstock_default],
  ["telos-evm-testnet", telos_evm_testnet_default],
  ["polkadot-testnet-darwinia-pangoro", polkadot_testnet_darwinia_pangoro_default],
  ["xdc-testnet", xdc_testnet_default],
  ["coinex_smart_chain-testnet", coinex_smart_chain_testnet_default],
  ["polkadot-testnet-astar-shibuya", polkadot_testnet_astar_shibuya_default],
  ["gate-chain-testnet-meteora", gate_chain_testnet_meteora_default],
  ["binance_smart_chain-testnet", binance_smart_chain_testnet_default],
  ["velas-testnet", velas_testnet_default],
  ["ethereum-testnet-sepolia-hashkey-1", ethereum_testnet_sepolia_hashkey_1_default],
  ["shibarium-testnet-puppynet", shibarium_testnet_puppynet_default],
  ["ethereum-testnet-sepolia-xlayer-1", ethereum_testnet_sepolia_xlayer_1_default],
  ["cronos-zkevm-testnet-sepolia", cronos_zkevm_testnet_sepolia_default],
  ["ethereum-testnet-goerli-zksync-1", ethereum_testnet_goerli_zksync_1_default],
  ["cronos-testnet-zkevm-1", cronos_testnet_zkevm_1_default],
  ["hedera-testnet", hedera_testnet_default],
  ["ethereum-testnet-sepolia-zksync-1", ethereum_testnet_sepolia_zksync_1_default],
  ["cronos-testnet", cronos_testnet_default],
  ["near-testnet", near_testnet_default],
  ["ethereum-testnet-goerli-optimism-1", ethereum_testnet_goerli_optimism_1_default],
  ["areon-testnet", areon_testnet_default],
  ["janction-testnet-sepolia", janction_testnet_sepolia_default],
  ["private-testnet-obsidian", private_testnet_obsidian_default],
  ["ethereum-testnet-sepolia-mode-1", ethereum_testnet_sepolia_mode_1_default],
  ["bittensor-testnet", bittensor_testnet_default],
  ["hyperliquid-testnet", hyperliquid_testnet_default],
  ["kaia-testnet-kairos", kaia_testnet_kairos_default],
  ["bittorrent_chain-testnet", bittorrent_chain_testnet_default],
  ["wemix-testnet", wemix_testnet_default],
  ["core-testnet", core_testnet_default],
  ["bitcoin-testnet-bsquared-1", bitcoin_testnet_bsquared_1_default],
  ["polkadot-testnet-moonbeam-moonbase", polkadot_testnet_moonbeam_moonbase_default],
  ["ethereum-testnet-sepolia-unichain-1", ethereum_testnet_sepolia_unichain_1_default],
  ["sei-testnet-atlantic", sei_testnet_atlantic_default],
  ["geth-testnet", geth_testnet_default],
  ["ethereum-testnet-goerli-polygon-zkevm-1", ethereum_testnet_goerli_polygon_zkevm_1_default],
  ["story-testnet", story_testnet_default],
  ["mint-testnet", mint_testnet_default],
  ["metal-testnet", metal_testnet_default],
  ["bitcichain-testnet", bitcichain_testnet_default],
  ["ethereum-testnet-sepolia-soneium-1", ethereum_testnet_sepolia_soneium_1_default],
  ["xlayer-testnet", xlayer_testnet_default],
  ["ronin-testnet-saigon", ronin_testnet_saigon_default],
  ["private-testnet-granite", private_testnet_granite_default],
  ["private-testnet-andesite", private_testnet_andesite_default],
  ["dtcc-testnet-andesite", dtcc_testnet_andesite_default],
  ["polkadot-testnet-centrifuge-altair", polkadot_testnet_centrifuge_altair_default],
  ["memento-testnet", memento_testnet_default],
  ["stable-testnet", stable_testnet_default],
  ["kava-testnet", kava_testnet_default],
  ["ethereum-testnet-sepolia-kroma-1", ethereum_testnet_sepolia_kroma_1_default],
  ["tac-testnet", tac_testnet_default],
  [
    "ethereum-testnet-sepolia-polygon-zkevm-1",
    ethereum_testnet_sepolia_polygon_zkevm_1_default
  ],
  ["ethereum-testnet-holesky-fraxtal-1", ethereum_testnet_holesky_fraxtal_1_default],
  ["ethereum-testnet-holesky-morph-1", ethereum_testnet_holesky_morph_1_default],
  ["ethereum-testnet-hoodi-morph", ethereum_testnet_hoodi_morph_default],
  ["bitcoin-testnet-botanix", bitcoin_testnet_botanix_default],
  ["fantom-testnet", fantom_testnet_default],
  ["ethereum-testnet-sepolia-lisk-1", ethereum_testnet_sepolia_lisk_1_default],
  ["ethereum-testnet-sepolia-worldchain-1", ethereum_testnet_sepolia_worldchain_1_default],
  ["ethereum-testnet-goerli-mantle-1", ethereum_testnet_goerli_mantle_1_default],
  ["ethereum-testnet-sepolia-mantle-1", ethereum_testnet_sepolia_mantle_1_default],
  ["binance_smart_chain-testnet-opbnb-1", binance_smart_chain_testnet_opbnb_1_default],
  ["nexon-dev", nexon_dev_default],
  ["megaeth-testnet", megaeth_testnet_default],
  ["megaeth-testnet-2", megaeth_testnet_2_default],
  ["everclear-testnet-sepolia", everclear_testnet_sepolia_default],
  ["nibiru-testnet", nibiru_testnet_default],
  ["ondo-testnet", ondo_testnet_default],
  ["neonlink-testnet", neonlink_testnet_default],
  ["plasma-testnet", plasma_testnet_default],
  ["gate-layer-testnet", gate_layer_testnet_default],
  ["monad-testnet", monad_testnet_default],
  ["gnosis_chain-testnet-chiado", gnosis_chain_testnet_chiado_default],
  ["mova-testnet", mova_testnet_default],
  ["abstract-testnet", abstract_testnet_default],
  [
    "ethereum-testnet-sepolia-arbitrum-1-l3x-1",
    ethereum_testnet_sepolia_arbitrum_1_l3x_1_default
  ],
  [
    "ethereum-testnet-sepolia-immutable-zkevm-1",
    ethereum_testnet_sepolia_immutable_zkevm_1_default
  ],
  ["sonic-testnet", sonic_testnet_default],
  ["0g-testnet-newton", _0g_testnet_newton_default],
  ["0g-testnet-galileo", _0g_testnet_galileo_default],
  ["0g-testnet-galileo-1", _0g_testnet_galileo_1_default],
  ["ethereum-testnet-holesky", ethereum_testnet_holesky_default],
  ["ab-testnet", ab_testnet_default],
  ["anvil-devnet", anvil_devnet_default],
  ["apechain-testnet-curtis", apechain_testnet_curtis_default],
  ["edge-testnet", edge_testnet_default],
  ["ethereum-testnet-sepolia-lens-1", ethereum_testnet_sepolia_lens_1_default],
  ["tempo-testnet", tempo_testnet_default],
  ["tempo-testnet-moderato", tempo_testnet_moderato_default],
  ["avalanche-testnet-fuji", avalanche_testnet_fuji_default],
  ["celo-testnet-alfajores", celo_testnet_alfajores_default],
  ["private-testnet-opala", private_testnet_opala_default],
  ["robinhood-testnet", robinhood_testnet_default],
  ["zircuit-testnet-garfield", zircuit_testnet_garfield_default],
  ["ethereum-testnet-sepolia-zircuit-1", ethereum_testnet_sepolia_zircuit_1_default],
  ["superseed-testnet", superseed_testnet_default],
  ["sonic-testnet-blaze", sonic_testnet_blaze_default],
  ["ethereum-testnet-goerli-linea-1", ethereum_testnet_goerli_linea_1_default],
  ["ethereum-testnet-sepolia-linea-1", ethereum_testnet_sepolia_linea_1_default],
  ["ethereum-testnet-sepolia-metis-1", ethereum_testnet_sepolia_metis_1_default],
  ["polygon-testnet-mumbai", polygon_testnet_mumbai_default],
  ["polygon-testnet-amoy", polygon_testnet_amoy_default],
  ["berachain-testnet-bepolia", berachain_testnet_bepolia_default],
  ["berachain-testnet-bartio", berachain_testnet_bartio_default],
  ["berachain-testnet-artio", berachain_testnet_artio_default],
  ["zero-g-testnet-galileo", zero_g_testnet_galileo_default],
  ["ethereum-testnet-goerli-base-1", ethereum_testnet_goerli_base_1_default],
  ["ethereum-testnet-sepolia-base-1", ethereum_testnet_sepolia_base_1_default],
  ["plume-devnet", plume_devnet_default],
  ["plume-testnet-sepolia", plume_testnet_sepolia_default],
  ["adi-testnet", adi_testnet_default],
  ["creditcoin-testnet", creditcoin_testnet_default],
  ["etherlink-testnet", etherlink_testnet_default],
  ["polygon-testnet-tatara", polygon_testnet_tatara_default],
  ["ethereum-testnet-holesky-taiko-1", ethereum_testnet_holesky_taiko_1_default],
  ["ethereum-testnet-hoodi-taiko", ethereum_testnet_hoodi_taiko_default],
  ["ethereum-testnet-hoodi-taiko-1", ethereum_testnet_hoodi_taiko_1_default],
  ["mind-testnet", mind_testnet_default],
  ["bitcoin-testnet-bitlayer-1", bitcoin_testnet_bitlayer_1_default],
  ["ethereum-testnet-sepolia-ronin-1", ethereum_testnet_sepolia_ronin_1_default],
  ["t-rex-testnet", t_rex_testnet_default],
  ["ethereum-testnet-goerli-arbitrum-1", ethereum_testnet_goerli_arbitrum_1_default],
  ["ethereum-testnet-sepolia-arbitrum-1", ethereum_testnet_sepolia_arbitrum_1_default],
  ["private-testnet-mica", private_testnet_mica_default],
  ["avalanche-subnet-dexalot-testnet", avalanche_subnet_dexalot_testnet_default],
  ["ethereum-testnet-sepolia-scroll-1", ethereum_testnet_sepolia_scroll_1_default],
  ["ethereum-testnet-hoodi", ethereum_testnet_hoodi_default],
  ["avalanche-testnet-nexon", avalanche_testnet_nexon_default],
  ["bitcoin-testnet-merlin", bitcoin_testnet_merlin_default],
  ["pharos-testnet", pharos_testnet_default],
  ["pharos-atlantic-testnet", pharos_atlantic_testnet_default],
  [
    "ethereum-testnet-sepolia-polygon-validium-1",
    ethereum_testnet_sepolia_polygon_validium_1_default
  ],
  ["hemi-testnet-sepolia", hemi_testnet_sepolia_default],
  ["ink-testnet-sepolia", ink_testnet_sepolia_default],
  ["bitcoin-testnet-sepolia-bob-1", bitcoin_testnet_sepolia_bob_1_default],
  ["zklink_nova-testnet", zklink_nova_testnet_default],
  ["codex-testnet", codex_testnet_default],
  [
    "ethereum-testnet-sepolia-arbitrum-1-treasure-1",
    ethereum_testnet_sepolia_arbitrum_1_treasure_1_default
  ],
  ["treasure-testnet-topaz", treasure_testnet_topaz_default],
  ["jovay-testnet", jovay_testnet_default],
  ["arc-testnet", arc_testnet_default],
  ["dogeos-testnet-chikyu", dogeos_testnet_chikyu_default],
  ["gravity-testnet-longevity", gravity_testnet_longevity_default],
  ["celo-sepolia", celo_sepolia_default],
  ["ethereum-testnet-sepolia", ethereum_testnet_sepolia_default],
  ["ethereum-testnet-sepolia-optimism-1", ethereum_testnet_sepolia_optimism_1_default],
  ["neox-testnet-t4", neox_testnet_t4_default],
  ["ethereum-testnet-sepolia-corn-1", ethereum_testnet_sepolia_corn_1_default],
  ["filecoin-testnet", filecoin_testnet_default],
  ["plume-testnet", plume_testnet_default],
  ["ethereum-testnet-sepolia-blast-1", ethereum_testnet_sepolia_blast_1_default],
  ["zora-testnet", zora_testnet_default],
  ["private-testnet-quartzite", private_testnet_quartzite_default],
  ["private-testnet-rhyolite", private_testnet_rhyolite_default],
  ["private-testnet-pumice", private_testnet_pumice_default],
  ["tron-testnet-shasta-evm", tron_testnet_shasta_evm_default],
  ["tron-devnet-evm", tron_devnet_evm_default],
  ["tron-testnet-nile-evm", tron_testnet_nile_evm_default],
  ["private-testnet-basalt", private_testnet_basalt_default],
  ["glamsterdam-devnet-6", glamsterdam_devnet_6_default],
  ["glamsterdam-devnet-5", glamsterdam_devnet_5_default],
  ["ethereum-testnet-plataberget", ethereum_testnet_plataberget_default],
  ["solana-testnet", solana_testnet_default],
  ["solana-devnet", solana_devnet_default],
  ["aptos-testnet", aptos_testnet_default],
  ["aptos-localnet", aptos_localnet_default],
  ["sui-testnet", sui_testnet_default],
  ["sui-localnet", sui_localnet_default],
  ["ton-testnet", ton_testnet_default],
  ["ton-localnet", ton_localnet_default],
  ["tron-testnet-shasta", tron_testnet_shasta_default],
  ["tron-devnet", tron_devnet_default],
  ["tron-testnet-nile", tron_testnet_nile_default]
]);
var mainnetBySelectorByFamily = {
  evm: new Map([
    [5009297550715157269n, ethereum_mainnet_default],
    [3734403246176062136n, ethereum_mainnet_optimism_1_default],
    [1456215246176062136n, cronos_mainnet_default],
    [11964252391146578476n, rootstock_mainnet_default],
    [1477345371608778000n, telos_evm_mainnet_default],
    [8866418665544333000n, polkadot_mainnet_darwinia_default],
    [17673274061779414707n, xdc_mainnet_default],
    [1761333065194157300n, coinex_smart_chain_mainnet_default],
    [11344663589394136015n, binance_smart_chain_mainnet_default],
    [9688382747979139404n, gate_chain_mainnet_default],
    [465200170687744372n, gnosis_chain_mainnet_default],
    [374210358663784372n, velas_mainnet_default],
    [3993510008929295315n, shibarium_mainnet_default],
    [1923510103922296319n, ethereum_mainnet_unichain_1_default],
    [4051577828743386545n, polygon_mainnet_default],
    [8481857512324358265n, monad_mainnet_default],
    [1673871237479749969n, sonic_mainnet_default],
    [7613811247471741961n, ethereum_mainnet_hashkey_1_default],
    [17164792800244661392n, mint_mainnet_default],
    [3016212468291539606n, ethereum_mainnet_xlayer_1_default],
    [3776006016387883143n, bittorrent_chain_mainnet_default],
    [465944652040885897n, binance_smart_chain_mainnet_opbnb_1_default],
    [5406759801798337480n, bitcoin_mainnet_bsquared_1_default],
    [11690709103138290329n, mind_mainnet_default],
    [5608378062013572713n, lens_mainnet_default],
    [5936861837188149645n, tac_mainnet_default],
    [3768048213127883732n, fantom_mainnet_default],
    [1462016016387883143n, fraxtal_mainnet_default],
    [3719320017875267166n, ethereum_mainnet_kroma_1_default],
    [8239338020728974000n, neonlink_mainnet_default],
    [3229138320728879060n, hedera_mainnet_default],
    [4561443241176882990n, filecoin_mainnet_default],
    [1562403441176082196n, ethereum_mainnet_zksync_1_default],
    [8788096068760390840n, cronos_zkevm_mainnet_default],
    [2039744413822257700n, near_mainnet_default],
    [1939936305787790600n, areon_mainnet_default],
    [2049429975587534727n, ethereum_mainnet_worldchain_1_default],
    [6422105447186081193n, polkadot_mainnet_astar_default],
    [9107126442626377432n, janction_mainnet_default],
    [2135107236357186872n, bittensor_mainnet_default],
    [16978377838628290997n, stable_mainnet_default],
    [2442541497099098535n, hyperliquid_mainnet_default],
    [3358365939762719202n, conflux_mainnet_default],
    [8805746078405598895n, ethereum_mainnet_metis_1_default],
    [4348158687435793198n, ethereum_mainnet_polygon_zkevm_1_default],
    [5142893604156789321n, wemix_mainnet_default],
    [1224752112135636129n, core_mainnet_default],
    [15293031020466096408n, lisk_mainnet_default],
    [1252863800116739621n, polkadot_mainnet_moonbeam_default],
    [1355020143337428062n, kusama_mainnet_moonriver_default],
    [9027416829622342829n, sei_mainnet_default],
    [7801139999541420232n, pharos_mainnet_default],
    [13447077090413146373n, metal_mainnet_default],
    [12505351618335765396n, soneium_mainnet_default],
    [4874388048629246000n, bitcichain_mainnet_default],
    [6916147374840168594n, ronin_mainnet_default],
    [8175830712062617656n, polkadot_mainnet_centrifuge_default],
    [7550000543357438061n, kava_mainnet_default],
    [3577778157919314504n, abstract_mainnet_default],
    [18164309074156128038n, morph_mainnet_default],
    [6325494908023253251n, edge_mainnet_default],
    [4560701533377838164n, bitcoin_mainnet_botanix_default],
    [1540201334317828111n, ethereum_mainnet_astar_zkevm_1_default],
    [241851231317828981n, bitcoin_merlin_mainnet_default],
    [7281642695469137430n, tempo_mainnet_default],
    [6093540873831549674n, megaeth_mainnet_default],
    [6180753054346818345n, robinhood_mainnet_default],
    [1556008542357238666n, ethereum_mainnet_mantle_1_default],
    [6370580034781731079n, arc_mainnet_default],
    [470401360549526817n, superseed_mainnet_default],
    [17349189558768828726n, nibiru_mainnet_default],
    [10817664450262215148n, zetachain_mainnet_default],
    [9813823125703490621n, kaia_mainnet_default],
    [15971525489660198786n, ethereum_mainnet_base_1_default],
    [9335212494177455608n, plasma_mainnet_default],
    [9373518659714509671n, gate_layer_mainnet_default],
    [3162193654116181371n, ethereum_mainnet_arbitrum_1_l3x_1_default],
    [1237925231416731909n, ethereum_mainnet_immutable_zkevm_1_default],
    [4426351306075016396n, _0g_mainnet_default],
    [9723842205701363942n, everclear_mainnet_default],
    [14894068710063348487n, apechain_mainnet_default],
    [7264351850409363825n, ethereum_mainnet_mode_1_default],
    [4829375610284793157n, ab_mainnet_default],
    [4059281736450291836n, adi_mainnet_default],
    [4949039107694359620n, ethereum_mainnet_arbitrum_1_default],
    [1346049177634351622n, celo_mainnet_default],
    [13624601974233774587n, etherlink_mainnet_default],
    [1804312132722180201n, hemi_mainnet_default],
    [6433500567565415381n, avalanche_mainnet_default],
    [7222032299962346917n, neox_mainnet_default],
    [17198166215261833993n, ethereum_mainnet_zircuit_1_default],
    [6473245816409426016n, memento_mainnet_default],
    [3461204551265785888n, ethereum_mainnet_ink_1_default],
    [4627098889531055414n, ethereum_mainnet_linea_1_default],
    [15758750456714168963n, nexon_mainnet_lith_default],
    [3849287863852499584n, bitcoin_mainnet_bob_1_default],
    [5214452172935136222n, treasure_mainnet_default],
    [3314641565992046393n, mova_mainnet_default],
    [4215185756725900654n, mova_mainnet_2_default],
    [12657445206920369324n, nexon_mainnet_henesys_default],
    [1294465214383781161n, berachain_mainnet_default],
    [9478124434908827753n, codex_mainnet_default],
    [4411394078118774322n, ethereum_mainnet_blast_1_default],
    [17912061998839310979n, plume_mainnet_default],
    [18240105181246962294n, creditcoin_mainnet_default],
    [2988178761202034333n, gravity_mainnet_default],
    [16468599424800719238n, ethereum_mainnet_taiko_1_default],
    [7937294810946806131n, bitcoin_mainnet_bitlayer_1_default],
    [5463201557265485081n, avalanche_subnet_dexalot_mainnet_default],
    [13204309965629103672n, ethereum_mainnet_scroll_1_default],
    [2459028469735686113n, polygon_mainnet_katana_default],
    [14632960069656270105n, nexon_qa_default],
    [4350319965322101699n, zklink_nova_mainnet_default],
    [5556806327594153475n, nexon_stage_default],
    [1010349088906777999n, ethereum_mainnet_arbitrum_1_treasure_1_default],
    [1523760397290643893n, jovay_mainnet_default],
    [3555797439612589184n, zora_mainnet_default],
    [9043146809313071210n, corn_mainnet_default],
    [1546563616611573946n, tron_mainnet_evm_default],
    [13879014182901017172n, dtcc_mainnet_appchain_default]
  ]),
  solana: new Map([[124615329519749607n, solana_mainnet_default]]),
  aptos: new Map([[4741433654826277614n, aptos_mainnet_default]]),
  sui: new Map([[17529533435026248318n, sui_mainnet_default]]),
  ton: new Map([[16448340667252469081n, ton_mainnet_default]]),
  tron: new Map([[1546563616611573945n, tron_mainnet_default]])
};
var testnetBySelectorByFamily = {
  evm: new Map([
    [8953668971247136127n, bitcoin_testnet_rootstock_default],
    [729797994450396300n, telos_evm_testnet_default],
    [4340886533089894000n, polkadot_testnet_darwinia_pangoro_default],
    [3017758115101368649n, xdc_testnet_default],
    [8955032871639343000n, coinex_smart_chain_testnet_default],
    [6955638871347136141n, polkadot_testnet_astar_shibuya_default],
    [3558960680482140165n, gate_chain_testnet_meteora_default],
    [13264668187771770619n, binance_smart_chain_testnet_default],
    [572210378683744374n, velas_testnet_default],
    [4356164186791070119n, ethereum_testnet_sepolia_hashkey_1_default],
    [17833296867764334567n, shibarium_testnet_puppynet_default],
    [2066098519157881736n, ethereum_testnet_sepolia_xlayer_1_default],
    [16487132492576884721n, cronos_zkevm_testnet_sepolia_default],
    [6802309497652714138n, ethereum_testnet_goerli_zksync_1_default],
    [3842103497652714138n, cronos_testnet_zkevm_1_default],
    [222782988166878823n, hedera_testnet_default],
    [6898391096552792247n, ethereum_testnet_sepolia_zksync_1_default],
    [2995292832068775165n, cronos_testnet_default],
    [5061593697262339000n, near_testnet_default],
    [2664363617261496610n, ethereum_testnet_goerli_optimism_1_default],
    [7317911323415911000n, areon_testnet_default],
    [5059197667603797935n, janction_testnet_sepolia_default],
    [6260932437388305511n, private_testnet_obsidian_default],
    [829525985033418733n, ethereum_testnet_sepolia_mode_1_default],
    [2177900824115119161n, bittensor_testnet_default],
    [4286062357653186312n, hyperliquid_testnet_default],
    [2624132734533621656n, kaia_testnet_kairos_default],
    [4459371029167934217n, bittorrent_chain_testnet_default],
    [9284632837123596123n, wemix_testnet_default],
    [4264732132125536123n, core_testnet_default],
    [1948510578179542068n, bitcoin_testnet_bsquared_1_default],
    [5361632739113536121n, polkadot_testnet_moonbeam_moonbase_default],
    [14135854469784514356n, ethereum_testnet_sepolia_unichain_1_default],
    [1216300075444106652n, sei_testnet_atlantic_default],
    [3379446385462418246n, geth_testnet_default],
    [11059667695644972511n, ethereum_testnet_goerli_polygon_zkevm_1_default],
    [4237030917318060427n, story_testnet_default],
    [10749384167430721561n, mint_testnet_default],
    [6286293440461807648n, metal_testnet_default],
    [4888058894222120000n, bitcichain_testnet_default],
    [686603546605904534n, ethereum_testnet_sepolia_soneium_1_default],
    [10212741611335999305n, xlayer_testnet_default],
    [13116810400804392105n, ronin_testnet_saigon_default],
    [3260900564719373474n, private_testnet_granite_default],
    [6915682381028791124n, private_testnet_andesite_default],
    [15513093881969820114n, dtcc_testnet_andesite_default],
    [2333097300889804761n, polkadot_testnet_centrifuge_altair_default],
    [12168171414969487009n, memento_testnet_default],
    [11793402411494852765n, stable_testnet_default],
    [2110537777356199208n, kava_testnet_default],
    [5990477251245693094n, ethereum_testnet_sepolia_kroma_1_default],
    [9488606126177218005n, tac_testnet_default],
    [1654667687261492630n, ethereum_testnet_sepolia_polygon_zkevm_1_default],
    [8901520481741771655n, ethereum_testnet_holesky_fraxtal_1_default],
    [8304510386741731151n, ethereum_testnet_holesky_morph_1_default],
    [1064004874793747259n, ethereum_testnet_hoodi_morph_default],
    [1467223411771711614n, bitcoin_testnet_botanix_default],
    [4905564228793744293n, fantom_testnet_default],
    [5298399861320400553n, ethereum_testnet_sepolia_lisk_1_default],
    [5299555114858065850n, ethereum_testnet_sepolia_worldchain_1_default],
    [4168263376276232250n, ethereum_testnet_goerli_mantle_1_default],
    [8236463271206331221n, ethereum_testnet_sepolia_mantle_1_default],
    [13274425992935471758n, binance_smart_chain_testnet_opbnb_1_default],
    [8911150974185440581n, nexon_dev_default],
    [2443239559770384419n, megaeth_testnet_default],
    [18241817625092392675n, megaeth_testnet_2_default],
    [379340054879810246n, everclear_testnet_sepolia_default],
    [305104239123120457n, nibiru_testnet_default],
    [344208382356656551n, ondo_testnet_default],
    [1113014352258747600n, neonlink_testnet_default],
    [3967220077692964309n, plasma_testnet_default],
    [3667207123485082040n, gate_layer_testnet_default],
    [2183018362218727504n, monad_testnet_default],
    [8871595565390010547n, gnosis_chain_testnet_chiado_default],
    [9211758560309513668n, mova_testnet_default],
    [16235373811196386733n, abstract_testnet_default],
    [3486622437121596122n, ethereum_testnet_sepolia_arbitrum_1_l3x_1_default],
    [4526165231216331901n, ethereum_testnet_sepolia_immutable_zkevm_1_default],
    [1763698235108410440n, sonic_testnet_default],
    [16088006396410204581n, _0g_testnet_newton_default],
    [2131427466778448014n, _0g_testnet_galileo_default],
    [6892437333620424805n, _0g_testnet_galileo_1_default],
    [7717148896336251131n, ethereum_testnet_holesky_default],
    [7051849327615092843n, ab_testnet_default],
    [7759470850252068959n, anvil_devnet_default],
    [9900119385908781505n, apechain_testnet_curtis_default],
    [13222148116102326311n, edge_testnet_default],
    [6827576821754315911n, ethereum_testnet_sepolia_lens_1_default],
    [3963528237232804922n, tempo_testnet_default],
    [8457817439310187923n, tempo_testnet_moderato_default],
    [14767482510784806043n, avalanche_testnet_fuji_default],
    [3552045678561919002n, celo_testnet_alfajores_default],
    [8446413392851542429n, private_testnet_opala_default],
    [2032988798112970440n, robinhood_testnet_default],
    [13781831279385219069n, zircuit_testnet_garfield_default],
    [4562743618362911021n, ethereum_testnet_sepolia_zircuit_1_default],
    [13694007683517087973n, superseed_testnet_default],
    [3676871237479449268n, sonic_testnet_blaze_default],
    [1355246678561316402n, ethereum_testnet_goerli_linea_1_default],
    [5719461335882077547n, ethereum_testnet_sepolia_linea_1_default],
    [3777822886988675105n, ethereum_testnet_sepolia_metis_1_default],
    [12532609583862916517n, polygon_testnet_mumbai_default],
    [16281711391670634445n, polygon_testnet_amoy_default],
    [7728255861635209484n, berachain_testnet_bepolia_default],
    [8999465244383784164n, berachain_testnet_bartio_default],
    [12336603543561911511n, berachain_testnet_artio_default],
    [2285225387454015855n, zero_g_testnet_galileo_default],
    [5790810961207155433n, ethereum_testnet_goerli_base_1_default],
    [10344971235874465080n, ethereum_testnet_sepolia_base_1_default],
    [3743020999916460931n, plume_devnet_default],
    [13874588925447303949n, plume_testnet_sepolia_default],
    [9418205736192840573n, adi_testnet_default],
    [16960985330067274105n, creditcoin_testnet_default],
    [1910019406958449359n, etherlink_testnet_default],
    [9090863410735740267n, polygon_testnet_tatara_default],
    [7248756420937879088n, ethereum_testnet_holesky_taiko_1_default],
    [9873759436596923887n, ethereum_testnet_hoodi_taiko_default],
    [15858691699034549072n, ethereum_testnet_hoodi_taiko_1_default],
    [7189150270347329685n, mind_testnet_default],
    [3789623672476206327n, bitcoin_testnet_bitlayer_1_default],
    [1091131740251125869n, ethereum_testnet_sepolia_ronin_1_default],
    [17611928792452358269n, t_rex_testnet_default],
    [6101244977088475029n, ethereum_testnet_goerli_arbitrum_1_default],
    [3478487238524512106n, ethereum_testnet_sepolia_arbitrum_1_default],
    [4489326297382772450n, private_testnet_mica_default],
    [1458281248224512906n, avalanche_subnet_dexalot_testnet_default],
    [2279865765895943307n, ethereum_testnet_sepolia_scroll_1_default],
    [10380998176179737091n, ethereum_testnet_hoodi_default],
    [7837562506228496256n, avalanche_testnet_nexon_default],
    [5269261765892944301n, bitcoin_testnet_merlin_default],
    [4012524741200567430n, pharos_testnet_default],
    [16098325658947243212n, pharos_atlantic_testnet_default],
    [4418231248214522936n, ethereum_testnet_sepolia_polygon_validium_1_default],
    [16126893759944359622n, hemi_testnet_sepolia_default],
    [9763904284804119144n, ink_testnet_sepolia_default],
    [5535534526963509396n, bitcoin_testnet_sepolia_bob_1_default],
    [5837261596322416298n, zklink_nova_testnet_default],
    [7225665875429174318n, codex_testnet_default],
    [10443705513486043421n, ethereum_testnet_sepolia_arbitrum_1_treasure_1_default],
    [3676916124122457866n, treasure_testnet_topaz_default],
    [945045181441419236n, jovay_testnet_default],
    [3034092155422581607n, arc_testnet_default],
    [7254999290874773717n, dogeos_testnet_chikyu_default],
    [9181335567442030426n, gravity_testnet_longevity_default],
    [3761762704474186180n, celo_sepolia_default],
    [16015286601757825753n, ethereum_testnet_sepolia_default],
    [5224473277236331295n, ethereum_testnet_sepolia_optimism_1_default],
    [2217764097022649312n, neox_testnet_t4_default],
    [1467427327723633929n, ethereum_testnet_sepolia_corn_1_default],
    [7060342227814389000n, filecoin_testnet_default],
    [14684575664602284776n, plume_testnet_default],
    [2027362563942762617n, ethereum_testnet_sepolia_blast_1_default],
    [16244020411108056671n, zora_testnet_default],
    [4175996748267305081n, private_testnet_quartzite_default],
    [604447335222770945n, private_testnet_rhyolite_default],
    [1564738277398880633n, private_testnet_pumice_default],
    [13231703482326770598n, tron_testnet_shasta_evm_default],
    [13231703482326770600n, tron_devnet_evm_default],
    [2052925811360307749n, tron_testnet_nile_evm_default],
    [18362000170840307455n, private_testnet_basalt_default],
    [410896468069059699n, glamsterdam_devnet_6_default],
    [10073034426865795585n, glamsterdam_devnet_5_default],
    [12540949017250913122n, ethereum_testnet_plataberget_default]
  ]),
  solana: new Map([
    [6302590918974934319n, solana_testnet_default],
    [16423721717087811551n, solana_devnet_default]
  ]),
  aptos: new Map([
    [743186221051783445n, aptos_testnet_default],
    [4457093679053095497n, aptos_localnet_default]
  ]),
  sui: new Map([
    [9762610643973837292n, sui_testnet_default],
    [18395503381733958356n, sui_localnet_default]
  ]),
  ton: new Map([
    [1399300952838017768n, ton_testnet_default],
    [13879075125137744094n, ton_localnet_default]
  ]),
  tron: new Map([
    [13231703482326770597n, tron_testnet_shasta_default],
    [13231703482326770599n, tron_devnet_default],
    [2052925811360307740n, tron_testnet_nile_default]
  ])
};
var mainnetByNameByFamily = {
  evm: new Map([
    ["ethereum-mainnet", ethereum_mainnet_default],
    ["ethereum-mainnet-optimism-1", ethereum_mainnet_optimism_1_default],
    ["cronos-mainnet", cronos_mainnet_default],
    ["rootstock-mainnet", rootstock_mainnet_default],
    ["telos-evm-mainnet", telos_evm_mainnet_default],
    ["polkadot-mainnet-darwinia", polkadot_mainnet_darwinia_default],
    ["xdc-mainnet", xdc_mainnet_default],
    ["coinex_smart_chain-mainnet", coinex_smart_chain_mainnet_default],
    ["binance_smart_chain-mainnet", binance_smart_chain_mainnet_default],
    ["gate-chain-mainnet", gate_chain_mainnet_default],
    ["gnosis_chain-mainnet", gnosis_chain_mainnet_default],
    ["velas-mainnet", velas_mainnet_default],
    ["shibarium-mainnet", shibarium_mainnet_default],
    ["ethereum-mainnet-unichain-1", ethereum_mainnet_unichain_1_default],
    ["polygon-mainnet", polygon_mainnet_default],
    ["monad-mainnet", monad_mainnet_default],
    ["sonic-mainnet", sonic_mainnet_default],
    ["ethereum-mainnet-hashkey-1", ethereum_mainnet_hashkey_1_default],
    ["mint-mainnet", mint_mainnet_default],
    ["ethereum-mainnet-xlayer-1", ethereum_mainnet_xlayer_1_default],
    ["bittorrent_chain-mainnet", bittorrent_chain_mainnet_default],
    ["binance_smart_chain-mainnet-opbnb-1", binance_smart_chain_mainnet_opbnb_1_default],
    ["bitcoin-mainnet-bsquared-1", bitcoin_mainnet_bsquared_1_default],
    ["mind-mainnet", mind_mainnet_default],
    ["lens-mainnet", lens_mainnet_default],
    ["tac-mainnet", tac_mainnet_default],
    ["fantom-mainnet", fantom_mainnet_default],
    ["fraxtal-mainnet", fraxtal_mainnet_default],
    ["ethereum-mainnet-kroma-1", ethereum_mainnet_kroma_1_default],
    ["neonlink-mainnet", neonlink_mainnet_default],
    ["hedera-mainnet", hedera_mainnet_default],
    ["filecoin-mainnet", filecoin_mainnet_default],
    ["ethereum-mainnet-zksync-1", ethereum_mainnet_zksync_1_default],
    ["cronos-zkevm-mainnet", cronos_zkevm_mainnet_default],
    ["near-mainnet", near_mainnet_default],
    ["areon-mainnet", areon_mainnet_default],
    ["ethereum-mainnet-worldchain-1", ethereum_mainnet_worldchain_1_default],
    ["polkadot-mainnet-astar", polkadot_mainnet_astar_default],
    ["janction-mainnet", janction_mainnet_default],
    ["bittensor-mainnet", bittensor_mainnet_default],
    ["stable-mainnet", stable_mainnet_default],
    ["hyperliquid-mainnet", hyperliquid_mainnet_default],
    ["conflux-mainnet", conflux_mainnet_default],
    ["ethereum-mainnet-metis-1", ethereum_mainnet_metis_1_default],
    ["ethereum-mainnet-polygon-zkevm-1", ethereum_mainnet_polygon_zkevm_1_default],
    ["wemix-mainnet", wemix_mainnet_default],
    ["core-mainnet", core_mainnet_default],
    ["lisk-mainnet", lisk_mainnet_default],
    ["polkadot-mainnet-moonbeam", polkadot_mainnet_moonbeam_default],
    ["kusama-mainnet-moonriver", kusama_mainnet_moonriver_default],
    ["sei-mainnet", sei_mainnet_default],
    ["pharos-mainnet", pharos_mainnet_default],
    ["metal-mainnet", metal_mainnet_default],
    ["soneium-mainnet", soneium_mainnet_default],
    ["bitcichain-mainnet", bitcichain_mainnet_default],
    ["ronin-mainnet", ronin_mainnet_default],
    ["polkadot-mainnet-centrifuge", polkadot_mainnet_centrifuge_default],
    ["kava-mainnet", kava_mainnet_default],
    ["abstract-mainnet", abstract_mainnet_default],
    ["morph-mainnet", morph_mainnet_default],
    ["edge-mainnet", edge_mainnet_default],
    ["bitcoin-mainnet-botanix", bitcoin_mainnet_botanix_default],
    ["ethereum-mainnet-astar-zkevm-1", ethereum_mainnet_astar_zkevm_1_default],
    ["bitcoin-merlin-mainnet", bitcoin_merlin_mainnet_default],
    ["tempo-mainnet", tempo_mainnet_default],
    ["megaeth-mainnet", megaeth_mainnet_default],
    ["robinhood-mainnet", robinhood_mainnet_default],
    ["ethereum-mainnet-mantle-1", ethereum_mainnet_mantle_1_default],
    ["arc-mainnet", arc_mainnet_default],
    ["superseed-mainnet", superseed_mainnet_default],
    ["nibiru-mainnet", nibiru_mainnet_default],
    ["zetachain-mainnet", zetachain_mainnet_default],
    ["kaia-mainnet", kaia_mainnet_default],
    ["ethereum-mainnet-base-1", ethereum_mainnet_base_1_default],
    ["plasma-mainnet", plasma_mainnet_default],
    ["gate-layer-mainnet", gate_layer_mainnet_default],
    ["ethereum-mainnet-arbitrum-1-l3x-1", ethereum_mainnet_arbitrum_1_l3x_1_default],
    ["ethereum-mainnet-immutable-zkevm-1", ethereum_mainnet_immutable_zkevm_1_default],
    ["0g-mainnet", _0g_mainnet_default],
    ["everclear-mainnet", everclear_mainnet_default],
    ["apechain-mainnet", apechain_mainnet_default],
    ["ethereum-mainnet-mode-1", ethereum_mainnet_mode_1_default],
    ["ab-mainnet", ab_mainnet_default],
    ["adi-mainnet", adi_mainnet_default],
    ["ethereum-mainnet-arbitrum-1", ethereum_mainnet_arbitrum_1_default],
    ["celo-mainnet", celo_mainnet_default],
    ["etherlink-mainnet", etherlink_mainnet_default],
    ["hemi-mainnet", hemi_mainnet_default],
    ["avalanche-mainnet", avalanche_mainnet_default],
    ["neox-mainnet", neox_mainnet_default],
    ["ethereum-mainnet-zircuit-1", ethereum_mainnet_zircuit_1_default],
    ["memento-mainnet", memento_mainnet_default],
    ["ethereum-mainnet-ink-1", ethereum_mainnet_ink_1_default],
    ["ethereum-mainnet-linea-1", ethereum_mainnet_linea_1_default],
    ["nexon-mainnet-lith", nexon_mainnet_lith_default],
    ["bitcoin-mainnet-bob-1", bitcoin_mainnet_bob_1_default],
    ["treasure-mainnet", treasure_mainnet_default],
    ["mova-mainnet", mova_mainnet_default],
    ["mova-mainnet-2", mova_mainnet_2_default],
    ["nexon-mainnet-henesys", nexon_mainnet_henesys_default],
    ["berachain-mainnet", berachain_mainnet_default],
    ["codex-mainnet", codex_mainnet_default],
    ["ethereum-mainnet-blast-1", ethereum_mainnet_blast_1_default],
    ["plume-mainnet", plume_mainnet_default],
    ["creditcoin-mainnet", creditcoin_mainnet_default],
    ["gravity-mainnet", gravity_mainnet_default],
    ["ethereum-mainnet-taiko-1", ethereum_mainnet_taiko_1_default],
    ["bitcoin-mainnet-bitlayer-1", bitcoin_mainnet_bitlayer_1_default],
    ["avalanche-subnet-dexalot-mainnet", avalanche_subnet_dexalot_mainnet_default],
    ["ethereum-mainnet-scroll-1", ethereum_mainnet_scroll_1_default],
    ["polygon-mainnet-katana", polygon_mainnet_katana_default],
    ["nexon-qa", nexon_qa_default],
    ["zklink_nova-mainnet", zklink_nova_mainnet_default],
    ["nexon-stage", nexon_stage_default],
    ["ethereum-mainnet-arbitrum-1-treasure-1", ethereum_mainnet_arbitrum_1_treasure_1_default],
    ["jovay-mainnet", jovay_mainnet_default],
    ["zora-mainnet", zora_mainnet_default],
    ["corn-mainnet", corn_mainnet_default],
    ["tron-mainnet-evm", tron_mainnet_evm_default],
    ["dtcc-mainnet-appchain", dtcc_mainnet_appchain_default]
  ]),
  solana: new Map([["solana-mainnet", solana_mainnet_default]]),
  aptos: new Map([["aptos-mainnet", aptos_mainnet_default]]),
  sui: new Map([["sui-mainnet", sui_mainnet_default]]),
  ton: new Map([["ton-mainnet", ton_mainnet_default]]),
  tron: new Map([["tron-mainnet", tron_mainnet_default]])
};
var testnetByNameByFamily = {
  evm: new Map([
    ["bitcoin-testnet-rootstock", bitcoin_testnet_rootstock_default],
    ["telos-evm-testnet", telos_evm_testnet_default],
    ["polkadot-testnet-darwinia-pangoro", polkadot_testnet_darwinia_pangoro_default],
    ["xdc-testnet", xdc_testnet_default],
    ["coinex_smart_chain-testnet", coinex_smart_chain_testnet_default],
    ["polkadot-testnet-astar-shibuya", polkadot_testnet_astar_shibuya_default],
    ["gate-chain-testnet-meteora", gate_chain_testnet_meteora_default],
    ["binance_smart_chain-testnet", binance_smart_chain_testnet_default],
    ["velas-testnet", velas_testnet_default],
    ["ethereum-testnet-sepolia-hashkey-1", ethereum_testnet_sepolia_hashkey_1_default],
    ["shibarium-testnet-puppynet", shibarium_testnet_puppynet_default],
    ["ethereum-testnet-sepolia-xlayer-1", ethereum_testnet_sepolia_xlayer_1_default],
    ["cronos-zkevm-testnet-sepolia", cronos_zkevm_testnet_sepolia_default],
    ["ethereum-testnet-goerli-zksync-1", ethereum_testnet_goerli_zksync_1_default],
    ["cronos-testnet-zkevm-1", cronos_testnet_zkevm_1_default],
    ["hedera-testnet", hedera_testnet_default],
    ["ethereum-testnet-sepolia-zksync-1", ethereum_testnet_sepolia_zksync_1_default],
    ["cronos-testnet", cronos_testnet_default],
    ["near-testnet", near_testnet_default],
    ["ethereum-testnet-goerli-optimism-1", ethereum_testnet_goerli_optimism_1_default],
    ["areon-testnet", areon_testnet_default],
    ["janction-testnet-sepolia", janction_testnet_sepolia_default],
    ["private-testnet-obsidian", private_testnet_obsidian_default],
    ["ethereum-testnet-sepolia-mode-1", ethereum_testnet_sepolia_mode_1_default],
    ["bittensor-testnet", bittensor_testnet_default],
    ["hyperliquid-testnet", hyperliquid_testnet_default],
    ["kaia-testnet-kairos", kaia_testnet_kairos_default],
    ["bittorrent_chain-testnet", bittorrent_chain_testnet_default],
    ["wemix-testnet", wemix_testnet_default],
    ["core-testnet", core_testnet_default],
    ["bitcoin-testnet-bsquared-1", bitcoin_testnet_bsquared_1_default],
    ["polkadot-testnet-moonbeam-moonbase", polkadot_testnet_moonbeam_moonbase_default],
    ["ethereum-testnet-sepolia-unichain-1", ethereum_testnet_sepolia_unichain_1_default],
    ["sei-testnet-atlantic", sei_testnet_atlantic_default],
    ["geth-testnet", geth_testnet_default],
    [
      "ethereum-testnet-goerli-polygon-zkevm-1",
      ethereum_testnet_goerli_polygon_zkevm_1_default
    ],
    ["story-testnet", story_testnet_default],
    ["mint-testnet", mint_testnet_default],
    ["metal-testnet", metal_testnet_default],
    ["bitcichain-testnet", bitcichain_testnet_default],
    ["ethereum-testnet-sepolia-soneium-1", ethereum_testnet_sepolia_soneium_1_default],
    ["xlayer-testnet", xlayer_testnet_default],
    ["ronin-testnet-saigon", ronin_testnet_saigon_default],
    ["private-testnet-granite", private_testnet_granite_default],
    ["private-testnet-andesite", private_testnet_andesite_default],
    ["dtcc-testnet-andesite", dtcc_testnet_andesite_default],
    ["polkadot-testnet-centrifuge-altair", polkadot_testnet_centrifuge_altair_default],
    ["memento-testnet", memento_testnet_default],
    ["stable-testnet", stable_testnet_default],
    ["kava-testnet", kava_testnet_default],
    ["ethereum-testnet-sepolia-kroma-1", ethereum_testnet_sepolia_kroma_1_default],
    ["tac-testnet", tac_testnet_default],
    [
      "ethereum-testnet-sepolia-polygon-zkevm-1",
      ethereum_testnet_sepolia_polygon_zkevm_1_default
    ],
    ["ethereum-testnet-holesky-fraxtal-1", ethereum_testnet_holesky_fraxtal_1_default],
    ["ethereum-testnet-holesky-morph-1", ethereum_testnet_holesky_morph_1_default],
    ["ethereum-testnet-hoodi-morph", ethereum_testnet_hoodi_morph_default],
    ["bitcoin-testnet-botanix", bitcoin_testnet_botanix_default],
    ["fantom-testnet", fantom_testnet_default],
    ["ethereum-testnet-sepolia-lisk-1", ethereum_testnet_sepolia_lisk_1_default],
    ["ethereum-testnet-sepolia-worldchain-1", ethereum_testnet_sepolia_worldchain_1_default],
    ["ethereum-testnet-goerli-mantle-1", ethereum_testnet_goerli_mantle_1_default],
    ["ethereum-testnet-sepolia-mantle-1", ethereum_testnet_sepolia_mantle_1_default],
    ["binance_smart_chain-testnet-opbnb-1", binance_smart_chain_testnet_opbnb_1_default],
    ["nexon-dev", nexon_dev_default],
    ["megaeth-testnet", megaeth_testnet_default],
    ["megaeth-testnet-2", megaeth_testnet_2_default],
    ["everclear-testnet-sepolia", everclear_testnet_sepolia_default],
    ["nibiru-testnet", nibiru_testnet_default],
    ["ondo-testnet", ondo_testnet_default],
    ["neonlink-testnet", neonlink_testnet_default],
    ["plasma-testnet", plasma_testnet_default],
    ["gate-layer-testnet", gate_layer_testnet_default],
    ["monad-testnet", monad_testnet_default],
    ["gnosis_chain-testnet-chiado", gnosis_chain_testnet_chiado_default],
    ["mova-testnet", mova_testnet_default],
    ["abstract-testnet", abstract_testnet_default],
    [
      "ethereum-testnet-sepolia-arbitrum-1-l3x-1",
      ethereum_testnet_sepolia_arbitrum_1_l3x_1_default
    ],
    [
      "ethereum-testnet-sepolia-immutable-zkevm-1",
      ethereum_testnet_sepolia_immutable_zkevm_1_default
    ],
    ["sonic-testnet", sonic_testnet_default],
    ["0g-testnet-newton", _0g_testnet_newton_default],
    ["0g-testnet-galileo", _0g_testnet_galileo_default],
    ["0g-testnet-galileo-1", _0g_testnet_galileo_1_default],
    ["ethereum-testnet-holesky", ethereum_testnet_holesky_default],
    ["ab-testnet", ab_testnet_default],
    ["anvil-devnet", anvil_devnet_default],
    ["apechain-testnet-curtis", apechain_testnet_curtis_default],
    ["edge-testnet", edge_testnet_default],
    ["ethereum-testnet-sepolia-lens-1", ethereum_testnet_sepolia_lens_1_default],
    ["tempo-testnet", tempo_testnet_default],
    ["tempo-testnet-moderato", tempo_testnet_moderato_default],
    ["avalanche-testnet-fuji", avalanche_testnet_fuji_default],
    ["celo-testnet-alfajores", celo_testnet_alfajores_default],
    ["private-testnet-opala", private_testnet_opala_default],
    ["robinhood-testnet", robinhood_testnet_default],
    ["zircuit-testnet-garfield", zircuit_testnet_garfield_default],
    ["ethereum-testnet-sepolia-zircuit-1", ethereum_testnet_sepolia_zircuit_1_default],
    ["superseed-testnet", superseed_testnet_default],
    ["sonic-testnet-blaze", sonic_testnet_blaze_default],
    ["ethereum-testnet-goerli-linea-1", ethereum_testnet_goerli_linea_1_default],
    ["ethereum-testnet-sepolia-linea-1", ethereum_testnet_sepolia_linea_1_default],
    ["ethereum-testnet-sepolia-metis-1", ethereum_testnet_sepolia_metis_1_default],
    ["polygon-testnet-mumbai", polygon_testnet_mumbai_default],
    ["polygon-testnet-amoy", polygon_testnet_amoy_default],
    ["berachain-testnet-bepolia", berachain_testnet_bepolia_default],
    ["berachain-testnet-bartio", berachain_testnet_bartio_default],
    ["berachain-testnet-artio", berachain_testnet_artio_default],
    ["zero-g-testnet-galileo", zero_g_testnet_galileo_default],
    ["ethereum-testnet-goerli-base-1", ethereum_testnet_goerli_base_1_default],
    ["ethereum-testnet-sepolia-base-1", ethereum_testnet_sepolia_base_1_default],
    ["plume-devnet", plume_devnet_default],
    ["plume-testnet-sepolia", plume_testnet_sepolia_default],
    ["adi-testnet", adi_testnet_default],
    ["creditcoin-testnet", creditcoin_testnet_default],
    ["etherlink-testnet", etherlink_testnet_default],
    ["polygon-testnet-tatara", polygon_testnet_tatara_default],
    ["ethereum-testnet-holesky-taiko-1", ethereum_testnet_holesky_taiko_1_default],
    ["ethereum-testnet-hoodi-taiko", ethereum_testnet_hoodi_taiko_default],
    ["ethereum-testnet-hoodi-taiko-1", ethereum_testnet_hoodi_taiko_1_default],
    ["mind-testnet", mind_testnet_default],
    ["bitcoin-testnet-bitlayer-1", bitcoin_testnet_bitlayer_1_default],
    ["ethereum-testnet-sepolia-ronin-1", ethereum_testnet_sepolia_ronin_1_default],
    ["t-rex-testnet", t_rex_testnet_default],
    ["ethereum-testnet-goerli-arbitrum-1", ethereum_testnet_goerli_arbitrum_1_default],
    ["ethereum-testnet-sepolia-arbitrum-1", ethereum_testnet_sepolia_arbitrum_1_default],
    ["private-testnet-mica", private_testnet_mica_default],
    ["avalanche-subnet-dexalot-testnet", avalanche_subnet_dexalot_testnet_default],
    ["ethereum-testnet-sepolia-scroll-1", ethereum_testnet_sepolia_scroll_1_default],
    ["ethereum-testnet-hoodi", ethereum_testnet_hoodi_default],
    ["avalanche-testnet-nexon", avalanche_testnet_nexon_default],
    ["bitcoin-testnet-merlin", bitcoin_testnet_merlin_default],
    ["pharos-testnet", pharos_testnet_default],
    ["pharos-atlantic-testnet", pharos_atlantic_testnet_default],
    [
      "ethereum-testnet-sepolia-polygon-validium-1",
      ethereum_testnet_sepolia_polygon_validium_1_default
    ],
    ["hemi-testnet-sepolia", hemi_testnet_sepolia_default],
    ["ink-testnet-sepolia", ink_testnet_sepolia_default],
    ["bitcoin-testnet-sepolia-bob-1", bitcoin_testnet_sepolia_bob_1_default],
    ["zklink_nova-testnet", zklink_nova_testnet_default],
    ["codex-testnet", codex_testnet_default],
    [
      "ethereum-testnet-sepolia-arbitrum-1-treasure-1",
      ethereum_testnet_sepolia_arbitrum_1_treasure_1_default
    ],
    ["treasure-testnet-topaz", treasure_testnet_topaz_default],
    ["jovay-testnet", jovay_testnet_default],
    ["arc-testnet", arc_testnet_default],
    ["dogeos-testnet-chikyu", dogeos_testnet_chikyu_default],
    ["gravity-testnet-longevity", gravity_testnet_longevity_default],
    ["celo-sepolia", celo_sepolia_default],
    ["ethereum-testnet-sepolia", ethereum_testnet_sepolia_default],
    ["ethereum-testnet-sepolia-optimism-1", ethereum_testnet_sepolia_optimism_1_default],
    ["neox-testnet-t4", neox_testnet_t4_default],
    ["ethereum-testnet-sepolia-corn-1", ethereum_testnet_sepolia_corn_1_default],
    ["filecoin-testnet", filecoin_testnet_default],
    ["plume-testnet", plume_testnet_default],
    ["ethereum-testnet-sepolia-blast-1", ethereum_testnet_sepolia_blast_1_default],
    ["zora-testnet", zora_testnet_default],
    ["private-testnet-quartzite", private_testnet_quartzite_default],
    ["private-testnet-rhyolite", private_testnet_rhyolite_default],
    ["private-testnet-pumice", private_testnet_pumice_default],
    ["tron-testnet-shasta-evm", tron_testnet_shasta_evm_default],
    ["tron-devnet-evm", tron_devnet_evm_default],
    ["tron-testnet-nile-evm", tron_testnet_nile_evm_default],
    ["private-testnet-basalt", private_testnet_basalt_default],
    ["glamsterdam-devnet-6", glamsterdam_devnet_6_default],
    ["glamsterdam-devnet-5", glamsterdam_devnet_5_default],
    ["ethereum-testnet-plataberget", ethereum_testnet_plataberget_default]
  ]),
  solana: new Map([
    ["solana-testnet", solana_testnet_default],
    ["solana-devnet", solana_devnet_default]
  ]),
  aptos: new Map([
    ["aptos-testnet", aptos_testnet_default],
    ["aptos-localnet", aptos_localnet_default]
  ]),
  sui: new Map([
    ["sui-testnet", sui_testnet_default],
    ["sui-localnet", sui_localnet_default]
  ]),
  ton: new Map([
    ["ton-testnet", ton_testnet_default],
    ["ton-localnet", ton_localnet_default]
  ]),
  tron: new Map([
    ["tron-testnet-shasta", tron_testnet_shasta_default],
    ["tron-devnet", tron_devnet_default],
    ["tron-testnet-nile", tron_testnet_nile_default]
  ])
};
class NetworkLookup {
  maps;
  constructor(maps) {
    this.maps = maps;
  }
  find(options) {
    const { chainSelector, chainSelectorName, isTestnet, chainFamily } = options;
    const getBySelector = (map) => {
      if (chainSelector === undefined)
        return;
      return map.get(chainSelector);
    };
    if (chainSelector === undefined && !chainSelectorName) {
      return;
    }
    if (chainFamily && chainSelector !== undefined) {
      if (isTestnet === false) {
        return getBySelector(this.maps.mainnetBySelectorByFamily[chainFamily]);
      }
      if (isTestnet === true) {
        return getBySelector(this.maps.testnetBySelectorByFamily[chainFamily]);
      }
      let network = getBySelector(this.maps.testnetBySelectorByFamily[chainFamily]);
      if (!network) {
        network = getBySelector(this.maps.mainnetBySelectorByFamily[chainFamily]);
      }
      return network;
    }
    if (chainFamily && chainSelectorName) {
      if (isTestnet === false) {
        return this.maps.mainnetByNameByFamily[chainFamily].get(chainSelectorName);
      }
      if (isTestnet === true) {
        return this.maps.testnetByNameByFamily[chainFamily].get(chainSelectorName);
      }
      let network = this.maps.testnetByNameByFamily[chainFamily].get(chainSelectorName);
      if (!network) {
        network = this.maps.mainnetByNameByFamily[chainFamily].get(chainSelectorName);
      }
      return network;
    }
    if (chainSelector !== undefined) {
      if (isTestnet === false) {
        return getBySelector(this.maps.mainnetBySelector);
      }
      if (isTestnet === true) {
        return getBySelector(this.maps.testnetBySelector);
      }
      let network = getBySelector(this.maps.testnetBySelector);
      if (!network) {
        network = getBySelector(this.maps.mainnetBySelector);
      }
      return network;
    }
    if (chainSelectorName) {
      if (isTestnet === false) {
        return this.maps.mainnetByName.get(chainSelectorName);
      }
      if (isTestnet === true) {
        return this.maps.testnetByName.get(chainSelectorName);
      }
      let network = this.maps.testnetByName.get(chainSelectorName);
      if (!network) {
        network = this.maps.mainnetByName.get(chainSelectorName);
      }
      return network;
    }
    return;
  }
}
var defaultLookup = new NetworkLookup({
  mainnetByName,
  mainnetByNameByFamily,
  mainnetBySelector,
  mainnetBySelectorByFamily,
  testnetByName,
  testnetByNameByFamily,
  testnetBySelector,
  testnetBySelectorByFamily
});
var getNetwork = (options) => defaultLookup.find(options);

class Int64 {
  static INT64_MIN = -(2n ** 63n);
  static INT64_MAX = 2n ** 63n - 1n;
  value;
  static toInt64Bigint(v) {
    if (typeof v === "string") {
      const bi = BigInt(v);
      return Int64.toInt64Bigint(bi);
    }
    if (typeof v === "bigint") {
      if (v > Int64.INT64_MAX)
        throw new Error("int64 overflow");
      else if (v < Int64.INT64_MIN)
        throw new Error("int64 underflow");
      return v;
    }
    assertSafeIntegerNumber(v, "int64");
    const bi = BigInt(v);
    if (bi > Int64.INT64_MAX)
      throw new Error("int64 overflow");
    else if (bi < Int64.INT64_MIN)
      throw new Error("int64 underflow");
    return bi;
  }
  constructor(v) {
    this.value = Int64.toInt64Bigint(v);
  }
  add(i, safe = true) {
    return safe ? new Int64(this.value + i.value) : new Int64(BigInt.asIntN(64, this.value + i.value));
  }
  sub(i, safe = true) {
    return safe ? new Int64(this.value - i.value) : new Int64(BigInt.asIntN(64, this.value - i.value));
  }
  mul(i, safe = true) {
    return safe ? new Int64(this.value * i.value) : new Int64(BigInt.asIntN(64, this.value * i.value));
  }
  div(i, safe = true) {
    return safe ? new Int64(this.value / i.value) : new Int64(BigInt.asIntN(64, this.value / i.value));
  }
}

class UInt64 {
  static UINT64_MAX = 2n ** 64n - 1n;
  value;
  static toUint64Bigint(v) {
    if (typeof v === "string") {
      const bi = BigInt(v);
      return UInt64.toUint64Bigint(bi);
    }
    if (typeof v === "bigint") {
      if (v > UInt64.UINT64_MAX)
        throw new Error("uint64 overflow");
      else if (v < 0n)
        throw new Error("uint64 underflow");
      return v;
    }
    assertSafeIntegerNumber(v, "uint64");
    const bi = BigInt(v);
    if (bi > UInt64.UINT64_MAX)
      throw new Error("uint64 overflow");
    else if (bi < 0n)
      throw new Error("uint64 underflow");
    return bi;
  }
  constructor(v) {
    this.value = UInt64.toUint64Bigint(v);
  }
  add(i, safe = true) {
    return safe ? new UInt64(this.value + i.value) : new UInt64(BigInt.asUintN(64, this.value + i.value));
  }
  sub(i, safe = true) {
    return safe ? new UInt64(this.value - i.value) : new UInt64(BigInt.asUintN(64, this.value - i.value));
  }
  mul(i, safe = true) {
    return safe ? new UInt64(this.value * i.value) : new UInt64(BigInt.asUintN(64, this.value * i.value));
  }
  div(i, safe = true) {
    return safe ? new UInt64(this.value / i.value) : new UInt64(BigInt.asUintN(64, this.value / i.value));
  }
}

class Decimal {
  coeffecient;
  exponent;
  static parse(s) {
    const m = /^([+-])?(\d*)(?:\.(\d*))?$/.exec(s.trim());
    if (!m || m[2] === "" && (m[3] === undefined || m[3] === ""))
      throw new Error("invalid decimal string");
    const signStr = m[1] ?? "+";
    const intPart = m[2] ?? "0";
    let fracPart = m[3] ?? "";
    while (fracPart.length > 0 && fracPart[fracPart.length - 1] === "0") {
      fracPart = fracPart.slice(0, -1);
    }
    const exponent = fracPart.length === 0 ? 0 : -fracPart.length;
    const digits = intPart + fracPart || "0";
    const coeffecient = BigInt((signStr === "-" ? "-" : "") + digits);
    return new Decimal(coeffecient, exponent);
  }
  constructor(coeffecient, exponent) {
    this.coeffecient = coeffecient;
    this.exponent = exponent;
  }
}

class Value {
  value;
  static from(value) {
    return new Value(value);
  }
  static wrap(value) {
    return new Value(value);
  }
  constructor(value) {
    if (value instanceof Value) {
      this.value = value.value;
    } else if (isValueProto(value)) {
      this.value = value;
    } else {
      this.value = Value.wrapInternal(value);
    }
  }
  proto() {
    return this.value;
  }
  static toUint8Array(input) {
    return input instanceof Uint8Array ? input : new Uint8Array(input);
  }
  static bigintToBytesBE(abs) {
    if (abs === 0n)
      return new Uint8Array;
    let hex = abs.toString(16);
    if (hex.length % 2 === 1)
      hex = "0" + hex;
    const len = hex.length / 2;
    const out = new Uint8Array(len);
    for (let i = 0;i < len; i++) {
      out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }
  static bigIntToProtoBigInt(v) {
    const sign = v === 0n ? 0n : v < 0n ? -1n : 1n;
    const abs = v < 0n ? -v : v;
    return create(BigIntSchema, {
      absVal: Value.bigintToBytesBE(abs),
      sign
    });
  }
  static toTimestamp(d) {
    const date = d instanceof Date ? d : new Date(d);
    return timestampFromDate(date);
  }
  static isPlainObject(v) {
    return typeof v === "object" && v !== null && v.constructor === Object;
  }
  static isObject(v) {
    return typeof v === "object" && v !== null;
  }
  static wrapInternal(v) {
    if (v === null || v === undefined)
      throw new Error("cannot wrap null/undefined into Value");
    if (v instanceof Value) {
      return v.proto();
    }
    if (v instanceof Uint8Array)
      return create(ValueSchema2, { value: { case: "bytesValue", value: v } });
    if (v instanceof ArrayBuffer)
      return create(ValueSchema2, {
        value: { case: "bytesValue", value: Value.toUint8Array(v) }
      });
    if (v instanceof Date)
      return create(ValueSchema2, {
        value: { case: "timeValue", value: Value.toTimestamp(v) }
      });
    if (v instanceof Int64) {
      return create(ValueSchema2, {
        value: { case: "int64Value", value: v.value }
      });
    }
    if (v instanceof UInt64) {
      return create(ValueSchema2, {
        value: { case: "uint64Value", value: v.value }
      });
    }
    if (v instanceof Decimal) {
      const decimalProto = create(DecimalSchema, {
        coefficient: Value.bigIntToProtoBigInt(v.coeffecient),
        exponent: v.exponent
      });
      return create(ValueSchema2, {
        value: { case: "decimalValue", value: decimalProto }
      });
    }
    switch (typeof v) {
      case "string":
        return create(ValueSchema2, {
          value: { case: "stringValue", value: v }
        });
      case "boolean":
        return create(ValueSchema2, { value: { case: "boolValue", value: v } });
      case "bigint": {
        return create(ValueSchema2, {
          value: { case: "bigintValue", value: Value.bigIntToProtoBigInt(v) }
        });
      }
      case "number": {
        return create(ValueSchema2, {
          value: { case: "float64Value", value: v }
        });
      }
      case "object":
        break;
      default:
        throw new Error(`unsupported type: ${typeof v}`);
    }
    if (Array.isArray(v)) {
      const fields = v.map(Value.wrapInternal);
      const list = create(ListSchema, { fields });
      return create(ValueSchema2, { value: { case: "listValue", value: list } });
    }
    if (Value.isPlainObject(v)) {
      const fields = {};
      for (const [k, vv] of Object.entries(v)) {
        fields[k] = Value.wrapInternal(vv);
      }
      const map = create(MapSchema, { fields });
      return create(ValueSchema2, { value: { case: "mapValue", value: map } });
    }
    if (Value.isObject(v) && v.constructor !== Object) {
      const fields = {};
      for (const [k, vv] of Object.entries(v)) {
        fields[k] = Value.wrapInternal(vv);
      }
      const map = create(MapSchema, { fields });
      return create(ValueSchema2, { value: { case: "mapValue", value: map } });
    }
    throw new Error("unsupported object instance");
  }
  unwrap() {
    return unwrap(this.value);
  }
  unwrapToType(options) {
    const unwrapped = this.unwrap();
    if ("instance" in options) {
      if (typeof unwrapped !== typeof options.instance) {
        throw new Error(`Cannot unwrap to type ${typeof options.instance}`);
      }
      return unwrapped;
    }
    if (options.schema) {
      return options.schema.parse(unwrapped);
    }
    const obj = options.factory();
    if (typeof unwrapped === "object" && unwrapped !== null) {
      Object.assign(obj, unwrapped);
    } else {
      throw new Error(`Cannot copy properties from primitive value to object instance. Use a schema instead.`);
    }
    return obj;
  }
}
function unwrap(value) {
  switch (value.value.case) {
    case "stringValue":
      return value.value.value;
    case "boolValue":
      return value.value.value;
    case "bytesValue":
      return value.value.value;
    case "int64Value":
      return new Int64(value.value.value);
    case "uint64Value":
      return new UInt64(value.value.value);
    case "float64Value":
      return value.value.value;
    case "bigintValue": {
      const bigIntValue = value.value.value;
      const absVal = bigIntValue.absVal;
      const sign = bigIntValue.sign;
      let result = 0n;
      for (const byte of absVal) {
        result = result << 8n | BigInt(byte);
      }
      return sign < 0n ? -result : result;
    }
    case "timeValue": {
      return timestampDate(value.value.value);
    }
    case "listValue": {
      const list = value.value.value;
      return list.fields.map(unwrap);
    }
    case "mapValue": {
      const map = value.value.value;
      const result = {};
      for (const [key, val] of Object.entries(map.fields)) {
        result[key] = unwrap(val);
      }
      return result;
    }
    case "decimalValue": {
      const decimal = value.value.value;
      const coefficient = decimal.coefficient;
      const exponent = decimal.exponent;
      if (!coefficient) {
        return new Decimal(0n, 0);
      }
      let coeffBigInt;
      const absVal = coefficient.absVal;
      const sign = coefficient.sign;
      let result = 0n;
      for (const byte of absVal) {
        result = result << 8n | BigInt(byte);
      }
      coeffBigInt = sign < 0n ? -result : result;
      return new Decimal(coeffBigInt, exponent);
    }
    default:
      throw new Error(`Unsupported value type: ${value.value.case}`);
  }
}
function isValueProto(value) {
  return value != null && typeof value.$typeName === "string" && value.$typeName === "values.v1.Value";
}
async function standardValidate(schema, input) {
  let result = schema["~standard"].validate(input);
  if (result instanceof Promise)
    result = await result;
  if (result.issues) {
    const errorDetails = JSON.stringify(result.issues, null, 2);
    throw new Error(`Config validation failed. Expectations were not matched:

${errorDetails}`);
  }
  return result.value;
}
var defaultJsonParser = (config) => JSON.parse(Buffer.from(config).toString());
var configHandler = async (request, { configParser, configSchema } = {}) => {
  const config = request.config;
  const parser = configParser || defaultJsonParser;
  let intermediateConfig;
  try {
    intermediateConfig = parser(config);
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to parse configuration: ${error.message}`);
    } else {
      throw new Error(`Failed to parse configuration: unknown error`);
    }
  }
  return configSchema ? standardValidate(configSchema, intermediateConfig) : intermediateConfig;
};
var globalHostBindingsSchema = objectType({
  switchModes: functionType().args(nativeEnumType(Mode)).returns(voidType()),
  log: functionType().args(stringType()).returns(voidType()),
  sendResponse: functionType().args(unionType([instanceOfType(Uint8Array), custom2()])).returns(numberType()),
  versionV2: functionType().args().returns(voidType()),
  callCapability: functionType().args(unionType([instanceOfType(Uint8Array), custom2()])).returns(numberType()),
  awaitCapabilities: functionType().args(unionType([instanceOfType(Uint8Array), custom2()]), numberType()).returns(unionType([instanceOfType(Uint8Array), custom2()])),
  getSecrets: functionType().args(unionType([instanceOfType(Uint8Array), custom2()]), numberType()).returns(anyType()),
  awaitSecrets: functionType().args(unionType([instanceOfType(Uint8Array), custom2()]), numberType()).returns(unionType([instanceOfType(Uint8Array), custom2()])),
  getWasiArgs: functionType().args().returns(stringType()),
  now: functionType().args().returns(numberType()),
  sleep: functionType().args(numberType()).returns(voidType())
});
var validateGlobalHostBindings = () => {
  const globalFunctions = globalThis;
  try {
    return globalHostBindingsSchema.parse(globalFunctions);
  } catch (error) {
    const missingFunctions = Object.keys(globalHostBindingsSchema.shape).filter((key) => !(key in globalFunctions));
    throw new Error(`Missing required global host functions: ${missingFunctions.join(", ")}. ` + `The CRE WASM runtime must provide these functions on globalThis. ` + `This usually means the workflow is being executed outside the CRE WASM environment, ` + `or the host runtime version is incompatible with this SDK version.`);
  }
};
var _hostBindings = null;
var hostBindings = new Proxy({}, {
  get(target, prop) {
    if (!_hostBindings) {
      _hostBindings = validateGlobalHostBindings();
    }
    return _hostBindings[prop];
  }
});

class ConsensusCapability {
  static CAPABILITY_ID = "consensus@1.0.0-alpha";
  static CAPABILITY_NAME = "consensus";
  static CAPABILITY_VERSION = "1.0.0-alpha";
  simple(runtime, input) {
    let payload;
    if (input.$typeName) {
      payload = input;
    } else {
      payload = fromJson(SimpleConsensusInputsSchema, input);
    }
    const capabilityId = ConsensusCapability.CAPABILITY_ID;
    const capabilityResponse = runtime.callCapability({
      capabilityId,
      method: "Simple",
      payload,
      inputSchema: SimpleConsensusInputsSchema,
      outputSchema: ValueSchema2
    });
    return {
      result: () => {
        const result = capabilityResponse.result();
        return result;
      }
    };
  }
  report(runtime, input) {
    let payload;
    if (input.$typeName) {
      payload = input;
    } else {
      payload = fromJson(ReportRequestSchema, input);
    }
    const capabilityId = ConsensusCapability.CAPABILITY_ID;
    const capabilityResponse = runtime.callCapability({
      capabilityId,
      method: "Report",
      payload,
      inputSchema: ReportRequestSchema,
      outputSchema: ReportResponseSchema
    });
    return {
      result: () => {
        const result = capabilityResponse.result();
        return new Report(result);
      }
    };
  }
}
var DEFAULT_SECRET_NAMESPACE = "main";

class BaseRuntimeImpl {
  config;
  nextCallId;
  helpers;
  maxResponseSize;
  mode;
  modeError;
  constructor(config, nextCallId, helpers, maxResponseSize, mode) {
    this.config = config;
    this.nextCallId = nextCallId;
    this.helpers = helpers;
    this.maxResponseSize = maxResponseSize;
    this.mode = mode;
  }
  callCapability({ capabilityId, method, payload, inputSchema, outputSchema }) {
    if (this.modeError) {
      return {
        result: () => {
          throw this.modeError;
        }
      };
    }
    const callbackId = this.allocateCallbackId();
    const anyPayload = anyPack(inputSchema, payload);
    const req = create(CapabilityRequestSchema, {
      id: capabilityId,
      method,
      payload: anyPayload,
      callbackId
    });
    if (!this.helpers.call(req)) {
      return {
        result: () => {
          throw new CapabilityError(`Capability '${capabilityId}' not found: the host rejected the call to method '${method}'. Verify the capability ID is correct and the capability is available in this CRE environment`, {
            callbackId,
            method,
            capabilityId
          });
        }
      };
    }
    return {
      result: () => this.awaitAndUnwrapCapabilityResponse(callbackId, capabilityId, method, outputSchema)
    };
  }
  allocateCallbackId() {
    const callbackId = this.nextCallId;
    if (this.mode === Mode.DON) {
      this.nextCallId++;
    } else {
      this.nextCallId--;
    }
    return callbackId;
  }
  awaitAndUnwrapCapabilityResponse(callbackId, capabilityId, method, outputSchema) {
    const awaitRequest = create(AwaitCapabilitiesRequestSchema, {
      ids: [callbackId]
    });
    const awaitResponse = this.helpers.await(awaitRequest, this.maxResponseSize);
    const capabilityResponse = awaitResponse.responses[callbackId];
    if (!capabilityResponse) {
      throw new CapabilityError(`No response found for capability '${capabilityId}' method '${method}' (callback ID ${callbackId}): the host returned a response map that does not contain an entry for this call`, {
        capabilityId,
        method,
        callbackId
      });
    }
    const response = capabilityResponse.response;
    switch (response.case) {
      case "payload": {
        try {
          return anyUnpack(response.value, outputSchema);
        } catch {
          throw new CapabilityError(`Failed to deserialize response payload for capability '${capabilityId}' method '${method}': the response could not be unpacked into the expected output schema`, {
            capabilityId,
            method,
            callbackId
          });
        }
      }
      case "error":
        throw deserializeErrorFromString(response.value);
      default:
        throw new CapabilityError(`Unexpected response type '${response.case}' for capability '${capabilityId}' method '${method}': expected 'payload' or 'error'`, {
          capabilityId,
          method,
          callbackId
        });
    }
  }
  getNextCallId() {
    return this.nextCallId;
  }
  now() {
    return new Date(this.helpers.now());
  }
  sleep(ms) {
    this.helpers.sleep(ms);
  }
  log(message) {
    this.helpers.log(message);
  }
}

class NodeRuntimeImpl extends BaseRuntimeImpl {
  _isNodeRuntime = true;
  constructor(config, nextCallId, helpers, maxResponseSize) {
    helpers.switchModes(Mode.NODE);
    super(config, nextCallId, helpers, maxResponseSize, Mode.NODE);
  }
}

class RuntimeImpl extends BaseRuntimeImpl {
  nextNodeCallId = -1;
  constructor(config, nextCallId, helpers, maxResponseSize) {
    helpers.switchModes(Mode.DON);
    super(config, nextCallId, helpers, maxResponseSize, Mode.DON);
  }
  runInNodeMode(fn, consensusAggregation, unwrapOptions) {
    return (...args) => {
      this.modeError = new DonModeError;
      const nodeRuntime = new NodeRuntimeImpl(this.config, this.nextNodeCallId, this.helpers, this.maxResponseSize);
      const consensusInput = this.prepareConsensusInput(consensusAggregation);
      try {
        const observation = fn(nodeRuntime, ...args);
        this.captureObservation(consensusInput, observation, consensusAggregation.descriptor);
      } catch (e) {
        this.captureError(consensusInput, e);
      } finally {
        this.restoreDonMode(nodeRuntime);
      }
      return this.runConsensusAndWrap(consensusInput, unwrapOptions);
    };
  }
  prepareConsensusInput(consensusAggregation) {
    const consensusInput = create(SimpleConsensusInputsSchema, {
      descriptors: consensusAggregation.descriptor
    });
    if (consensusAggregation.defaultValue) {
      const defaultValue = Value.from(consensusAggregation.defaultValue).proto();
      clearIgnoredFields(defaultValue, consensusAggregation.descriptor);
      consensusInput.default = defaultValue;
    }
    return consensusInput;
  }
  captureObservation(consensusInput, observation, descriptor) {
    const observationValue = Value.from(observation).proto();
    clearIgnoredFields(observationValue, descriptor);
    consensusInput.observation = {
      case: "value",
      value: observationValue
    };
  }
  captureError(consensusInput, e) {
    consensusInput.observation = {
      case: "error",
      value: e instanceof Error && e.message || String(e)
    };
  }
  restoreDonMode(nodeRuntime) {
    this.modeError = undefined;
    this.nextNodeCallId = nodeRuntime.nextCallId;
    nodeRuntime.modeError = new NodeModeError;
    this.helpers.switchModes(Mode.DON);
  }
  runConsensusAndWrap(consensusInput, unwrapOptions) {
    const consensus = new ConsensusCapability;
    const call = consensus.simple(this, consensusInput);
    return {
      result: () => {
        const result = call.result();
        const wrappedValue = Value.wrap(result);
        return unwrapOptions ? wrappedValue.unwrapToType(unwrapOptions) : wrappedValue.unwrap();
      }
    };
  }
  getSecrets(requests) {
    if (this.modeError) {
      return {
        result: () => {
          throw this.modeError;
        }
      };
    }
    const normalizedRequests = requests.map((request) => request.$typeName ? create(SecretRequestSchema, {
      id: request.id,
      namespace: request.namespace || DEFAULT_SECRET_NAMESPACE
    }) : create(SecretRequestSchema, {
      id: request.id,
      namespace: request.namespace || DEFAULT_SECRET_NAMESPACE
    }));
    if (normalizedRequests.length === 0) {
      return {
        result: () => ({})
      };
    }
    const seenIds = new Set;
    for (const request of normalizedRequests) {
      if (seenIds.has(request.id)) {
        return {
          result: () => {
            throw new SecretsBatchError(normalizedRequests, `duplicate secret id requested: ${request.id}`);
          }
        };
      }
      seenIds.add(request.id);
    }
    const id = this.nextCallId;
    this.nextCallId++;
    const secretsReq = create(GetSecretsRequestSchema, {
      callbackId: id,
      requests: normalizedRequests
    });
    try {
      this.helpers.getSecrets(secretsReq, this.maxResponseSize);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        result: () => {
          throw new SecretsBatchError(normalizedRequests, message);
        }
      };
    }
    return {
      result: () => this.awaitAndUnwrapSecrets(id, normalizedRequests)
    };
  }
  getSecret(request) {
    const secretRequest = request.$typeName ? request : create(SecretRequestSchema, request);
    const getSecretsCall = this.getSecrets([secretRequest]);
    return {
      result: () => {
        let secretMap;
        try {
          secretMap = getSecretsCall.result();
        } catch (err) {
          if (err instanceof SecretsBatchError) {
            throw new SecretsError(secretRequest, err.error);
          }
          throw err;
        }
        return this.unwrapSingleSecretResult(secretMap, secretRequest);
      }
    };
  }
  awaitAndUnwrapSecrets(id, requests) {
    const awaitRequest = create(AwaitSecretsRequestSchema, { ids: [id] });
    let awaitResponse;
    try {
      awaitResponse = this.helpers.awaitSecrets(awaitRequest, this.maxResponseSize);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new SecretsBatchError(requests, message);
    }
    const secretsResponse = awaitResponse.responses[id];
    if (!secretsResponse) {
      throw new SecretsBatchError(requests, "no response");
    }
    if (secretsResponse.responses.length !== requests.length) {
      throw new SecretsBatchError(requests, "invalid value returned from host");
    }
    const failedResponses = secretsResponse.responses.filter((response) => response.response.case === "error");
    if (failedResponses.length > 0) {
      const errorMessages = failedResponses.map((response) => {
        if (response.response.case !== "error") {
          return "unknown: unknown error";
        }
        const { id, error } = response.response.value;
        return `${id || "unknown"}: ${error || "unknown error"}`;
      });
      throw new SecretsBatchError(requests, errorMessages.join(`
`));
    }
    const result = {};
    for (let i = 0;i < requests.length; i++) {
      const response = secretsResponse.responses[i];
      if (response.response.case !== "secret") {
        throw new SecretsBatchError(requests, "cannot unmarshal returned value from host");
      }
      result[requests[i].id] = response.response.value;
    }
    return result;
  }
  unwrapSingleSecretResult(secretMap, request) {
    const secret = secretMap[request.id];
    if (!secret) {
      throw new SecretsError(request, "invalid value returned from host");
    }
    return secret;
  }
  report(input) {
    const consensus = new ConsensusCapability;
    const call = consensus.report(this, input);
    return {
      result: () => call.result()
    };
  }
}

class TeeRuntimeImpl {
  config;
  nextCallId;
  runtime;
  constructor(config, nextCallId, helpers, maxResponseSize) {
    this.config = config;
    this.nextCallId = nextCallId;
    this.runtime = new RuntimeImpl(config, nextCallId, helpers, maxResponseSize);
  }
  getSecrets(requests) {
    return this.runtime.getSecrets(requests);
  }
  getSecret(request) {
    return this.runtime.getSecret(request);
  }
  now() {
    return this.runtime.now();
  }
  log(message) {
    this.runtime.log(message);
  }
  callCapability({ capabilityId, method, payload, inputSchema, outputSchema }) {
    return this.runtime.callCapability({
      capabilityId,
      method,
      payload,
      inputSchema,
      outputSchema
    });
  }
  reportFromDon(input) {
    return this.runtime.report(input);
  }
  usingTheDons() {
    return this.runtime;
  }
}
function clearIgnoredFields(value, descriptor) {
  if (!descriptor || !value) {
    return;
  }
  const fieldsMap = descriptor.descriptor?.case === "fieldsMap" ? descriptor.descriptor.value : undefined;
  if (!fieldsMap) {
    return;
  }
  if (value.value?.case === "mapValue") {
    const mapValue = value.value.value;
    if (!mapValue || !mapValue.fields) {
      return;
    }
    for (const [key, val] of Object.entries(mapValue.fields)) {
      const nestedDescriptor = fieldsMap.fields[key];
      if (!nestedDescriptor) {
        delete mapValue.fields[key];
        continue;
      }
      const nestedFieldsMap = nestedDescriptor.descriptor?.case === "fieldsMap" ? nestedDescriptor.descriptor.value : undefined;
      if (nestedFieldsMap && val.value?.case === "mapValue") {
        clearIgnoredFields(val, nestedDescriptor);
      }
    }
  }
}

class Runtime extends RuntimeImpl {
  constructor(config, nextCallId, maxResponseSize) {
    super(config, nextCallId, WasmRuntimeHelpers.getInstance(), maxResponseSize);
  }
}

class TeeRuntime extends TeeRuntimeImpl {
  constructor(config, nextCallId, maxResponseSize) {
    super(config, nextCallId, WasmRuntimeHelpers.getInstance(), maxResponseSize);
  }
}
function toI32ResponseSize(maxResponseSize) {
  if (maxResponseSize > 2147483647n || maxResponseSize < -2147483648n) {
    throw new Error(`maxResponseSize ${maxResponseSize} exceeds i32 range. Expected a value between -2147483648 and 2147483647`);
  }
  return Math.trunc(Number(maxResponseSize));
}

class WasmRuntimeHelpers {
  static instance;
  constructor() {}
  now() {
    return hostBindings.now();
  }
  sleep(ms) {
    hostBindings.sleep(ms);
  }
  static getInstance() {
    if (!WasmRuntimeHelpers.instance) {
      WasmRuntimeHelpers.instance = new WasmRuntimeHelpers;
    }
    return WasmRuntimeHelpers.instance;
  }
  call(request) {
    return hostBindings.callCapability(toBinary(CapabilityRequestSchema, request)) >= 0;
  }
  await(request, maxResponseSize) {
    const responseSize = toI32ResponseSize(maxResponseSize);
    const response = hostBindings.awaitCapabilities(toBinary(AwaitCapabilitiesRequestSchema, request), responseSize);
    const responseBytes = Array.isArray(response) ? new Uint8Array(response) : response;
    return fromBinary(AwaitCapabilitiesResponseSchema, responseBytes);
  }
  getSecrets(request, maxResponseSize) {
    const responseSize = toI32ResponseSize(maxResponseSize);
    hostBindings.getSecrets(toBinary(GetSecretsRequestSchema, request), responseSize);
  }
  awaitSecrets(request, maxResponseSize) {
    const responseSize = toI32ResponseSize(maxResponseSize);
    const response = hostBindings.awaitSecrets(toBinary(AwaitSecretsRequestSchema, request), responseSize);
    const responseBytes = Array.isArray(response) ? new Uint8Array(response) : response;
    return fromBinary(AwaitSecretsResponseSchema, responseBytes);
  }
  switchModes(mode) {
    hostBindings.switchModes(mode);
  }
  log(message) {
    hostBindings.log(message);
  }
}

class RunnerBase {
  config;
  request;
  constructor(config, request) {
    this.config = config;
    this.request = request;
  }
  static async newRunnerHelper(newRunner, configHandlerParams) {
    hostBindings.versionV2();
    const request = RunnerBase.getRequest();
    const config = await configHandler(request, configHandlerParams);
    return newRunner(config, request);
  }
  static getRequest() {
    const argsString = hostBindings.getWasiArgs();
    let args;
    try {
      args = JSON.parse(argsString);
    } catch (e) {
      throw new Error("Invalid request: could not parse WASI arguments as JSON. Ensure the WASM runtime is passing valid arguments to the workflow");
    }
    if (args.length !== 2) {
      throw new Error(`Invalid request: expected exactly 2 WASI arguments (script name and base64-encoded request payload), but received ${args.length}`);
    }
    const base64Request = args[1];
    const bytes = Buffer.from(base64Request, "base64");
    return fromBinary(ExecuteRequestSchema, bytes);
  }
  async run(initFn) {
    const runtime = new Runtime(this.config, 0, this.request.maxResponseSize);
    let result;
    try {
      const workflow = await initFn(this.config, {
        getSecrets: runtime.getSecrets.bind(runtime),
        getSecret: runtime.getSecret.bind(runtime)
      });
      switch (this.request.request.case) {
        case "subscribe":
          result = this.handleSubscribePhase(this.request, workflow);
          break;
        case "trigger":
          result = this.handleExecutionPhase(this.request, workflow, runtime);
          break;
        case "preHook":
          result = this.handlePreHookPhase(this.request, workflow);
          break;
        default:
          throw new Error(`Unknown request type '${this.request.request.case}': expected 'subscribe', 'trigger', or 'preHook'. This may indicate a version mismatch between the SDK and the CRE runtime`);
      }
    } catch (e) {
      const err = e instanceof Error ? e.message : String(e);
      result = create(ExecutionResultSchema, {
        result: { case: "error", value: err }
      });
    }
    const awaitedResult = await result;
    hostBindings.sendResponse(toBinary(ExecutionResultSchema, awaitedResult));
  }
  async handleExecutionPhase(req, workflow, runtime) {
    if (req.request.case !== "trigger") {
      throw new Error(`cannot handle non-trigger request as a trigger: received request type '${req.request.case}' in handleExecutionPhase. This is an internal SDK error`);
    }
    const triggerMsg = req.request.value;
    const id = BigInt(triggerMsg.id);
    if (id > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error(`Trigger ID ${id} exceeds JavaScript safe integer range (Number.MAX_SAFE_INTEGER = ${Number.MAX_SAFE_INTEGER}). This trigger ID cannot be safely represented as a number`);
    }
    const index = Number(triggerMsg.id);
    if (Number.isFinite(index) && index >= 0 && index < workflow.length) {
      const entry = workflow[index];
      const schema = entry.trigger.outputSchema();
      if (!triggerMsg.payload) {
        return create(ExecutionResultSchema, {
          result: {
            case: "error",
            value: `trigger payload is missing for handler at index ${index} (trigger ID ${triggerMsg.id}). The trigger event must include a payload`
          }
        });
      }
      const payloadAny = triggerMsg.payload;
      const decoded = fromBinary(schema, payloadAny.value);
      const adapted = entry.trigger.adapt(decoded);
      const handlerRuntime = entry.requirements != null ? new TeeRuntime(this.config, 0, req.maxResponseSize) : runtime;
      try {
        const result = await entry.fn(handlerRuntime, adapted);
        const wrapped = Value.wrap(result);
        return create(ExecutionResultSchema, {
          result: { case: "value", value: wrapped.proto() }
        });
      } catch (e) {
        const err = e instanceof Error ? e.message : String(e);
        return create(ExecutionResultSchema, {
          result: { case: "error", value: err }
        });
      }
    }
    return create(ExecutionResultSchema, {
      result: {
        case: "error",
        value: `trigger not found: no workflow handler registered at index ${index} (trigger ID ${triggerMsg.id}). The workflow has ${workflow.length} handler(s) registered. Verify the trigger subscription matches a registered handler`
      }
    });
  }
  handlePreHookPhase(req, workflow) {
    if (req.request.case !== "preHook") {
      return create(ExecutionResultSchema, {
        result: {
          case: "error",
          value: `preHook request expected but received '${req.request.case}' in handlePreHookPhase. This is an internal SDK error`
        }
      });
    }
    const triggerMsg = req.request.value;
    const id = BigInt(triggerMsg.id);
    if (id > BigInt(Number.MAX_SAFE_INTEGER)) {
      return create(ExecutionResultSchema, {
        result: {
          case: "error",
          value: `Trigger ID ${id} exceeds JavaScript safe integer range (Number.MAX_SAFE_INTEGER = ${Number.MAX_SAFE_INTEGER}). This trigger ID cannot be safely represented as a number`
        }
      });
    }
    const index = Number(triggerMsg.id);
    if (!Number.isFinite(index) || index < 0 || index >= workflow.length) {
      return create(ExecutionResultSchema, {
        result: {
          case: "error",
          value: `trigger not found: no workflow handler registered at index ${index} (trigger ID ${triggerMsg.id}). The workflow has ${workflow.length} handler(s) registered. Verify the trigger subscription matches a registered handler`
        }
      });
    }
    const entry = workflow[index];
    if (!entry.hooks?.preHook) {
      return create(ExecutionResultSchema, {
        result: {
          case: "error",
          value: `no preHook registered for handler at index ${index} (trigger ID ${triggerMsg.id}). The handler was subscribed with preHook enabled but no preHook function was provided`
        }
      });
    }
    if (!triggerMsg.payload) {
      return create(ExecutionResultSchema, {
        result: {
          case: "error",
          value: `trigger payload is missing for preHook at index ${index} (trigger ID ${triggerMsg.id}). The trigger event must include a payload`
        }
      });
    }
    const schema = entry.trigger.outputSchema();
    const decoded = fromBinary(schema, triggerMsg.payload.value);
    const adapted = entry.trigger.adapt(decoded);
    const restrictionsJson = entry.hooks.preHook(this.config, adapted);
    const restrictions = fromJson(RestrictionsSchema, restrictionsJson);
    return create(ExecutionResultSchema, {
      result: { case: "restrictions", value: restrictions }
    });
  }
  handleSubscribePhase(req, workflow) {
    if (req.request.case !== "subscribe") {
      return create(ExecutionResultSchema, {
        result: {
          case: "error",
          value: `subscribe request expected but received '${req.request.case}' in handleSubscribePhase. This is an internal SDK error`
        }
      });
    }
    const subscriptions = workflow.map((entry) => ({
      id: entry.trigger.capabilityId(),
      method: entry.trigger.method(),
      payload: entry.trigger.configAsAny(),
      preHook: !!entry.hooks?.preHook,
      requirements: entry.requirements
    }));
    const subscriptionRequest = create(TriggerSubscriptionRequestSchema, {
      subscriptions
    });
    return create(ExecutionResultSchema, {
      result: { case: "triggerSubscriptions", value: subscriptionRequest }
    });
  }
}

class Runner extends RunnerBase {
  constructor(config, request) {
    super(config, request);
  }
  static async newRunner(configHandlerParams) {
    return RunnerBase.newRunnerHelper((config, request) => new Runner(config, request), configHandlerParams);
  }
}
var prepareErrorResponse = (error) => {
  let errorMessage = null;
  if (error instanceof Error) {
    errorMessage = error.message;
  } else if (typeof error === "string") {
    errorMessage = error;
  } else {
    errorMessage = String(error) || null;
  }
  if (typeof errorMessage !== "string") {
    return null;
  }
  const result = create(ExecutionResultSchema, {
    result: { case: "error", value: errorMessage }
  });
  return toBinary(ExecutionResultSchema, result);
};
var sendErrorResponse = (error) => {
  const payload = prepareErrorResponse(error);
  if (payload === null) {
    console.error("Failed to serialize error response: the error could not be converted to a string. Original error:", error);
    const fallback = prepareErrorResponse("Unknown error: the original error could not be serialized");
    if (fallback !== null) {
      hostBindings.sendResponse(fallback);
    }
    return;
  }
  hostBindings.sendResponse(payload);
};
function getEnumValues(entries) {
  const numericValues = Object.values(entries).filter((v) => typeof v === "number");
  const values = Object.entries(entries).filter(([k, _]) => numericValues.indexOf(+k) === -1).map(([_, v]) => v);
  return values;
}
function joinValues(array, separator = "|") {
  return array.map((val) => stringifyPrimitive(val)).join(separator);
}
function jsonStringifyReplacer(_, value) {
  if (typeof value === "bigint")
    return value.toString();
  return value;
}

class Cached {
  constructor(getter) {
    this._getter = getter;
    this._value = undefined;
  }
  get value() {
    const getter = this._getter;
    if (getter !== undefined) {
      this._value = getter();
      this._getter = undefined;
    }
    return this._value;
  }
}
function cached(getter) {
  return new Cached(getter);
}
function nullish(input) {
  return input === null || input === undefined;
}
function cleanRegex(source) {
  const start = source.startsWith("^") ? 1 : 0;
  const end = source.endsWith("$") ? source.length - 1 : source.length;
  return source.slice(start, end);
}
function floatSafeRemainder2(val, step) {
  const ratio = val / step;
  const roundedRatio = Math.round(ratio);
  const tolerance = 4 * Number.EPSILON * Math.max(Math.abs(ratio), 1);
  if (Math.abs(ratio - roundedRatio) < tolerance)
    return 0;
  return ratio - roundedRatio;
}
function assignProp(target, prop, value) {
  Object.defineProperty(target, prop, {
    value,
    writable: true,
    enumerable: true,
    configurable: true
  });
}
function rawShape(def) {
  const desc = Object.getOwnPropertyDescriptor(def, "shape");
  return desc?.get ? desc.get.raw : desc?.value;
}
function sourceShape(schema) {
  return rawShape(schema._zod.def) ?? schema._zod.def.shape;
}
function deferProp(target, key, getter) {
  Object.defineProperty(target, key, {
    get() {
      const value = getter();
      assignProp(this, key, value);
      return value;
    },
    enumerable: true,
    configurable: true
  });
}
function putProp(target, key, value) {
  if (key in target)
    assignProp(target, key, value);
  else
    target[key] = value;
}
function mirrorShape(target, source, keys, wrap) {
  const raw = sourceShape(source);
  for (const key of keys) {
    const desc = Object.getOwnPropertyDescriptor(raw, key);
    if (!desc.enumerable)
      continue;
    if (desc.get) {
      deferProp(target, key, () => {
        const value = source._zod.def.shape[key];
        return wrap ? wrap(value, key) : value;
      });
    } else
      putProp(target, key, wrap ? wrap(desc.value, key) : desc.value);
  }
}
function mirrorProps(target, source) {
  for (const key of Reflect.ownKeys(source)) {
    const desc = Object.getOwnPropertyDescriptor(source, key);
    if (!desc.enumerable)
      continue;
    if (desc.get)
      deferProp(target, key, () => source[key]);
    else
      putProp(target, key, desc.value);
  }
}
function mergeDefs(...defs) {
  const mergedDescriptors = {};
  for (const def of defs) {
    const descriptors = Object.getOwnPropertyDescriptors(def);
    Object.assign(mergedDescriptors, descriptors);
  }
  return Object.defineProperties({}, mergedDescriptors);
}
function esc(str) {
  return JSON.stringify(str);
}
function slugify(input) {
  return input.toLowerCase().trim().replace(/[^\w\s-]/g, "").replace(/[\s_-]+/g, "-").replace(/^-+|-+$/g, "");
}
var captureStackTrace = "captureStackTrace" in Error ? Error.captureStackTrace : (..._args) => {};
function isObject2(data) {
  return typeof data === "object" && data !== null && !Array.isArray(data);
}
var allowsEval = /* @__PURE__ */ cached(() => {
  if (globalConfig.jitless) {
    return false;
  }
  if (typeof navigator !== "undefined" && navigator?.userAgent?.includes("Cloudflare")) {
    return false;
  }
  try {
    const F = Function;
    new F("");
    return true;
  } catch (_) {
    return false;
  }
});
function isPlainObject(o) {
  if (isObject2(o) === false)
    return false;
  const ctor = o.constructor;
  if (ctor === undefined)
    return true;
  if (typeof ctor !== "function")
    return true;
  const prot = ctor.prototype;
  if (isObject2(prot) === false)
    return false;
  if (Object.prototype.hasOwnProperty.call(prot, "isPrototypeOf") === false) {
    return false;
  }
  return true;
}
function shallowClone(o) {
  if (isPlainObject(o))
    return { ...o };
  if (Array.isArray(o))
    return [...o];
  if (o instanceof Map)
    return new Map(o);
  if (o instanceof Set)
    return new Set(o);
  return o;
}
var propertyKeyTypes = /* @__PURE__ */ new Set(["string", "number", "symbol"]);
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function clone2(inst, def, params) {
  const cl = new inst._zod.constr(def ?? inst._zod.def);
  if (!def || params?.parent)
    cl._zod.parent = inst;
  return cl;
}
function normalizeParams(_params) {
  const params = _params;
  if (!params)
    return {};
  if (typeof params === "string")
    return { error: () => params };
  if (params?.message !== undefined) {
    if (params?.error !== undefined)
      throw new Error("Cannot specify both `message` and `error` params");
    params.error = params.message;
  }
  delete params.message;
  if (typeof params.error === "string")
    return { ...params, error: () => params.error };
  return params;
}
function stringifyPrimitive(value) {
  if (typeof value === "bigint")
    return value.toString() + "n";
  if (typeof value === "string")
    return `"${value}"`;
  return `${value}`;
}
function optionalKeys(shape) {
  return Object.keys(shape).filter((k) => {
    return shape[k]._zod.optin !== undefined && shape[k]._zod.optout === "optional";
  });
}
var NUMBER_FORMAT_RANGES = /* @__PURE__ */ (() => ({
  safeint: [Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER],
  int32: [-2147483648, 2147483647],
  uint32: [0, 4294967295],
  float32: [-340282346638528860000000000000000000000, 340282346638528860000000000000000000000],
  float64: [-Number.MAX_VALUE, Number.MAX_VALUE]
}))();
var BIGINT_FORMAT_RANGES = {
  int64: [/* @__PURE__ */ BigInt("-9223372036854775808"), /* @__PURE__ */ BigInt("9223372036854775807")],
  uint64: [/* @__PURE__ */ BigInt(0), /* @__PURE__ */ BigInt("18446744073709551615")]
};
function pick(schema, mask) {
  const currDef = schema._zod.def;
  const checks = currDef.checks;
  const hasChecks = checks && checks.length > 0;
  if (hasChecks) {
    throw new Error(".pick() cannot be used on object schemas containing refinements");
  }
  const newShape = {};
  mirrorShape(newShape, schema, maskedKeys(schema, mask));
  return clone2(schema, mergeDefs(currDef, { shape: newShape, checks: [] }));
}
function maskedKeys(schema, mask) {
  const raw = sourceShape(schema);
  const keys = [];
  for (const key of Reflect.ownKeys(mask)) {
    if (!Object.getOwnPropertyDescriptor(raw, key)?.enumerable) {
      throw new Error(`Unrecognized key: "${String(key)}"`);
    }
    if (mask[key])
      keys.push(key);
  }
  return keys;
}
function omit(schema, mask) {
  const currDef = schema._zod.def;
  const checks = currDef.checks;
  const hasChecks = checks && checks.length > 0;
  if (hasChecks) {
    throw new Error(".omit() cannot be used on object schemas containing refinements");
  }
  const omitted = new Set(maskedKeys(schema, mask));
  const newShape = {};
  mirrorShape(newShape, schema, Reflect.ownKeys(sourceShape(schema)).filter((key) => !omitted.has(key)));
  return clone2(schema, mergeDefs(currDef, { shape: newShape, checks: [] }));
}
function extend(schema, shape) {
  if (!isPlainObject(shape)) {
    throw new Error("Invalid input to extend: expected a plain object");
  }
  const checks = schema._zod.def.checks;
  const hasChecks = checks && checks.length > 0;
  if (hasChecks) {
    const existingShape = sourceShape(schema);
    for (const key of Reflect.ownKeys(shape)) {
      if (Object.getOwnPropertyDescriptor(existingShape, key) !== undefined) {
        throw new Error("Cannot overwrite keys on object schemas containing refinements. Use `.safeExtend()` instead.");
      }
    }
  }
  return clone2(schema, mergeDefs(schema._zod.def, { shape: extended(schema, shape) }));
}
function extended(schema, shape) {
  const newShape = {};
  mirrorShape(newShape, schema, Reflect.ownKeys(sourceShape(schema)));
  mirrorProps(newShape, shape);
  return newShape;
}
function safeExtend(schema, shape) {
  if (!isPlainObject(shape)) {
    throw new Error("Invalid input to safeExtend: expected a plain object");
  }
  return clone2(schema, mergeDefs(schema._zod.def, { shape: extended(schema, shape) }));
}
function merge2(a, b) {
  if (!b?._zod?.def) {
    throw new Error("Invalid input to merge: expected an object schema. To merge a plain shape, use `.extend()`.");
  }
  if (a._zod.def.checks?.length) {
    throw new Error(".merge() cannot be used on object schemas containing refinements. Use .safeExtend() instead.");
  }
  const newShape = {};
  mirrorShape(newShape, a, Reflect.ownKeys(sourceShape(a)));
  mirrorShape(newShape, b, Reflect.ownKeys(sourceShape(b)));
  const def = mergeDefs(a._zod.def, {
    shape: newShape,
    get catchall() {
      return b._zod.def.catchall;
    },
    checks: b._zod.def.checks ?? []
  });
  return clone2(a, def);
}
function partial(Class, schema, mask, name = "partial") {
  const currDef = schema._zod.def;
  const checks = currDef.checks;
  const hasChecks = checks && checks.length > 0;
  if (hasChecks) {
    throw new Error(`.${name}() cannot be used on object schemas containing refinements`);
  }
  const selected = mask ? new Set(maskedKeys(schema, mask)) : undefined;
  const newShape = {};
  mirrorShape(newShape, schema, Reflect.ownKeys(sourceShape(schema)), Class && ((value, key) => selected && !selected.has(key) ? value : new Class({ type: "optional", innerType: value })));
  return clone2(schema, mergeDefs(schema._zod.def, { shape: newShape, checks: [] }));
}
function required(Class, schema, mask) {
  const selected = mask ? new Set(maskedKeys(schema, mask)) : undefined;
  const newShape = {};
  mirrorShape(newShape, schema, Reflect.ownKeys(sourceShape(schema)), (value, key) => selected && !selected.has(key) ? value : new Class({ type: "nonoptional", innerType: value }));
  return clone2(schema, mergeDefs(schema._zod.def, { shape: newShape }));
}
function aborted(x, startIndex = 0) {
  if (x.aborted === true)
    return true;
  for (let i = startIndex;i < x.issues.length; i++) {
    if (x.issues[i]?.continue !== true) {
      return true;
    }
  }
  return false;
}
function explicitlyAborted(x, startIndex = 0) {
  if (x.aborted === true)
    return true;
  for (let i = startIndex;i < x.issues.length; i++) {
    if (x.issues[i]?.continue === false) {
      return true;
    }
  }
  return false;
}
function prefixIssues(path, issues) {
  return issues.map((iss) => {
    var _a;
    (_a = iss).path ?? (_a.path = []);
    iss.path.unshift(path);
    return iss;
  });
}
function unwrapMessage(message) {
  return typeof message === "string" ? message : message?.message;
}
function attachSchema(issues, start, inst) {
  var _a;
  for (let i = start;i < issues.length; i++) {
    (_a = issues[i]).schema ?? (_a.schema = inst);
  }
}
function finalizeIssue(iss, ctx, config) {
  var _a;
  const traits = iss.inst?._zod?.traits;
  if (traits?.has("$ZodType")) {
    if (traits.has("$ZodCheck"))
      (_a = iss).schema ?? (_a.schema = iss.inst);
    else
      iss.schema = iss.inst;
  }
  const schemaError = iss.schema !== iss.inst ? iss.schema?._zod.def?.error : undefined;
  const message = iss.message ? iss.message : unwrapMessage(iss.inst?._zod.def?.error?.(iss)) ?? unwrapMessage(schemaError?.(iss)) ?? unwrapMessage(ctx?.error?.(iss)) ?? unwrapMessage(config.customError?.(iss)) ?? unwrapMessage(config.localeError?.(iss)) ?? "Invalid input";
  const full = {};
  for (const k of Object.keys(iss)) {
    if (k === "inst" || k === "schema" || k === "continue" || k === "input" || k === "__proto__")
      continue;
    full[k] = iss[k];
  }
  full.path ?? (full.path = []);
  full.message = message;
  if (ctx?.reportInput) {
    full.input = iss.input;
  }
  return full;
}
var highSurrogate = /[\uD800-\uDBFF]/;
function codePointLength(str) {
  const units = str.length;
  if (!highSurrogate.test(str))
    return units;
  let count = units;
  for (let i = 0;i < units - 1; i++) {
    if ((str.charCodeAt(i) & 64512) === 55296 && (str.charCodeAt(i + 1) & 64512) === 56320) {
      count--;
      i++;
    }
  }
  return count;
}
function getLengthableOrigin(input) {
  if (Array.isArray(input))
    return "array";
  if (typeof input === "string")
    return "string";
  return "unknown";
}
function parsedType(data) {
  const t = typeof data;
  switch (t) {
    case "number": {
      return Number.isNaN(data) ? "nan" : "number";
    }
    case "object": {
      if (data === null) {
        return "null";
      }
      if (Array.isArray(data)) {
        return "array";
      }
      const obj = data;
      if (obj && Object.getPrototypeOf(obj) !== Object.prototype && "constructor" in obj && obj.constructor) {
        return obj.constructor.name;
      }
    }
  }
  return t;
}
function issue(...args) {
  const [iss, input, inst] = args;
  if (typeof iss === "string") {
    return {
      message: iss,
      code: "custom",
      input,
      inst
    };
  }
  return { ...iss };
}
function members(proto, table) {
  for (const key in table) {
    const desc = Object.getOwnPropertyDescriptor(table, key);
    if (desc.get)
      Object.defineProperty(proto, key, { ...desc, enumerable: false });
    else
      defineBound(proto, key, desc.value);
  }
}
function own(inst, key, value, enumerable = true) {
  Object.defineProperty(inst, key, { configurable: true, writable: true, enumerable, value });
  return value;
}
function hide(inst, key, value) {
  return own(inst, key, value, false);
}
function derived(computes, table) {
  for (const key in computes) {
    const compute = computes[key];
    Object.defineProperty(table, key, {
      configurable: true,
      enumerable: true,
      get() {
        return own(this, key, compute(this));
      },
      set(value) {
        own(this, key, value);
      }
    });
  }
  return table;
}
function defineBound(proto, key, fn) {
  Object.defineProperty(proto, key, {
    configurable: true,
    get() {
      return this == null ? fn : own(this, key, fn.bind(this));
    },
    set(value) {
      own(this, key, value);
    }
  });
}
function claim(inst, sentinel) {
  const proto = Object.getPrototypeOf(inst);
  return sentinel in proto ? undefined : proto;
}
var installing;
var broke = false;
var breaker = {
  configurable: true,
  get() {
    broke = true;
    return;
  }
};
function defineLazyInternal(inst, key, compute) {
  const proto = Object.getPrototypeOf(inst._zod);
  if (key in proto && installing !== inst._zod) {
    installing = undefined;
    return;
  }
  installing = inst._zod;
  Object.defineProperty(proto, key, {
    configurable: true,
    get() {
      Object.defineProperty(this, key, breaker);
      const outer = broke;
      broke = false;
      try {
        const value = compute(this);
        if (broke)
          delete this[key];
        else
          Object.defineProperty(this, key, { configurable: true, writable: true, value });
        broke = broke || outer;
        return value;
      } catch (err) {
        delete this[key];
        broke = broke || outer;
        throw err;
      }
    },
    set(value) {
      Object.defineProperty(this, key, { configurable: true, writable: true, value });
    }
  });
}
function installLazyProp(inst, key, make, enumerable) {
  const proto = claim(inst, key);
  if (!proto)
    return;
  Object.defineProperty(proto, key, {
    configurable: true,
    get() {
      const desc = { configurable: true, writable: true, enumerable, value: undefined };
      Object.defineProperty(this, key, desc);
      desc.value = make(this);
      Object.defineProperty(this, key, desc);
      return desc.value;
    },
    set(value) {
      Object.defineProperty(this, key, { configurable: true, writable: true, enumerable, value });
    }
  });
}
var CONSTANT_CATCH = "~constantCatch";
function constantCatch(value) {
  const fn = () => value;
  fn[CONSTANT_CATCH] = true;
  return fn;
}
var _a;
var _zodDesc = { value: undefined, enumerable: false };
var _E = "captureStackTrace" in Error ? Error : null;
function newError(Definition) {
  const E = _E;
  if (E) {
    const saved = E.stackTraceLimit;
    if (typeof saved === "number") {
      try {
        E.stackTraceLimit = 0;
      } catch {
        _E = null;
        return new Definition;
      }
      try {
        return new Definition;
      } finally {
        E.stackTraceLimit = saved;
      }
    }
  }
  return new Definition;
}
function $constructor(name, initializer, proto, params) {
  const zodProto = {};
  function Internals(def) {
    this.def = def;
    this.constr = _;
    this.traits = new Set;
  }
  Internals.prototype = zodProto;
  const protoMembers = proto;
  const initialized = protoMembers && new WeakSet;
  function init(inst, def) {
    if (!inst._zod) {
      _zodDesc.value = new Internals(def);
      try {
        Object.defineProperty(inst, "_zod", _zodDesc);
      } finally {
        _zodDesc.value = undefined;
      }
    } else if (inst._zod.traits.has(name)) {
      return;
    }
    inst._zod.traits.add(name);
    initializer(inst, def);
    if (initialized) {
      const own = Object.getPrototypeOf(inst);
      const ctorProto = inst._zod.constr.prototype;
      let up = own;
      while (up && up !== ctorProto)
        up = Object.getPrototypeOf(up);
      const target = up ?? own;
      if (!initialized.has(target)) {
        initialized.add(target);
        members(target, protoMembers);
      }
    }
    const proto = _.prototype;
    for (const k in proto) {
      if (!Object.prototype.hasOwnProperty.call(proto, k))
        continue;
      if (!(k in inst)) {
        inst[k] = proto[k].bind(inst);
      }
    }
  }
  const Parent = params?.Parent ?? Object;

  class Definition extends Parent {
  }
  Object.defineProperty(Definition, "name", { value: name });
  function _(def) {
    const inst = params?.Parent ? newError(Definition) : this;
    init(inst, def);
    const deferred = inst._zod.deferred;
    if (deferred) {
      for (const fn of deferred) {
        fn();
      }
      inst._zod.deferred = undefined;
    }
    const pp = globalThis.__zod_globalConfig?.postProcessor;
    if (pp)
      pp(inst);
    return inst;
  }
  Object.defineProperty(_, "init", { value: init });
  Object.defineProperty(_, Symbol.hasInstance, {
    value: (inst) => {
      if (params?.Parent && inst instanceof params.Parent)
        return true;
      return inst?._zod?.traits?.has(name);
    }
  });
  Object.defineProperty(_, "name", { value: name });
  return _;
}

class $ZodAsyncError extends Error {
  constructor() {
    super(`Encountered Promise during synchronous parse. Use .parseAsync() instead.`);
  }
}

class $ZodEncodeError extends Error {
  constructor(name) {
    super(`Encountered unidirectional transform during encode: ${name}`);
    this.name = "ZodEncodeError";
  }
}
(_a = globalThis).__zod_globalConfig ?? (_a.__zod_globalConfig = {});
var globalConfig = globalThis.__zod_globalConfig;
function config(newConfig) {
  if (newConfig)
    Object.assign(globalConfig, newConfig);
  return globalConfig;
}
function _getMessage() {
  const internals = this._zod;
  internals.message ?? (internals.message = JSON.stringify(internals.def, jsonStringifyReplacer, 2));
  return internals.message;
}
function _setMessage(value) {
  this._zod.message = value;
}
var _messageDesc = {
  get: _getMessage,
  set: _setMessage,
  enumerable: true,
  configurable: true
};
var _issuesDesc = { value: undefined, enumerable: false };
var _installedToString = /* @__PURE__ */ new WeakSet([Object.prototype, Error.prototype]);
var initializer = (inst, def) => {
  inst.name = "$ZodError";
  _issuesDesc.value = def;
  Object.defineProperty(inst, "issues", _issuesDesc);
  _issuesDesc.value = undefined;
  Object.defineProperty(inst, "message", _messageDesc);
  const proto = Object.getPrototypeOf(inst);
  if (!_installedToString.has(proto)) {
    _installedToString.add(proto);
    Object.defineProperty(proto, "toString", {
      configurable: true,
      enumerable: false,
      get() {
        const value = () => this.message;
        Object.defineProperty(this, "toString", { value, configurable: true, writable: true });
        return value;
      },
      set(value) {
        Object.defineProperty(this, "toString", { value, configurable: true, writable: true });
      }
    });
  }
};
var $ZodError = $constructor("$ZodError", initializer);
var $ZodRealError = $constructor("$ZodError", initializer, undefined, {
  Parent: Error
});
function node(obj, key, make) {
  if (!Object.prototype.hasOwnProperty.call(obj, key)) {
    if (key === "__proto__") {
      Object.defineProperty(obj, key, { value: make(), writable: true, enumerable: true, configurable: true });
    } else {
      obj[key] = make();
    }
  }
  return obj[key];
}
function flattenError(error, mapper = (issue) => issue.message) {
  const fieldErrors = {};
  const formErrors = [];
  for (const sub of error.issues) {
    if (sub.path.length > 0) {
      node(fieldErrors, sub.path[0], () => []).push(mapper(sub));
    } else {
      formErrors.push(mapper(sub));
    }
  }
  return { formErrors, fieldErrors };
}
function formatError(error, mapper = (issue) => issue.message) {
  const fieldErrors = { _errors: [] };
  const processError = (error, path = []) => {
    for (const issue of error.issues) {
      if (issue.code === "invalid_union" && issue.errors.length) {
        issue.errors.map((issues) => processError({ issues }, [...path, ...issue.path]));
      } else if (issue.code === "invalid_key") {
        processError({ issues: issue.issues }, [...path, ...issue.path]);
      } else if (issue.code === "invalid_element") {
        processError({ issues: issue.issues }, [...path, ...issue.path]);
      } else {
        const fullpath = [...path, ...issue.path];
        if (fullpath.length === 0) {
          fieldErrors._errors.push(mapper(issue));
        } else {
          let curr = fieldErrors;
          let i = 0;
          while (i < fullpath.length) {
            const el = fullpath[i];
            const terminal = i === fullpath.length - 1;
            if (el === "_errors") {
              if (terminal)
                curr._errors.push(mapper(issue));
              i++;
              continue;
            }
            if (!Object.prototype.hasOwnProperty.call(curr, el)) {
              Object.defineProperty(curr, el, {
                value: { _errors: [] },
                enumerable: true,
                writable: true,
                configurable: true
              });
            }
            const node = curr[el];
            if (terminal) {
              node._errors.push(mapper(issue));
            }
            curr = node;
            i++;
          }
        }
      }
    }
  };
  processError(error);
  return fieldErrors;
}
function finalizeParams(callee, params) {
  return { callee: params?.callee ?? callee, Err: params?.Err };
}
var _parse = (_Err) => {
  const fn = (schema, value, _ctx, _params) => {
    const ctx = _ctx ? { ..._ctx, async: false } : { async: false };
    const result = schema._zod.run({ value, issues: [] }, ctx);
    if (result instanceof Promise) {
      throw new $ZodAsyncError;
    }
    if (result.issues.length) {
      const e = new (_params?.Err ?? _Err)(result.issues.map((iss) => finalizeIssue(iss, ctx, config())));
      captureStackTrace(e, _params?.callee ?? fn);
      throw e;
    }
    return result.value;
  };
  return fn;
};
var _parseAsync = (_Err) => {
  const fn = async (schema, value, _ctx, params) => {
    const ctx = _ctx ? { ..._ctx, async: true } : { async: true };
    let result = schema._zod.run({ value, issues: [] }, ctx);
    if (result instanceof Promise)
      result = await result;
    if (result.issues.length) {
      const e = new (params?.Err ?? _Err)(result.issues.map((iss) => finalizeIssue(iss, ctx, config())));
      captureStackTrace(e, params?.callee ?? fn);
      throw e;
    }
    return result.value;
  };
  return fn;
};
var _safeParse = (_Err) => (schema, value, _ctx) => {
  const ctx = _ctx ? { ..._ctx, async: false } : { async: false };
  const result = schema._zod.run({ value, issues: [] }, ctx);
  if (result instanceof Promise) {
    throw new $ZodAsyncError;
  }
  return result.issues.length ? failure(_Err, result.issues, ctx) : { success: true, data: result.value };
};
function failure(Err, issues, ctx) {
  let error;
  return {
    success: false,
    get error() {
      if (!error) {
        error = new Err(issues.map((iss) => finalizeIssue(iss, ctx, config())));
        issues = undefined;
        ctx = undefined;
      }
      return error;
    },
    set error(e) {
      error = e;
      issues = undefined;
      ctx = undefined;
    }
  };
}
var _safeParseAsync = (_Err) => async (schema, value, _ctx) => {
  const ctx = _ctx ? { ..._ctx, async: true } : { async: true };
  let result = schema._zod.run({ value, issues: [] }, ctx);
  if (result instanceof Promise)
    result = await result;
  return result.issues.length ? failure(_Err, result.issues, ctx) : { success: true, data: result.value };
};
var COMPILE_INVALID = /* @__PURE__ */ Symbol.for("zod.compile.invalid");
var COMPILE_FALLBACK = /* @__PURE__ */ Symbol.for("zod.compile.fallback");
var validate = (schema, value, _ctx) => {
  const validator = schema._zod.bag.validator;
  if (validator !== undefined) {
    if (validator(value) !== COMPILE_INVALID)
      return true;
    if (validator.definite === true && _ctx === undefined)
      return false;
  }
  return validateFallback(schema, value, _ctx);
};
function validateFallback(schema, value, _ctx) {
  const ctx = _ctx ? { ..._ctx, async: false, abortEarly: true } : { async: false, abortEarly: true };
  const fallbackRun = schema._zod.bag.fallbackRun;
  let result;
  if (fallbackRun) {
    ctx[COMPILE_FALLBACK] = true;
    result = fallbackRun({ value, issues: [] }, ctx);
  } else {
    result = schema._zod.run({ value, issues: [] }, ctx);
  }
  if (result instanceof Promise) {
    throw new $ZodAsyncError;
  }
  return result.issues.length === 0;
}
var validateAsync = async (schema, value, _ctx) => {
  const ctx = _ctx ? { ..._ctx, async: true, abortEarly: true } : { async: true, abortEarly: true };
  let result = schema._zod.run({ value, issues: [] }, ctx);
  if (result instanceof Promise)
    result = await result;
  return result.issues.length === 0;
};
var _encode = (_Err) => {
  const parse = _parse(_Err);
  const fn = (schema, value, _ctx, _params) => {
    const ctx = _ctx ? { ..._ctx, direction: "backward" } : { direction: "backward" };
    return parse(schema, value, ctx, finalizeParams(fn, _params));
  };
  return fn;
};
var _decode = (_Err) => {
  const parse = _parse(_Err);
  const fn = (schema, value, _ctx, _params) => {
    return parse(schema, value, _ctx, finalizeParams(fn, _params));
  };
  return fn;
};
var _encodeAsync = (_Err) => {
  const parseAsync = _parseAsync(_Err);
  const fn = async (schema, value, _ctx, _params) => {
    const ctx = _ctx ? { ..._ctx, direction: "backward" } : { direction: "backward" };
    return await parseAsync(schema, value, ctx, finalizeParams(fn, _params));
  };
  return fn;
};
var _decodeAsync = (_Err) => {
  const parseAsync = _parseAsync(_Err);
  const fn = async (schema, value, _ctx, _params) => {
    return await parseAsync(schema, value, _ctx, finalizeParams(fn, _params));
  };
  return fn;
};
var _safeEncode = (_Err) => (schema, value, _ctx) => {
  const ctx = _ctx ? { ..._ctx, direction: "backward" } : { direction: "backward" };
  return _safeParse(_Err)(schema, value, ctx);
};
var _safeDecode = (_Err) => (schema, value, _ctx) => {
  return _safeParse(_Err)(schema, value, _ctx);
};
var _safeEncodeAsync = (_Err) => async (schema, value, _ctx) => {
  const ctx = _ctx ? { ..._ctx, direction: "backward" } : { direction: "backward" };
  return _safeParseAsync(_Err)(schema, value, ctx);
};
var _safeDecodeAsync = (_Err) => async (schema, value, _ctx) => {
  return _safeParseAsync(_Err)(schema, value, _ctx);
};
var cuid = /^[cC][0-9a-z]{6,}$/;
var cuid2 = /^[0-9a-z]+$/;
var ulid = /^[0-7][0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{25}$/;
var xid = /^[0-9a-vA-V]{20}$/;
var ksuid = /^[A-Za-z0-9]{27}$/;
var nanoid = /^[a-zA-Z0-9_-]{21}$/;
function nanoidOfLength(length) {
  return new RegExp(`^[a-zA-Z0-9_-]{${length}}$`);
}
var duration = /^P(?:(\d+W)|(?!.*W)(?=\d|T\d)(\d+Y)?(\d+M)?(\d+D)?(T(?=\d)(\d+H)?(\d+M)?(\d+([.,]\d+)?S)?)?)$/;
var guid = /^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$/;
var uuid = (version) => {
  if (!version)
    return /^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$/;
  return new RegExp(`^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-${version}[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})$`);
};
var email = /^(?:[A-Za-z0-9_'+\-]+\.)*[A-Za-z0-9_'+\-]*[A-Za-z0-9_+-]@(?:[A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$/;
var _emoji = `^(?=[\\s\\S]*[\\p{Extended_Pictographic}\\p{Regional_Indicator}\\u20E3])[\\p{Extended_Pictographic}\\p{Emoji_Component}]+$`;
function emoji() {
  return new RegExp(_emoji, "u");
}
var ipv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/;
var ipv6 = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;
var cidrv4 = /^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\/([0-9]|[1-2][0-9]|3[0-2])$/;
var cidrv6 = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))\/(12[0-8]|1[01][0-9]|[1-9]?[0-9])$/;
var base64 = /^$|^(?:[0-9a-zA-Z+/]{4})*(?:(?:[0-9a-zA-Z+/]{2}==)|(?:[0-9a-zA-Z+/]{3}=))?$/;
var base64url = /^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2,3})?$/;
var httpProtocol = /^https?$/;
var e164 = /^\+[1-9]\d{6,14}$/;
var dateSource = `(?:(?:\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\\d|30)|(?:02)-(?:0[1-9]|1\\d|2[0-8])))`;
function anchor(source) {
  return new RegExp(`^${source}$`);
}
var date = /* @__PURE__ */ anchor(dateSource);
function timeSource(args) {
  const hhmm = `(?:[01]\\d|2[0-3]):[0-5]\\d`;
  const regex = typeof args.precision === "number" ? args.precision === -1 ? `${hhmm}` : args.precision === 0 ? `${hhmm}:[0-5]\\d` : `${hhmm}:[0-5]\\d\\.\\d{${args.precision}}` : args.seconds ? `${hhmm}:[0-5]\\d(?:\\.\\d+)?` : `${hhmm}(?::[0-5]\\d(?:\\.\\d+)?)?`;
  return regex;
}
function time(args) {
  return new RegExp(`^${timeSource(args)}$`);
}
function datetime(args) {
  const opts = ["Z"];
  if (args.offset)
    opts.push(`([+-](?:[01]\\d|2[0-3]):[0-5]\\d)`);
  const qualified = `${timeSource({ precision: args.precision, seconds: true })}(?:${opts.join("|")})`;
  const timeRegex = args.local ? `${qualified}|${timeSource({ precision: args.precision })}` : qualified;
  return new RegExp(`^${dateSource}T(?:${timeRegex})$`);
}
var anyString = /^[\s\S]{0,}$/;
var number = /^-?\d+(?:\.\d+)?$/;
var lowercase = /^[^A-Z]*$/;
var uppercase = /^[^a-z]*$/;
var $ZodCheck = /* @__PURE__ */ $constructor("$ZodCheck", (inst, def) => {
  var _a;
  inst._zod ?? (inst._zod = {});
  inst._zod.def = def;
  (_a = inst._zod).onattach ?? (_a.onattach = []);
});
var _whenHasLength = (payload) => {
  const val = payload.value;
  return !nullish(val) && val.length !== undefined;
};
var numericOriginMap = {
  number: "number",
  bigint: "bigint",
  object: "date"
};
var $ZodCheckLessThan = /* @__PURE__ */ $constructor("$ZodCheckLessThan", (inst, def) => {
  $ZodCheck.init(inst, def);
  const origin = numericOriginMap[typeof def.value];
  inst._zod.check = (payload) => {
    if (def.inclusive ? payload.value <= def.value : payload.value < def.value) {
      return;
    }
    payload.issues.push({
      origin: numericOriginMap[typeof payload.value] ?? origin,
      code: "too_big",
      maximum: typeof def.value === "object" ? def.value.getTime() : def.value,
      input: payload.value,
      inclusive: def.inclusive,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckGreaterThan = /* @__PURE__ */ $constructor("$ZodCheckGreaterThan", (inst, def) => {
  $ZodCheck.init(inst, def);
  const origin = numericOriginMap[typeof def.value];
  inst._zod.check = (payload) => {
    if (def.inclusive ? payload.value >= def.value : payload.value > def.value) {
      return;
    }
    payload.issues.push({
      origin: numericOriginMap[typeof payload.value] ?? origin,
      code: "too_small",
      minimum: typeof def.value === "object" ? def.value.getTime() : def.value,
      input: payload.value,
      inclusive: def.inclusive,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckMultipleOf = /* @__PURE__ */ $constructor("$ZodCheckMultipleOf", (inst, def) => {
  $ZodCheck.init(inst, def);
  inst._zod.check = (payload) => {
    if (typeof payload.value !== typeof def.value)
      throw new Error("Cannot mix number and bigint in multiple_of check.");
    const isMultiple = typeof payload.value === "bigint" ? def.value !== BigInt(0) && payload.value % def.value === BigInt(0) : floatSafeRemainder2(payload.value, def.value) === 0;
    if (isMultiple)
      return;
    payload.issues.push({
      origin: typeof payload.value,
      code: "not_multiple_of",
      divisor: def.value,
      input: payload.value,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckNumberFormat = /* @__PURE__ */ $constructor("$ZodCheckNumberFormat", (inst, def) => {
  $ZodCheck.init(inst, def);
  def.format = def.format || "float64";
  const isInt = def.format?.includes("int");
  const origin = isInt ? "int" : "number";
  const [minimum, maximum] = NUMBER_FORMAT_RANGES[def.format];
  inst._zod.check = (payload) => {
    const input = payload.value;
    if (isInt) {
      if (!Number.isInteger(input)) {
        payload.issues.push({
          expected: origin,
          format: def.format,
          code: "invalid_type",
          continue: false,
          input,
          inst
        });
        return;
      }
      if (!Number.isSafeInteger(input)) {
        if (input > 0) {
          payload.issues.push({
            input,
            code: "too_big",
            maximum: Number.MAX_SAFE_INTEGER,
            note: "Integers must be within the safe integer range.",
            inst,
            origin,
            inclusive: true,
            continue: !def.abort
          });
        } else {
          payload.issues.push({
            input,
            code: "too_small",
            minimum: Number.MIN_SAFE_INTEGER,
            note: "Integers must be within the safe integer range.",
            inst,
            origin,
            inclusive: true,
            continue: !def.abort
          });
        }
        return;
      }
    }
    if (input < minimum) {
      payload.issues.push({
        origin: "number",
        input,
        code: "too_small",
        minimum,
        inclusive: true,
        inst,
        continue: !def.abort
      });
    }
    if (input > maximum) {
      payload.issues.push({
        origin: "number",
        input,
        code: "too_big",
        maximum,
        inclusive: true,
        inst,
        continue: !def.abort
      });
    }
  };
});
var $ZodCheckMaxLength = /* @__PURE__ */ $constructor("$ZodCheckMaxLength", (inst, def) => {
  var _a;
  $ZodCheck.init(inst, def);
  (_a = inst._zod.def).when ?? (_a.when = _whenHasLength);
  inst._zod.check = (payload) => {
    const input = payload.value;
    const units = input.length;
    const length = typeof input === "string" && units > def.maximum ? codePointLength(input) : units;
    if (length <= def.maximum)
      return;
    const origin = getLengthableOrigin(input);
    payload.issues.push({
      origin,
      code: "too_big",
      maximum: def.maximum,
      inclusive: true,
      input,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckMinLength = /* @__PURE__ */ $constructor("$ZodCheckMinLength", (inst, def) => {
  var _a;
  $ZodCheck.init(inst, def);
  (_a = inst._zod.def).when ?? (_a.when = _whenHasLength);
  inst._zod.check = (payload) => {
    const input = payload.value;
    const units = input.length;
    const length = typeof input === "string" && units >= def.minimum && units < def.minimum * 2 ? codePointLength(input) : units;
    if (length >= def.minimum)
      return;
    const origin = getLengthableOrigin(input);
    payload.issues.push({
      origin,
      code: "too_small",
      minimum: def.minimum,
      inclusive: true,
      input,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckLengthEquals = /* @__PURE__ */ $constructor("$ZodCheckLengthEquals", (inst, def) => {
  var _a;
  $ZodCheck.init(inst, def);
  (_a = inst._zod.def).when ?? (_a.when = _whenHasLength);
  inst._zod.check = (payload) => {
    const input = payload.value;
    const units = input.length;
    const length = typeof input === "string" && units >= def.length && units <= def.length * 2 ? codePointLength(input) : units;
    if (length === def.length)
      return;
    const origin = getLengthableOrigin(input);
    const tooBig = length > def.length;
    payload.issues.push({
      origin,
      ...tooBig ? { code: "too_big", maximum: def.length } : { code: "too_small", minimum: def.length },
      inclusive: true,
      exact: true,
      input: payload.value,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckStringFormat = /* @__PURE__ */ $constructor("$ZodCheckStringFormat", (inst, def) => {
  var _a, _b;
  $ZodCheck.init(inst, def);
  if (def.pattern)
    (_a = inst._zod).check ?? (_a.check = (payload) => {
      def.pattern.lastIndex = 0;
      if (def.pattern.test(payload.value))
        return;
      payload.issues.push({
        origin: "string",
        code: "invalid_format",
        format: def.format,
        input: payload.value,
        ...def.pattern ? { pattern: def.pattern.toString() } : {},
        inst,
        continue: !def.abort
      });
    });
  else
    (_b = inst._zod).check ?? (_b.check = () => {});
});
var $ZodCheckRegex = /* @__PURE__ */ $constructor("$ZodCheckRegex", (inst, def) => {
  $ZodCheckStringFormat.init(inst, def);
  inst._zod.check = (payload) => {
    def.pattern.lastIndex = 0;
    if (def.pattern.test(payload.value))
      return;
    payload.issues.push({
      origin: "string",
      code: "invalid_format",
      format: "regex",
      input: payload.value,
      pattern: def.pattern.toString(),
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckLowerCase = /* @__PURE__ */ $constructor("$ZodCheckLowerCase", (inst, def) => {
  def.pattern ?? (def.pattern = lowercase);
  $ZodCheckStringFormat.init(inst, def);
});
var $ZodCheckUpperCase = /* @__PURE__ */ $constructor("$ZodCheckUpperCase", (inst, def) => {
  def.pattern ?? (def.pattern = uppercase);
  $ZodCheckStringFormat.init(inst, def);
});
var $ZodCheckIncludes = /* @__PURE__ */ $constructor("$ZodCheckIncludes", (inst, def) => {
  $ZodCheck.init(inst, def);
  const escapedRegex = escapeRegex(def.includes);
  const pattern = new RegExp(typeof def.position === "number" ? `^.{${def.position},}${escapedRegex}` : escapedRegex);
  def.pattern = pattern;
  inst._zod.check = (payload) => {
    if (payload.value.includes(def.includes, def.position))
      return;
    payload.issues.push({
      origin: "string",
      code: "invalid_format",
      format: "includes",
      includes: def.includes,
      input: payload.value,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckStartsWith = /* @__PURE__ */ $constructor("$ZodCheckStartsWith", (inst, def) => {
  $ZodCheck.init(inst, def);
  const pattern = new RegExp(`^${escapeRegex(def.prefix)}.*`);
  def.pattern ?? (def.pattern = pattern);
  inst._zod.check = (payload) => {
    if (payload.value.startsWith(def.prefix))
      return;
    payload.issues.push({
      origin: "string",
      code: "invalid_format",
      format: "starts_with",
      prefix: def.prefix,
      input: payload.value,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckEndsWith = /* @__PURE__ */ $constructor("$ZodCheckEndsWith", (inst, def) => {
  $ZodCheck.init(inst, def);
  const pattern = new RegExp(`.*${escapeRegex(def.suffix)}$`);
  def.pattern ?? (def.pattern = pattern);
  inst._zod.check = (payload) => {
    if (payload.value.endsWith(def.suffix))
      return;
    payload.issues.push({
      origin: "string",
      code: "invalid_format",
      format: "ends_with",
      suffix: def.suffix,
      input: payload.value,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodCheckOverwrite = /* @__PURE__ */ $constructor("$ZodCheckOverwrite", (inst, def) => {
  $ZodCheck.init(inst, def);
  inst._zod.check = (payload) => {
    payload.value = def.tx(payload.value);
  };
});

class Doc {
  constructor(args = [], closed = {}) {
    this.content = [];
    this.indent = 0;
    this.args = args;
    this.closed = closed;
  }
  indented(fn) {
    this.indent += 1;
    try {
      fn(this);
    } finally {
      this.indent -= 1;
    }
  }
  write(arg) {
    if (typeof arg === "function") {
      arg(this, { execution: "sync" });
      arg(this, { execution: "async" });
      return;
    }
    const content = arg;
    const lines = content.split(`
`).filter((x) => x);
    const minIndent = Math.min(...lines.map((x) => x.length - x.trimStart().length));
    const dedented = lines.map((x) => x.slice(minIndent)).map((x) => " ".repeat(this.indent * 2) + x);
    for (const line of dedented) {
      this.content.push(line);
    }
  }
  compile() {
    const F = Function;
    const content = this?.content ?? [``];
    const factory = new F(...Object.keys(this.closed), `return function (${this.args.join(", ")}) {
${content.join(`
`)}
};`);
    return factory(...Object.values(this.closed));
  }
}
var version3 = {
  major: 4,
  minor: 6,
  patch: 5
};
var $ZodType = /* @__PURE__ */ $constructor("$ZodType", (inst, def) => {
  var _a;
  inst ?? (inst = {});
  inst._zod.def = def;
  inst._zod.bag = inst._zod.bag || {};
  inst._zod.version = version3;
  const defChecks = inst._zod.def.checks;
  const checks = inst._zod.traits.has("$ZodCheck") ? [inst, ...defChecks ?? []] : defChecks?.length ? [...defChecks] : [];
  for (const ch of checks) {
    for (const fn of ch._zod.onattach) {
      fn(inst);
    }
  }
  if (checks.length === 0) {
    (_a = inst._zod).deferred ?? (_a.deferred = []);
    inst._zod.deferred?.push(() => {
      inst._zod.run = inst._zod.parse;
    });
  } else {
    const runChecks = (payload, checks, ctx) => {
      if (payload.memo)
        return payload;
      let isAborted = aborted(payload);
      let asyncResult;
      for (const ch of checks) {
        if (ch._zod.def.when) {
          if (explicitlyAborted(payload))
            continue;
          const shouldRun = ch._zod.def.when(payload);
          if (!shouldRun)
            continue;
        } else if (isAborted) {
          continue;
        }
        const currLen = payload.issues.length;
        const _ = ch._zod.check(payload);
        if (_ instanceof Promise && ctx?.async === false) {
          throw new $ZodAsyncError;
        }
        if (asyncResult || _ instanceof Promise) {
          asyncResult = (asyncResult ?? Promise.resolve()).then(async () => {
            await _;
            const nextLen = payload.issues.length;
            if (nextLen === currLen)
              return;
            attachSchema(payload.issues, currLen, inst);
            if (!isAborted)
              isAborted = aborted(payload, currLen);
          });
        } else {
          const nextLen = payload.issues.length;
          if (nextLen === currLen)
            continue;
          attachSchema(payload.issues, currLen, inst);
          if (!isAborted)
            isAborted = aborted(payload, currLen);
        }
      }
      if (asyncResult) {
        return asyncResult.then(() => {
          return payload;
        });
      }
      return payload;
    };
    const handleCanaryResult = (canary, payload, ctx) => {
      if (aborted(canary)) {
        canary.aborted = true;
        return canary;
      }
      const checkResult = runChecks(payload, checks, ctx);
      if (checkResult instanceof Promise) {
        if (ctx.async === false)
          throw new $ZodAsyncError;
        return checkResult.then((checkResult) => inst._zod.parse(checkResult, ctx));
      }
      return inst._zod.parse(checkResult, ctx);
    };
    inst._zod.run = (payload, ctx) => {
      if (ctx.skipChecks) {
        return inst._zod.parse(payload, ctx);
      }
      if (ctx.direction === "backward") {
        const canary = inst._zod.parse({ value: payload.value, issues: [] }, { ...ctx, skipChecks: true });
        if (canary instanceof Promise) {
          return canary.then((canary) => {
            return handleCanaryResult(canary, payload, ctx);
          });
        }
        return handleCanaryResult(canary, payload, ctx);
      }
      const result = inst._zod.parse(payload, ctx);
      if (result instanceof Promise) {
        if (ctx.async === false)
          throw new $ZodAsyncError;
        return result.then((result) => runChecks(result, checks, ctx));
      }
      return runChecks(result, checks, ctx);
    };
  }
}, {
  get "~standard"() {
    return hide(this, "~standard", standardProps(this));
  },
  set "~standard"(value) {
    own(this, "~standard", value);
  }
});
var toStandardResult = (r, ctx) => r.issues.length ? { issues: r.issues.map((iss) => finalizeIssue(iss, ctx, config())) } : { value: r.value };
async function validateAsync2(inst, value) {
  const ctx = { async: true };
  return toStandardResult(await inst._zod.run({ value, issues: [] }, ctx), ctx);
}
function standardProps(inst) {
  return {
    validate: (value) => {
      const ctx = { async: false };
      try {
        const r = inst._zod.run({ value, issues: [] }, ctx);
        if (!(r instanceof Promise))
          return toStandardResult(r, ctx);
      } catch (_) {}
      return validateAsync2(inst, value);
    },
    vendor: "zod",
    version: 1
  };
}
var $ZodString = /* @__PURE__ */ $constructor("$ZodString", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.pattern = def.pattern ?? anyString;
  inst._zod.parse = (payload, _) => {
    if (def.coerce)
      try {
        payload.value = String(payload.value);
      } catch (_) {}
    if (typeof payload.value === "string")
      return payload;
    payload.issues.push({
      expected: "string",
      code: "invalid_type",
      input: payload.value,
      inst
    });
    return payload;
  };
});
var $ZodStringFormat = /* @__PURE__ */ $constructor("$ZodStringFormat", (inst, def) => {
  $ZodCheckStringFormat.init(inst, def);
  $ZodString.init(inst, def);
});
var $ZodGUID = /* @__PURE__ */ $constructor("$ZodGUID", (inst, def) => {
  def.pattern ?? (def.pattern = guid);
  $ZodStringFormat.init(inst, def);
});
var $ZodUUID = /* @__PURE__ */ $constructor("$ZodUUID", (inst, def) => {
  if (def.version) {
    const versionMap = {
      v1: 1,
      v2: 2,
      v3: 3,
      v4: 4,
      v5: 5,
      v6: 6,
      v7: 7,
      v8: 8
    };
    const v = versionMap[def.version];
    if (v === undefined)
      throw new Error(`Invalid UUID version: "${def.version}"`);
    def.pattern ?? (def.pattern = uuid(v));
  } else
    def.pattern ?? (def.pattern = uuid());
  $ZodStringFormat.init(inst, def);
});
var $ZodEmail = /* @__PURE__ */ $constructor("$ZodEmail", (inst, def) => {
  def.pattern ?? (def.pattern = email);
  $ZodStringFormat.init(inst, def);
});
var URL_BAD_FORMAT = 1;
var URL_UNPARSEABLE = 2;
function canParseURL(input) {
  try {
    if (typeof URL !== "undefined" && typeof URL.canParse === "function")
      return URL.canParse(input);
    new URL(input);
    return true;
  } catch {
    return false;
  }
}
function validateURL(trimmed, def) {
  if (!("normalize" in def) && !("hostname" in def) && !("protocol" in def)) {
    return canParseURL(trimmed) || URL_UNPARSEABLE;
  }
  return parseURLObject(trimmed, def);
}
function parseURLObject(trimmed, def) {
  if (!def.normalize && def.protocol?.source === httpProtocol.source && !/^https?:\/\//i.test(trimmed)) {
    return URL_BAD_FORMAT;
  }
  try {
    if (typeof URL !== "undefined") {
      const URLStatic = URL;
      if (typeof URLStatic.parse === "function")
        return URLStatic.parse(trimmed) ?? URL_UNPARSEABLE;
    }
    return new URL(trimmed);
  } catch {
    return URL_UNPARSEABLE;
  }
}
var asciiTabOrNewline = /[\t\n\r]/g;
function stripTabAndNewline(value) {
  return value.replace(asciiTabOrNewline, "");
}
function urlHostnameOk(url, hostname) {
  hostname.lastIndex = 0;
  return hostname.test(url.hostname);
}
function urlProtocolOk(url, protocol) {
  protocol.lastIndex = 0;
  return protocol.test(url.protocol.endsWith(":") ? url.protocol.slice(0, -1) : url.protocol);
}
var $ZodURL = /* @__PURE__ */ $constructor("$ZodURL", (inst, def) => {
  $ZodStringFormat.init(inst, def);
  inst._zod.check = (payload) => {
    try {
      const trimmed = payload.value.trim();
      const url = validateURL(trimmed, def);
      if (url === URL_BAD_FORMAT) {
        payload.issues.push({
          code: "invalid_format",
          format: "url",
          note: "Invalid URL format",
          input: payload.value,
          inst,
          continue: !def.abort
        });
        return;
      }
      if (url === URL_UNPARSEABLE) {
        payload.issues.push({
          code: "invalid_format",
          format: "url",
          input: payload.value,
          inst,
          continue: !def.abort
        });
        return;
      }
      if (url === true) {
        payload.value = stripTabAndNewline(trimmed);
        return;
      }
      if (def.hostname && !urlHostnameOk(url, def.hostname)) {
        payload.issues.push({
          code: "invalid_format",
          format: "url",
          note: "Invalid hostname",
          pattern: def.hostname.source,
          input: payload.value,
          inst,
          continue: !def.abort
        });
      }
      if (def.protocol && !urlProtocolOk(url, def.protocol)) {
        payload.issues.push({
          code: "invalid_format",
          format: "url",
          note: "Invalid protocol",
          pattern: def.protocol.source,
          input: payload.value,
          inst,
          continue: !def.abort
        });
      }
      payload.value = def.normalize ? url.href : stripTabAndNewline(trimmed);
      return;
    } catch (_) {
      payload.issues.push({
        code: "invalid_format",
        format: "url",
        input: payload.value,
        inst,
        continue: !def.abort
      });
    }
  };
});
var $ZodEmoji = /* @__PURE__ */ $constructor("$ZodEmoji", (inst, def) => {
  def.pattern ?? (def.pattern = emoji());
  $ZodStringFormat.init(inst, def);
});
var $ZodNanoID = /* @__PURE__ */ $constructor("$ZodNanoID", (inst, def) => {
  if (def.length !== undefined && (!Number.isInteger(def.length) || def.length < 1))
    throw new Error(`Invalid nanoid length: ${def.length}`);
  def.pattern ?? (def.pattern = def.length === undefined ? nanoid : nanoidOfLength(def.length));
  $ZodStringFormat.init(inst, def);
});
var $ZodCUID = /* @__PURE__ */ $constructor("$ZodCUID", (inst, def) => {
  def.pattern ?? (def.pattern = cuid);
  $ZodStringFormat.init(inst, def);
});
var $ZodCUID2 = /* @__PURE__ */ $constructor("$ZodCUID2", (inst, def) => {
  def.pattern ?? (def.pattern = cuid2);
  $ZodStringFormat.init(inst, def);
});
var $ZodULID = /* @__PURE__ */ $constructor("$ZodULID", (inst, def) => {
  def.pattern ?? (def.pattern = ulid);
  $ZodStringFormat.init(inst, def);
});
var $ZodXID = /* @__PURE__ */ $constructor("$ZodXID", (inst, def) => {
  def.pattern ?? (def.pattern = xid);
  $ZodStringFormat.init(inst, def);
});
var $ZodKSUID = /* @__PURE__ */ $constructor("$ZodKSUID", (inst, def) => {
  def.pattern ?? (def.pattern = ksuid);
  $ZodStringFormat.init(inst, def);
});
var $ZodISODateTime = /* @__PURE__ */ $constructor("$ZodISODateTime", (inst, def) => {
  def.pattern ?? (def.pattern = datetime(def));
  $ZodStringFormat.init(inst, def);
});
var $ZodISODate = /* @__PURE__ */ $constructor("$ZodISODate", (inst, def) => {
  def.pattern ?? (def.pattern = date);
  $ZodStringFormat.init(inst, def);
});
var $ZodISOTime = /* @__PURE__ */ $constructor("$ZodISOTime", (inst, def) => {
  def.pattern ?? (def.pattern = time(def));
  $ZodStringFormat.init(inst, def);
});
var $ZodISODuration = /* @__PURE__ */ $constructor("$ZodISODuration", (inst, def) => {
  def.pattern ?? (def.pattern = duration);
  $ZodStringFormat.init(inst, def);
});
var $ZodIPv4 = /* @__PURE__ */ $constructor("$ZodIPv4", (inst, def) => {
  def.pattern ?? (def.pattern = ipv4);
  $ZodStringFormat.init(inst, def);
});
var ipv6Alphabet = /^[0-9a-fA-F:.]+$/;
function isValidIPv6(value) {
  if (!ipv6Alphabet.test(value))
    return false;
  return canParseURL(`http://[${value}]`);
}
var $ZodIPv6 = /* @__PURE__ */ $constructor("$ZodIPv6", (inst, def) => {
  def.pattern ?? (def.pattern = ipv6);
  $ZodStringFormat.init(inst, def);
  inst._zod.check = (payload) => {
    if (!isValidIPv6(payload.value)) {
      payload.issues.push({
        code: "invalid_format",
        format: "ipv6",
        input: payload.value,
        inst,
        continue: !def.abort
      });
    }
  };
});
var $ZodCIDRv4 = /* @__PURE__ */ $constructor("$ZodCIDRv4", (inst, def) => {
  def.pattern ?? (def.pattern = cidrv4);
  $ZodStringFormat.init(inst, def);
});
function isValidCIDRv6(value) {
  const parts = value.split("/");
  if (parts.length !== 2)
    return false;
  const [address, prefix] = parts;
  if (!prefix)
    return false;
  const prefixNum = Number(prefix);
  if (`${prefixNum}` !== prefix)
    return false;
  if (prefixNum < 0 || prefixNum > 128)
    return false;
  return isValidIPv6(address);
}
var $ZodCIDRv6 = /* @__PURE__ */ $constructor("$ZodCIDRv6", (inst, def) => {
  def.pattern ?? (def.pattern = cidrv6);
  $ZodStringFormat.init(inst, def);
  inst._zod.check = (payload) => {
    if (!isValidCIDRv6(payload.value)) {
      payload.issues.push({
        code: "invalid_format",
        format: "cidrv6",
        input: payload.value,
        inst,
        continue: !def.abort
      });
    }
  };
});
function isValidBase64(data) {
  if (data === "")
    return true;
  if (/\s/.test(data))
    return false;
  if (data.length % 4 !== 0)
    return false;
  try {
    atob(data);
    return true;
  } catch {
    return false;
  }
}
var base64Charset = /^[0-9a-zA-Z+/]*={0,2}$/;
var $ZodBase64 = /* @__PURE__ */ $constructor("$ZodBase64", (inst, def) => {
  def.pattern ?? (def.pattern = base64Charset);
  $ZodStringFormat.init(inst, def);
  inst._zod.check = (payload) => {
    if (isValidBase64(payload.value))
      return;
    payload.issues.push({
      code: "invalid_format",
      format: "base64",
      input: payload.value,
      inst,
      continue: !def.abort
    });
  };
});
var base64urlCharset = /^[A-Za-z0-9_-]*$/;
function isValidBase64URL(data) {
  if (!base64urlCharset.test(data))
    return false;
  const base64 = data.replace(/[-_]/g, (c) => c === "-" ? "+" : "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  return isValidBase64(padded);
}
var $ZodBase64URL = /* @__PURE__ */ $constructor("$ZodBase64URL", (inst, def) => {
  def.pattern ?? (def.pattern = base64urlCharset);
  $ZodStringFormat.init(inst, def);
  inst._zod.check = (payload) => {
    if (isValidBase64URL(payload.value))
      return;
    payload.issues.push({
      code: "invalid_format",
      format: "base64url",
      input: payload.value,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodE164 = /* @__PURE__ */ $constructor("$ZodE164", (inst, def) => {
  def.pattern ?? (def.pattern = e164);
  $ZodStringFormat.init(inst, def);
});
function isValidJWT2(token, algorithm = null) {
  try {
    const tokensParts = token.split(".");
    if (tokensParts.length !== 3)
      return false;
    const [header] = tokensParts;
    if (!header)
      return false;
    const parsedHeader = JSON.parse(atob(header));
    if ("typ" in parsedHeader && parsedHeader?.typ !== "JWT")
      return false;
    if (!parsedHeader.alg)
      return false;
    if (algorithm && (!("alg" in parsedHeader) || parsedHeader.alg !== algorithm))
      return false;
    return true;
  } catch {
    return false;
  }
}
var $ZodJWT = /* @__PURE__ */ $constructor("$ZodJWT", (inst, def) => {
  $ZodStringFormat.init(inst, def);
  inst._zod.check = (payload) => {
    if (isValidJWT2(payload.value, def.alg))
      return;
    payload.issues.push({
      code: "invalid_format",
      format: "jwt",
      input: payload.value,
      inst,
      continue: !def.abort
    });
  };
});
var $ZodNumber = /* @__PURE__ */ $constructor("$ZodNumber", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.pattern = number;
  inst._zod.parse = (payload, _ctx) => {
    if (def.coerce)
      try {
        payload.value = Number(payload.value);
      } catch (_) {}
    const input = payload.value;
    if (typeof input === "number" && !Number.isNaN(input) && Number.isFinite(input)) {
      return payload;
    }
    const received = typeof input === "number" ? Number.isNaN(input) ? "NaN" : !Number.isFinite(input) ? String(input) : undefined : undefined;
    payload.issues.push({
      expected: "number",
      code: "invalid_type",
      input,
      inst,
      ...received ? { received } : {}
    });
    return payload;
  };
});
var $ZodNumberFormat = /* @__PURE__ */ $constructor("$ZodNumberFormat", (inst, def) => {
  $ZodCheckNumberFormat.init(inst, def);
  $ZodNumber.init(inst, def);
});
var $ZodUnknown = /* @__PURE__ */ $constructor("$ZodUnknown", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.parse = (payload) => payload;
});
var $ZodNever = /* @__PURE__ */ $constructor("$ZodNever", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.parse = (payload, _ctx) => {
    payload.issues.push({
      expected: "never",
      code: "invalid_type",
      input: payload.value,
      inst
    });
    return payload;
  };
});
function handleArrayResult(result, final, index) {
  if (result.issues.length) {
    final.issues.push(...prefixIssues(index, result.issues));
  }
  final.value[index] = result.value;
}
var $ZodArray = /* @__PURE__ */ $constructor("$ZodArray", (inst, def) => {
  $ZodType.init(inst, def);
  const memo = globalConfig.memoizer;
  memo?.attach(inst);
  inst._zod.parse = (payload, ctx) => {
    const input = payload.value;
    if (!Array.isArray(input)) {
      payload.issues.push({
        expected: "array",
        code: "invalid_type",
        input,
        inst
      });
      return payload;
    }
    payload.value = memo ? memo.alloc(inst, payload, Array(input.length), ctx) : Array(input.length);
    const proms = [];
    const abortEarly = ctx?.abortEarly;
    for (let i = 0;i < input.length; i++) {
      const item = input[i];
      const result = def.element._zod.run({
        value: item,
        issues: []
      }, ctx);
      if (result instanceof Promise) {
        proms.push(result.then((result) => handleArrayResult(result, payload, i)));
      } else {
        handleArrayResult(result, payload, i);
        if (abortEarly && result.issues.length !== 0 && aborted(result))
          break;
      }
    }
    if (proms.length) {
      return Promise.all(proms).then(() => payload);
    }
    return payload;
  };
});
function handlePropertyResult(result, final, key, input, optin, optout) {
  const isPresent = key in input;
  const isOptionalOut = optout === "optional";
  if (!isPresent && isOptionalOut && optin === "optional") {
    return;
  }
  if (result.issues.length) {
    if (optin !== undefined && isOptionalOut && !isPresent) {
      return;
    }
    final.issues.push(...prefixIssues(key, result.issues));
  }
  if (!isPresent && optin === undefined) {
    if (!result.issues.length) {
      final.issues.push({
        code: "invalid_type",
        expected: "nonoptional",
        input: undefined,
        path: [key]
      });
    }
    return;
  }
  if (result.value === undefined) {
    if (isPresent || optin === "defaulted" && !isOptionalOut) {
      final.value[key] = undefined;
    }
  } else {
    final.value[key] = result.value;
  }
}
var NO_SYMBOL_KEYS = [];
function normalizeDef(def) {
  const keys = Object.keys(def.shape);
  const ownSymbols = Object.getOwnPropertySymbols(def.shape);
  const symbolKeys = ownSymbols.length ? ownSymbols : NO_SYMBOL_KEYS;
  const allKeys = symbolKeys.length ? [...keys, ...symbolKeys] : keys;
  for (const k of allKeys) {
    if (!def.shape?.[k]?._zod?.traits?.has("$ZodType")) {
      throw new Error(`Invalid element at key "${String(k)}": expected a Zod schema`);
    }
  }
  const okeys = optionalKeys(def.shape);
  return {
    ...def,
    allKeys,
    symbolKeys,
    keySet: new Set(keys),
    numKeys: keys.length,
    optionalKeys: new Set(okeys)
  };
}
function handleCatchall(proms, input, payload, ctx, def, inst, abortEarly) {
  const unrecognized = [];
  const keySet = def.keySet;
  const _catchall = def.catchall._zod;
  const t = _catchall.def.type;
  const optin = _catchall.optin;
  const optout = _catchall.optout;
  let seen = 0;
  for (const key in input) {
    if (abortEarly && payload.issues.length !== seen) {
      if (aborted(payload, seen))
        break;
      seen = payload.issues.length;
    }
    if (keySet.has(key))
      continue;
    if (key === "__proto__") {
      if (t === "never")
        unrecognized.push(key);
      continue;
    }
    if (t === "never") {
      unrecognized.push(key);
      continue;
    }
    const r = _catchall.run({ value: input[key], issues: [] }, ctx);
    if (r instanceof Promise) {
      proms.push(r.then((r) => handlePropertyResult(r, payload, key, input, optin, optout)));
    } else {
      handlePropertyResult(r, payload, key, input, optin, optout);
    }
  }
  if (unrecognized.length) {
    payload.issues.push({
      code: "unrecognized_keys",
      keys: unrecognized,
      input,
      inst,
      continue: true
    });
  }
  if (!proms.length)
    return payload;
  return Promise.all(proms).then(() => {
    return payload;
  });
}
var $ZodObject = /* @__PURE__ */ $constructor("$ZodObject", (inst, def) => {
  $ZodType.init(inst, def);
  const desc = Object.getOwnPropertyDescriptor(def, "shape");
  const sh = desc?.get ? desc.get.raw : def.shape ?? {};
  if (sh) {
    const get = () => {
      const newSh = { ...sh };
      Object.defineProperty(def, "shape", { value: newSh });
      get.raw = newSh;
      return newSh;
    };
    get.raw = sh;
    Object.defineProperty(def, "shape", { get });
  }
  const _normalized = cached(() => normalizeDef(def));
  defineLazyInternal(inst, "propValues", (zod) => {
    const shape = zod.def.shape;
    const propValues = {};
    for (const key in shape) {
      const field = shape[key]._zod;
      if (field.values) {
        if (!Object.prototype.hasOwnProperty.call(propValues, key)) {
          assignProp(propValues, key, new Set);
        }
        for (const v of field.values)
          propValues[key].add(v);
        if (field.optin !== undefined)
          propValues[key].add(undefined);
      }
    }
    return propValues;
  });
  const isObject = isObject2;
  const catchall = def.catchall;
  let value;
  const memo = globalConfig.memoizer;
  memo?.attach(inst);
  inst._zod.parse = (payload, ctx) => {
    value ?? (value = _normalized.value);
    const input = payload.value;
    if (!isObject(input)) {
      payload.issues.push({
        expected: "object",
        code: "invalid_type",
        input,
        inst
      });
      return payload;
    }
    payload.value = memo ? memo.alloc(inst, payload, {}, ctx) : {};
    const proms = [];
    const shape = value.shape;
    const abortEarly = ctx?.abortEarly;
    let seen = payload.issues.length;
    for (const key of value.allKeys) {
      if (abortEarly && payload.issues.length !== seen) {
        if (aborted(payload, seen))
          break;
        seen = payload.issues.length;
      }
      if (key === "__proto__")
        continue;
      const el = shape[key];
      const optin = el._zod.optin;
      const optout = el._zod.optout;
      const r = el._zod.run({ value: input[key], issues: [] }, ctx);
      if (r instanceof Promise) {
        proms.push(r.then((r) => handlePropertyResult(r, payload, key, input, optin, optout)));
      } else {
        handlePropertyResult(r, payload, key, input, optin, optout);
      }
    }
    if (!catchall) {
      return proms.length ? Promise.all(proms).then(() => payload) : payload;
    }
    return handleCatchall(proms, input, payload, ctx, _normalized.value, inst, abortEarly === true);
  };
});
var $ZodObjectJIT = /* @__PURE__ */ $constructor("$ZodObjectJIT", (inst, def) => {
  $ZodObject.init(inst, def);
  const superParse = inst._zod.parse;
  const _normalized = cached(() => normalizeDef(def));
  const memo = globalConfig.memoizer;
  const generateFastpass = (shape) => {
    const normalized = _normalized.value;
    const syms = normalized.symbolKeys;
    const doc = new Doc(["payload", "ctx"], { shape, inst, memo, syms });
    const parseStr = (k) => `shape[${k}]._zod.run({ value: input[${k}], issues: [] }, ctx)`;
    const prefixStr = (id, k) => `
          let ${id}_ab = false;
          for (let i = 0; i < ${id}.issues.length; i++) {
            const iss = ${id}.issues[i];
            iss.path = iss.path ? [${k}, ...iss.path] : [${k}];
            payload.issues.push(iss);
            if (iss.continue !== true) ${id}_ab = true;
          }
          if (${id}_ab && ctx && ctx.abortEarly) {
            payload.value = newResult;
            return payload;
          }`;
    doc.write(`const input = payload.value;`);
    const ids = Object.create(null);
    let counter = 0;
    for (const key of normalized.allKeys) {
      ids[key] = `key_${counter++}`;
    }
    doc.write(memo ? `const newResult = memo.alloc(inst, payload, {}, ctx);` : `const newResult = {};`);
    for (const key of normalized.allKeys) {
      if (key === "__proto__")
        continue;
      const id = ids[key];
      const k = typeof key === "symbol" ? `syms[${syms.indexOf(key)}]` : esc(key);
      const isPresent = `${k} in input`;
      const schema = shape[key];
      const optin = schema?._zod?.optin;
      const isOptionalIn = optin !== undefined;
      const isOptionalOut = schema?._zod?.optout === "optional";
      doc.write(`const ${id} = ${parseStr(k)};`);
      if (isOptionalIn && isOptionalOut) {
        const assign = optin === "optional" ? `${id}_present` : `${id}.value !== undefined || ${id}_present`;
        doc.write(`
        const ${id}_present = ${isPresent};
        if (!${id}.issues.length || ${id}_present) {
          if (${id}.issues.length) {${prefixStr(id, k)}
          }

          if (${assign}) {
            newResult[${k}] = ${id}.value;
          }
        }

      `);
      } else if (!isOptionalIn) {
        doc.write(`
        const ${id}_present = ${isPresent};
        if (${id}.issues.length) {${prefixStr(id, k)}
        }
        if (!${id}_present && !${id}.issues.length) {
          payload.issues.push({
            code: "invalid_type",
            expected: "nonoptional",
            input: undefined,
            path: [${k}]
          });
          if (ctx && ctx.abortEarly) {
            payload.value = newResult;
            return payload;
          }
        }

        if (${id}_present) {
          newResult[${k}] = ${id}.value;
        }

      `);
      } else {
        doc.write(`
        if (${id}.issues.length) {${prefixStr(id, k)}
        }
      `);
        if (optin === "defaulted") {
          doc.write(`newResult[${k}] = ${id}.value;`);
        } else {
          doc.write(`
        if (${id}.value !== undefined || ${isPresent}) {
          newResult[${k}] = ${id}.value;
        }
      `);
        }
      }
    }
    doc.write(`payload.value = newResult;`);
    doc.write(`return payload;`);
    return doc.compile();
  };
  let fastpass;
  const isObject = isObject2;
  const jit = !globalConfig.jitless;
  const allowsEval2 = allowsEval;
  const fastEnabled = jit && allowsEval2.value;
  const catchall = def.catchall;
  let value;
  inst._zod.parse = (payload, ctx) => {
    value ?? (value = _normalized.value);
    const input = payload.value;
    if (!isObject(input)) {
      payload.issues.push({
        expected: "object",
        code: "invalid_type",
        input,
        inst
      });
      return payload;
    }
    if (jit && fastEnabled && ctx?.async === false && ctx.jitless !== true) {
      if (!fastpass)
        fastpass = generateFastpass(def.shape);
      payload = fastpass(payload, ctx);
      if (!catchall)
        return payload;
      return handleCatchall([], input, payload, ctx, value, inst, ctx?.abortEarly === true);
    }
    return superParse(payload, ctx);
  };
});
function handleUnionResults(results, final, inst, ctx) {
  for (const result of results) {
    if (result.issues.length === 0) {
      final.value = result.value;
      return final;
    }
  }
  const nonaborted = results.filter((r) => !aborted(r));
  if (nonaborted.length === 1) {
    final.value = nonaborted[0].value;
    return nonaborted[0];
  }
  final.issues.push({
    code: "invalid_union",
    input: final.value,
    inst,
    errors: results.map((result) => result.issues.map((iss) => finalizeIssue(iss, ctx, config())))
  });
  return final;
}
var $ZodUnion = /* @__PURE__ */ $constructor("$ZodUnion", (inst, def) => {
  $ZodType.init(inst, def);
  defineLazyInternal(inst, "optin", (zod) => zod.def.options.some((o) => o._zod.optin === "defaulted") ? "defaulted" : zod.def.options.some((o) => o._zod.optin !== undefined) ? "optional" : undefined);
  defineLazyInternal(inst, "optout", (zod) => zod.def.options.some((o) => o._zod.optout === "optional") ? "optional" : undefined);
  defineLazyInternal(inst, "values", (zod) => {
    if (zod.def.options.every((o) => o._zod.values)) {
      return new Set(zod.def.options.flatMap((option) => Array.from(option._zod.values)));
    }
    return;
  });
  defineLazyInternal(inst, "pattern", (zod) => {
    if (zod.def.options.every((o) => o._zod.pattern)) {
      const patterns = zod.def.options.map((o) => o._zod.pattern);
      return new RegExp(`^(${patterns.map((p) => cleanRegex(p.source)).join("|")})$`);
    }
    return;
  });
  const first = def.options.length === 1 ? def.options[0]._zod.run : null;
  inst._zod.parse = (payload, ctx) => {
    if (first) {
      return first(payload, ctx);
    }
    let async = false;
    const results = [];
    for (const option of def.options) {
      const result = option._zod.run({
        value: payload.value,
        issues: []
      }, ctx);
      if (result instanceof Promise) {
        results.push(result);
        async = true;
      } else {
        if (result.issues.length === 0)
          return result;
        results.push(result);
      }
    }
    if (!async)
      return handleUnionResults(results, payload, inst, ctx);
    return Promise.all(results).then((results) => {
      return handleUnionResults(results, payload, inst, ctx);
    });
  };
});
var $ZodIntersection = /* @__PURE__ */ $constructor("$ZodIntersection", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.parse = (payload, ctx) => {
    const input = payload.value;
    const left = def.left._zod.run({ value: input, issues: [] }, ctx);
    const right = def.right._zod.run({ value: input, issues: [] }, ctx);
    const async = left instanceof Promise || right instanceof Promise;
    if (async) {
      return Promise.all([left, right]).then(([left, right]) => {
        return handleIntersectionResults(payload, left, right);
      });
    }
    return handleIntersectionResults(payload, left, right);
  };
});
function mergeValues2(a, b) {
  if (a === b) {
    return { valid: true, data: a };
  }
  if (a instanceof Date && b instanceof Date && +a === +b) {
    return { valid: true, data: a };
  }
  if (isPlainObject(a) && isPlainObject(b)) {
    const bKeys = Object.keys(b);
    const sharedKeys = Object.keys(a).filter((key) => bKeys.indexOf(key) !== -1);
    const newObj = { ...a, ...b };
    if (Object.prototype.hasOwnProperty.call(newObj, "__proto__"))
      delete newObj.__proto__;
    for (const key of sharedKeys) {
      if (key === "__proto__")
        continue;
      const sharedValue = mergeValues2(a[key], b[key]);
      if (!sharedValue.valid) {
        return {
          valid: false,
          mergeErrorPath: [key, ...sharedValue.mergeErrorPath]
        };
      }
      newObj[key] = sharedValue.data;
    }
    return { valid: true, data: newObj };
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) {
      return { valid: false, mergeErrorPath: [] };
    }
    const newArray = [];
    for (let index = 0;index < a.length; index++) {
      const itemA = a[index];
      const itemB = b[index];
      const sharedValue = mergeValues2(itemA, itemB);
      if (!sharedValue.valid) {
        return {
          valid: false,
          mergeErrorPath: [index, ...sharedValue.mergeErrorPath]
        };
      }
      newArray.push(sharedValue.data);
    }
    return { valid: true, data: newArray };
  }
  return { valid: false, mergeErrorPath: [] };
}
function handleIntersectionResults(result, left, right) {
  const unrecKeys = new Map;
  let unrecIssue;
  const keyIssues = new Map;
  const collect = (iss, side) => {
    let keys;
    if (iss.code === "unrecognized_keys" && !iss.path?.length) {
      unrecIssue ?? (unrecIssue = iss);
      keys = iss.keys;
    } else if (iss.code === "invalid_key" && iss.origin === "record" && iss.path?.length === 1) {
      const k = String(iss.path[0]);
      if (!keyIssues.has(k))
        keyIssues.set(k, iss);
      keys = [k];
    } else {
      return false;
    }
    for (const k of keys) {
      if (!unrecKeys.has(k))
        unrecKeys.set(k, {});
      unrecKeys.get(k)[side] = true;
    }
    return true;
  };
  for (const iss of left.issues) {
    if (!collect(iss, "l"))
      result.issues.push(iss);
  }
  for (const iss of right.issues) {
    if (!collect(iss, "r"))
      result.issues.push(iss);
  }
  const bothKeys = [...unrecKeys].filter(([, f]) => f.l && f.r).map(([k]) => k);
  if (bothKeys.length) {
    const aggregated = unrecIssue ? bothKeys.filter((k) => unrecIssue.keys.includes(k)) : [];
    if (aggregated.length)
      result.issues.push({ ...unrecIssue, keys: aggregated });
    for (const k of bothKeys) {
      if (!aggregated.includes(k) && keyIssues.has(k))
        result.issues.push(keyIssues.get(k));
    }
  }
  const merged = mergeValues2(left.value, right.value);
  if (!merged.valid) {
    if (aborted(result))
      return result;
    throw new Error(`Unmergable intersection. Error path: ` + `${JSON.stringify(merged.mergeErrorPath)}`);
  }
  result.value = merged.data;
  return result;
}
var $ZodEnum = /* @__PURE__ */ $constructor("$ZodEnum", (inst, def) => {
  $ZodType.init(inst, def);
  const values = getEnumValues(def.entries);
  const valuesSet = new Set(values);
  inst._zod.values = valuesSet;
  defineLazyInternal(inst, "pattern", (zod) => {
    const patternValues = getEnumValues(zod.def.entries).filter((k) => propertyKeyTypes.has(typeof k));
    return new RegExp(patternValues.length ? `^(${patternValues.map((o) => escapeRegex(o.toString())).join("|")})$` : "^[^\\s\\S]$");
  });
  inst._zod.parse = (payload, _ctx) => {
    const input = payload.value;
    if (valuesSet.has(input)) {
      return payload;
    }
    payload.issues.push({
      code: "invalid_value",
      values,
      input,
      inst
    });
    return payload;
  };
});
var $ZodTransform = /* @__PURE__ */ $constructor("$ZodTransform", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.optin = "optional";
  globalConfig.memoizer?.guard(inst);
  inst._zod.parse = (payload, ctx) => {
    if (ctx.direction === "backward") {
      throw new $ZodEncodeError(inst.constructor.name);
    }
    const _out = def.transform(payload.value, payload);
    if (ctx.async) {
      const output = _out instanceof Promise ? _out : Promise.resolve(_out);
      return output.then((output) => {
        payload.value = output;
        return payload;
      });
    }
    if (_out instanceof Promise) {
      throw new $ZodAsyncError;
    }
    payload.value = _out;
    return payload;
  };
});
function handleOptionalResult(payload, result) {
  payload.value = result.issues.length ? undefined : result.value;
  return payload;
}
var $ZodOptional = /* @__PURE__ */ $constructor("$ZodOptional", (inst, def) => {
  $ZodType.init(inst, def);
  defineLazyInternal(inst, "optin", (zod) => zod.def.innerType._zod.optin === "defaulted" ? "defaulted" : "optional");
  inst._zod.optout = "optional";
  defineLazyInternal(inst, "values", (zod) => {
    const values = zod.def.innerType._zod.values;
    return values ? new Set([...values, undefined]) : undefined;
  });
  defineLazyInternal(inst, "pattern", (zod) => {
    const pattern = zod.def.innerType._zod.pattern;
    return pattern ? new RegExp(`^(${cleanRegex(pattern.source)})?$`) : undefined;
  });
  inst._zod.parse = (payload, ctx) => {
    if (payload.value === undefined) {
      if (def.innerType._zod.optin !== "defaulted")
        return payload;
      const result = def.innerType._zod.run({ value: payload.value, issues: [] }, ctx);
      if (result instanceof Promise)
        return result.then((result) => handleOptionalResult(payload, result));
      return handleOptionalResult(payload, result);
    }
    return def.innerType._zod.run(payload, ctx);
  };
});
var $ZodExactOptional = /* @__PURE__ */ $constructor("$ZodExactOptional", (inst, def) => {
  $ZodOptional.init(inst, def);
  defineLazyInternal(inst, "values", (zod) => zod.def.innerType._zod.values);
  defineLazyInternal(inst, "pattern", (zod) => zod.def.innerType._zod.pattern);
  inst._zod.parse = (payload, ctx) => {
    return def.innerType._zod.run(payload, ctx);
  };
});
var $ZodNullable = /* @__PURE__ */ $constructor("$ZodNullable", (inst, def) => {
  $ZodType.init(inst, def);
  defineLazyInternal(inst, "optin", (zod) => zod.def.innerType._zod.optin);
  defineLazyInternal(inst, "optout", (zod) => zod.def.innerType._zod.optout);
  defineLazyInternal(inst, "pattern", (zod) => {
    const pattern = zod.def.innerType._zod.pattern;
    return pattern ? new RegExp(`^(${cleanRegex(pattern.source)}|null)$`) : undefined;
  });
  defineLazyInternal(inst, "values", (zod) => {
    return zod.def.innerType._zod.values ? new Set([...zod.def.innerType._zod.values, null]) : undefined;
  });
  inst._zod.parse = (payload, ctx) => {
    if (payload.value === null)
      return payload;
    return def.innerType._zod.run(payload, ctx);
  };
});
var $ZodDefault = /* @__PURE__ */ $constructor("$ZodDefault", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.optin = "defaulted";
  defineLazyInternal(inst, "values", (zod) => zod.def.innerType._zod.values);
  inst._zod.parse = (payload, ctx) => {
    if (ctx.direction === "backward") {
      return def.innerType._zod.run(payload, ctx);
    }
    if (payload.value === undefined) {
      payload.value = def.defaultValue;
      return payload;
    }
    const result = def.innerType._zod.run(payload, ctx);
    if (result instanceof Promise) {
      return result.then((result) => handleDefaultResult(result, def));
    }
    return handleDefaultResult(result, def);
  };
});
function handleDefaultResult(payload, def) {
  if (payload.value === undefined) {
    payload.value = def.defaultValue;
  }
  return payload;
}
var $ZodPrefault = /* @__PURE__ */ $constructor("$ZodPrefault", (inst, def) => {
  $ZodType.init(inst, def);
  inst._zod.optin = "defaulted";
  defineLazyInternal(inst, "values", (zod) => zod.def.innerType._zod.values);
  inst._zod.parse = (payload, ctx) => {
    if (ctx.direction === "backward") {
      return def.innerType._zod.run(payload, ctx);
    }
    if (payload.value === undefined) {
      payload.value = def.defaultValue;
    }
    return def.innerType._zod.run(payload, ctx);
  };
});
var $ZodNonOptional = /* @__PURE__ */ $constructor("$ZodNonOptional", (inst, def) => {
  $ZodType.init(inst, def);
  defineLazyInternal(inst, "values", (zod) => {
    const v = zod.def.innerType._zod.values;
    return v ? new Set([...v].filter((x) => x !== undefined)) : undefined;
  });
  inst._zod.parse = (payload, ctx) => {
    const result = def.innerType._zod.run(payload, ctx);
    if (result instanceof Promise) {
      return result.then((result) => handleNonOptionalResult(result, inst));
    }
    return handleNonOptionalResult(result, inst);
  };
});
function handleNonOptionalResult(payload, inst) {
  if (!payload.issues.length && payload.value === undefined) {
    payload.issues.push({
      code: "invalid_type",
      expected: "nonoptional",
      input: payload.value,
      inst
    });
  }
  return payload;
}
function handleCatchResult(payload, result, def, ctx) {
  if (!result.issues.length) {
    payload.value = result.value;
    if (result.memo)
      payload.memo = true;
    return payload;
  }
  payload.value = def.catchValue({
    ...result,
    value: payload.value,
    error: {
      issues: result.issues.map((iss) => finalizeIssue(iss, ctx, config()))
    },
    input: payload.value
  });
  return payload;
}
var $ZodCatch = /* @__PURE__ */ $constructor("$ZodCatch", (inst, def) => {
  $ZodType.init(inst, def);
  defineLazyInternal(inst, "optin", (zod) => zod.def.innerType._zod.optin === "defaulted" ? "defaulted" : "optional");
  defineLazyInternal(inst, "optout", (zod) => zod.def.innerType._zod.optout);
  defineLazyInternal(inst, "values", (zod) => zod.def.innerType._zod.values);
  inst._zod.parse = (payload, ctx) => {
    if (ctx.direction === "backward") {
      return def.innerType._zod.run(payload, ctx);
    }
    const result = def.innerType._zod.run({ value: payload.value, issues: [] }, ctx);
    if (result instanceof Promise) {
      return result.then((result) => handleCatchResult(payload, result, def, ctx));
    }
    return handleCatchResult(payload, result, def, ctx);
  };
});
var $ZodPipe = /* @__PURE__ */ $constructor("$ZodPipe", (inst, def) => {
  $ZodType.init(inst, def);
  defineLazyInternal(inst, "values", (zod) => zod.def.in._zod.values);
  defineLazyInternal(inst, "optin", (zod) => zod.def.in._zod.optin);
  defineLazyInternal(inst, "optout", (zod) => zod.def.out._zod.optout);
  defineLazyInternal(inst, "propValues", (zod) => zod.def.in._zod.propValues);
  inst._zod.parse = (payload, ctx) => {
    if (ctx.direction === "backward") {
      const right = def.out._zod.run(payload, ctx);
      if (right instanceof Promise) {
        return right.then((right) => handlePipeResult(right, def.in, ctx));
      }
      return handlePipeResult(right, def.in, ctx);
    }
    const left = def.in._zod.run(payload, ctx);
    if (left instanceof Promise) {
      return left.then((left) => handlePipeResult(left, def.out, ctx));
    }
    return handlePipeResult(left, def.out, ctx);
  };
});
function handlePipeResult(left, next, ctx) {
  if (left.issues.some((iss) => iss.code !== "unrecognized_keys")) {
    left.aborted = true;
    return left;
  }
  return next._zod.run({ value: left.value, issues: left.issues }, ctx);
}
var $ZodReadonly = /* @__PURE__ */ $constructor("$ZodReadonly", (inst, def) => {
  $ZodType.init(inst, def);
  defineLazyInternal(inst, "propValues", (zod) => zod.def.innerType._zod.propValues);
  defineLazyInternal(inst, "values", (zod) => zod.def.innerType._zod.values);
  defineLazyInternal(inst, "optin", (zod) => zod.def.innerType?._zod?.optin);
  defineLazyInternal(inst, "optout", (zod) => zod.def.innerType?._zod?.optout);
  inst._zod.parse = (payload, ctx) => {
    if (ctx.direction === "backward") {
      return def.innerType._zod.run(payload, ctx);
    }
    const result = def.innerType._zod.run(payload, ctx);
    if (result instanceof Promise) {
      return result.then(handleReadonlyResult);
    }
    return handleReadonlyResult(result);
  };
});
function handleReadonlyResult(payload) {
  if (!payload.memo)
    payload.value = Object.freeze(payload.value);
  return payload;
}
var $ZodCustom = /* @__PURE__ */ $constructor("$ZodCustom", (inst, def) => {
  $ZodCheck.init(inst, def);
  $ZodType.init(inst, def);
  inst._zod.parse = (payload, _) => {
    return payload;
  };
  inst._zod.check = (payload) => {
    const input = payload.value;
    const r = def.fn(input);
    if (r instanceof Promise) {
      return r.then((r) => handleRefineResult(r, payload, input, inst));
    }
    handleRefineResult(r, payload, input, inst);
    return;
  };
});
function handleRefineResult(result, payload, input, inst) {
  if (!result) {
    const _iss = {
      code: "custom",
      input,
      inst,
      path: [...inst._zod.def.path ?? []],
      continue: !inst._zod.def.abort
    };
    if (inst._zod.def.params)
      _iss.params = inst._zod.def.params;
    payload.issues.push(issue(_iss));
  }
}

class $ZodCyclicError extends Error {
  constructor() {
    super(`Cannot parse a reference cycle that closes through a transform`);
    this.name = "ZodCyclicError";
  }
}
var STATE = "~memo";
var NO_ISSUES = [];
function isRef(value) {
  return value !== null && typeof value === "object";
}
function cloneIssues(issues) {
  return issues.map((iss) => iss.path ? { ...iss, path: iss.path.slice() } : { ...iss });
}
var recursive = /* @__PURE__ */ new WeakMap;
var NONE = 0;
var ASSUMED = 1;
var PROVEN = 2;
function isRecursive(inst, stack, resolve) {
  const cached = recursive.get(inst);
  if (cached !== undefined)
    return cached ? PROVEN : NONE;
  if (stack.has(inst))
    return PROVEN;
  stack.add(inst);
  let result = NONE;
  const check = (child) => {
    if (result !== PROVEN && child?._zod) {
      const answer = isRecursive(child, stack, resolve);
      if (answer > result)
        result = answer;
    }
  };
  const shape = (sh, spread) => {
    let answer = NONE;
    for (const key of Reflect.ownKeys(sh)) {
      const desc = Object.getOwnPropertyDescriptor(sh, key);
      if (spread && !desc.enumerable)
        continue;
      const child = desc.get ? ASSUMED : desc.value?._zod ? isRecursive(desc.value, stack, resolve) : NONE;
      if (child > answer)
        answer = child;
    }
    return answer;
  };
  const merge = (answer) => {
    if (answer > result)
      result = answer;
  };
  const def = inst._zod.def;
  const kind = def.type;
  switch (kind) {
    case "object": {
      const raw = rawShape(def);
      merge(raw ? shape(raw, true) : ASSUMED);
      check(def.catchall);
      break;
    }
    case "array":
      check(def.element);
      break;
    case "tuple":
      for (const el of def.items)
        check(el);
      check(def.rest);
      break;
    case "record":
    case "map":
      check(def.keyType);
      check(def.valueType);
      break;
    case "set":
      check(def.valueType);
      break;
    case "union":
      for (const el of def.options)
        check(el);
      break;
    case "intersection":
      check(def.left);
      check(def.right);
      break;
    case "optional":
    case "nullable":
    case "default":
    case "prefault":
    case "catch":
    case "readonly":
    case "nonoptional":
    case "promise":
    case "success":
      check(def.innerType);
      break;
    case "pipe":
      check(def.in);
      check(def.out);
      break;
    case "function":
      check(def.input);
      check(def.output);
      break;
    case "lazy": {
      const inner = def._cachedInner ?? (resolve ? inst._zod.innerType : undefined);
      merge(inner ? isRecursive(inner, stack, false) : ASSUMED);
      break;
    }
    case "template_literal":
    case "string":
    case "number":
    case "int":
    case "boolean":
    case "bigint":
    case "symbol":
    case "undefined":
    case "null":
    case "void":
    case "never":
    case "any":
    case "unknown":
    case "date":
    case "nan":
    case "enum":
    case "literal":
    case "file":
    case "transform":
    case "custom":
      break;
    default: {
      for (const key in def) {
        const desc = Object.getOwnPropertyDescriptor(def, key);
        if (!desc || desc.get)
          continue;
        const value = desc.value;
        if (!value || typeof value !== "object")
          continue;
        if (value._zod)
          check(value);
        else if (Array.isArray(value))
          for (const el of value)
            check(el);
      }
    }
  }
  stack.delete(inst);
  return settle(inst, result);
}
function settle(inst, answer) {
  if (answer !== ASSUMED)
    recursive.set(inst, answer === PROVEN);
  return answer;
}
function bucketFor(state, inst) {
  let bucket = state.buckets.get(inst);
  if (!bucket) {
    bucket = new WeakMap;
    state.buckets.set(inst, bucket);
  }
  return bucket;
}
var handoff;
var open = [];
var memo = {
  alloc(_inst, payload, empty) {
    const bucket = handoff;
    if (!bucket)
      return empty;
    handoff = undefined;
    const entry = { value: empty, issues: null };
    bucket.set(payload.value, entry);
    open.push(entry);
    return empty;
  },
  guard(inst) {
    var _a;
    (_a = inst._zod).deferred ?? (_a.deferred = []);
    inst._zod.deferred.push(() => {
      const base = inst._zod.parse;
      const wrapped = (payload, ctx) => {
        if (ctx.direction !== "backward" && isBackEdge(ctx, payload.value))
          throw new $ZodCyclicError;
        return base(payload, ctx);
      };
      inst._zod.parse = wrapped;
      if (inst._zod.run === base)
        inst._zod.run = wrapped;
    });
  },
  attach(inst) {
    var _a;
    let isRecursiveInst;
    let rechecked = false;
    let lastCtx;
    let lastBucket;
    (_a = inst._zod).deferred ?? (_a.deferred = []);
    inst._zod.deferred.push(() => {
      const base = inst._zod.parse;
      const wrapped = (payload, ctx) => {
        if (isRecursiveInst === undefined) {
          const walked = isRecursive(inst, new Set, false);
          if (walked === NONE) {
            inst._zod.parse = base;
            if (inst._zod.run === wrapped)
              inst._zod.run = base;
            return base(payload, ctx);
          }
          if (walked === PROVEN || rechecked)
            isRecursiveInst = true;
          else
            rechecked = true;
        }
        const input = payload.value;
        if (!isRef(input))
          return base(payload, ctx);
        let state = ctx[STATE];
        if (!state) {
          state = { buckets: new WeakMap, backEdges: undefined };
          ctx[STATE] = state;
        }
        let bucket;
        if (lastCtx === ctx) {
          bucket = lastBucket;
        } else {
          bucket = bucketFor(state, inst);
          lastCtx = ctx;
          lastBucket = bucket;
        }
        const hit = bucket.get(input);
        if (hit) {
          payload.value = hit.value;
          if (hit.issues) {
            if (hit.issues.length)
              payload.issues.push(...cloneIssues(hit.issues));
          } else {
            payload.memo = true;
            state.backEdges ?? (state.backEdges = new WeakSet);
            state.backEdges.add(hit.value);
          }
          return payload;
        }
        handoff = bucket;
        const depth = open.length;
        const result = base(payload, ctx);
        handoff = undefined;
        const entry = open.length > depth ? open.pop() : undefined;
        if (result instanceof Promise) {
          return result.then((r) => {
            if (entry)
              entry.issues = r.issues.length ? cloneIssues(r.issues) : NO_ISSUES;
            return r;
          });
        }
        if (entry)
          entry.issues = result.issues.length ? cloneIssues(result.issues) : NO_ISSUES;
        return result;
      };
      inst._zod.parse = wrapped;
      if (inst._zod.run === base)
        inst._zod.run = wrapped;
    });
  }
};
function memoizer() {
  return memo;
}
function isBackEdge(ctx, value) {
  const backEdges = ctx[STATE]?.backEdges;
  return backEdges !== undefined && isRef(value) && backEdges.has(value);
}
var error2 = () => {
  const Sizable = {
    string: { unit: "characters", verb: "to have" },
    file: { unit: "bytes", verb: "to have" },
    array: { unit: "items", verb: "to have" },
    set: { unit: "items", verb: "to have" },
    map: { unit: "entries", verb: "to have" }
  };
  function getSizing(origin) {
    return Sizable[origin] ?? null;
  }
  const FormatDictionary = {
    regex: "input",
    email: "email address",
    url: "URL",
    emoji: "emoji",
    uuid: "UUID",
    uuidv4: "UUIDv4",
    uuidv6: "UUIDv6",
    nanoid: "nanoid",
    guid: "GUID",
    cuid: "cuid",
    cuid2: "cuid2",
    ulid: "ULID",
    xid: "XID",
    ksuid: "KSUID",
    datetime: "ISO datetime",
    date: "ISO date",
    time: "ISO time",
    duration: "ISO duration",
    ipv4: "IPv4 address",
    ipv6: "IPv6 address",
    mac: "MAC address",
    cidrv4: "IPv4 range",
    cidrv6: "IPv6 range",
    base64: "base64-encoded string",
    base64url: "base64url-encoded string",
    json_string: "JSON string",
    e164: "E.164 number",
    currency_code: "currency code",
    credit_card: "credit card number",
    iban: "IBAN",
    jwt: "JWT",
    template_literal: "input"
  };
  const TypeDictionary = {
    nan: "NaN"
  };
  function getTypeName(type, input) {
    if (type === "number" && typeof input === "number" && !Number.isFinite(input)) {
      return String(input);
    }
    return TypeDictionary[type] ?? type;
  }
  return (issue) => {
    switch (issue.code) {
      case "invalid_type": {
        const expected = getTypeName(issue.expected);
        const receivedType = parsedType(issue.input);
        const received = getTypeName(receivedType, issue.input);
        return `Invalid input: expected ${expected}, received ${received}`;
      }
      case "invalid_value":
        if (issue.values.length === 1)
          return `Invalid input: expected ${stringifyPrimitive(issue.values[0])}`;
        return `Invalid option: expected one of ${joinValues(issue.values, "|")}`;
      case "too_big": {
        const adj = issue.exact ? "exactly " : issue.inclusive ? "<=" : "<";
        const sizing = getSizing(issue.origin);
        if (sizing)
          return `Too big: expected ${issue.origin ?? "value"} to have ${adj}${issue.maximum.toString()} ${sizing.unit ?? "elements"}`;
        return `Too big: expected ${issue.origin ?? "value"} to be ${adj}${issue.maximum.toString()}`;
      }
      case "too_small": {
        const adj = issue.exact ? "exactly " : issue.inclusive ? ">=" : ">";
        const sizing = getSizing(issue.origin);
        if (sizing) {
          return `Too small: expected ${issue.origin} to have ${adj}${issue.minimum.toString()} ${sizing.unit}`;
        }
        return `Too small: expected ${issue.origin} to be ${adj}${issue.minimum.toString()}`;
      }
      case "invalid_format": {
        const _issue = issue;
        if (_issue.format === "starts_with") {
          return `Invalid string: must start with "${_issue.prefix}"`;
        }
        if (_issue.format === "ends_with")
          return `Invalid string: must end with "${_issue.suffix}"`;
        if (_issue.format === "includes")
          return `Invalid string: must include "${_issue.includes}"`;
        if (_issue.format === "regex")
          return `Invalid string: must match pattern ${_issue.pattern}`;
        return `Invalid ${FormatDictionary[_issue.format] ?? issue.format}`;
      }
      case "not_multiple_of":
        return `Invalid number: must be a multiple of ${issue.divisor}`;
      case "unrecognized_keys":
        return `Unrecognized key${issue.keys.length > 1 ? "s" : ""}: ${joinValues(issue.keys, ", ")}`;
      case "invalid_key":
        return `Invalid key in ${issue.origin}`;
      case "invalid_union":
        if (issue.options && Array.isArray(issue.options) && issue.options.length > 0) {
          const opts = issue.options.map((o) => `'${o}'`).join(" | ");
          return `Invalid discriminator value. Expected ${opts}`;
        }
        if (issue.inclusive === false) {
          return "Invalid input: more than one option matched";
        }
        return "Invalid input";
      case "invalid_element":
        return `Invalid value in ${issue.origin}`;
      default:
        return `Invalid input`;
    }
  };
};
function en_default2() {
  return {
    localeError: error2()
  };
}
var _a2;

class $ZodRegistry {
  constructor() {
    this._map = new WeakMap;
    this._idmap = new Map;
  }
  add(schema, ..._meta) {
    const meta = _meta[0];
    this._map.set(schema, meta);
    if (meta && typeof meta === "object" && "id" in meta) {
      this._idmap.set(meta.id, schema);
    }
    return this;
  }
  clear() {
    this._map = new WeakMap;
    this._idmap = new Map;
    return this;
  }
  remove(schema) {
    const meta = this._map.get(schema);
    if (meta && typeof meta === "object" && "id" in meta) {
      this._idmap.delete(meta.id);
    }
    this._map.delete(schema);
    return this;
  }
  get(schema) {
    const p = schema._zod.parent;
    if (p) {
      const pm = { ...this.get(p) ?? {} };
      delete pm.id;
      const f = { ...pm, ...this._map.get(schema) };
      return Object.keys(f).length ? f : undefined;
    }
    return this._map.get(schema);
  }
  has(schema) {
    return this._map.has(schema);
  }
}
function registry2() {
  return new $ZodRegistry;
}
(_a2 = globalThis).__zod_globalRegistry ?? (_a2.__zod_globalRegistry = registry2());
var globalRegistry = globalThis.__zod_globalRegistry;
function snapshotChecks(def) {
  if (def.checks)
    def.checks = [...def.checks];
  return def;
}
function _string(Class, params) {
  return new Class(snapshotChecks({ type: "string", ...normalizeParams(params) }));
}
function _email(Class, params) {
  return new Class({
    type: "string",
    format: "email",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _guid(Class, params) {
  return new Class({
    type: "string",
    format: "guid",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _uuid(Class, params) {
  return new Class({
    type: "string",
    format: "uuid",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _uuidv4(Class, params) {
  return new Class({
    type: "string",
    format: "uuid",
    check: "string_format",
    abort: false,
    version: "v4",
    ...normalizeParams(params)
  });
}
function _uuidv6(Class, params) {
  return new Class({
    type: "string",
    format: "uuid",
    check: "string_format",
    abort: false,
    version: "v6",
    ...normalizeParams(params)
  });
}
function _uuidv7(Class, params) {
  return new Class({
    type: "string",
    format: "uuid",
    check: "string_format",
    abort: false,
    version: "v7",
    ...normalizeParams(params)
  });
}
function _url(Class, params) {
  return new Class({
    type: "string",
    format: "url",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _emoji2(Class, params) {
  return new Class({
    type: "string",
    format: "emoji",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _nanoid(Class, params) {
  return new Class({
    type: "string",
    format: "nanoid",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _cuid(Class, params) {
  return new Class({
    type: "string",
    format: "cuid",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _cuid2(Class, params) {
  return new Class({
    type: "string",
    format: "cuid2",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _ulid(Class, params) {
  return new Class({
    type: "string",
    format: "ulid",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _xid(Class, params) {
  return new Class({
    type: "string",
    format: "xid",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _ksuid(Class, params) {
  return new Class({
    type: "string",
    format: "ksuid",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _ipv4(Class, params) {
  return new Class({
    type: "string",
    format: "ipv4",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _ipv6(Class, params) {
  return new Class({
    type: "string",
    format: "ipv6",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _cidrv4(Class, params) {
  return new Class({
    type: "string",
    format: "cidrv4",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _cidrv6(Class, params) {
  return new Class({
    type: "string",
    format: "cidrv6",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _base64(Class, params) {
  return new Class({
    type: "string",
    format: "base64",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _base64url(Class, params) {
  return new Class({
    type: "string",
    format: "base64url",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _e164(Class, params) {
  return new Class({
    type: "string",
    format: "e164",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _jwt(Class, params) {
  return new Class({
    type: "string",
    format: "jwt",
    check: "string_format",
    abort: false,
    ...normalizeParams(params)
  });
}
function _isoDateTime(Class, params) {
  return new Class({
    type: "string",
    format: "datetime",
    check: "string_format",
    offset: false,
    local: false,
    precision: null,
    ...normalizeParams(params)
  });
}
function _isoDate(Class, params) {
  return new Class({
    type: "string",
    format: "date",
    check: "string_format",
    ...normalizeParams(params)
  });
}
function _isoTime(Class, params) {
  return new Class({
    type: "string",
    format: "time",
    check: "string_format",
    precision: null,
    ...normalizeParams(params)
  });
}
function _isoDuration(Class, params) {
  return new Class({
    type: "string",
    format: "duration",
    check: "string_format",
    ...normalizeParams(params)
  });
}
function _number(Class, params) {
  return new Class(snapshotChecks({ type: "number", checks: [], ...normalizeParams(params) }));
}
function _int(Class, params) {
  return new Class({
    type: "number",
    check: "number_format",
    abort: false,
    format: "safeint",
    ...normalizeParams(params)
  });
}
function _unknown(Class) {
  return new Class({
    type: "unknown"
  });
}
function _never(Class, params) {
  return new Class({
    type: "never",
    ...normalizeParams(params)
  });
}
function _lt(value, params) {
  return new $ZodCheckLessThan({
    check: "less_than",
    ...normalizeParams(params),
    value,
    inclusive: false
  });
}
function _lte(value, params) {
  return new $ZodCheckLessThan({
    check: "less_than",
    ...normalizeParams(params),
    value,
    inclusive: true
  });
}
function _gt(value, params) {
  return new $ZodCheckGreaterThan({
    check: "greater_than",
    ...normalizeParams(params),
    value,
    inclusive: false
  });
}
function _gte(value, params) {
  return new $ZodCheckGreaterThan({
    check: "greater_than",
    ...normalizeParams(params),
    value,
    inclusive: true
  });
}
function _multipleOf(value, params) {
  return new $ZodCheckMultipleOf({
    check: "multiple_of",
    ...normalizeParams(params),
    value
  });
}
function _maxLength(maximum, params) {
  const ch = new $ZodCheckMaxLength({
    check: "max_length",
    ...normalizeParams(params),
    maximum
  });
  return ch;
}
function _minLength(minimum, params) {
  return new $ZodCheckMinLength({
    check: "min_length",
    ...normalizeParams(params),
    minimum
  });
}
function _length(length, params) {
  return new $ZodCheckLengthEquals({
    check: "length_equals",
    ...normalizeParams(params),
    length
  });
}
function _regex(pattern, params) {
  return new $ZodCheckRegex({
    check: "string_format",
    format: "regex",
    ...normalizeParams(params),
    pattern
  });
}
function _lowercase(params) {
  return new $ZodCheckLowerCase({
    check: "string_format",
    format: "lowercase",
    ...normalizeParams(params)
  });
}
function _uppercase(params) {
  return new $ZodCheckUpperCase({
    check: "string_format",
    format: "uppercase",
    ...normalizeParams(params)
  });
}
function _includes(includes, params) {
  return new $ZodCheckIncludes({
    check: "string_format",
    format: "includes",
    ...normalizeParams(params),
    includes
  });
}
function _startsWith(prefix, params) {
  return new $ZodCheckStartsWith({
    check: "string_format",
    format: "starts_with",
    ...normalizeParams(params),
    prefix
  });
}
function _endsWith(suffix, params) {
  return new $ZodCheckEndsWith({
    check: "string_format",
    format: "ends_with",
    ...normalizeParams(params),
    suffix
  });
}
function _overwrite(tx) {
  return new $ZodCheckOverwrite({
    check: "overwrite",
    tx
  });
}
function _normalize(form) {
  return _overwrite((input) => input.normalize(form));
}
function _trim() {
  return _overwrite((input) => input.trim());
}
function _toLowerCase() {
  return _overwrite((input) => input.toLowerCase());
}
function _toUpperCase() {
  return _overwrite((input) => input.toUpperCase());
}
function _slugify() {
  return _overwrite((input) => slugify(input));
}
function _array(Class, element, params) {
  return new Class({
    type: "array",
    element,
    ...normalizeParams(params)
  });
}
function _refine(Class, fn, _params) {
  const schema = new Class({
    type: "custom",
    check: "custom",
    fn,
    ...normalizeParams(_params)
  });
  return schema;
}
function _superRefine(fn, params) {
  const ch = _check((payload) => {
    payload.addIssue = (issue2) => {
      if (typeof issue2 === "string") {
        payload.issues.push(issue(issue2, payload.value, ch._zod.def));
      } else {
        const _issue = issue2;
        if (_issue.fatal)
          _issue.continue = false;
        _issue.code ?? (_issue.code = "custom");
        if (!("input" in _issue))
          _issue.input = payload.value;
        _issue.inst ?? (_issue.inst = ch);
        _issue.continue ?? (_issue.continue = !ch._zod.def.abort);
        payload.issues.push(issue(_issue));
      }
    };
    return fn(payload.value, payload);
  }, params);
  return ch;
}
function _check(fn, params) {
  const ch = new $ZodCheck({
    check: "custom",
    ...normalizeParams(params)
  });
  ch._zod.check = fn;
  return ch;
}
function assignProps(target, ...sources) {
  for (const source of sources) {
    for (const key of Reflect.ownKeys(source)) {
      if (Object.prototype.propertyIsEnumerable.call(source, key)) {
        assignProp(target, key, source[key]);
      }
    }
  }
  return target;
}
function initializeContext(params) {
  let target = params?.target ?? "draft-2020-12";
  if (target === "draft-4")
    target = "draft-04";
  if (target === "draft-7")
    target = "draft-07";
  return {
    processors: params.processors ?? {},
    metadataRegistry: params?.metadata ?? globalRegistry,
    target,
    unrepresentable: params?.unrepresentable ?? "throw",
    override: params?.override ?? (() => {}),
    io: params?.io ?? "output",
    counter: 0,
    seen: new Map,
    sharedDefsExtractedFor: undefined,
    sharedEmitDoneFor: undefined,
    cycles: params?.cycles ?? "ref",
    reused: params?.reused ?? "inline",
    intersections: [],
    deferred: [],
    external: params?.external ?? undefined
  };
}
function handleUnrepresentable(schema, ctx, json, params, message) {
  const result = typeof ctx.unrepresentable === "function" ? ctx.unrepresentable({ zodSchema: schema, path: params.path, message }) : ctx.unrepresentable;
  if (result === "any")
    return false;
  if (result === undefined || result === "throw")
    throw new Error(message);
  Object.assign(json, result);
  return true;
}
function processSchema(schema, ctx, _params = { path: [], schemaPath: [] }) {
  var _a;
  const def = schema._zod.def;
  const seen = ctx.seen.get(schema);
  if (seen) {
    seen.count++;
    const isCycle = _params.schemaPath.includes(schema);
    if (isCycle) {
      seen.cycle = _params.path;
    }
    return seen.schema;
  }
  const result = { schema: {}, count: 1, cycle: undefined, path: _params.path };
  ctx.seen.set(schema, result);
  ctx.sharedDefsExtractedFor = undefined;
  ctx.sharedEmitDoneFor = undefined;
  const overrideSchema = schema._zod.toJSONSchema?.();
  if (overrideSchema) {
    result.schema = overrideSchema;
  } else {
    const params = {
      ..._params,
      schemaPath: [..._params.schemaPath, schema],
      path: _params.path
    };
    if (schema._zod.processJSONSchema) {
      schema._zod.processJSONSchema(ctx, result.schema, params);
    } else {
      const _json = result.schema;
      const processor = ctx.processors[def.type];
      if (!processor) {
        throw new Error(`[toJSONSchema]: Non-representable type encountered: ${def.type}`);
      }
      processor(schema, ctx, _json, params);
    }
    const parent = schema._zod.parent;
    if (parent) {
      if (!result.ref)
        result.ref = parent;
      processSchema(parent, ctx, params);
      ctx.seen.get(parent).isParent = true;
    }
  }
  const meta = ctx.metadataRegistry.get(schema);
  if (meta)
    assignProps(result.schema, meta);
  if (ctx.io === "input" && isTransforming(schema)) {
    delete result.schema.examples;
    delete result.schema.default;
  }
  if (ctx.io === "input" && "_prefault" in result.schema)
    (_a = result.schema).default ?? (_a.default = result.schema._prefault);
  delete result.schema._prefault;
  const _result = ctx.seen.get(schema);
  return _result.schema;
}
function encodeJSONPointerSegment(segment) {
  return segment.replace(/~/g, "~0").replace(/\//g, "~1");
}
function extractDefs(ctx, schema) {
  const root = ctx.seen.get(schema);
  if (!root)
    throw new Error("Unprocessed schema. This is a bug in Zod.");
  if (ctx.external && ctx.sharedDefsExtractedFor === ctx.external)
    return;
  const idToSchema = new Map;
  for (const entry of ctx.seen.entries()) {
    const id = ctx.metadataRegistry.get(entry[0])?.id;
    if (id) {
      const existing = idToSchema.get(id);
      if (existing && existing !== entry[0]) {
        throw new Error(`Duplicate schema id "${id}" detected during JSON Schema conversion. Two different schemas cannot share the same id when converted together.`);
      }
      idToSchema.set(id, entry[0]);
    }
  }
  const makeURI = (entry) => {
    const defsSegment = ctx.target === "draft-2020-12" ? "$defs" : "definitions";
    if (ctx.external) {
      const externalId = ctx.external.registry.get(entry[0])?.id;
      const uriGenerator = ctx.external.uri ?? ((id) => id);
      if (externalId) {
        return { ref: uriGenerator(externalId) };
      }
      const id = entry[1].defId ?? entry[1].schema.id ?? `schema${ctx.counter++}`;
      entry[1].defId = id;
      return { defId: id, ref: `${uriGenerator("__shared")}#/${defsSegment}/${encodeJSONPointerSegment(id)}` };
    }
    const uriPrefix = `#`;
    const defUriPrefix = `${uriPrefix}/${defsSegment}/`;
    if (entry[1] === root && !entry[1].schema.id) {
      return { ref: uriPrefix };
    }
    const defId = entry[1].schema.id ?? `__schema${ctx.counter++}`;
    return { defId, ref: defUriPrefix + encodeJSONPointerSegment(defId) };
  };
  const extractToDef = (entry) => {
    if (entry[1].schema.$ref) {
      return;
    }
    const seen = entry[1];
    const { ref, defId } = makeURI(entry);
    seen.def = { ...seen.schema };
    if (defId)
      seen.defId = defId;
    const schema = seen.schema;
    for (const key in schema) {
      delete schema[key];
    }
    schema.$ref = ref;
  };
  if (ctx.cycles === "throw") {
    for (const entry of ctx.seen.entries()) {
      const seen = entry[1];
      if (seen.cycle) {
        throw new Error("Cycle detected: " + `#/${seen.cycle?.join("/")}/<root>` + '\n\nSet the `cycles` parameter to `"ref"` to resolve cyclical schemas with defs.');
      }
    }
  }
  for (const entry of ctx.seen.entries()) {
    const seen = entry[1];
    if (schema === entry[0]) {
      extractToDef(entry);
      continue;
    }
    if (ctx.external) {
      const ext = ctx.external.registry.get(entry[0])?.id;
      if (schema !== entry[0] && ext) {
        extractToDef(entry);
        continue;
      }
    }
    const id = ctx.metadataRegistry.get(entry[0])?.id;
    if (id) {
      extractToDef(entry);
      continue;
    }
    if (seen.cycle) {
      extractToDef(entry);
      continue;
    }
    if (seen.count > 1) {
      if (ctx.reused === "ref") {
        extractToDef(entry);
      }
    }
  }
  if (ctx.external)
    ctx.sharedDefsExtractedFor = ctx.external;
}
function compactTypeUnion(schema) {
  const options = schema.anyOf;
  if (!Array.isArray(options) || options.length === 0 || schema.type !== undefined)
    return;
  const types = [];
  for (const option of options) {
    if (!option || typeof option !== "object")
      return;
    compactTypeUnion(option);
    const keys = Object.keys(option);
    if (keys.length !== 1 || keys[0] !== "type")
      return;
    const type = option.type;
    for (const member of Array.isArray(type) ? type : [type]) {
      if (typeof member !== "string")
        return;
      if (!types.includes(member))
        types.push(member);
    }
  }
  delete schema.anyOf;
  schema.type = types.length === 1 ? types[0] : types;
}
var FOLDABLE_KEYS = new Set(["type", "properties", "required", "additionalProperties"]);
var UNION_KEYS = ["oneOf", "anyOf"];
function undeclaredConstraint(member) {
  const extra = member.additionalProperties;
  if (extra === undefined || extra === false || typeof extra !== "object" || extra === null)
    return null;
  return Object.keys(extra).length ? extra : null;
}
function foldObjects(members) {
  const objects = [];
  for (const member of members) {
    if (typeof member !== "object" || member.type !== "object")
      return null;
    for (const key in member) {
      if (!FOLDABLE_KEYS.has(key))
        return null;
    }
    objects.push(member);
  }
  const properties = {};
  const required = new Set;
  for (const object of objects) {
    for (const key in object.properties) {
      if (Object.prototype.hasOwnProperty.call(properties, key))
        continue;
      const parts = [];
      for (const other of objects) {
        const part = other.properties?.[key] ?? undeclaredConstraint(other);
        if (part === null || part === undefined)
          continue;
        if (!parts.some((seen) => JSON.stringify(seen) === JSON.stringify(part)))
          parts.push(part);
      }
      const merged = parts.length === 1 ? parts[0] : foldObjects(parts) ?? { allOf: parts };
      assignProp(properties, key, merged);
    }
    for (const key of object.required ?? [])
      required.add(key);
  }
  const folded = { type: "object", properties };
  if (required.size)
    folded.required = [...required];
  if (objects.every((object) => object.additionalProperties === false)) {
    folded.additionalProperties = false;
  } else {
    const constraints = [];
    for (const object of objects) {
      const constraint = undeclaredConstraint(object);
      if (constraint && !constraints.some((seen) => JSON.stringify(seen) === JSON.stringify(constraint)))
        constraints.push(constraint);
    }
    if (constraints.length === 1)
      folded.additionalProperties = constraints[0];
    else if (constraints.length > 1)
      folded.additionalProperties = { allOf: constraints };
  }
  return folded;
}
function foldIntersection(json) {
  const allOf = json.allOf;
  if (!Array.isArray(allOf) || allOf.length < 2)
    return;
  for (const key of FOLDABLE_KEYS)
    if (key in json)
      return;
  const unions = allOf.filter((m) => UNION_KEYS.some((k) => Array.isArray(m[k])));
  let folded = null;
  if (!unions.length) {
    folded = foldObjects(allOf);
  } else {
    const union = unions[0];
    const keyword = UNION_KEYS.find((k) => Array.isArray(union[k]));
    if (Object.keys(union).length !== 1)
      return;
    const rest = allOf.filter((m) => m !== union);
    const branches = union[keyword].map((branch) => foldObjects([...rest, branch]));
    if (branches.some((b) => !b))
      return;
    folded = { [keyword]: branches };
  }
  if (!folded)
    return;
  delete json.allOf;
  assignProps(json, folded);
}
function finalize(ctx, schema) {
  const root = ctx.seen.get(schema);
  if (!root)
    throw new Error("Unprocessed schema. This is a bug in Zod.");
  const flattenRef = (zodSchema) => {
    const seen = ctx.seen.get(zodSchema);
    if (seen.ref === null)
      return;
    const schema = seen.def ?? seen.schema;
    const _cached = { ...schema };
    const ref = seen.ref;
    seen.ref = null;
    if (ref) {
      flattenRef(ref);
      const refSeen = ctx.seen.get(ref);
      const refSchema = refSeen.schema;
      if (refSchema.$ref && (ctx.target === "draft-07" || ctx.target === "draft-04" || ctx.target === "openapi-3.0")) {
        schema.allOf = schema.allOf ?? [];
        schema.allOf.push(refSchema);
      } else {
        assignProps(schema, refSchema);
      }
      assignProps(schema, _cached);
      const isParentRef = zodSchema._zod.parent === ref;
      if (isParentRef) {
        for (const key in schema) {
          if (key === "$ref" || key === "allOf")
            continue;
          if (!(key in _cached)) {
            delete schema[key];
          }
        }
      }
      if (refSchema.$ref && refSeen.def) {
        for (const key in schema) {
          if (key === "$ref" || key === "allOf")
            continue;
          if (key in refSeen.def && JSON.stringify(schema[key]) === JSON.stringify(refSeen.def[key])) {
            delete schema[key];
          }
        }
      }
    }
    const parent = zodSchema._zod.parent;
    if (parent && parent !== ref) {
      flattenRef(parent);
      const parentSeen = ctx.seen.get(parent);
      if (parentSeen?.schema.$ref) {
        schema.$ref = parentSeen.schema.$ref;
        if (parentSeen.def) {
          for (const key in schema) {
            if (key === "$ref" || key === "allOf")
              continue;
            if (key in parentSeen.def && JSON.stringify(schema[key]) === JSON.stringify(parentSeen.def[key])) {
              delete schema[key];
            }
          }
        }
      }
    }
    ctx.override({
      zodSchema,
      jsonSchema: schema,
      path: seen.path ?? []
    });
  };
  if (!ctx.external || ctx.sharedEmitDoneFor !== ctx.external) {
    for (const entry of [...ctx.seen.entries()].reverse()) {
      flattenRef(entry[0]);
    }
    if (ctx.target !== "openapi-3.0") {
      for (const entry of ctx.seen.entries()) {
        compactTypeUnion(entry[1].def ?? entry[1].schema);
      }
    }
    for (const rewrite of ctx.deferred)
      rewrite();
    if (ctx.intersections.length) {
      const carriers = new Map;
      for (const seen of ctx.seen.values()) {
        for (const json of [seen.schema, seen.def]) {
          const allOf = json?.allOf;
          if (!Array.isArray(allOf))
            continue;
          const existing = carriers.get(allOf);
          if (existing)
            existing.push(json);
          else
            carriers.set(allOf, [json]);
        }
      }
      for (const allOf of ctx.intersections) {
        for (const json of carriers.get(allOf) ?? [])
          foldIntersection(json);
      }
    }
  }
  const result = {};
  if (ctx.target === "draft-2020-12") {
    result.$schema = "https://json-schema.org/draft/2020-12/schema";
  } else if (ctx.target === "draft-07") {
    result.$schema = "http://json-schema.org/draft-07/schema#";
  } else if (ctx.target === "draft-04") {
    result.$schema = "http://json-schema.org/draft-04/schema#";
  } else if (ctx.target === "openapi-3.0") {}
  if (ctx.external?.uri) {
    const id = ctx.external.registry.get(schema)?.id;
    if (!id)
      throw new Error("Schema is missing an `id` property");
    result.$id = ctx.external.uri(id);
  }
  assignProps(result, root.defId ? root.schema : root.def ?? root.schema);
  const rootMetaId = ctx.metadataRegistry.get(schema)?.id;
  if (rootMetaId !== undefined && result.id === rootMetaId)
    delete result.id;
  const defs = ctx.external?.defs ?? {};
  if (!ctx.external || ctx.sharedEmitDoneFor !== ctx.external) {
    for (const entry of ctx.seen.entries()) {
      const seen = entry[1];
      if (seen.def && seen.defId) {
        if (seen.def.id === seen.defId)
          delete seen.def.id;
        assignProp(defs, seen.defId, seen.def);
      }
    }
  }
  if (ctx.external)
    ctx.sharedEmitDoneFor = ctx.external;
  if (ctx.external) {} else {
    if (Object.keys(defs).length > 0) {
      if (ctx.target === "draft-2020-12") {
        result.$defs = defs;
      } else {
        result.definitions = defs;
      }
    }
  }
  try {
    const finalized = JSON.parse(JSON.stringify(result));
    Object.defineProperty(finalized, "~standard", {
      value: {
        ...schema["~standard"],
        jsonSchema: {
          input: createStandardJSONSchemaMethod(schema, "input", ctx.processors),
          output: createStandardJSONSchemaMethod(schema, "output", ctx.processors)
        }
      },
      enumerable: false,
      writable: false
    });
    return finalized;
  } catch (_err) {
    throw new Error("Error converting schema to JSON.");
  }
}
function isTransforming(_schema, _ctx) {
  const ctx = _ctx ?? { seen: new Set };
  if (ctx.seen.has(_schema))
    return false;
  ctx.seen.add(_schema);
  const def = _schema._zod.def;
  if (def.type === "transform")
    return true;
  if (def.type === "array")
    return isTransforming(def.element, ctx);
  if (def.type === "set")
    return isTransforming(def.valueType, ctx);
  if (def.type === "lazy")
    return isTransforming(def.getter(), ctx);
  if (def.type === "promise" || def.type === "optional" || def.type === "nonoptional" || def.type === "nullable" || def.type === "readonly" || def.type === "default" || def.type === "prefault" || def.type === "catch") {
    return isTransforming(def.innerType, ctx);
  }
  if (def.type === "intersection") {
    return isTransforming(def.left, ctx) || isTransforming(def.right, ctx);
  }
  if (def.type === "record" || def.type === "map") {
    return isTransforming(def.keyType, ctx) || isTransforming(def.valueType, ctx);
  }
  if (def.type === "pipe") {
    if (_schema._zod.traits.has("$ZodCodec"))
      return true;
    return isTransforming(def.in, ctx) || isTransforming(def.out, ctx);
  }
  if (def.type === "object") {
    for (const key in def.shape) {
      if (isTransforming(def.shape[key], ctx))
        return true;
    }
    return false;
  }
  if (def.type === "union") {
    for (const option of def.options) {
      if (isTransforming(option, ctx))
        return true;
    }
    return false;
  }
  if (def.type === "tuple") {
    for (const item of def.items) {
      if (isTransforming(item, ctx))
        return true;
    }
    if (def.rest && isTransforming(def.rest, ctx))
      return true;
    return false;
  }
  return false;
}
var createToJSONSchemaMethod = (schema, processors = {}) => (params) => {
  const ctx = initializeContext({ ...params, processors });
  processSchema(schema, ctx);
  extractDefs(ctx, schema);
  return finalize(ctx, schema);
};
var createStandardJSONSchemaMethod = (schema, io, processors = {}) => (params) => {
  const { libraryOptions, target } = params ?? {};
  const ctx = initializeContext({ ...libraryOptions ?? {}, target, io, processors });
  processSchema(schema, ctx);
  extractDefs(ctx, schema);
  return finalize(ctx, schema);
};
var narrowMin = (agg, key, value) => {
  if (agg[key] === undefined || value > agg[key])
    agg[key] = value;
};
var narrowMax = (agg, key, value) => {
  if (agg[key] === undefined || value < agg[key])
    agg[key] = value;
};
var narrowBoth = (agg, value) => {
  narrowMin(agg, "minimum", value);
  narrowMax(agg, "maximum", value);
};
var addDivisor = (agg, value) => {
  agg.multipleOf ?? (agg.multipleOf = []);
  if (!agg.multipleOf.includes(value))
    agg.multipleOf.push(value);
};
var addPattern = (agg, pattern) => {
  agg.patterns ?? (agg.patterns = new Set);
  agg.patterns.add(pattern);
};
var intersectMime = (agg, mime) => {
  agg.mime = agg.mime ? agg.mime.filter((m) => mime.includes(m)) : [...mime];
};
var setFormat = (agg, format) => {
  agg.format = format;
  if (format.includes("int"))
    agg.isInt = true;
};
var minContributor = (agg, def) => narrowMin(agg, "minimum", def.minimum);
var maxContributor = (agg, def) => narrowMax(agg, "maximum", def.maximum);
var formatContributor = (ranges) => (agg, def) => {
  setFormat(agg, def.format);
  const [minimum, maximum] = ranges[def.format];
  narrowMin(agg, "minimum", minimum);
  narrowMax(agg, "maximum", maximum);
};
var contributors = {
  greater_than: (agg, def) => narrowMin(agg, def.inclusive ? "minimum" : "exclusiveMinimum", def.value),
  less_than: (agg, def) => narrowMax(agg, def.inclusive ? "maximum" : "exclusiveMaximum", def.value),
  multiple_of: (agg, def) => addDivisor(agg, def.value),
  number_format: formatContributor(NUMBER_FORMAT_RANGES),
  bigint_format: formatContributor(BIGINT_FORMAT_RANGES),
  min_length: minContributor,
  max_length: maxContributor,
  length_equals: (agg, def) => narrowBoth(agg, def.length),
  min_size: minContributor,
  max_size: maxContributor,
  size_equals: (agg, def) => narrowBoth(agg, def.size),
  string_format: (agg, def) => {
    setFormat(agg, def.format);
    if (def.pattern)
      addPattern(agg, def.pattern);
    if (def.format === "base64" || def.format === "base64url")
      agg.contentEncoding = def.format;
    if (def.local || def.precision === -1)
      agg.laxFormat = true;
  },
  mime_type: (agg, def) => intersectMime(agg, def.mime)
};
function aggregateChecks(schema) {
  const agg = {};
  const def = schema._zod.def;
  const list = schema._zod.traits.has("$ZodCheck") ? [schema, ...def.checks ?? []] : def.checks ?? [];
  for (const ch of list)
    contributors[ch._zod.def.check]?.(agg, ch._zod.def);
  const bag = schema._zod.bag;
  if (bag.minimum !== undefined)
    narrowMin(agg, "minimum", bag.minimum);
  if (bag.exclusiveMinimum !== undefined)
    narrowMin(agg, "exclusiveMinimum", bag.exclusiveMinimum);
  if (bag.maximum !== undefined)
    narrowMax(agg, "maximum", bag.maximum);
  if (bag.exclusiveMaximum !== undefined)
    narrowMax(agg, "exclusiveMaximum", bag.exclusiveMaximum);
  if (bag.multipleOf !== undefined)
    addDivisor(agg, bag.multipleOf);
  if (bag.format !== undefined) {
    agg.format ?? (agg.format = bag.format);
    if (bag.format.includes("int"))
      agg.isInt = true;
  }
  if (bag.mime)
    intersectMime(agg, bag.mime);
  for (const pattern of bag.patterns ?? [])
    addPattern(agg, pattern);
  return agg;
}
var formatMap = {
  guid: "uuid",
  url: "uri",
  datetime: "date-time",
  json_string: "json-string",
  regex: ""
};
var exactPatterns = new Map([
  [base64Charset, base64],
  [base64urlCharset, base64url]
]);
var exactPattern = (p) => exactPatterns.get(p) ?? p;
var stringProcessor = (schema, ctx, _json, _params) => {
  const json = _json;
  json.type = "string";
  const { minimum, maximum, format, patterns, contentEncoding, laxFormat } = aggregateChecks(schema);
  if (typeof minimum === "number")
    json.minLength = minimum;
  if (typeof maximum === "number")
    json.maxLength = maximum;
  if (format) {
    json.format = formatMap[format] ?? format;
    if (json.format === "")
      delete json.format;
    if (format === "time" || laxFormat) {
      delete json.format;
    }
  }
  if (contentEncoding)
    json.contentEncoding = contentEncoding;
  if (patterns && patterns.size > 0) {
    const patternList = [...patterns].map(exactPattern);
    if (patternList.length === 1)
      json.pattern = patternList[0].source;
    else if (patternList.length > 1) {
      json.allOf = [
        ...patternList.map((regex) => ({
          ...ctx.target === "draft-07" || ctx.target === "draft-04" || ctx.target === "openapi-3.0" ? { type: "string" } : {},
          pattern: regex.source
        }))
      ];
    }
  }
};
var numberProcessor = (schema, ctx, _json, params) => {
  const json = _json;
  const { minimum, maximum, multipleOf, exclusiveMaximum, exclusiveMinimum, isInt } = aggregateChecks(schema);
  json.type = isInt ? "integer" : "number";
  const exMin = typeof exclusiveMinimum === "number" && exclusiveMinimum >= (minimum ?? Number.NEGATIVE_INFINITY);
  const exMax = typeof exclusiveMaximum === "number" && exclusiveMaximum <= (maximum ?? Number.POSITIVE_INFINITY);
  const legacy = ctx.target === "draft-04" || ctx.target === "openapi-3.0";
  if (exMin) {
    if (legacy) {
      json.minimum = exclusiveMinimum;
      json.exclusiveMinimum = true;
    } else {
      json.exclusiveMinimum = exclusiveMinimum;
    }
  } else if (typeof minimum === "number") {
    json.minimum = minimum;
  }
  if (exMax) {
    if (legacy) {
      json.maximum = exclusiveMaximum;
      json.exclusiveMaximum = true;
    } else {
      json.exclusiveMaximum = exclusiveMaximum;
    }
  } else if (typeof maximum === "number") {
    json.maximum = maximum;
  }
  if (multipleOf) {
    const divisors = new Set;
    for (const divisor of multipleOf) {
      if (Number.isFinite(divisor) && divisor !== 0)
        divisors.add(Math.abs(divisor));
      else
        handleUnrepresentable(schema, ctx, json, params, `A multipleOf divisor of ${divisor} cannot be represented in JSON Schema`);
    }
    const [first, ...rest] = divisors;
    if (first !== undefined)
      json.multipleOf = first;
    if (rest.length)
      json.allOf = [...json.allOf ?? [], ...rest.map((m) => ({ multipleOf: m }))];
  }
};
var neverProcessor = (_schema, _ctx, json, _params) => {
  json.not = {};
};
var unknownProcessor = (_schema, _ctx, _json, _params) => {};
var enumProcessor = (schema, _ctx, json, _params) => {
  const def = schema._zod.def;
  const values = getEnumValues(def.entries);
  if (values.length === 0) {
    json.not = {};
    return;
  }
  if (values.every((v) => typeof v === "number"))
    json.type = "number";
  if (values.every((v) => typeof v === "string"))
    json.type = "string";
  json.enum = values;
};
var customProcessor = (schema, ctx, json, params) => {
  handleUnrepresentable(schema, ctx, json, params, "Custom types cannot be represented in JSON Schema");
};
var transformProcessor = (schema, ctx, json, params) => {
  handleUnrepresentable(schema, ctx, json, params, "Transforms cannot be represented in JSON Schema");
};
var arrayProcessor = (schema, ctx, _json, params) => {
  const json = _json;
  const def = schema._zod.def;
  const { minimum, maximum } = aggregateChecks(schema);
  if (typeof minimum === "number")
    json.minItems = minimum;
  if (typeof maximum === "number")
    json.maxItems = maximum;
  json.type = "array";
  json.items = processSchema(def.element, ctx, {
    ...params,
    path: [...params.path, "items"]
  });
};
function inputOptin(schema) {
  const def = schema._zod.def;
  if (def.type === "pipe" && def.in._zod.traits.has("$ZodTransform")) {
    return inputOptin(def.out);
  }
  if (def.type === "catch") {
    return inputOptin(def.innerType);
  }
  return schema._zod.optin;
}
var objectProcessor = (schema, ctx, _json, params) => {
  const json = _json;
  const def = schema._zod.def;
  const shape = def.shape;
  const symbolKeys = Object.getOwnPropertySymbols(shape);
  if (symbolKeys.length && handleUnrepresentable(schema, ctx, json, params, "Symbol keys cannot be represented in JSON Schema")) {
    return;
  }
  json.type = "object";
  json.properties = {};
  for (const key in shape) {
    assignProp(json.properties, key, processSchema(shape[key], ctx, {
      ...params,
      path: [...params.path, "properties", key]
    }));
  }
  const requiredKeys = [];
  for (const key of Object.keys(shape)) {
    const field = def.shape[key];
    if (ctx.io === "input" ? inputOptin(field) === undefined : field._zod.optout === undefined) {
      requiredKeys.push(key);
    }
  }
  if (requiredKeys.length > 0) {
    json.required = requiredKeys;
  }
  if (def.catchall?._zod.def.type === "never") {
    json.additionalProperties = false;
  } else if (!def.catchall) {
    if (ctx.io === "output")
      json.additionalProperties = false;
  } else if (def.catchall) {
    json.additionalProperties = processSchema(def.catchall, ctx, {
      ...params,
      path: [...params.path, "additionalProperties"]
    });
  }
};
var unionProcessor = (schema, ctx, json, params) => {
  const def = schema._zod.def;
  const isExclusive = def.inclusive === false;
  const options = def.options.map((x, i) => processSchema(x, ctx, {
    ...params,
    path: [...params.path, isExclusive ? "oneOf" : "anyOf", i]
  }));
  if (isExclusive) {
    json.oneOf = options;
  } else {
    json.anyOf = options;
  }
};
var intersectionProcessor = (schema, ctx, json, params) => {
  const def = schema._zod.def;
  const a = processSchema(def.left, ctx, {
    ...params,
    path: [...params.path, "allOf", 0]
  });
  const b = processSchema(def.right, ctx, {
    ...params,
    path: [...params.path, "allOf", 1]
  });
  const isSimpleIntersection = (val) => ("allOf" in val) && Object.keys(val).length === 1;
  const allOf = [
    ...isSimpleIntersection(a) ? a.allOf : [a],
    ...isSimpleIntersection(b) ? b.allOf : [b]
  ];
  json.allOf = allOf;
  ctx.intersections.push(allOf);
};
var pendingRecords = new WeakMap;
var nullableProcessor = (schema, ctx, json, params) => {
  const def = schema._zod.def;
  const inner = processSchema(def.innerType, ctx, params);
  const seen = ctx.seen.get(schema);
  if (ctx.target === "openapi-3.0") {
    seen.ref = def.innerType;
    json.nullable = true;
  } else {
    json.anyOf = [inner, { type: "null" }];
  }
};
var nonoptionalProcessor = (schema, ctx, _json, params) => {
  const def = schema._zod.def;
  processSchema(def.innerType, ctx, params);
  const seen = ctx.seen.get(schema);
  seen.ref = def.innerType;
};
var UNREPRESENTABLE_DEFAULT = Symbol();
function serializeDefaultValue(value, schema, ctx, json, params) {
  let unrepresentable = false;
  const serialized = JSON.stringify(value, (_, val) => {
    if (typeof val !== "bigint")
      return val;
    unrepresentable = true;
    return null;
  });
  if (!unrepresentable)
    return JSON.parse(serialized);
  handleUnrepresentable(schema, ctx, json, params, "BigInt defaults cannot be represented in JSON Schema");
  return UNREPRESENTABLE_DEFAULT;
}
var defaultProcessor = (schema, ctx, json, params) => {
  const def = schema._zod.def;
  processSchema(def.innerType, ctx, params);
  const seen = ctx.seen.get(schema);
  seen.ref = def.innerType;
  const value = serializeDefaultValue(def.defaultValue, schema, ctx, json, params);
  if (value !== UNREPRESENTABLE_DEFAULT)
    json.default = value;
};
var prefaultProcessor = (schema, ctx, json, params) => {
  const def = schema._zod.def;
  processSchema(def.innerType, ctx, params);
  const seen = ctx.seen.get(schema);
  seen.ref = def.innerType;
  if (ctx.io !== "input")
    return;
  const value = serializeDefaultValue(def.defaultValue, schema, ctx, json, params);
  if (value !== UNREPRESENTABLE_DEFAULT)
    json._prefault = value;
};
var catchProcessor = (schema, ctx, json, params) => {
  const def = schema._zod.def;
  processSchema(def.innerType, ctx, params);
  const seen = ctx.seen.get(schema);
  seen.ref = def.innerType;
  let catchValue;
  try {
    catchValue = def.catchValue(undefined);
  } catch {
    handleUnrepresentable(schema, ctx, json, params, "Dynamic catch values are not supported in JSON Schema");
    return;
  }
  json.default = catchValue;
};
var pipeProcessor = (schema, ctx, _json, params) => {
  const def = schema._zod.def;
  const inIsTransform = def.in._zod.traits.has("$ZodTransform");
  const innerType = ctx.io === "input" ? inIsTransform ? def.out : def.in : def.out;
  processSchema(innerType, ctx, params);
  const seen = ctx.seen.get(schema);
  seen.ref = innerType;
};
var readonlyProcessor = (schema, ctx, json, params) => {
  const def = schema._zod.def;
  processSchema(def.innerType, ctx, params);
  const seen = ctx.seen.get(schema);
  seen.ref = def.innerType;
  json.readOnly = true;
};
var optionalProcessor = (schema, ctx, _json, params) => {
  const def = schema._zod.def;
  processSchema(def.innerType, ctx, params);
  const seen = ctx.seen.get(schema);
  seen.ref = def.innerType;
};
var _installedErrorProtos = /* @__PURE__ */ new WeakSet([Object.prototype, Error.prototype]);
function _lazyMethod(proto, key, make) {
  Object.defineProperty(proto, key, {
    configurable: true,
    enumerable: false,
    get() {
      const value = make(this);
      Object.defineProperty(this, key, { value, configurable: true, writable: true });
      return value;
    },
    set(value) {
      Object.defineProperty(this, key, { value, configurable: true, writable: true });
    }
  });
}
var initializer2 = (inst, issues) => {
  $ZodError.init(inst, issues);
  inst.name = "ZodError";
  const proto = Object.getPrototypeOf(inst);
  if (_installedErrorProtos.has(proto))
    return;
  _installedErrorProtos.add(proto);
  _lazyMethod(proto, "format", (self) => (mapper) => formatError(self, mapper));
  _lazyMethod(proto, "flatten", (self) => (mapper) => flattenError(self, mapper));
  _lazyMethod(proto, "addIssue", (self) => (issue) => {
    self.issues.push(issue);
    self.message = JSON.stringify(self.issues, jsonStringifyReplacer, 2);
  });
  _lazyMethod(proto, "addIssues", (self) => (issues) => {
    self.issues.push(...issues);
    self.message = JSON.stringify(self.issues, jsonStringifyReplacer, 2);
  });
  Object.defineProperty(proto, "isEmpty", {
    configurable: true,
    enumerable: false,
    get() {
      return this.issues.length === 0;
    }
  });
};
var ZodRealError = /* @__PURE__ */ $constructor("ZodError", initializer2, undefined, {
  Parent: Error
});
var parse2 = /* @__PURE__ */ _parse(ZodRealError);
var parseAsync = /* @__PURE__ */ _parseAsync(ZodRealError);
var safeParse = /* @__PURE__ */ _safeParse(ZodRealError);
var safeParseAsync = /* @__PURE__ */ _safeParseAsync(ZodRealError);
var encode = /* @__PURE__ */ _encode(ZodRealError);
var decode = /* @__PURE__ */ _decode(ZodRealError);
var encodeAsync = /* @__PURE__ */ _encodeAsync(ZodRealError);
var decodeAsync = /* @__PURE__ */ _decodeAsync(ZodRealError);
var safeEncode = /* @__PURE__ */ _safeEncode(ZodRealError);
var safeDecode = /* @__PURE__ */ _safeDecode(ZodRealError);
var safeEncodeAsync = /* @__PURE__ */ _safeEncodeAsync(ZodRealError);
var safeDecodeAsync = /* @__PURE__ */ _safeDecodeAsync(ZodRealError);
function _ensureDefaultLocale() {
  if (!globalConfig.localeError)
    config(en_default2());
}
function _ensureDefaultMemoizer() {
  if (!globalConfig.memoizer)
    config({ memoizer: memoizer() });
}
var ZodType2 = /* @__PURE__ */ $constructor("ZodType", (inst, def) => {
  _ensureDefaultLocale();
  $ZodType.init(inst, def);
  inst.def = def;
  inst.type = def.type;
  return inst;
}, {
  check(...chks) {
    const def = this.def;
    return this.clone(mergeDefs(def, {
      checks: [
        ...def.checks ?? [],
        ...chks.map((ch) => typeof ch === "function" ? { _zod: { check: ch, def: { check: "custom" }, onattach: [] } } : ch)
      ]
    }), { parent: true });
  },
  with(...chks) {
    return this.check(...chks);
  },
  clone(def, params) {
    return clone2(this, def, params);
  },
  brand() {
    return this;
  },
  register(reg, meta) {
    reg.add(this, meta);
    return this;
  },
  refine(check, params) {
    return this.check(refine(check, params));
  },
  superRefine(refinement, params) {
    return this.check(superRefine(refinement, params));
  },
  overwrite(fn) {
    return this.check(_overwrite(fn));
  },
  optional() {
    return optional(this);
  },
  exactOptional() {
    return exactOptional(this);
  },
  nullable() {
    return nullable(this);
  },
  nullish() {
    return optional(nullable(this));
  },
  nonoptional(params) {
    return nonoptional(this, params);
  },
  array() {
    return array(this);
  },
  or(arg) {
    return union([this, arg]);
  },
  and(arg) {
    return intersection(this, arg);
  },
  transform(tx) {
    return pipe(this, transform(tx));
  },
  default(d) {
    return _default(this, d);
  },
  prefault(d) {
    return prefault(this, d);
  },
  catch(params) {
    return _catch(this, params);
  },
  pipe(target) {
    return pipe(this, target);
  },
  readonly() {
    return readonly(this);
  },
  describe(description) {
    const cl = this.clone();
    globalRegistry.add(cl, { description });
    return cl;
  },
  meta(...args) {
    if (args.length === 0)
      return globalRegistry.get(this);
    const cl = this.clone();
    globalRegistry.add(cl, args[0]);
    return cl;
  },
  isOptional() {
    return this.safeParse(undefined).success;
  },
  isNullable() {
    return this.safeParse(null).success;
  },
  apply(fn, ...args) {
    return args.length === 0 ? fn(this) : fn(this, ...args);
  },
  get "~standard"() {
    return hide(this, "~standard", {
      ...standardProps(this),
      jsonSchema: {
        input: createStandardJSONSchemaMethod(this, "input"),
        output: createStandardJSONSchemaMethod(this, "output")
      }
    });
  },
  set "~standard"(value) {
    own(this, "~standard", value);
  },
  parse: function _parse(data, params) {
    return parse2(this, data, params, { callee: _parse });
  },
  parseAsync: async function _parseAsync(data, params) {
    return await parseAsync(this, data, params, { callee: _parseAsync });
  },
  safeParse(data, params) {
    return safeParse(this, data, params);
  },
  async safeParseAsync(data, params) {
    return safeParseAsync(this, data, params);
  },
  get spa() {
    return this?.safeParseAsync;
  },
  set spa(value) {
    own(this, "spa", value);
  },
  validate(data, params) {
    return validate(this, data, params);
  },
  validateAsync(data, params) {
    return validateAsync(this, data, params);
  },
  encode: function _encode(data, params) {
    return encode(this, data, params, { callee: _encode });
  },
  decode: function _decode(data, params) {
    return decode(this, data, params, { callee: _decode });
  },
  encodeAsync: async function _encodeAsync(data, params) {
    return await encodeAsync(this, data, params, { callee: _encodeAsync });
  },
  decodeAsync: async function _decodeAsync(data, params) {
    return await decodeAsync(this, data, params, { callee: _decodeAsync });
  },
  safeEncode(data, params) {
    return safeEncode(this, data, params);
  },
  safeDecode(data, params) {
    return safeDecode(this, data, params);
  },
  async safeEncodeAsync(data, params) {
    return safeEncodeAsync(this, data, params);
  },
  async safeDecodeAsync(data, params) {
    return safeDecodeAsync(this, data, params);
  },
  toJSONSchema(params) {
    return createToJSONSchemaMethod(this, {})(params);
  },
  get description() {
    return globalRegistry.get(this)?.description;
  },
  get _def() {
    return this._zod.def;
  }
});
var _ZodString = /* @__PURE__ */ $constructor("_ZodString", (inst, def) => {
  $ZodString.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => stringProcessor(inst, ctx, json, params);
}, /* @__PURE__ */ derived({
  format: (inst) => aggregateChecks(inst).format ?? null,
  minLength: (inst) => aggregateChecks(inst).minimum ?? null,
  maxLength: (inst) => aggregateChecks(inst).maximum ?? null
}, {
  regex(...args) {
    return this.check(_regex(...args));
  },
  includes(...args) {
    return this.check(_includes(...args));
  },
  startsWith(...args) {
    return this.check(_startsWith(...args));
  },
  endsWith(...args) {
    return this.check(_endsWith(...args));
  },
  min(...args) {
    return this.check(_minLength(...args));
  },
  max(...args) {
    return this.check(_maxLength(...args));
  },
  length(...args) {
    return this.check(_length(...args));
  },
  nonempty(...args) {
    return this.check(_minLength(1, ...args));
  },
  lowercase(params) {
    return this.check(_lowercase(params));
  },
  uppercase(params) {
    return this.check(_uppercase(params));
  },
  trim() {
    return this.check(_trim());
  },
  normalize(...args) {
    return this.check(_normalize(...args));
  },
  toLowerCase() {
    return this.check(_toLowerCase());
  },
  toUpperCase() {
    return this.check(_toUpperCase());
  },
  slugify() {
    return this.check(_slugify());
  }
}));
var ZodString2 = /* @__PURE__ */ $constructor("ZodString", (inst, def) => {
  $ZodString.init(inst, def);
  _ZodString.init(inst, def);
}, {
  email(params) {
    return this.check(_email(ZodEmail, params));
  },
  url(params) {
    return this.check(_url(ZodURL, params));
  },
  jwt(params) {
    return this.check(_jwt(ZodJWT, params));
  },
  emoji(params) {
    return this.check(_emoji2(ZodEmoji, params));
  },
  guid(params) {
    return this.check(_guid(ZodGUID, params));
  },
  uuid(params) {
    return this.check(_uuid(ZodUUID, params));
  },
  uuidv4(params) {
    return this.check(_uuidv4(ZodUUID, params));
  },
  uuidv6(params) {
    return this.check(_uuidv6(ZodUUID, params));
  },
  uuidv7(params) {
    return this.check(_uuidv7(ZodUUID, params));
  },
  nanoid(params) {
    return this.check(_nanoid(ZodNanoID, params));
  },
  cuid(params) {
    return this.check(_cuid(ZodCUID, params));
  },
  cuid2(params) {
    return this.check(_cuid2(ZodCUID2, params));
  },
  ulid(params) {
    return this.check(_ulid(ZodULID, params));
  },
  base64(params) {
    return this.check(_base64(ZodBase64, params));
  },
  base64url(params) {
    return this.check(_base64url(ZodBase64URL, params));
  },
  xid(params) {
    return this.check(_xid(ZodXID, params));
  },
  ksuid(params) {
    return this.check(_ksuid(ZodKSUID, params));
  },
  ipv4(params) {
    return this.check(_ipv4(ZodIPv4, params));
  },
  ipv6(params) {
    return this.check(_ipv6(ZodIPv6, params));
  },
  cidrv4(params) {
    return this.check(_cidrv4(ZodCIDRv4, params));
  },
  cidrv6(params) {
    return this.check(_cidrv6(ZodCIDRv6, params));
  },
  e164(params) {
    return this.check(_e164(ZodE164, params));
  },
  datetime(params) {
    return this.check(_isoDateTime(ZodISODateTime, params));
  },
  date(params) {
    return this.check(_isoDate(ZodISODate, params));
  },
  time(params) {
    return this.check(_isoTime(ZodISOTime, params));
  },
  duration(params) {
    return this.check(_isoDuration(ZodISODuration, params));
  }
});
function string2(params) {
  return _string(ZodString2, params);
}
var ZodStringFormat = /* @__PURE__ */ $constructor("ZodStringFormat", (inst, def) => {
  $ZodStringFormat.init(inst, def);
  _ZodString.init(inst, def);
});
var ZodISODateTime = /* @__PURE__ */ $constructor("ZodISODateTime", (inst, def) => {
  $ZodISODateTime.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodISODate = /* @__PURE__ */ $constructor("ZodISODate", (inst, def) => {
  $ZodISODate.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodISOTime = /* @__PURE__ */ $constructor("ZodISOTime", (inst, def) => {
  $ZodISOTime.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodISODuration = /* @__PURE__ */ $constructor("ZodISODuration", (inst, def) => {
  $ZodISODuration.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodEmail = /* @__PURE__ */ $constructor("ZodEmail", (inst, def) => {
  $ZodEmail.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodGUID = /* @__PURE__ */ $constructor("ZodGUID", (inst, def) => {
  $ZodGUID.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodUUID = /* @__PURE__ */ $constructor("ZodUUID", (inst, def) => {
  $ZodUUID.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodURL = /* @__PURE__ */ $constructor("ZodURL", (inst, def) => {
  $ZodURL.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodEmoji = /* @__PURE__ */ $constructor("ZodEmoji", (inst, def) => {
  $ZodEmoji.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodNanoID = /* @__PURE__ */ $constructor("ZodNanoID", (inst, def) => {
  $ZodNanoID.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodCUID = /* @__PURE__ */ $constructor("ZodCUID", (inst, def) => {
  $ZodCUID.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodCUID2 = /* @__PURE__ */ $constructor("ZodCUID2", (inst, def) => {
  $ZodCUID2.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodULID = /* @__PURE__ */ $constructor("ZodULID", (inst, def) => {
  $ZodULID.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodXID = /* @__PURE__ */ $constructor("ZodXID", (inst, def) => {
  $ZodXID.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodKSUID = /* @__PURE__ */ $constructor("ZodKSUID", (inst, def) => {
  $ZodKSUID.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodIPv4 = /* @__PURE__ */ $constructor("ZodIPv4", (inst, def) => {
  $ZodIPv4.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodIPv6 = /* @__PURE__ */ $constructor("ZodIPv6", (inst, def) => {
  $ZodIPv6.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodCIDRv4 = /* @__PURE__ */ $constructor("ZodCIDRv4", (inst, def) => {
  $ZodCIDRv4.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodCIDRv6 = /* @__PURE__ */ $constructor("ZodCIDRv6", (inst, def) => {
  $ZodCIDRv6.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodBase64 = /* @__PURE__ */ $constructor("ZodBase64", (inst, def) => {
  $ZodBase64.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodBase64URL = /* @__PURE__ */ $constructor("ZodBase64URL", (inst, def) => {
  $ZodBase64URL.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodE164 = /* @__PURE__ */ $constructor("ZodE164", (inst, def) => {
  $ZodE164.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodJWT = /* @__PURE__ */ $constructor("ZodJWT", (inst, def) => {
  $ZodJWT.init(inst, def);
  ZodStringFormat.init(inst, def);
});
var ZodNumber2 = /* @__PURE__ */ $constructor("ZodNumber", (inst, def) => {
  $ZodNumber.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => numberProcessor(inst, ctx, json, params);
  inst.isFinite = true;
}, /* @__PURE__ */ derived({
  minValue: (inst) => {
    const { minimum, exclusiveMinimum } = aggregateChecks(inst);
    return Math.max(minimum ?? Number.NEGATIVE_INFINITY, exclusiveMinimum ?? Number.NEGATIVE_INFINITY);
  },
  maxValue: (inst) => {
    const { maximum, exclusiveMaximum } = aggregateChecks(inst);
    return Math.min(maximum ?? Number.POSITIVE_INFINITY, exclusiveMaximum ?? Number.POSITIVE_INFINITY);
  },
  isInt: (inst) => {
    const { isInt, multipleOf } = aggregateChecks(inst);
    return !!isInt || !!multipleOf?.some(Number.isSafeInteger);
  },
  format: (inst) => aggregateChecks(inst).format ?? null
}, {
  gt(value, params) {
    return this.check(_gt(value, params));
  },
  gte(value, params) {
    return this.check(_gte(value, params));
  },
  min(value, params) {
    return this.check(_gte(value, params));
  },
  lt(value, params) {
    return this.check(_lt(value, params));
  },
  lte(value, params) {
    return this.check(_lte(value, params));
  },
  max(value, params) {
    return this.check(_lte(value, params));
  },
  int(params) {
    return this.check(int(params));
  },
  safe(params) {
    return this.check(int(params));
  },
  positive(params) {
    return this.check(_gt(0, params));
  },
  nonnegative(params) {
    return this.check(_gte(0, params));
  },
  negative(params) {
    return this.check(_lt(0, params));
  },
  nonpositive(params) {
    return this.check(_lte(0, params));
  },
  multipleOf(value, params) {
    return this.check(_multipleOf(value, params));
  },
  step(value, params) {
    return this.check(_multipleOf(value, params));
  },
  finite() {
    return this;
  }
}));
function number2(params) {
  return _number(ZodNumber2, params);
}
var ZodNumberFormat = /* @__PURE__ */ $constructor("ZodNumberFormat", (inst, def) => {
  $ZodNumberFormat.init(inst, def);
  ZodNumber2.init(inst, def);
});
function int(params) {
  return _int(ZodNumberFormat, params);
}
var ZodUnknown2 = /* @__PURE__ */ $constructor("ZodUnknown", (inst, def) => {
  $ZodUnknown.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => unknownProcessor(inst, ctx, json, params);
});
function unknown() {
  return _unknown(ZodUnknown2);
}
var ZodNever2 = /* @__PURE__ */ $constructor("ZodNever", (inst, def) => {
  $ZodNever.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => neverProcessor(inst, ctx, json, params);
});
function never(params) {
  return _never(ZodNever2, params);
}
var ZodArray2 = /* @__PURE__ */ $constructor("ZodArray", (inst, def) => {
  _ensureDefaultMemoizer();
  $ZodArray.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => arrayProcessor(inst, ctx, json, params);
  inst.element = def.element;
}, {
  min(n, params) {
    return this.check(_minLength(n, params));
  },
  nonempty(params) {
    return this.check(_minLength(1, params));
  },
  max(n, params) {
    return this.check(_maxLength(n, params));
  },
  length(n, params) {
    return this.check(_length(n, params));
  },
  unwrap() {
    return this.element;
  }
});
function array(element, params) {
  return _array(ZodArray2, element, params);
}
var ZodObject2 = /* @__PURE__ */ $constructor("ZodObject", (inst, def) => {
  _ensureDefaultMemoizer();
  $ZodObjectJIT.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => objectProcessor(inst, ctx, json, params);
  installLazyProp(inst, "shape", (self) => self._zod.def.shape, false);
}, {
  keyof() {
    return _enum(Object.keys(this._zod.def.shape));
  },
  catchall(catchall) {
    return this.clone(mergeDefs(this._zod.def, { catchall }));
  },
  passthrough() {
    return this.clone(mergeDefs(this._zod.def, { catchall: unknown() }));
  },
  loose() {
    return this.clone(mergeDefs(this._zod.def, { catchall: unknown() }));
  },
  strict() {
    return this.clone(mergeDefs(this._zod.def, { catchall: never() }));
  },
  strip() {
    return this.clone(mergeDefs(this._zod.def, { catchall: undefined }));
  },
  extend(incoming) {
    return extend(this, incoming);
  },
  safeExtend(incoming) {
    return safeExtend(this, incoming);
  },
  merge(other) {
    return merge2(this, other);
  },
  pick(mask) {
    return pick(this, mask);
  },
  omit(mask) {
    return omit(this, mask);
  },
  partial(...args) {
    return partial(ZodOptional2, this, args[0]);
  },
  exactPartial(...args) {
    return partial(ZodExactOptional, this, args[0], "exactPartial");
  },
  required(...args) {
    return required(ZodNonOptional, this, args[0]);
  }
});
function object(shape, params) {
  const def = {
    type: "object",
    shape: shape ?? {},
    ...normalizeParams(params)
  };
  return new ZodObject2(def);
}
var ZodUnion2 = /* @__PURE__ */ $constructor("ZodUnion", (inst, def) => {
  $ZodUnion.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => unionProcessor(inst, ctx, json, params);
  inst.options = def.options;
});
function union(options, params) {
  return new ZodUnion2({
    type: "union",
    options,
    ...normalizeParams(params)
  });
}
var ZodIntersection2 = /* @__PURE__ */ $constructor("ZodIntersection", (inst, def) => {
  $ZodIntersection.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => intersectionProcessor(inst, ctx, json, params);
});
function intersection(left, right) {
  return new ZodIntersection2({
    type: "intersection",
    left,
    right
  });
}
var ZodEnum2 = /* @__PURE__ */ $constructor("ZodEnum", (inst, def) => {
  $ZodEnum.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => enumProcessor(inst, ctx, json, params);
  inst.enum = def.entries;
  inst.options = [...inst._zod.values];
  const keys = new Set(Object.keys(def.entries));
  inst.extract = (values, params) => {
    const newEntries = {};
    for (const value of values) {
      if (keys.has(value)) {
        newEntries[value] = def.entries[value];
      } else
        throw new Error(`Key ${value} not found in enum`);
    }
    return new ZodEnum2({
      ...def,
      checks: [],
      ...normalizeParams(params),
      entries: newEntries
    });
  };
  inst.exclude = (values, params) => {
    const newEntries = { ...def.entries };
    for (const value of values) {
      if (keys.has(value)) {
        delete newEntries[value];
      } else
        throw new Error(`Key ${value} not found in enum`);
    }
    return new ZodEnum2({
      ...def,
      checks: [],
      ...normalizeParams(params),
      entries: newEntries
    });
  };
});
function _enum(values, params) {
  const entries = Array.isArray(values) ? Object.fromEntries(values.map((v) => [v, v])) : values;
  return new ZodEnum2({
    type: "enum",
    entries,
    ...normalizeParams(params)
  });
}
var ZodTransform = /* @__PURE__ */ $constructor("ZodTransform", (inst, def) => {
  _ensureDefaultMemoizer();
  $ZodTransform.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => transformProcessor(inst, ctx, json, params);
  inst._zod.parse = (payload, _ctx) => {
    if (_ctx.direction === "backward") {
      throw new $ZodEncodeError(inst.constructor.name);
    }
    payload.addIssue = (issue2) => {
      if (typeof issue2 === "string") {
        payload.issues.push(issue(issue2, payload.value, def));
      } else {
        const _issue = issue2;
        if (_issue.fatal)
          _issue.continue = false;
        _issue.code ?? (_issue.code = "custom");
        if (!("input" in _issue))
          _issue.input = payload.value;
        _issue.inst ?? (_issue.inst = inst);
        payload.issues.push(issue(_issue));
      }
    };
    const output = def.transform(payload.value, payload);
    if (output instanceof Promise) {
      return output.then((output) => {
        payload.value = output;
        return payload;
      });
    }
    payload.value = output;
    return payload;
  };
});
function transform(fn) {
  return new ZodTransform({
    type: "transform",
    transform: fn
  });
}
var ZodOptional2 = /* @__PURE__ */ $constructor("ZodOptional", (inst, def) => {
  $ZodOptional.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => optionalProcessor(inst, ctx, json, params);
  inst.unwrap = () => inst._zod.def.innerType;
});
function optional(innerType) {
  return new ZodOptional2({
    type: "optional",
    innerType
  });
}
var ZodExactOptional = /* @__PURE__ */ $constructor("ZodExactOptional", (inst, def) => {
  $ZodExactOptional.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => optionalProcessor(inst, ctx, json, params);
  inst.unwrap = () => inst._zod.def.innerType;
});
function exactOptional(innerType) {
  return new ZodExactOptional({
    type: "optional",
    innerType
  });
}
var ZodNullable2 = /* @__PURE__ */ $constructor("ZodNullable", (inst, def) => {
  $ZodNullable.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => nullableProcessor(inst, ctx, json, params);
  inst.unwrap = () => inst._zod.def.innerType;
});
function nullable(innerType) {
  return new ZodNullable2({
    type: "nullable",
    innerType
  });
}
var ZodDefault2 = /* @__PURE__ */ $constructor("ZodDefault", (inst, def) => {
  $ZodDefault.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => defaultProcessor(inst, ctx, json, params);
  inst.unwrap = () => inst._zod.def.innerType;
  inst.removeDefault = inst.unwrap;
});
function _default(innerType, defaultValue) {
  return new ZodDefault2({
    type: "default",
    innerType,
    get defaultValue() {
      return typeof defaultValue === "function" ? defaultValue() : shallowClone(defaultValue);
    }
  });
}
var ZodPrefault = /* @__PURE__ */ $constructor("ZodPrefault", (inst, def) => {
  $ZodPrefault.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => prefaultProcessor(inst, ctx, json, params);
  inst.unwrap = () => inst._zod.def.innerType;
});
function prefault(innerType, defaultValue) {
  return new ZodPrefault({
    type: "prefault",
    innerType,
    get defaultValue() {
      return typeof defaultValue === "function" ? defaultValue() : shallowClone(defaultValue);
    }
  });
}
var ZodNonOptional = /* @__PURE__ */ $constructor("ZodNonOptional", (inst, def) => {
  $ZodNonOptional.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => nonoptionalProcessor(inst, ctx, json, params);
  inst.unwrap = () => inst._zod.def.innerType;
});
function nonoptional(innerType, params) {
  return new ZodNonOptional({
    type: "nonoptional",
    innerType,
    ...normalizeParams(params)
  });
}
var ZodCatch2 = /* @__PURE__ */ $constructor("ZodCatch", (inst, def) => {
  $ZodCatch.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => catchProcessor(inst, ctx, json, params);
  inst.unwrap = () => inst._zod.def.innerType;
  inst.removeCatch = inst.unwrap;
});
function _catch(innerType, catchValue) {
  return new ZodCatch2({
    type: "catch",
    innerType,
    catchValue: typeof catchValue === "function" ? catchValue : constantCatch(catchValue)
  });
}
var ZodPipe = /* @__PURE__ */ $constructor("ZodPipe", (inst, def) => {
  $ZodPipe.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => pipeProcessor(inst, ctx, json, params);
  inst.in = def.in;
  inst.out = def.out;
});
function pipe(in_, out) {
  return new ZodPipe({
    type: "pipe",
    in: in_,
    out
  });
}
var ZodReadonly2 = /* @__PURE__ */ $constructor("ZodReadonly", (inst, def) => {
  $ZodReadonly.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => readonlyProcessor(inst, ctx, json, params);
  inst.unwrap = () => inst._zod.def.innerType;
});
function readonly(innerType) {
  return new ZodReadonly2({
    type: "readonly",
    innerType
  });
}
var ZodCustom = /* @__PURE__ */ $constructor("ZodCustom", (inst, def) => {
  $ZodCustom.init(inst, def);
  ZodType2.init(inst, def);
  inst._zod.processJSONSchema = (ctx, json, params) => customProcessor(inst, ctx, json, params);
});
function refine(fn, _params = {}) {
  return _refine(ZodCustom, fn, _params);
}
function superRefine(fn, params) {
  return _superRefine(fn, params);
}
var baseConfig = object({
  chainSelectorName: string2(),
  market: string2(),
  stablecoin: string2(),
  eurUsdFeed: string2(),
  railsUrl: string2(),
  gasLimit: string2()
});
var Action = {
  ListLoan: 1,
  VerifyLender: 2,
  FiatFunding: 3,
  Disbursed: 4,
  Repaid: 5,
  FiatRedeemed: 6,
  LoanStatus: 7,
  Reconciliation: 8
};
var marketAbi = parseAbi([
  "function loanCount() view returns (uint256)",
  "function reserved() view returns (uint256)",
  "function totalFiatIn() view returns (uint256)",
  "function unallocated() view returns (uint256)",
  "function secondsPerDay() view returns (uint32)",
  "function usedRef(bytes32 ref) view returns (bool)",
  "function loanStates(uint256 fromId, uint256 toId) view returns (uint8[] statuses, uint64[] maturities, uint256[] funded, uint256[] fiatFunded)",
  "function getLoan(uint256 loanId) view returns ((address borrower, uint8 assetType, uint8 riskGrade, bytes3 currency, uint8 status, uint32 aprBps, uint32 tenorDays, uint64 listedAt, uint64 fundedAt, uint64 disbursedAt, uint64 maturity, uint64 repaidAt, uint256 faceValueMinor, uint256 fxRateE8, uint256 target, uint256 funded, uint256 fiatFunded, uint256 repaidAmount, bytes32 docHash, string ref))",
  "function loanToken(uint256 loanId) view returns (address)",
  "function identityRegistry() view returns (address)"
]);
var erc20Abi2 = parseAbi(["function balanceOf(address) view returns (uint256)"]);
var loanTokenAbi = parseAbi([
  "function balanceOf(address) view returns (uint256)",
  "function totalSupply() view returns (uint256)",
  "function paused() view returns (bool)"
]);
var identityRegistryAbi = parseAbi(["function isVerified(address) view returns (bool)"]);
var feedAbi = parseAbi([
  "function latestRoundData() view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)"
]);
function evm(runtime) {
  const network = getNetwork({ chainFamily: "evm", chainSelectorName: runtime.config.chainSelectorName, isTestnet: true });
  if (!network)
    throw new Error(`unknown chain selector name ${runtime.config.chainSelectorName}`);
  return new ClientCapability(network.chainSelector.selector);
}
function read2(runtime, to, abi, functionName, args = []) {
  const reply = evm(runtime).callContract(runtime, {
    call: encodeCallMsg({
      from: zeroAddress,
      to,
      data: encodeFunctionData({ abi, functionName, args })
    }),
    blockNumber: LATEST_BLOCK_NUMBER
  }).result();
  return decodeFunctionResult({ abi, functionName, data: bytesToHex3(reply.data) });
}
function readEurUsd(runtime, maxAgeSeconds = 2n * 86400n) {
  const [roundId, answer, , updatedAt, answeredInRound] = read2(runtime, runtime.config.eurUsdFeed, feedAbi, "latestRoundData");
  if (roundId === 0n || answeredInRound < roundId || answer <= 0n)
    throw new Error("EUR/USD round not answered");
  const now = BigInt(Math.floor(runtime.now().getTime() / 1000));
  if (updatedAt > now + 300n)
    throw new Error("EUR/USD round from the future");
  if (now - updatedAt > maxAgeSeconds)
    throw new Error("EUR/USD feed is stale");
  return answer;
}
function writeAction(runtime, action, payload) {
  const encoded = encodeAbiParameters(parseAbiParameters("uint8 action, bytes payload"), [action, payload]);
  const report = runtime.report(prepareReportRequest(encoded)).result();
  const reply = evm(runtime).writeReport(runtime, {
    receiver: runtime.config.market,
    report,
    gasConfig: { gasLimit: runtime.config.gasLimit }
  }).result();
  if (reply.txStatus !== TxStatus.SUCCESS) {
    throw new Error(reply.errorMessage ?? `report write failed with status ${reply.txStatus}`);
  }
  if (!reply.txHash)
    throw new Error("report write succeeded without a transaction hash");
  const hash = bytesToHex3(reply.txHash);
  if ((reply.receiverContractExecutionStatus ?? 0) !== 0) {
    throw new Error(`market rejected the report (action ${action}), tx ${hash}`);
  }
  runtime.log(`report delivered: action=${action} tx=${hash}`);
  return hash;
}
function loanTokenOf(runtime, loanId) {
  const token = read2(runtime, runtime.config.market, marketAbi, "loanToken", [loanId]);
  if (token === zeroAddress)
    throw new Error(`loan ${loanId} has no ERC-3643 token`);
  return token;
}
function isVerifiedInRegistry(runtime, wallet) {
  const registry = read2(runtime, runtime.config.market, marketAbi, "identityRegistry");
  return read2(runtime, registry, identityRegistryAbi, "isVerified", [wallet]);
}
var tokenSymbol = (loanId) => `TFN${loanId}`;
var refHash = (ref) => keccak256(toHex(ref));
function decodeInput(input) {
  return JSON.parse(new TextDecoder().decode(input));
}
var toUsd6 = (amountMinor, rateE8) => amountMinor * rateE8 * 10000n / 100000000n;
var bigintJson = (v) => JSON.stringify(v, (_, x) => typeof x === "bigint" ? x.toString() : x);
var configSchema = baseConfig.extend({
  authorizedKeys: array(string2()),
  apiKeySecretId: string2(),
  secretOwner: string2(),
  maxFxDeviationBps: number2()
});
function confidentialRequest(runtime, method, path, body) {
  const res = new ClientCapability2().sendRequest(runtime, {
    vaultDonSecrets: [{ key: runtime.config.apiKeySecretId, owner: runtime.config.secretOwner }],
    request: {
      url: `${runtime.config.railsUrl}${path}`,
      method,
      ...body === undefined ? {} : { bodyString: JSON.stringify(body) },
      multiHeaders: {
        "x-api-key": { values: [`{{.${runtime.config.apiKeySecretId}}}`] },
        "content-type": { values: ["application/json"] }
      },
      encryptOutput: false
    }
  }).result();
  if (!ok(res))
    throw new Error(`${method} ${path} HTTP ${res.statusCode}: ${new TextDecoder().decode(res.body).slice(0, 200)}`);
  return json(res);
}
var confidentialGet = (runtime, path) => confidentialRequest(runtime, "GET", path);
var ISO_NUMERIC = {
  AE: 784,
  AR: 32,
  AT: 40,
  AU: 36,
  BD: 50,
  BE: 56,
  BR: 76,
  CA: 124,
  CH: 756,
  CI: 384,
  CL: 152,
  CN: 156,
  CO: 170,
  CR: 188,
  CU: 192,
  CZ: 203,
  DE: 276,
  DK: 208,
  EC: 218,
  EG: 818,
  ES: 724,
  ET: 231,
  FI: 246,
  FR: 250,
  GB: 826,
  GH: 288,
  GR: 300,
  HK: 344,
  HU: 348,
  ID: 360,
  IE: 372,
  IL: 376,
  IN: 356,
  IR: 364,
  IT: 380,
  JP: 392,
  KE: 404,
  KP: 408,
  KR: 410,
  LK: 144,
  MA: 504,
  MX: 484,
  MY: 458,
  NG: 566,
  NL: 528,
  NO: 578,
  NZ: 554,
  PA: 591,
  PE: 604,
  PH: 608,
  PK: 586,
  PL: 616,
  PT: 620,
  QA: 634,
  RO: 642,
  SA: 682,
  SE: 752,
  SG: 702,
  SY: 760,
  TH: 764,
  TR: 792,
  TW: 158,
  TZ: 834,
  UG: 800,
  US: 840,
  UY: 858,
  VN: 704,
  ZA: 710
};
var onVerifyLender = (runtime, payload) => {
  const { lenderId } = decodeInput(payload.input);
  const kyc = confidentialGet(runtime, `/v1/kyc/${lenderId}`);
  runtime.log(`KYC file received: ${kyc.status}`);
  if (kyc.status !== "approved") {
    runtime.log(`KYC not approved for ${lenderId}: ${kyc.status}`);
    return JSON.stringify({ verified: false, lenderId, status: kyc.status });
  }
  const alpha2 = String(kyc.country ?? "").toUpperCase();
  const country = ISO_NUMERIC[alpha2];
  if (!country) {
    const reason = `KYC country ${alpha2 || "(none)"} has no ISO 3166 numeric code on file, so no identity claim can be issued`;
    runtime.log(`identity not registered: ${reason}`);
    return JSON.stringify({ verified: false, lenderId, status: "unsupported country", reason });
  }
  const wallet = kyc.wallet;
  if (isVerifiedInRegistry(runtime, wallet)) {
    runtime.log("wallet already verified in the ERC-3643 identity registry, nothing to write");
    return JSON.stringify({ verified: true, lenderId, wallet, level: kyc.level, country, alreadyVerified: true });
  }
  const kycRef = refHash(`kyc|${kyc.lenderId}|${kyc.level}`);
  const tx = writeAction(runtime, Action.VerifyLender, encodeAbiParameters(parseAbiParameters("address lender, bool verified, bytes32 kycRef, uint16 country"), [wallet, true, kycRef, country]));
  const registered = isVerifiedInRegistry(runtime, wallet);
  runtime.log(registered ? `KYC claim issued, wallet registered in the ERC-3643 identity registry (country ${country})` : "report accepted, but the ERC-3643 identity registry does not show the wallet as verified yet");
  return JSON.stringify({ verified: true, lenderId, wallet, level: kyc.level, country, identityVerified: registered, tx });
};
var onFiatDeposit = (runtime, payload) => {
  const { reference } = decodeInput(payload.input);
  const market = runtime.config.market.toLowerCase();
  const dep = confidentialGet(runtime, `/v1/onramp/deposits/${reference}`);
  if (dep.status === "awaiting_funds")
    throw new Error(`no transfer has arrived for ${reference}`);
  const fiat = `${(dep.fiatAmountMinor / 100).toFixed(2)} ${dep.currency}`;
  runtime.log(`bank: ${fiat} received for reference ${reference}`);
  const kyc = confidentialGet(runtime, `/v1/kyc/${dep.lenderId}`);
  if (kyc.status !== "approved")
    throw new Error(`lender ${dep.lenderId} is not KYC approved`);
  if (kyc.wallet.toLowerCase() !== dep.wallet.toLowerCase())
    throw new Error("deposit wallet does not match KYC file");
  runtime.log("KYC file approved and matches the deposit wallet");
  const feedRate = dep.currency === "EUR" ? readEurUsd(runtime) : 100000000n;
  const minRateE8 = dep.currency === "EUR" ? feedRate * (10000n - BigInt(runtime.config.maxFxDeviationBps)) / 10000n : feedRate;
  const conv = dep.status === "received" ? confidentialRequest(runtime, "POST", "/v1/onramp/conversions", {
    reference,
    destination: runtime.config.market,
    minRateE8: minRateE8.toString(),
    idempotencyKey: `convert-${reference}`
  }) : { status: dep.status, fxRateE8: dep.fxRateE8, stablecoinAmount: dep.stablecoinAmount, mintTx: dep.mintTx, destination: dep.destination };
  if (conv.destination.toLowerCase() !== market)
    throw new Error("on-ramp delivered to the wrong destination");
  runtime.log(`on-ramp instructed: ${fiat} converted to ${(Number(conv.stablecoinAmount) / 1e6).toFixed(2)} USDC and delivered to the market, tx ${conv.mintTx}`);
  const providerRate = BigInt(conv.fxRateE8);
  if (dep.currency === "EUR") {
    const diff = providerRate > feedRate ? providerRate - feedRate : feedRate - providerRate;
    const deviationBps = diff * 10000n / feedRate;
    if (deviationBps > BigInt(runtime.config.maxFxDeviationBps)) {
      throw new Error(`on-ramp FX ${providerRate} deviates ${deviationBps} bps from Chainlink ${feedRate}`);
    }
    runtime.log(`EUR/USD ${(Number(feedRate) / 1e8).toFixed(4)} from the data feed, on-ramp rate ${deviationBps} bps off (limit ${runtime.config.maxFxDeviationBps})`);
  } else if (providerRate !== 100000000n) {
    throw new Error("USD deposit quoted with a non-unit rate");
  }
  const expected = toUsd6(BigInt(dep.fiatAmountMinor), providerRate);
  const claimed = BigInt(conv.stablecoinAmount);
  if (claimed !== expected)
    throw new Error(`on-ramp delivered ${claimed}, expected ${expected}`);
  const unallocated = read2(runtime, runtime.config.market, marketAbi, "unallocated");
  if (unallocated < claimed)
    throw new Error(`only ${unallocated} unallocated in the market, need ${claimed}`);
  runtime.log("stablecoin amount recomputed and found in the market");
  const loanId = BigInt(dep.loanId);
  if (!isVerifiedInRegistry(runtime, dep.wallet))
    throw new Error("lender wallet is not verified in the ERC-3643 identity registry");
  const token = loanTokenOf(runtime, loanId);
  const before = read2(runtime, token, loanTokenAbi, "balanceOf", [dep.wallet]);
  const tx = writeAction(runtime, Action.FiatFunding, encodeAbiParameters(parseAbiParameters("uint256 loanId, address lender, uint256 amount, bytes32 depositRef"), [
    loanId,
    dep.wallet,
    claimed,
    refHash(`deposit|${reference}`)
  ]));
  const minted = read2(runtime, token, loanTokenAbi, "balanceOf", [dep.wallet]) - before;
  runtime.log(`loan notes minted: ${(Number(minted) / 1e6).toFixed(2)} ${tokenSymbol(loanId)} (ERC-3643) to the lender's wallet`);
  return bigintJson({
    credited: true,
    reference,
    loanId: dep.loanId,
    token,
    notesMinted: minted,
    lender: dep.lenderId,
    fiat: `${dep.fiatAmountMinor / 100} ${dep.currency}`,
    providerRate,
    chainlinkRate: feedRate,
    stablecoins: claimed,
    tx
  });
};
var initWorkflow = (config) => {
  const http = new HTTPCapability;
  return [
    handler(http.trigger({ authorizedKeys: config.authorizedKeys }), onVerifyLender),
    handler(http.trigger({ authorizedKeys: config.authorizedKeys }), onFiatDeposit)
  ];
};
async function main() {
  const runner = await Runner.newRunner({ configSchema });
  await runner.run(initWorkflow);
}
main().catch(sendErrorResponse);
export {
  main
};
