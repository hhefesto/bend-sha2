import Base

# Sha2: SHA-256 (FIPS 180-4) over bytes (0..255, one List cell each)
# (cryptohash-sha256's job in the Haskell backend), for
# what the backend names by its hash: a session's token is kept as its
# hash, an image is named by the first 16 hex digits of its own, as mugen's
# /image names one. Its meaning is the standard's: probe/Sha.bend checks
# it on the standard's examples.
#
# Every def is prefixed `sha.` (a program's defs share one namespace).

# the working variables a to h
type sha.S is Data:
  sha.S{a: U32, b: U32, c: U32, d: U32, e: U32, f: U32, g: U32, h: U32}

def sha.k() -> List<&2, U32>:
  [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221,
   3624381080, 310598401, 607225278, 1426881987, 1925078388, 2162078206, 2614888103, 3248222580,
   3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986,
   2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895,
   666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037,
   2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344,
   430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779,
   1955562222, 2024104815, 2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298]

def sha.h0() -> sha.S:
  sha.S{1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225}

# The functions
# -------------

def sha.rotr(+x: U32, n: Nat, m: Nat) -> U32:
  U32.or(U32.shrn(x, n), U32.shln(x, m))

def sha.big0(+x: U32) -> U32:
  U32.xor(U32.xor(sha.rotr(x, 2n, 30n), sha.rotr(x, 13n, 19n)), sha.rotr(x, 22n, 10n))

def sha.big1(+x: U32) -> U32:
  U32.xor(U32.xor(sha.rotr(x, 6n, 26n), sha.rotr(x, 11n, 21n)), sha.rotr(x, 25n, 7n))

def sha.small0(+x: U32) -> U32:
  U32.xor(U32.xor(sha.rotr(x, 7n, 25n), sha.rotr(x, 18n, 14n)), U32.shrn(x, 3n))

def sha.small1(+x: U32) -> U32:
  U32.xor(U32.xor(sha.rotr(x, 17n, 15n), sha.rotr(x, 19n, 13n)), U32.shrn(x, 10n))

def sha.ch(+e: U32, +f: U32, +g: U32) -> U32:
  U32.xor(U32.and(e, f), U32.and(U32.not(e), g))

def sha.maj(+a: U32, +b: U32, +c: U32) -> U32:
  U32.xor(U32.xor(U32.and(a, b), U32.and(a, c)), U32.and(b, c))

def sha.round.t(+a: U32, +b: U32, +c: U32, +d: U32, +e: U32, +f: U32, +g: U32, +t1: U32) -> sha.S:
  sha.S{(t1 + sha.big0(a) + sha.maj(a, b, c) : U32), a, b, c, (d + t1 : U32), e, f, g}

# One round, with its constant k and word w.
def sha.round(s: sha.S, +k: U32, +w: U32) -> sha.S:
  match s:
    case sha.S{+a, +b, +c, +d, +e, +f, +g, +h}:
      sha.round.t(a, b, c, d, e, f, g, (h + sha.big1(e) + sha.ch(e, f, g) + k + w : U32))

def sha.rounds(ks: List<&2, U32>, ws: List<&2, U32>, s: sha.S) -> sha.S:
  match ks ws:
    case Con{+k, kt} Con{+w, wt}:
      sha.rounds(kt, wt, sha.round(s, k, w))
    case _ _:
      s

# The message schedule: from a block's 16 words, all 64 (oldest first);
# win is the last 16, acc all so far reversed.
def sha.at(xs: List<&2, U32>, n: Nat) -> U32:
  match xs n:
    case Nil{} _:
      0
    case Con{x, t} 0n:
      x
    case Con{x, t} 1n+p:
      sha.at(t, p)

def sha.drop1(xs: List<&2, U32>) -> List<&2, U32>:
  match xs:
    case Nil{}:
      []
    case Con{x, t}:
      t

def sha.sched(fuel: Nat, +win: List<&2, U32>, acc: List<&2, U32>) -> List<&2, U32>:
  match fuel:
    case 0n:
      List.reverse(&2, U32, acc)
    case 1n+p:
      +w = (sha.small1(sha.at(win, 14n)) + sha.at(win, 9n) + sha.small0(sha.at(win, 1n)) + sha.at(win, 0n) : U32)
      sha.sched(p, List.append(&2, U32, sha.drop1(win), [w]), w <> acc)

# a block's 64 bytes as 16 big-endian words
def sha.words(bs: List<&2, U32>) -> List<&2, U32>:
  match bs:
    case Con{+a, Con{+b, Con{+c, Con{+d, t}}}}:
      U32.or(U32.or(U32.shln(a, 24n), U32.shln(b, 16n)), U32.or(U32.shln(c, 8n), d)) <> sha.words(t)
    case _:
      []

def sha.add(s: sha.S, t: sha.S) -> sha.S:
  match s t:
    case sha.S{a, b, c, d, e, f, g, h} sha.S{a2, b2, c2, d2, e2, f2, g2, h2}:
      sha.S{(a + a2 : U32), (b + b2 : U32), (c + c2 : U32), (d + d2 : U32), (e + e2 : U32), (f + f2 : U32), (g + g2 : U32), (h + h2 : U32)}

def sha.block.ws(+ws: List<&2, U32>, +st: sha.S) -> sha.S:
  sha.add(st, sha.rounds(sha.k(), sha.sched(48n, ws, List.reverse(&2, U32, ws)), st))

def sha.block(bs: List<&2, U32>, +st: sha.S) -> sha.S:
  sha.block.ws(sha.words(bs), st)

# Bytes fed in: blk the block so far (reversed), n its length
def sha.feed.at(full: Bool, blk: List<&2, U32>, +n: U32, +st: sha.S, more: List<&2, U32> -> U32 -> sha.S -> sha.S) -> sha.S:
  match full:
    case True{}:
      more([], 0, sha.block(List.reverse(&2, U32, blk), st))
    case False{}:
      more(blk, (n + 1 : U32), st)

def sha.feed(bs: List<&2, U32>, blk: List<&2, U32>, +n: U32, +st: sha.S) -> sha.S:
  match bs:
    case Nil{}:
      st
    case Con{+b, t}:
      sha.feed.at(U32.is_eq(n, 63), b <> blk, n, st, x => m => s => sha.feed(t, x, m, s))

# Padding: 0x80, zeros up to 8 bytes short of a block, the length in bits
def sha.zeros(n: Nat) -> List<&2, U32>:
  match n:
    case 0n:
      []
    case 1n+p:
      0 <> sha.zeros(p)

def sha.be(+x: U32) -> List<&2, U32>:
  [U32.shrn(x, 24n), U32.and(U32.shrn(x, 16n), 255), U32.and(U32.shrn(x, 8n), 255), U32.and(x, 255)]

def sha.tail(+len: U32) -> List<&2, U32>:
  List.concat(&2, U32, [[128], sha.zeros(U32.to_nat(U32.mod((64 - U32.mod((len + 9 : U32), 64) : U32), 64))),
                        sha.be(U32.shrn(len, 29n)), sha.be(U32.shln(len, 3n))])

def sha.pad(+bs: List<&2, U32>) -> List<&2, U32>:
  List.append(&2, U32, bs, sha.tail(U32.from_nat(List.length(&2, U32, bs))))

# Hex
# ---

def sha.digit(+d: U32) -> Char:
  Chr{Bool.pick(U32, U32.is_lt(d, 10), (d + 48 : U32), (d + 87 : U32))}

def sha.hex.go(n: Nat, +x: U32, acc: String) -> String:
  match n:
    case 0n:
      acc
    case 1n+p:
      sha.hex.go(p, U32.shrn(x, 4n), SCon{sha.digit(U32.and(x, 15)), acc})

# a word as 8 hex digits
def sha.hex(+x: U32) -> String:
  sha.hex.go(8n, x, "")

def sha.hex.of(s: sha.S) -> String:
  match s:
    case sha.S{a, b, c, d, e, f, g, h}:
      String.concat([sha.hex(a), sha.hex(b), sha.hex(c), sha.hex(d), sha.hex(e), sha.hex(f), sha.hex(g), sha.hex(h)])

# The hash
# --------

# SHA-256 of the bytes, as 64 hex digits (lower case)
def sha.sum(+bs: List<&2, U32>) -> String:
  sha.hex.of(sha.feed(sha.pad(bs), [], 0, sha.h0()))

# the digest as its 32 bytes
def sha.bytes.go(ws: List<&2, U32>) -> List<&2, U32>:
  match ws:
    case Nil{}:
      []
    case Con{w, t}:
      List.append(&2, U32, sha.be(w), sha.bytes.go(t))

def sha.words.of(s: sha.S) -> List<&2, U32>:
  match s:
    case sha.S{a, b, c, d, e, f, g, h}:
      [a, b, c, d, e, f, g, h]

def sha.digest(+bs: List<&2, U32>) -> List<&2, U32>:
  sha.bytes.go(sha.words.of(sha.feed(sha.pad(bs), [], 0, sha.h0())))
