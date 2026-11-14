import Base
import ../Sha2.bend as Sha
import ../../wire/Wire.bend as H

# SHA-256 on the examples of FIPS 180-4 (and the empty message): prints each
# digest, then whether all are the standard's.

def sha.probe.one(+got: String, +want: String) -> Bool:
  String.eq(got, want)

def main() -> IO(Unit):
  do IO<Unit>:
    a : String = Sha.sha.sum(H.wr.utf8.of(""))
    b : String = Sha.sha.sum(H.wr.utf8.of("abc"))
    c : String = Sha.sha.sum(H.wr.utf8.of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
    d : String = Sha.sha.sum(H.wr.utf8.of("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))
    IO.print(String.join([a, b, c, d], "\n"))
    IO.print(Bool.pick(String,
      sha.probe.one(Sha.sha.sum(H.wr.utf8.of("")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        && sha.probe.one(Sha.sha.sum(H.wr.utf8.of("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        && sha.probe.one(Sha.sha.sum(H.wr.utf8.of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        && sha.probe.one(Sha.sha.sum(H.wr.utf8.of("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")), "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
      "sha ok", "sha WRONG"))
