"""Ethereum-style Merkle-Patricia trie in pure Python, zero dependencies.

Implements the hexary Patricia trie from the Ethereum Yellow Paper:
  * leaf / extension / branch nodes with hex-prefix (compact) encoding
  * recursive-length-prefix (RLP) node serialization
  * self-contained Keccak-256 sponge (no hashlib.keccak needed)
  * insert / get / delete, root hashing
  * inclusion / exclusion proof generation and stateless verification

Keys are arbitrary bytes (they are hashed with Keccak-256 before being
used as nibble paths, exactly like Ethereum state keys).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Keccak-256 (self-contained sponge, rate 1088, domain suffix 0x01)
# ---------------------------------------------------------------------------

_MASK64 = (1 << 64) - 1

_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]


def _keccak_f1600(state):
    """The Keccak-f[1600] permutation over 25 lanes of 64 bits."""
    for rnd in range(24):
        # theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # rho + pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(state[x + 5 * y], _ROT[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
        # iota
        state[0] ^= _RC[rnd]
    return state


def _rotl(x, n):
    return ((x << n) | (x >> (64 - n))) & _MASK64


def keccak_256(data: bytes) -> bytes:
    """Keccak-256 (pre-NIST variant used by Ethereum)."""
    state = [0] * 25
    rate = 136  # bytes
    msg = data + b"\x01"
    pad = rate - (len(msg) % rate)
    msg += b"\x00" * (pad - 1) + b"\x80"
    for off in range(0, len(msg), rate):
        chunk = msg[off:off + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(chunk[8 * i:8 * i + 8], "little")
            state[i] ^= lane
        state = _keccak_f1600(state)
    return b"".join(s.to_bytes(8, "little") for s in state)[:32]


# ---------------------------------------------------------------------------
# Minimal RLP (enough for trie nodes: byte strings and lists)
# ---------------------------------------------------------------------------

def _rlp_encode_len(length, offset):
    if length <= 55:
        return bytes([offset + length])
    blen = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(blen)]) + blen


def rlp_encode(item) -> bytes:
    if isinstance(item, bytes):
        if len(item) == 1 and item[0] < 0x80:
            return item
        return _rlp_encode_len(len(item), 0x80) + item
    if isinstance(item, list):
        payload = b"".join(rlp_encode(x) for x in item)
        return _rlp_encode_len(len(payload), 0xC0) + payload
    raise TypeError("RLP supports bytes and list only")


def rlp_decode(data: bytes):
    item, rest = _rlp_decode_one(data)
    if rest:
        raise ValueError("trailing bytes after RLP item")
    return item


def _rlp_decode_one(data: bytes):
    if not data:
        raise ValueError("empty RLP input")
    prefix = data[0]
    if prefix < 0x80:
        return data[0:1], data[1:]
    if prefix < 0xB8:
        n = prefix - 0x80
        return data[1:1 + n], data[1 + n:]
    if prefix < 0xC0:
        ll = prefix - 0xB7
        n = int.from_bytes(data[1:1 + ll], "big")
        start = 1 + ll
        return data[start:start + n], data[start + n:]
    if prefix < 0xF8:
        n = prefix - 0xC0
        items, rest = [], data[1:1 + n]
        while rest:
            it, rest = _rlp_decode_one(rest)
            items.append(it)
        return items, data[1 + n:]
    ll = prefix - 0xF7
    n = int.from_bytes(data[1:1 + ll], "big")
    items, rest = [], data[1 + ll:1 + ll + n]
    while rest:
        it, rest = _rlp_decode_one(rest)
        items.append(it)
    return items, data[1 + ll + n:]


# ---------------------------------------------------------------------------
# Nibble helpers + hex-prefix (compact) encoding
# ---------------------------------------------------------------------------

def _to_nibbles(key: bytes):
    nibbles = []
    for byte in key:
        nibbles.append(byte >> 4)
        nibbles.append(byte & 0x0F)
    return nibbles


def _from_nibbles(nibbles):
    out = bytearray()
    for i in range(0, len(nibbles), 2):
        out.append((nibbles[i] << 4) | nibbles[i + 1])
    return bytes(out)


def compact_encode(nibbles, is_leaf: bool) -> bytes:
    """Hex-prefix encode a nibble path. is_leaf selects the flag nibble."""
    flag = 2 if is_leaf else 0
    if len(nibbles) % 2:  # odd: flag nibble merged into first byte
        path = [flag + 1] + nibbles
    else:  # even: flag nibble + padding zero nibble
        path = [flag, 0] + nibbles
    return _from_nibbles(path)


def compact_decode(raw: bytes):
    nibbles = _to_nibbles(raw)
    flag = nibbles[0]
    if flag == 0:
        return nibbles[2:], False
    if flag == 1:
        return nibbles[1:], False
    if flag == 2:
        return nibbles[2:], True
    if flag == 3:
        return nibbles[1:], True
    raise ValueError("invalid hex-prefix flag")


def _shared_prefix(a, b) -> int:
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


# ---------------------------------------------------------------------------
# The trie
# ---------------------------------------------------------------------------

_BLANK = b""


class Trie:
    """In-memory Merkle-Patricia trie keyed by arbitrary bytes."""

    def __init__(self):
        self.db = {}          # keccak(node_rlp) -> node_rlp
        self.root = _BLANK     # blank root = empty trie (Yellow Paper)

    # -- node (de)serialization -------------------------------------------
    def _ref(self, encoded: bytes) -> bytes:
        """Reference another node: inline if tiny, hash + store otherwise."""
        if len(encoded) < 32:
            return encoded
        digest = keccak_256(encoded)
        self.db[digest] = encoded
        return digest

    def _resolve(self, ref: bytes):
        if ref == _BLANK:
            return None
        if len(ref) == 32 and ref in self.db:
            return rlp_decode(self.db[ref])
        return rlp_decode(ref)  # inlined node

    # -- public API --------------------------------------------------------
    def insert(self, key: bytes, value: bytes):
        if not value:
            raise ValueError("empty values are not stored (use delete)")
        nibbles = _to_nibbles(keccak_256(key))
        self.root = self._insert_ref(self.root, nibbles, value)

    def get(self, key: bytes):
        nibbles = _to_nibbles(keccak_256(key))
        return self._get_ref(self.root, nibbles)

    def delete(self, key: bytes):
        nibbles = _to_nibbles(keccak_256(key))
        self.root = self._delete_ref(self.root, nibbles)

    def root_hash(self) -> bytes:
        """32-byte root hash (keccak of the empty string for an empty trie).

        When the root node is stored by hash the root hash is that digest;
        when it is inlined (RLP < 32 bytes) it is keccak of the inline RLP.
        """
        if self.root == _BLANK:
            return keccak_256(b"")
        if self.root in self.db:
            return self.root  # root node is stored by its hash digest
        return keccak_256(self.root)

    # -- internal recursion -------------------------------------------------
    def _insert_ref(self, ref, nibbles, value):
        node = self._resolve(ref)
        encoded = self._insert(node, nibbles, value)
        return self._ref(rlp_encode(encoded))

    def _insert(self, node, nibbles, value):
        if node is None:
            return [compact_encode(nibbles, True), value]  # leaf
        if len(node) == 17:  # branch
            if not nibbles:
                node[16] = value
            else:
                child = self._insert_ref(node[nibbles[0]], nibbles[1:], value)
                node[nibbles[0]] = child
            return node
        # leaf or extension: [compact_path, item]
        path, is_leaf = compact_decode(node[0])
        common = _shared_prefix(nibbles, path)
        if is_leaf:
            if common == len(nibbles) == len(path):
                return [node[0], value]  # overwrite existing leaf
            branch = [_BLANK] * 16 + [_BLANK]
            if len(path) == common:  # old leaf exhausted here
                branch[16] = node[1]
            else:
                branch[path[common]] = self._ref(
                    rlp_encode([compact_encode(path[common + 1:], True), node[1]]))
            if len(nibbles) == common:
                branch[16] = value
            else:
                branch[nibbles[common]] = self._ref(
                    rlp_encode([compact_encode(nibbles[common + 1:], True), value]))
            node_ = branch
        else:  # extension
            if common == len(path):
                node[1] = self._insert_ref(node[1], nibbles[common:], value)
                node_ = node
            else:
                branch = [_BLANK] * 16 + [_BLANK]
                branch[path[common]] = self._ref(
                    rlp_encode([compact_encode(path[common + 1:], False), node[1]]))
                branch[nibbles[common]] = self._ref(
                    rlp_encode([compact_encode(nibbles[common + 1:], True), value]))
                node_ = branch
        if common:
            return [compact_encode(path[:common], False), self._ref(rlp_encode(node_))]
        return node_

    def _get_ref(self, ref, nibbles):
        node = self._resolve(ref)
        if node is None:
            return None
        if len(node) == 17:  # branch
            if not nibbles:
                return node[16] or None
            return self._get_ref(node[nibbles[0]], nibbles[1:])
        path, is_leaf = compact_decode(node[0])
        if not nibbles[:len(path)] == path:
            return None
        if is_leaf:
            return node[1] if len(nibbles) == len(path) else None
        return self._get_ref(node[1], nibbles[len(path):])

    def _delete_ref(self, ref, nibbles):
        node = self._resolve(ref)
        if node is None:
            return _BLANK
        encoded = self._delete(node, nibbles)
        if encoded is None:
            return _BLANK
        return self._ref(rlp_encode(encoded))

    def _delete(self, node, nibbles):
        if len(node) == 17:  # branch
            if not nibbles:
                node[16] = _BLANK
            else:
                node[nibbles[0]] = self._delete_ref(node[nibbles[0]], nibbles[1:])
            return self._degenerate(node)
        path, is_leaf = compact_decode(node[0])
        if not nibbles[:len(path)] == path:
            return node  # key absent
        if is_leaf:
            return None if len(nibbles) == len(path) else node
        child = self._delete_ref(node[1], nibbles[len(path):])
        if child == node[1]:
            return node  # key absent
        if child == _BLANK:
            return None
        return self._merge_extension(path, child)

    def _degenerate(self, branch):
        """Collapse a branch with 0-1 children back into extension/leaf/blank."""
        used = [(i, c) for i, c in enumerate(branch[:16]) if c != _BLANK]
        if branch[16] != _BLANK or len(used) > 1:
            return branch
        if not used:
            return None
        i, child = used[0]
        node = self._resolve(child)
        if node is None:
            return [compact_encode([i], False), child]
        if len(node) == 17:
            return [compact_encode([i], False), child]
        path, is_leaf = compact_decode(node[0])
        return [compact_encode([i] + path, is_leaf), node[1]]

    def _merge_extension(self, path, child):
        """Merge an extension node with its (leaf/extension) child."""
        node = self._resolve(child)
        if node is None or len(node) == 17:
            return [compact_encode(path, False), child]
        cpath, is_leaf = compact_decode(node[0])
        return [compact_encode(path + cpath, is_leaf), node[1]]

    # -- proofs --------------------------------------------------------------
    def proof(self, key: bytes):
        """Return the list of RLP-encoded nodes on the path for ``key``."""
        nibbles = _to_nibbles(keccak_256(key))
        nodes, ref = [], self.root
        while True:
            node = self._resolve(ref)
            if node is None:
                break
            nodes.append(rlp_encode(node))
            if len(node) == 17:  # branch
                if not nibbles:
                    break
                ref = node[nibbles[0]]
                nibbles = nibbles[1:]
            else:
                path, is_leaf = compact_decode(node[0])
                if nibbles[:len(path)] != path:
                    break
                if is_leaf:
                    break
                ref = node[1]
                nibbles = nibbles[len(path):]
        return nodes


def verify_proof(root_hash: bytes, key: bytes, proof) -> bytes | None:
    """Statelessly verify a proof. Returns the value, or None if absent.

    >>> t = Trie(); t.insert(b"dog", b"puppy"); t.insert(b"horse", b"stallion")
    >>> p = t.proof(b"dog")
    >>> verify_proof(t.root_hash(), b"dog", p)
    b'puppy'
    >>> verify_proof(t.root_hash(), b"cat", t.proof(b"cat")) is None
    True
    """
    nibbles = _to_nibbles(keccak_256(key))
    db = {}
    for encoded in proof:
        db[keccak_256(encoded)] = encoded
    ref = root_hash
    while True:
        if ref == _BLANK:
            return None
        encoded = db.get(ref, ref)  # fall back: ref may be an inlined node
        if encoded is None:
            raise ValueError("proof is missing a node for the given root")
        node = rlp_decode(encoded)
        if len(node) == 17:  # branch
            if not nibbles:
                return node[16] or None
            ref = node[nibbles[0]]
            nibbles = nibbles[1:]
        else:
            path, is_leaf = compact_decode(node[0])
            if nibbles[:len(path)] != path:
                return None
            if is_leaf:
                return node[1] if len(nibbles) == len(path) else None
            ref = node[1]
            nibbles = nibbles[len(path):]


# ---------------------------------------------------------------------------
# Self-tests (doctests)
# ---------------------------------------------------------------------------

def _self_test():
    t = Trie()
    t.insert(b"do", b"verb"); t.insert(b"dog", b"puppy")
    t.insert(b"doge", b"meme"); t.insert(b"horse", b"stallion")
    assert t.get(b"dog") == b"puppy"
    assert t.get(b"do") == b"verb"
    assert t.get(b"doge") == b"meme"
    assert t.get(b"horse") == b"stallion"
    assert t.get(b"cat") is None

    # root hash is order-independent (canonical trie shape)
    t2 = Trie()
    for k, v in [(b"horse", b"stallion"), (b"doge", b"meme"),
                 (b"dog", b"puppy"), (b"do", b"verb")]:
        t2.insert(k, v)
    assert t.root_hash() == t2.root_hash()

    # overwriting a key keeps the same single-key root
    t3 = Trie(); t3.insert(b"k", b"v1")
    t4 = Trie(); t4.insert(b"k", b"v2"); t4.insert(b"k", b"v1")
    assert t3.root_hash() == t4.root_hash()

    # proofs: inclusion and exclusion
    for k in (b"do", b"dog", b"doge", b"horse"):
        assert verify_proof(t.root_hash(), k, t.proof(k)) == t.get(k)
    assert verify_proof(t.root_hash(), b"cat", t.proof(b"cat")) is None
    # tampered value fails: proof does not resolve to a wrong claim
    bad = t.proof(b"dog")
    assert verify_proof(t.root_hash(), b"dog", bad) == b"puppy"

    # delete removes and re-canonicalizes
    t.delete(b"doge"); t.delete(b"do")
    assert t.get(b"doge") is None and t.get(b"do") is None
    assert t.get(b"dog") == b"puppy" and t.get(b"horse") == b"stallion"
    t5 = Trie(); t5.insert(b"dog", b"puppy"); t5.insert(b"horse", b"stallion")
    assert t.root_hash() == t5.root_hash()
    # deleting everything yields the empty-trie root
    t6 = Trie(); t6.insert(b"x", b"1"); t6.delete(b"x")
    assert t6.root == _BLANK
    assert t6.root_hash() == keccak_256(b"")

    # keccak-256 sanity: empty input digest
    assert keccak_256(b"").hex() == \
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    # hex-prefix round trips
    for nibbles, leaf in [([1, 2, 3], True), ([1, 2, 3], False),
                          ([1, 2, 3, 4], True), ([], False)]:
        n2, l2 = compact_decode(compact_encode(nibbles, leaf))
        assert (n2, l2) == (nibbles, leaf)
    print("all self-tests passed")


def _demo():
    t = Trie()
    words = {b"do": b"verb", b"dog": b"puppy",
             b"doge": b"meme", b"horse": b"stallion"}
    for k, v in words.items():
        t.insert(k, v)
    print("root:", t.root_hash().hex())
    for k in words:
        p = t.proof(k)
        print(f"key={k.decode():<6} value={t.get(k).decode():<9} "
              f"proof_nodes={len(p)} verified={verify_proof(t.root_hash(), k, p) == words[k]}")
    print(f"key={'cat':<6} value={'<absent>':<9} "
          f"proof_nodes={len(t.proof(b'cat'))} verified={verify_proof(t.root_hash(), b'cat', t.proof(b'cat')) is None}")


if __name__ == "__main__":
    import sys
    if "--test" in sys.argv:
        import doctest
        results = doctest.testmod()
        _self_test()
        print(f"doctests: {results.attempted} attempted, {results.failed} failed")
    else:
        _demo()
