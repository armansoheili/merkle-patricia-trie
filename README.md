# merkle-patricia-trie

An Ethereum-style **Merkle-Patricia trie** in pure Python — zero dependencies.

This is the data structure behind Ethereum's world state: every account
balance, contract storage slot, and transaction receipt is committed to a
trie like this one. This implementation follows the Ethereum Yellow Paper:

- **Leaf / extension / branch nodes** with hex-prefix (compact) key encoding
- **RLP** node serialization (minimal, self-contained codec)
- **Self-contained Keccak-256** sponge (no `hashlib` shortcut, no packages)
- `insert` / `get` / `delete` with canonical trie shape (insertion-order
  independent root hashes)
- **Inclusion & exclusion proofs** with stateless verification

Keys are arbitrary bytes; they are Keccak-256 hashed into nibble paths,
exactly like Ethereum state keys. Nodes smaller than 32 bytes are inlined,
larger ones are referenced by hash — so the root hash is a single 32-byte
commitment to the whole key/value set.

## Usage

```python
from mpt import Trie, verify_proof

t = Trie()
t.insert(b"do", b"verb")
t.insert(b"dog", b"puppy")
t.insert(b"doge", b"meme")
t.insert(b"horse", b"stallion")

print(t.root_hash().hex())   # 32-byte state commitment
print(t.get(b"dog"))         # b'puppy'

# Merkle proof that "dog" -> "puppy" is in the trie under this root
proof = t.proof(b"dog")
assert verify_proof(t.root_hash(), b"dog", proof) == b"puppy"

# Exclusion proof: "cat" is provably absent
assert verify_proof(t.root_hash(), b"cat", t.proof(b"cat")) is None

t.delete(b"doge")
```

## CLI

```bash
python mpt.py            # run the demo (root hash + proofs for do/dog/doge/horse)
python mpt.py --test     # doctests + self-tests (order-independence, overwrite,
                         # proof verify, delete re-canonicalization, keccak KAT)
```

## Notes

- Single file, stdlib only, works on Python 3.8+.
- Delete degenerates branches back into extension/leaf nodes so the root
  stays canonical (inserting the same key set always yields the same root,
  regardless of order or history).
- The empty trie has root `keccak256(b"")` =
  `c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`,
  matching the Ethereum convention.
