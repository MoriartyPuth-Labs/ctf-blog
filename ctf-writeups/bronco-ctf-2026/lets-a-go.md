# LEts A go

> **Category:** Crypto / Reverse Engineering
>
> **Flag:** `bronco{n0t_r4nd0m_3nough}`

### Challenge

The challenge provides `challenge.py` and `output.txt`.

The script generates 50 random bytes as a key, then:

1. Creates a 100-character "random garbage" string of lowercase letters
2. Encrypts the garbage with `block_encrypt(key, garbage)` — printing the hex result
3. Scrambles the key (bit-reverses each byte)
4. Encrypts the flag with `block_encrypt(scramble(key), flag)` — printing the hex result

Output:

```
Random garbage:
96dbcaae807788b5e3abae8e91dc467bd6b5291094a33033c7f47fb66cccf6d41b2bc01426033a73f444fa44eb412e3ee249
The flag:
2d4f326d141f0c75e1ff445d23b39880581c09e0585645eab8
```

The critical weakness: `python/seeded` uses `time.time()` for seeding by default, so the PRNG is deterministic if you know the seed. But more importantly, we don't even need the seed — we know the "random garbage" is **all lowercase letters**, which is enough to recover the key.

### Solution

#### Step 1: Understand `block_encrypt`

The function builds an extended key stream from the initial key:

```python
def block_encrypt(key, string):
    keys = [key]
    while len(string) - sum(map(len, keys)) > 0:
        key_ext = []
        for element in keys[-1]:
            # Deterministic transform of the byte
            newkey = 0
            for i in range(4):
                sub = (element >> (2 * i)) & 3
                sub = (sub & 1) ^ (sub >> 1)
                newkey += sub << (7 - i)
            # But adds 4 random bits (from the same RNG)
            newkey += random.getrandbits(4)
            key_ext.append(newkey)
        keys.append(bytes(key_ext))
    # XOR plaintext with key stream
    return bytes(k ^ ord(c) for k, c in zip(flat_keys, string))
```

The initial key is 50 bytes. The garbage is 100 bytes (2×50), so the key stream is extended once.

#### Step 2: Recover the key via known-plaintext

At position `i` (0–49), the garbage byte is a lowercase letter (`a`–`z`). Try all 26 possibilities:

```python
key_candidates = []
for i in range(N):
    candidates = []
    for c in range(ord('a'), ord('z') + 1):
        k = garb_enc[i] ^ c
        candidates.append((k, chr(c)))
    key_candidates.append(candidates)
```

#### Step 3: Constrain with the extended key stream

At position `N + j` (50–99), the key stream byte is:

```
extended[j] = deterministic_part(key[j]) | random_4_bits
```

The top 4 bits (`0xF0`) depend only on `key[j]`. The bottom 4 bits are random but the plaintext is still lowercase. This gives us a consistency check: for each candidate `key[j]`, compute `deterministic_part(key[j])` and verify it matches the top 4 bits of the extended key byte at position `N+j`.

#### Step 4: Backtrack to find the consistent key

```python
deterministic = lambda x: sum(
    (((x >> (2 * i)) & 3) & 1) ^ (((x >> (2 * i)) & 3) >> 1) << (7 - i)
    for i in range(4))

def solve(idx, key):
    if idx == N:
        return key[:]
    for k, _ in key_candidates[idx]:
        # Verify against the extended garbage
        top4 = deterministic(k)
        for c2 in range(ord('a'), ord('z') + 1):
            ext_byte = garb_enc[N + idx] ^ c2
            if (ext_byte & 0xF0) == top4:
                key[idx] = k
                result = solve(idx + 1, key)
                if result:
                    return result
                key[idx] = 0
    return None
```

#### Step 5: Decrypt the flag

```python
def scramble(key):
    nums = []
    for k in key:
        num = 0
        for i in range(8):
            num |= ((k & (1 << i)) >> i) << (7 - i)
        nums.append(num)
    return bytes(nums)

scrambled = scramble(recovered_key)
flag = bytes(f ^ s for f, s in zip(flag_enc, scrambled))
# bronco{n0t_r4nd0m_3nough}
```

### Key Takeaway

The PRNG seed is irrelevant because we know the plaintext structure of the "random garbage" (all lowercase letters). A known-plaintext attack on the XOR stream cipher recovers the key, and the scrambled key stream directly decrypts the flag. The name says it all — it's **not random enough**.
