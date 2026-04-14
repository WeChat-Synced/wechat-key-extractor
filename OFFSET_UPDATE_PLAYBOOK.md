## Future Linux WeChat Offset Playbook

This is the procedure to update the Linux raw-key offset when Tencent moves the
binary layout in a future WeChat build.

The goal is not "guess a new offset." The goal is to recover and validate the
real SQLCipher/AES key path for the exact build under test, then record the new
base-relative offset only after it is proven.

### 1. Capture exact build evidence first

Before touching `WECHAT_RAW_STORE_OFFSET`, record:

- WeChat version string
- architecture (`arm64` / `x86_64`)
- container or host image used
- launcher path and `WeChatAppEx` path
- binary hashes (`sha256sum`)

Never reuse an old offset recipe across builds without this evidence.

### 2. Prefer the key-application path over blind memory scans

The fastest path is still:

1. attach early
2. catch the real key application flow
3. dump nearby memory
4. extract the `x'....'` or raw 64-hex payload
5. validate against real WCDB files

Treat the offset as a byproduct of the working capture, not as the primary
target.

### 3. Use the existing extractor in this order

For future versions, keep the search order:

1. cached validated keys
2. broad runtime memory scan
3. `gdb` capture around the raw-store address
4. candidate validation against live DB page HMACs

This keeps the common case cheap while preserving the debugger fallback for
builds that move the payload into a short-lived buffer.

Relevant moving pieces:

- `WECHAT_RAW_STORE_OFFSET`
- `XKEY_PAYLOAD_PATTERN`
- `RAW_KEY_PATTERN`
- `_capture_gdb_key_candidates()`
- `_validate_key_candidates()`
- `_verify_page_hmac()`

### 4. Make the offset hunt easier next time

Use this checklist when a version bump breaks extraction:

1. Confirm the real active data root and DB set first.
   If the running UI and the monitored volume are split, offset work is wasted.

2. Break on the real key application path, not on generic crypto code.
   A late wide memory scan produces too many false positives. The useful moment
   is when the raw SQLCipher key is assembled and handed to the DB layer.

3. Dump around the caller and around the candidate base immediately.
   Capture the surrounding instructions, registers, and nearby payload bytes in
   one pass so the next attempt is reproducible.

4. Validate candidates immediately with real DB salts and page HMACs.
   Do not keep candidates that cannot open `sqlite_master` on `message_0.db`,
   `contact.db`, and `session.db`.

5. Record both the absolute runtime address and the base-relative offset.
   The offset is useful later only if it is tied back to the exact binary hash.

6. Save one small proof artifact per successful build.
   Keep:
   - version
   - arch
   - binary hash
   - module base
   - raw-store address
   - relative offset
   - one validated DB path

### 5. Practical improvements worth implementing

To reduce future reverse-engineering time, prioritize these improvements:

1. Add a helper that records module base addresses and emits a versioned offset
   manifest keyed by binary hash.

2. Add a helper that captures a narrow memory window around the key-application
   site instead of depending on one hardcoded offset alone.

3. Add a small signature scan for the surrounding instruction pattern so the
   extractor can derive the raw-store address from the current binary, then fall
   back to the fixed offset only if that signature fails.

4. Keep validation strict.
   A "found a 64-hex string" result is not success. A candidate is only real if
   `_verify_page_hmac()` and `sqlite_master` reads succeed.

### 6. Update procedure after a successful new version

Once a new version is proven:

1. update `WECHAT_RAW_STORE_OFFSET`
2. update the README version note
3. append the new build evidence to the postmortem or changelog
4. keep the old build metadata instead of overwriting it blindly

The durable lesson is simple: future breakage should be handled as a
version-specific validation workflow, not a one-off offset guess.
