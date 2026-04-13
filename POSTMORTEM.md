# Postmortem: Linux `arm64` WeChat `4.1.1` Key Extraction

This repo exists because the obvious approaches were not enough on Linux
`arm64` WeChat `4.1.1`.

## What Finally Worked

The working extraction path was:

1. Treat the launcher binary `/opt/wechat/wechat` as the important process,
   not only `WeChatAppEx`.
2. Capture launcher-emitted payloads shaped like:

   ```text
   x'<64-hex-key><32-hex-salt>'
   ```

3. Validate the first 64 hex characters against real encrypted DB page-1 HMACs.
4. Cache validated per-DB keys and reuse them across WeChat PID changes.

In practice, the package now combines two paths:

- fast path: scan WeChat-owned and anonymous readable mappings for
  launcher-style `x'key+salt'` payloads
- fallback path: attach `gdb` to the launcher and capture the same payload at
  the proven raw-store write site

## What Did Not Work

These were explored and ruled out during validation:

- assuming the old x86/x86_64 `setCipherKey` recipes would transfer directly to
  Linux `arm64`
- late `gdb` attach after the login transition had already happened
- scanning only `WeChatAppEx` for the final key material
- treating the repeated 32-byte binary blob as the usable SQLCipher key
- parsing `key_info.db`, `key_info_data`, `login_configv2`, or MMKV metadata as
  if they directly contained the DB key
- watching SQLCipher pragma strings such as `kdf_iter`, `cipher_page_size`, or
  `sqlcipher_export('migrate')` and expecting them to reveal the active key
- opening copied verification targets directly through unstable
  `/proc/<pid>/root/...` paths during repeated login/logout cycles

The key point is that the useful artifact is not the old broad memory-scan
assumption of “find any 64-hex key.” It is the launcher-side transient
`x'key+salt'` payload, captured at the right time and then validated against the
actual DB files.

## Validation Outcome

The extraction path in this repo was validated on Ubuntu 24.04 `arm64` against
Linux WeChat `4.1.1`.

What was verified:

- the extractor found validated keys for the live encrypted DB set
- those keys successfully opened real databases such as `message_0.db` and
  `session.db`
- repeated fresh logout/login cycles continued to yield usable keys

The matching downstream daemon integration was also validated separately: the
captured keys were sufficient for the monitor to open the DBs and read message
rows in the real stack.

## Existing References

These references were useful, but none of them solved the exact Linux `arm64`
WeChat `4.1.1` path by themselves.

### `ylytdeng/wechat-decrypt`

Repo:

- <https://github.com/ylytdeng/wechat-decrypt>

What helped:

- the Linux scanner direction was broadly correct
- the `x'key+salt'` payload shape was the right family of artifact to chase
- page-1 HMAC validation against SQLCipher/WCDB DB files was the right way to
  distinguish real keys from noise

What did not hold as-is:

- the direct scanner still failed against the live `arm64` `4.1.1` session
  until the launcher-side timing and write-site capture were understood

### `ylytdeng/wechat-decrypt` PR #18

Pull request:

- <https://github.com/ylytdeng/wechat-decrypt/pull/18>

What helped:

- it confirmed that Linux support should focus on process-memory extraction and
  DB-backed validation instead of static file parsing alone

What did not hold as-is:

- it still reflects the older direct-memory-scan model and does not by itself
  account for the transient launcher-side capture problem we hit on `arm64`
  `4.1.1`

### `PigeonCoders/MimicWX-Linux`

Repo:

- <https://github.com/PigeonCoders/MimicWX-Linux>

What helped:

- the main strategic hint was correct: attach early and hook the real key
  application path instead of hoping a late broad memory scan will catch it

What did not transfer:

- the published offset/register recipe was for a different build and
  architecture, so it was not directly usable on Linux `arm64` `4.1.1`

### `linuxserver/docker-weixin`

Repo:

- <https://github.com/linuxserver/docker-weixin>

What helped:

- container runtime ideas
- browser/VNC-style access patterns for debugging headless WeChat

What it did not solve:

- it is not a key-extraction reference and did not help with the actual DB key
  recovery path

## Practical Lessons

- treat extraction as a validation problem, not only a search problem
- prioritize WeChat-version-specific runtime evidence over older offset recipes
- keep the fast path cheap, but keep a debugger fallback for transient launcher
  payloads
- when validating repeated login cycles, use copied DB probes rather than
  opening live DBs through unstable `/proc/<pid>/root` paths
- expect process ownership to be split between the launcher and `WeChatAppEx`
