<!-- ©AngelaMos | 2026 -->
<!-- README.md -->

These files must never be flagged.

They are not random innocent code. Each one deliberately trips exactly one
indicator from `pymapper-fs-loader`, because a weighted-sum signature is only
honest if no single indicator can carry a file over the threshold on its own.

| File | Indicator it trips | Weight | Required verdict |
|---|---|---:|---|
| `simple_xor_helper.py` | `xor_decoder_lambda` | 40 | suspicious, never malicious |
| `crc_table.py` | `embedded_encrypted_blob` | 25 | clean |
| `chunked_cipher.py` | `hmac_keystream_block` | 20 | clean |
| `plugin_registry.py` | none | 0 | clean |

`simple_xor_helper.py` is the interesting one. 40 points clears half the
threshold of 60, so it lands in the suspicious band by design. That is the
correct answer: a bare XOR lambda is worth a second look and nothing more.
