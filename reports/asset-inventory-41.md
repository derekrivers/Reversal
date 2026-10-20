# R41-C: installed resources and reproducible RGB565 extraction

The offline inventory identifies **304 installed resource/data/configuration files, 286 unique contents**, without reading saves or accessing a game process. [The sanitized manifest](../evidence/ui-assets-41-inventory.json) records each content hash, opaque source aliases, format evidence and unresolved use/rights. The private alias manifest maps those aliases to installation-relative paths. Deduplication retains every alias; it does not delete or modify originals.

This is the local installation observed on 20 October 2026, not a pristine retail asset set. The converted splash screen visibly says **May 2026 Data Update**. The installed English commentary hash also differs from the earlier community configuration recorded in `docs/PROVENANCE.md`. A matching executable does not authenticate these data, configuration or assets as original SI content.

| Category | Source files | Established metadata / limits |
| --- | ---: | --- |
| RGN backgrounds | 66 (58 unique) | All 800 × 600, 960,048 bytes: 48-byte header plus 960,000 bytes of little-endian RGB565. File-row-order conversion visually verified on two representatives. Runtime color keys and screen selection remain unknown. |
| WAV | 135 | RIFF WAVE, PCM signed 16-bit, mono/stereo at 22,050 or 44,100 Hz. Playback dispatch is unknown. |
| Game FNT | 7 | Opaque game font containers; sizes/hashes retained. File names suggest Arial and Trade Condensed variants, but glyph layout and metrics remain unparsed. No substitution is claimed equivalent. |
| TTF | 1 | sfnt TrueType signature; metrics and mappings unparsed. |
| PCT | 40 | Tactical container candidates under the data directory; extension does not establish a picture format. No image decoder applied. |
| EXE/DLL | 9 | Eight PE32 x86 containers parsed. Legacy `piccfg.exe` is explicitly unresolved by the PE parser. |
| DAT/LNG/CFG identities | 46 | Contents hashed only, not exported or decoded. Language, configuration and database identities remain separate from executable identity. |

Both main executable resource trees contain 13 leaves: three cursors, five icons, three group cursors and two group icons. Individual cursor/icon DIBs are 32 × 32 except one 16 × 16 icon; they use 1 or 4 bits per pixel and an AND transparency mask. The main executable has no RT_BITMAP leaf. The broader installation also includes editor resources, including bitmaps, strings, dialogs and raw data. These findings do not establish that all UI widgets are images, or that their drawing handlers have been recovered.

## Reproduction and integrity

The standard-library-only [inventory/converter](../scripts/inventory_asset_41.py) performs no launch, process inspection, screenshot capture or original-file mutation:

```text
python scripts/inventory_asset_41.py inventory INSTALL_ROOT --public-output results/asset-inventory.json --private-alias-output results/asset-aliases.json
python scripts/inventory_asset_41.py convert-rgn INSTALL_ROOT/Data/default_pic.rgn results/default-pic.png
python scripts/check_asset_41.py
python -O scripts/check_asset_41.py
```

Outputs are created exclusively: reruns require new output names. Keep the alias manifest and conversions under ignored `results/` or another private location. Public source aliases are derived from path hashes; content identities use full SHA-256. PE resource offsets are checked against the declared directory and file-backed section mapping; cyclic, deep, ambiguous or out-of-bounds trees are rejected. A container that cannot be parsed is marked unresolved rather than counted as a decoded PE resource tree.

The RGN converter admits explicit RGB565 masks (`f800`, `07e0`, `001f`), bounded dimensions and exact payload size. It expands channel bits by replication into RGB PNG, preserving file row order. Header words at `+0x0c` through `+0x18` have no established semantics and are not interpreted as dimensions or alpha. No palette or alpha channel is invented.

| Representative | Original SHA-256 | Converted PNG SHA-256 |
| --- | --- | --- |
| Default background, source alias `source-87acf9107905103d` | `d3f7a0d4bea834eea0e0206380d26f69421fbdf75601543a023a13cf91b1f392` | `bdd044f06bb957907f9e05e0607ba098231a5f619429a866d181c27c851b0174` |
| Splash background, source alias `source-8814d3a9c74a5673` | `93b7c1e2947ae014ab9946ca864d5dacdedce11b9c5790a67b6a458e58749241` | `4ea1116b21b0a7cbd36ef5b555fcfa1c63ac79791801d7d61c492ffa82571f69` |

Both converted images were opened and inspected: the default shows a goal/net photograph; the splash has upright legible update branding. This supports orientation and channel interpretation for these files. It is not a pixel comparison with game rendering, nor proof that opaque header words cannot affect runtime display.

The synthetic checker verifies exact six-color conversion, PNG chunk CRCs and decompressed row order, PE resource identity/dimensions, and eight malformed input rejections (RGN truncation/trailing data/masks/dimensions; PE cycle/directory bounds/unmapped payload/oversized payload). Checks remain active under optimized Python. Normal and optimized installed inventories were byte-identical.

Validation used Python 3.13.7 and bundled Node 24.19.0. The standalone checker passed normally and under `-O`; the full repository `npm run check` passed, and `git diff --check` found no whitespace errors. The new asset checker is standalone and does not modify the shared research runner. The [extraction receipt](../evidence/ui-assets-41-extraction-receipt.json) records inventory and conversion digests.

## Identity and preservation

The manifest independently reproduces pinned executable SHA-256 `0c78e7da6d0bcb4603fa179449bbe6d1b6b5e1c627a22c445d14d489bd9bff86` and GDI executable SHA-256 `0e50572c292bdfb9de8b3e087dd29043a13bcd0985ed198c9011e5a0f694388b`.

Selected current installation identities are:

| Input | SHA-256 |
| --- | --- |
| English language container | `391017caa3177e8343f5576f7dcebf5a716c7df58f60cc853dd39733f270b217` |
| English commentary configuration | `94cb8623c6f305335b9ce7761444766f9fe374ab53b075a935cebdf595e489ed` |
| Database index | `7bfa6c804eb849c5bd7bb1e8c10e45a6fc579a9b44bd79b5e7e21e385cde235b` |
| Staff database | `af693eb69669e59e012e445614e0e46397e32616bd0bed9a2942cf9233f5ecce` |
| Root game configuration | `0dc5364c9ee381a2dffa548603ef0bbcb6404529b6f3f3555e5d542211f81855` |

Original files remain in their installed location, read only by this work. Private task outputs are in the worker's ignored `results/`: `asset-aliases-v3.json`, normal/optimized inventories and two PNG conversions. This is **local preservation only** until the coordinator records a durable backup. No original asset, screenshot, save, executable byte or font glyph is included in Git. Accessibility does not establish redistribution permission: rights remain unknown and React use is local only.
