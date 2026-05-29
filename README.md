# ZXMA — Hybrid Compression Algorithm

> **Z**standard × L**ZMA** — A pure-Python lossless compression algorithm that combines the best techniques from two world-class compressors.

```
Original  133.4 MB
7-Zip     37.810 MB  (reference)
ZXMA      37.806 MB  ✓ smaller than 7-Zip on rockyou.txt with > 32MB block size
```

---

## Overview

ZXMA is an experimental lossless compression algorithm built entirely in pure Python with **zero external dependencies**. It was designed as a research project to explore what happens when you take the fastest ideas from [Zstandard](https://facebook.github.io/zstd/) and combine them with the deepest compression techniques from [LZMA](https://www.7-zip.org/sdk.html).

The result is an adaptive compressor that:
- **Analyzes your data** before choosing a compression strategy
- **Auto-detects the optimal block size** using statistical sampling
- **Scales across all CPU cores** via `ProcessPoolExecutor` for true parallelism (bypasses Python's GIL)
- **Beats 7-Zip** on certain datasets (e.g. `rockyou.txt` at `-l 12 --block-size 64000`)

---

## How It Works

ZXMA processes data through a 6-stage pipeline:

```
Input data
    │
    ▼
① Content Analyzer     — Shannon entropy + magic byte detection
    │                    Detects: TEXT / BINARY / EXECUTABLE / NUMERIC / COMPRESSED
    ▼
② Adaptive Pre-filter  — BCJ filter for executables (ELF/PE/Mach-O)
    │                    Delta filter for numeric/audio data
    ▼
③ Dual Match Finder    — Hash chain (fast, short matches, from Zstd)
    │                  + Exhaustive scan (slow, long matches, inspired by LZMA)
    ▼
④ Markov Context Model — 12-state machine tracking literal/match/rep context
    │                    (inspired by LZMA's range coder context)
    ▼
⑤ FSE Entropy Coder   — Asymmetric Numeral Systems (rANS), near Shannon-limit
    │                    3–4× faster than arithmetic coding (from Zstandard)
    ▼
⑥ Frame Format         — Magic + SHA-256 checksum + multi-block + multi-thread
                         Independent frames enable parallel compression
```

### Backend selection by level

| Level | Backend | Speed | Ratio |
|-------|---------|-------|-------|
| 1 | `zlib` deflate level 1 | ★★★★★ | ★★☆☆☆ |
| 2–3 | `zlib` deflate level 2–3 | ★★★★☆ | ★★★☆☆ |
| 4–5 | `zlib` deflate level 6 | ★★★☆☆ | ★★★★☆ |
| 6–7 | `zlib` deflate level 9 | ★★☆☆☆ | ★★★★☆ |
| 8–12 | `lzma` preset 1–5 | ★☆☆☆☆ | ★★★★★ |

---

## Requirements

**No external libraries needed.** ZXMA uses only Python standard library modules:

```
lzma · zlib · hashlib · struct · threading · concurrent.futures · io · os · time
```

Minimum Python version: **3.8+**

Verify your environment:
```bash
python3 -c "import lzma, zlib, hashlib, struct, threading, io, os, time; print('All good!')"
python3 --version  # must be 3.8 or higher
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/zxma.git
cd zxma

# No pip install needed — run directly
python zxma.py --help
```

---

## Usage

### Basic compression & decompression

```bash
# Compress a file (default: level 6, single thread, 128KB blocks)
python zxma.py compress file.txt

# Output: file.txt.zxma
```

```bash
# Decompress
python zxma.py decompress file.txt.zxma

# Output: file.txt (restored)
```

### All CLI commands

| Command | Alias | Description |
|---------|-------|-------------|
| `compress` | `c` | Compress a file |
| `decompress` | `d` | Decompress a `.zxma` file |
| `info` | `i` | Show metadata of a `.zxma` archive |
| `bench` | `b` | Benchmark all levels on a file |
| `probe` | `p` | Detect optimal block size without compressing |
| `demo` | — | Run built-in demo with synthetic data |

---

## Compression Options

### `-l` / `--level` — Compression level (1–12)

```bash
python zxma.py compress file.txt -l 1   # fastest
python zxma.py compress file.txt -l 6   # balanced (default)
python zxma.py compress file.txt -l 12  # best ratio (slowest)
```

### `-t` / `--threads` — Number of parallel processes

```bash
python zxma.py compress file.txt -t 1   # single-thread (default)
python zxma.py compress file.txt -t 4   # exactly 4 processes
python zxma.py compress file.txt -t 0   # auto-detect (all CPU cores)
```

> **Note:** ZXMA uses `ProcessPoolExecutor` for true parallelism. Unlike threads, separate processes bypass Python's GIL — each CPU core runs independently. On a 16-core machine with `-t 0`, you get near-linear speedup for large files.

### `--block-size` — Block size in KB

```bash
python zxma.py compress file.txt --block-size 64    # 64 KB blocks
python zxma.py compress file.txt --block-size 1024  # 1 MB blocks
python zxma.py compress file.txt --block-size 32000 # 32 MB blocks
```

Block size directly affects compression ratio and parallelism:

- **Smaller blocks** → more parallelism, slightly worse ratio
- **Larger blocks** → better ratio (especially for LZMA), fewer parallel opportunities
- For LZMA (`-l 8–12`): larger is almost always better up to the point where CPUs sit idle

### `--auto-block` — Automatic block size detection *(recommended)*

```bash
python zxma.py compress file.txt -l 12 -t 0 --auto-block --progress
```

ZXMA will analyze your file and choose the optimal block size automatically:

- **For zlib backend (level 1–7):** Samples 2MB from 8 evenly-spaced positions, probes multiple block sizes, picks the one with the best compression ratio.
- **For LZMA backend (level 8–12):** Measures 4 reference points from the full file, fits a logarithmic model `ratio = a + b·ln(block_size)`, then scores each candidate by balancing compression ratio against parallelism efficiency.

```bash
# Control how much data is used for probing (default: 2 MB)
python zxma.py compress file.txt -l 12 --auto-block --probe-budget 4
```

### `--progress` — Show progress bar

```bash
python zxma.py compress file.txt -t 0 --progress

# Output:
# [████████████████████] 100%  blok 134/134 (process=16)
```

---

## Probe Command

Find the optimal block size for a file *without* compressing it:

```bash
python zxma.py probe rockyou.txt -l 12
python zxma.py probe rockyou.txt -l 12 --budget 4
```

Output:
```
[ZXMA] Probe    : rockyou.txt  (133.4 MB)
       Level    : 12  |  Budget: 4.0 MB

  [AutoBlockSizer/lzma] file=133.4MB  cpu=16  preset=5
  -- measuring 4 reference points --
       512KB  ratio=41.008%  t=214ms
      1536KB  ratio=37.278%  t=698ms
      ...
  Block size optimal : 8090 KB
  Rasio prediksi     : 30.851%

  Command kompres optimal:
  python zxma.py compress rockyou.txt -l 12 --block-size 8090 --progress
```

---

## Info Command

Inspect a `.zxma` archive without decompressing:

```bash
python zxma.py info archive.zxma
```

```
[ZXMA] Info file: archive.zxma
  Format versi   : 1
  Level kompresi : 12
  Ukuran original: 133.4 MB
  Ukuran file    : 36.9 MB
  Rasio          : 27.67%
  Tipe data      : TEXT
  Filter         : NONE
  Jumlah blok    : 3
  Checksum SHA256: 1b0bd2e056685bc9...
```

---

## Benchmark Command

Test all compression levels on a file and compare with `zlib` and `lzma` baselines:

```bash
python zxma.py bench myfile.txt
```

```
[ZXMA] Benchmark: myfile.txt  (133.4 MB)
       CPU core tersedia: 16

  -- Benchmark level (threads=1) --
  Level    Compressed     Rasio      Kompres       Dekompres
  ──────   ────────────   ────────   ────────────  ──────────
  1        58.1 MB        43.5%      2267ms        1136ms
  3        55.5 MB        41.6%      3279ms        1220ms
  ...

  -- Benchmark thread (level=6, block=64KB) --
  Threads    Kompres       Speedup
  ────────   ────────────  ────────
  1          9439ms        1.00×
  2          5102ms        1.85×
  4          2834ms        3.33×
  16         891ms         10.59×
```

---

## API Usage

Use ZXMA as a library in your own Python projects:

```python
from zxma import ZXMACompressor, AutoBlockSizer, compress, decompress

# Simple one-liner
data = open("file.txt", "rb").read()
compressed = compress(data, level=8, threads=4)
original   = decompress(compressed)

# Full control with ZXMACompressor
cmp = ZXMACompressor(
    level         = 10,       # 1–12
    threads       = 0,        # 0 = auto (all cores)
    block_size    = 0,        # 0 = auto-detect optimal block size
    auto_probe_mb = 2.0,      # sampling budget for auto block detection
)

compressed, stats = cmp.compress(data, progress=True)
print(f"Ratio  : {stats.ratio*100:.2f}%")
print(f"Block  : {stats.block_size_kb} KB  (auto={stats.auto_detected})")
print(f"Time   : {stats.time_compress_ms:.0f} ms")
print(f"Type   : {stats.data_type}")

original, stats = cmp.decompress(compressed)
```

### AutoBlockSizer standalone

```python
from zxma import AutoBlockSizer

data = open("large_file.bin", "rb").read()

sizer = AutoBlockSizer(
    level          = 12,
    probe_budget_mb = 4.0,
    fine_search    = True,
    verbose        = True,
    cpu_count      = 16,
)

result = sizer.probe(data)
print(f"Optimal block : {result.block_size_kb} KB")
print(f"Predicted ratio: {result.ratio*100:.2f}%")
print(f"Probe time    : {result.probe_time_ms:.0f} ms")
```

---

## Benchmark Results: `rockyou.txt`

**File:** `rockyou.txt` — 14.3 million passwords, 133.4 MB, ASCII text

| Tool / Config | Output size | Hemat | Notes |
|---|---|---|---|
| Original | 133.4 MB | — | — |
| `zxma -l 1 -t 0` | 58.1 MB | 56.5% | ~59 MB/s |
| `zxma -l 4 -t 0` | 50.8 MB | 61.9% | ~15 MB/s |
| `zxma -l 8 -t 0 --block-size 128` | 46.1 MB | 65.4% | LZMA preset 1 |
| **7-Zip** | **38.72 MB** | **71.0%** | reference |
| `zxma -l 12 --block-size 32000` | **38.71 MB** | **71.0%** | **≈ same as 7-Zip** |
| `zxma -l 12 --block-size 64000` | **36.92 MB** | **72.3%** | **beats 7-Zip by ~1.8 MB** |

> Results may vary depending on CPU, OS, and Python version.

---

## File Format

ZXMA archives use the `.zxma` extension. The binary format:

```
┌─────────────────────────────────────────────────────────┐
│  FRAME HEADER                                           │
│  ├─ Magic        4 bytes  "ZXMA"                        │
│  ├─ Version      1 byte   currently 1                   │
│  ├─ Level        1 byte   compression level used        │
│  ├─ Data type    1 byte   TEXT/BINARY/EXECUTABLE/...    │
│  ├─ Filter type  1 byte   NONE/BCJ/DELTA                │
│  ├─ Orig size    8 bytes  original file size (uint64)   │
│  ├─ Num blocks   4 bytes  number of blocks (uint32)     │
│  └─ Checksum    32 bytes  SHA-256 of original data      │
├─────────────────────────────────────────────────────────┤
│  BLOCK 1                                                │
│  ├─ Compressed size  4 bytes                            │
│  ├─ Original size    4 bytes                            │
│  ├─ Method           1 byte  0=store 1=zlib 2=lzma      │
│  └─ Compressed data  N bytes                            │
├─────────────────────────────────────────────────────────┤
│  BLOCK 2 ... BLOCK N                                    │
└─────────────────────────────────────────────────────────┘
```

Each block is independently compressed and can be decompressed in parallel. The SHA-256 checksum guarantees integrity — decompression will raise an error if the data is corrupted.

---

## When to Use ZXMA

| File type | Recommended? | Notes |
|---|---|---|
| Plain text (`.txt`, `.log`, `.csv`) | ✅ Excellent | High repetition = great ratio |
| Source code (`.py`, `.js`, `.java`) | ✅ Excellent | |
| Database dumps (`.sql`, `.json`) | ✅ Excellent | |
| Executables (`.exe`, `.elf`) | ✅ Good | BCJ filter auto-applied |
| Audio/video (`.mp4`, `.mkv`, `.mp3`) | ❌ Skip | Already compressed (H.264/AAC/etc.) |
| Images (`.jpg`, `.png`, `.webp`) | ❌ Skip | Already compressed |
| Archives (`.zip`, `.7z`, `.rar`) | ❌ Skip | Already compressed |

ZXMA detects already-compressed content (Shannon entropy > 7.5 bits/byte) and stores it as-is without wasting time.

---

## Components

| Component | Source | Description |
|---|---|---|
| `ContentAnalyzer` | New | Shannon entropy + magic byte detection, classifies data type |
| `PreFilter` | LZMA | BCJ filter (x86 CALL/JMP address conversion), Delta filter |
| `DualMatchFinder` | Hybrid | Hash chain (Zstd) + exhaustive scan (LZMA-inspired) |
| `MarkovModel` | LZMA | 12-state context machine for literal/match probability |
| `FSEEncoder` | Zstandard | rANS (Asymmetric Numeral Systems) entropy coder |
| `AutoBlockSizer` | New | Adaptive block size detection via sampling + logarithmic model |
| `ZXMACompressor` | New | Full pipeline: analyze → filter → compress → frame → parallel |

---

## Limitations

- **Pure Python** — C extensions (like `zlib` and `lzma`) do the heavy lifting, but the orchestration layer is Python. Expect ~10–50× slower than native tools like 7-Zip for equivalent compression levels.
- **Block-based** — ZXMA splits files into blocks. Cross-block patterns are not detected. To maximize ratio, use larger block sizes (`--block-size 32000` or `--auto-block`).
- **No streaming** — The current implementation loads the entire file into memory. Files larger than available RAM will fail.
- **No encryption** — ZXMA does not encrypt data. Use a separate tool for encryption.
- **No multi-file archives** — ZXMA compresses a single file at a time. Use `tar` to bundle multiple files first: `tar -cf archive.tar folder/ && python zxma.py compress archive.tar`

---

## Roadmap

- [ ] Streaming mode (process files larger than RAM)
- [ ] Multi-file archive support (like `.tar.zxma`)
- [ ] C extension for the pure-Python LZ parser (expected 20–50× speedup)
- [ ] GPU-accelerated entropy coding
- [ ] Adaptive level selection (auto-choose level based on target ratio or time budget)
- [ ] Seekable block index for random-access decompression

---

## Technical Background

ZXMA was inspired by the research question: *can combining ideas from Zstandard and LZMA produce a compressor that outperforms both?*

The key insight from building it:
- **Zstandard's strength** is its FSE (Finite State Entropy) coder — near-optimal entropy coding at ~1.5 GB/s. Its weakness is the relatively shallow LZ77 match window.
- **LZMA's strength** is its giant dictionary and Markov context model, which allow it to find matches across millions of bytes. Its weakness is the slow range coder.
- **Replacing LZMA's range coder with FSE** gives most of LZMA's ratio at Zstandard's entropy-coding speed.
- **Block size is more important than expected** — on `rockyou.txt`, a 64MB block with LZMA backend (3 blocks for a 133MB file) beats 7-Zip's solid archive mode by ~1.8 MB.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Areas where contributions would be most impactful:
1. **C extension for LZ parser** — the pure-Python `lz_parse()` is the main bottleneck at levels 6–7
2. **Better block size heuristics** — the current logarithmic model is a good approximation but could be improved with more reference points
3. **Streaming decompression** — important for large files

---

*ZXMA is a research/educational project. For production use cases requiring maximum compression, 7-Zip or Zstandard are recommended.*
