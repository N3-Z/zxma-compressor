"""
ZXMA - Hybrid Compression Algorithm
=====================================
Referrence Algoritm
  Dari Zstandard : FSE (Finite State Entropy / ANS-lite) entropy coder,
                   frame format dengan magic + checksum, multi-block streaming
  Dari LZMA      : BCJ pre-filter untuk executable, Delta filter untuk data
                   numerik, Markov context model 12-state, match length encoding
"""

from __future__ import annotations

import hashlib
import io
import lzma
import os
import struct
import threading
import time
import zlib
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Callable

# ─── Konstanta format ────────────────────────────────────────────────────────

MAGIC            = b"ZXMA"          # 4-byte magic number
VERSION          = 1
BLOCK_SIZE       = 1 << 17          # 128 KB per block default
MAX_DICT_SIZE    = 1 << 20          # 1 MB dict window
MIN_MATCH_LEN    = 4
MAX_MATCH_LEN    = 256
HASH_BITS        = 16               # hash table size = 2^16
HASH_SIZE        = 1 << HASH_BITS
HASH_MASK        = HASH_SIZE - 1
MARKOV_STATES    = 12               # jumlah state Markov model
FSE_TABLE_LOG    = 10               # log2 dari FSE table size

# Thread mode
THREAD_AUTO      = 0                # deteksi otomatis dari CPU core
THREAD_SINGLE    = 1                # single-thread (default)


# ─── Tipe data ────────────────────────────────────────────────────────────────

class DataType(IntEnum):
    UNKNOWN    = 0
    TEXT       = 1
    BINARY     = 2
    EXECUTABLE = 3   # ELF / PE / Mach-O
    NUMERIC    = 4   # data numerik berulang (audio PCM, sensor data)
    COMPRESSED = 5   # sudah terkompresi / terenkripsi — skip

class FilterType(IntEnum):
    NONE  = 0
    BCJ   = 1   # Branch/Call/Jump (untuk executable)
    DELTA = 2   # Delta filter (untuk numerik)

@dataclass
class ZXMAHeader:
    version:     int
    data_type:   DataType
    filter_type: FilterType
    original_size: int
    num_blocks:  int
    checksum:    bytes = b""   # SHA-256 dari data original

@dataclass
class BlockHeader:
    compressed_size:   int
    original_size:     int
    compression_method: int    # 0=store, 1=zlib-backend, 2=lzma-backend

@dataclass
class CompressionStats:
    original_size:     int = 0
    compressed_size:   int = 0
    ratio:             float = 0.0
    time_compress_ms:  float = 0.0
    time_decompress_ms: float = 0.0
    data_type:         str = ""
    filter_used:       str = ""
    blocks:            int = 0
    threads_used:      int = 1
    block_size_kb:     int = 0        # block size yang digunakan
    auto_detected:     bool = False   # True jika block size dari AutoBlockSizer
    probe_time_ms:     float = 0.0    # waktu probing (jika auto)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. CONTENT ANALYZER
#    Hitung entropi Shannon, deteksi tipe data dari distribusi byte + magic bytes
# ═══════════════════════════════════════════════════════════════════════════════

class ContentAnalyzer:
    """
    Membaca sample data dan menghasilkan:
      - entropi Shannon (0.0 = seragam, 8.0 = random/terkompresi)
      - DataType yang disarankan
      - FilterType yang optimal
    """

    EXE_MAGIC = {
        b"\x7fELF":     "ELF",       # Linux executable
        b"MZ":          "PE",        # Windows PE
        b"\xcf\xfa\xed\xfe": "Mach-O64",
        b"\xce\xfa\xed\xfe": "Mach-O32",
    }

    def analyze(self, data: bytes) -> tuple[DataType, FilterType, float]:
        sample = data[:4096]
        entropy = self._shannon_entropy(sample)
        dtype, ftype = self._detect_type(data, entropy)
        return dtype, ftype, entropy

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        h = 0.0
        import math
        for f in freq:
            if f > 0:
                p = f / n
                h -= p * math.log2(p)
        return h

    def _detect_type(self, data: bytes, entropy: float) -> tuple[DataType, FilterType]:
        if entropy > 7.5:
            return DataType.COMPRESSED, FilterType.NONE

        head = data[:4]
        for magic, _ in self.EXE_MAGIC.items():
            if head[:len(magic)] == magic:
                return DataType.EXECUTABLE, FilterType.BCJ

        # Hitung distribusi karakter printable
        sample = data[:2048]
        printable = sum(1 for b in sample if 0x20 <= b <= 0x7E or b in (9, 10, 13))
        ratio_text = printable / max(len(sample), 1)
        if ratio_text > 0.85:
            return DataType.TEXT, FilterType.NONE

        # Deteksi data numerik: byte yang berulang dengan delta kecil
        if len(sample) >= 8:
            deltas = [abs(sample[i] - sample[i-1]) for i in range(1, min(256, len(sample)))]
            avg_delta = sum(deltas) / len(deltas)
            if avg_delta < 20:
                return DataType.NUMERIC, FilterType.DELTA

        return DataType.BINARY, FilterType.NONE


# ═══════════════════════════════════════════════════════════════════════════════
# 2. PRE-FILTER (BCJ & DELTA)
#    Transformasi data sebelum kompresi untuk meningkatkan kompressibilitas
# ═══════════════════════════════════════════════════════════════════════════════

class PreFilter:
    """
    BCJ (Branch/Call/Jump) filter: mengkonversi alamat relatif di instruksi
    x86 CALL/JMP menjadi absolut → pattern lebih berulang → LZ lebih efisien.

    Delta filter: simpan selisih antar byte, bukan nilai absolut.
    Sangat efektif untuk audio PCM, data sensor, array integer.
    """

    def apply(self, data: bytes, ftype: FilterType) -> bytes:
        if ftype == FilterType.BCJ:
            return self._bcj_encode(data)
        if ftype == FilterType.DELTA:
            return self._delta_encode(data)
        return data

    def reverse(self, data: bytes, ftype: FilterType) -> bytes:
        if ftype == FilterType.BCJ:
            return self._bcj_decode(data)
        if ftype == FilterType.DELTA:
            return self._delta_decode(data)
        return data

    def _bcj_encode(self, data: bytes) -> bytes:
        """
        Scan untuk opcode x86 CALL (0xE8) dan JMP (0xE9).
        Konversi operand relatif 32-bit ke nilai absolut.
        """
        buf = bytearray(data)
        i = 0
        while i < len(buf) - 4:
            if buf[i] in (0xE8, 0xE9):   # CALL / JMP near
                rel = struct.unpack_from("<i", buf, i + 1)[0]
                abs_addr = (rel + i + 5) & 0xFFFFFFFF
                struct.pack_into("<I", buf, i + 1, abs_addr)
                i += 5
            else:
                i += 1
        return bytes(buf)

    def _bcj_decode(self, data: bytes) -> bytes:
        buf = bytearray(data)
        i = 0
        while i < len(buf) - 4:
            if buf[i] in (0xE8, 0xE9):
                abs_addr = struct.unpack_from("<I", buf, i + 1)[0]
                rel = (abs_addr - i - 5) & 0xFFFFFFFF
                struct.pack_into("<i", buf, i + 1, struct.unpack("<i", struct.pack("<I", rel))[0])
                i += 5
            else:
                i += 1
        return bytes(buf)

    def _delta_encode(self, data: bytes) -> bytes:
        if not data:
            return data
        buf = bytearray(len(data))
        buf[0] = data[0]
        for i in range(1, len(data)):
            buf[i] = (data[i] - data[i-1]) & 0xFF
        return bytes(buf)

    def _delta_decode(self, data: bytes) -> bytes:
        if not data:
            return data
        buf = bytearray(len(data))
        buf[0] = data[0]
        for i in range(1, len(data)):
            buf[i] = (data[i] + buf[i-1]) & 0xFF
        return bytes(buf)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. DUAL MATCH FINDER
#    Hash chain (cepat, match pendek) + exhaustive scan (lambat, match panjang)
#    Terinspirasi oleh kombinasi Zstd HC dan LZMA binary tree
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Match:
    offset: int   # jarak ke belakang (1 = byte sebelumnya)
    length: int   # panjang match

class DualMatchFinder:
    """
    Dua strategi match finding dalam satu pass:

    1. Hash chain (dari Zstd):
       - Hash 4 byte pertama → lookup di hash table
       - Simpan chain of previous positions dengan hash sama
       - O(chain_depth) per posisi, cepat, match 4–48 byte

    2. Exhaustive scan (terinspirasi LZMA binary tree):
       - Untuk posisi yang sudah punya kandidat dari hash chain,
         coba extend sejauh mungkin
       - Juga scan lebih dalam di window untuk match lebih panjang
       - O(window * scan_depth), lambat tapi menemukan match optimal
    """

    def __init__(self, window: int = MAX_DICT_SIZE, chain_depth: int = 32,
                 deep_search: bool = False):
        self.window      = window
        self.chain_depth = chain_depth
        self.deep_search = deep_search    # aktifkan exhaustive scan
        self._htable: list[int] = [-1] * HASH_SIZE
        self._chain:  list[int] = []

    def find(self, data: bytes, pos: int) -> Match | None:
        if pos + MIN_MATCH_LEN > len(data):
            return None

        best = Match(0, 0)
        limit = max(0, pos - self.window)

        # ── Hash chain search ──
        h = self._hash4(data, pos)
        chain_pos = self._htable[h]
        depth = 0

        while chain_pos >= limit and depth < self.chain_depth:
            mlen = self._match_len(data, pos, chain_pos)
            if mlen > best.length:
                best = Match(pos - chain_pos, mlen)
                if mlen >= MAX_MATCH_LEN:
                    break
            if chain_pos < len(self._chain) and self._chain[chain_pos] != chain_pos:
                chain_pos = self._chain[chain_pos]
            else:
                break
            depth += 1

        # Update hash table & chain
        if len(self._chain) <= pos:
            self._chain.extend([-1] * (pos - len(self._chain) + 1))
        self._chain[pos] = self._htable[h]
        self._htable[h] = pos

        # ── Exhaustive deep search (opsional, seperti LZMA binary tree) ──
        if self.deep_search and best.length < 64:
            scan_start = max(limit, pos - 4096)   # scan 4 KB ke belakang
            step = max(1, (pos - scan_start) // 64)
            p = pos - MIN_MATCH_LEN
            count = 0
            while p >= scan_start and count < 64:
                mlen = self._match_len(data, pos, p)
                if mlen > best.length:
                    best = Match(pos - p, mlen)
                    if mlen >= MAX_MATCH_LEN:
                        break
                p -= step
                count += 1

        return best if best.length >= MIN_MATCH_LEN else None

    def _hash4(self, data: bytes, pos: int) -> int:
        v = (data[pos] | data[pos+1]<<8 | data[pos+2]<<16 | data[pos+3]<<24)
        return ((v * 0x9E3779B1) >> (32 - HASH_BITS)) & HASH_MASK

    def _match_len(self, data: bytes, pos: int, ref: int) -> int:
        end = min(len(data) - pos, MAX_MATCH_LEN)
        n = 0
        while n < end and data[pos + n] == data[ref + n]:
            n += 1
        return n


# ═══════════════════════════════════════════════════════════════════════════════
# 4. MARKOV CONTEXT MODEL (terinspirasi LZMA)
#    12-state machine yang melacak konteks encoding — literal vs match vs rep
# ═══════════════════════════════════════════════════════════════════════════════

class MarkovModel:
    """
    Simplified Markov state machine terinspirasi LZMA.
    State menentukan probabilitas token berikutnya:
      state < 7  → literal sebelumnya
      state >= 7 → match sebelumnya

    Digunakan untuk memilih tabel FSE yang tepat dan
    memberikan bias probabilitas pada encoder.
    """

    def __init__(self):
        self.state = 0
        # Transition tables: [current_state] → next_state
        self._lit_transitions  = [0,0,0,0,1,2,3, 4, 5, 6, 4, 5]
        self._match_transitions= [7,8,9,10,11,11,11,11,11,11,11,11]
        self._rep_transitions  = [8,9,10,11,11,11,11,11,11,11,11,11]

    def is_literal_state(self) -> bool:
        return self.state < 7

    def update_literal(self):
        self.state = self._lit_transitions[self.state]

    def update_match(self):
        self.state = self._match_transitions[self.state]

    def update_rep(self):
        self.state = self._rep_transitions[self.state]

    def reset(self):
        self.state = 0


# ═══════════════════════════════════════════════════════════════════════════════
# 5. LZ PARSER (menggunakan Dual Match Finder + Markov Model)
#    Menghasilkan sequence token: literal atau (offset, length) match
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class LZToken:
    is_match: bool
    value: int       # byte jika literal, offset jika match
    length: int = 0  # hanya untuk match
    offset: int = 0  # alias eksplisit untuk value saat is_match=True

    def __post_init__(self):
        if self.is_match:
            self.offset = self.value

def lz_parse(data: bytes, deep: bool = False) -> list[LZToken]:
    """
    Main LZ parsing loop.
    Lazy evaluation: sebelum emit match di posisi i, coba posisi i+1.
    Jika posisi i+1 menghasilkan match lebih panjang, emit literal di i,
    lalu match di i+1 (strategi "lazy matching" dari Zstd).
    """
    finder = DualMatchFinder(deep_search=deep)
    model  = MarkovModel()
    tokens: list[LZToken] = []
    pos    = 0
    n      = len(data)

    while pos < n:
        if pos + MIN_MATCH_LEN > n:
            # Sisa bytes jadi literal
            for b in data[pos:]:
                tokens.append(LZToken(False, b))
                model.update_literal()
            break

        match = finder.find(data, pos)

        # Lazy matching: cek apakah posisi berikutnya lebih baik
        if match and match.length < MAX_MATCH_LEN and pos + 1 + MIN_MATCH_LEN <= n:
            next_match = finder.find(data, pos + 1)
            if next_match and next_match.length > match.length + 1:
                # Emit literal, pakai match berikutnya
                tokens.append(LZToken(False, data[pos]))
                model.update_literal()
                pos += 1
                match = next_match

        if match:
            tokens.append(LZToken(True, match.offset, match.length))
            model.update_match()
            pos += match.length
        else:
            tokens.append(LZToken(False, data[pos]))
            model.update_literal()
            pos += 1

    return tokens


# ═══════════════════════════════════════════════════════════════════════════════
# 6. FSE-LITE ENTROPY CODER (terinspirasi Zstandard ANS)
#    Asymmetric Numeral Systems — mendekati Shannon limit tanpa divisi
#    Implementasi ini adalah versi disederhanakan menggunakan rANS
# ═══════════════════════════════════════════════════════════════════════════════

class FSEEncoder:
    """
    rANS (range Asymmetric Numeral Systems) encoder sederhana.

    State x dimulai dari L = 2^table_log.
    Untuk encode simbol s dengan frekuensi fs dan total M:
      x = (x // fs) * M + cumul[s] + (x % fs)
    State x dikompres ke output sebagai base-256 digits.
    """

    def __init__(self, freqs: list[int]):
        self.total = sum(freqs)
        self.freqs = freqs
        self.cumul = [0] * (len(freqs) + 1)
        for i, f in enumerate(freqs):
            self.cumul[i+1] = self.cumul[i] + f

    def encode(self, symbols: list[int]) -> bytes:
        if not symbols or self.total == 0:
            return b""
        M  = self.total
        L  = 1 << FSE_TABLE_LOG
        x  = L
        out: list[int] = []

        for s in reversed(symbols):
            fs = self.freqs[s]
            if fs == 0:
                # Simbol dengan frekuensi 0 — emit as escape byte
                out.append(0xFF)
                out.append(s & 0xFF)
                continue
            # Normalisasi: keluarkan byte jika x terlalu besar
            while x >= fs * (M << 8):
                out.append(x & 0xFF)
                x >>= 8
            # rANS step
            x = (x // fs) * M + self.cumul[s] + (x % fs)

        # Flush state x (4 byte big-endian)
        out.append((x >> 24) & 0xFF)
        out.append((x >> 16) & 0xFF)
        out.append((x >> 8)  & 0xFF)
        out.append(x & 0xFF)
        out.reverse()
        return bytes(out)

    def decode(self, data: bytes, n_symbols: int) -> list[int]:
        if not data or n_symbols == 0:
            return []
        M = self.total
        L = 1 << FSE_TABLE_LOG

        # Baca state awal (4 byte)
        if len(data) < 4:
            return []
        x   = (data[0]<<24)|(data[1]<<16)|(data[2]<<8)|data[3]
        pos = 4
        out = []
        escaping = False

        for _ in range(n_symbols):
            if escaping:
                if pos < len(data):
                    out.append(data[pos])
                    pos += 1
                escaping = False
                continue

            # rANS decode: cari simbol s di mana cumul[s] <= x%M < cumul[s+1]
            remainder = x % M
            s = 0
            # Binary search di cumulative table
            lo, hi = 0, len(self.cumul) - 2
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if self.cumul[mid] <= remainder:
                    lo = mid
                else:
                    hi = mid - 1
            s = lo

            if self.freqs[s] == 0:
                escaping = True
                continue

            out.append(s)
            fs = self.freqs[s]
            x  = fs * (x // M) + remainder - self.cumul[s]

            # Renormalisasi: baca byte baru
            while x < L and pos < len(data):
                if data[pos] == 0xFF and pos+1 < len(data):
                    # Escape sequence
                    out.append(data[pos+1])
                    pos += 2
                    break
                x = (x << 8) | data[pos]
                pos += 1

        return out


def build_fse(symbols: list[int], alphabet: int = 256) -> FSEEncoder:
    """Hitung frekuensi dan buat FSEEncoder."""
    freqs = [0] * alphabet
    for s in symbols:
        if 0 <= s < alphabet:
            freqs[s] += 1
    # Pastikan tidak ada simbol yang dikirim tapi frekuensi 0
    return FSEEncoder(freqs)


# ═══════════════════════════════════════════════════════════════════════════════
# 7. TOKEN SERIALIZER
#    Mengubah list[LZToken] menjadi byte stream dan sebaliknya
# ═══════════════════════════════════════════════════════════════════════════════

def serialize_tokens(tokens: list[LZToken]) -> bytes:
    """
    Format: setiap token dikode sebagai:
      Literal  : 0x00 <byte>
      Match    : 0x01 <offset:2B> <length:2B>   (length 2 byte, max 65535)
    """
    buf = io.BytesIO()
    for t in tokens:
        if t.is_match:
            buf.write(b"\x01")
            buf.write(struct.pack(">HH", min(t.value, 0xFFFF), min(t.length, 0xFFFF)))
        else:
            buf.write(b"\x00")
            buf.write(bytes([t.value & 0xFF]))
    return buf.getvalue()

def deserialize_tokens(data: bytes) -> list[LZToken]:
    tokens = []
    i = 0
    while i < len(data):
        tag = data[i]; i += 1
        if tag == 0x00 and i < len(data):
            tokens.append(LZToken(False, data[i])); i += 1
        elif tag == 0x01 and i + 3 < len(data):
            offset, length = struct.unpack_from(">HH", data, i)
            tokens.append(LZToken(True, offset, max(length, MIN_MATCH_LEN)))
            i += 4
    return tokens

def reconstruct(tokens: list[LZToken]) -> bytes:
    """Rekonstruksi data original dari token stream."""
    buf = bytearray()
    for t in tokens:
        if not t.is_match:
            buf.append(t.value & 0xFF)
        else:
            offset = t.value   # offset disimpan di value
            length = t.length
            if offset <= 0 or offset > len(buf):
                continue
            start = len(buf) - offset
            for i in range(length):
                idx = start + (i % offset)
                if 0 <= idx < len(buf):
                    buf.append(buf[idx])
                else:
                    break
    return bytes(buf)


# ═══════════════════════════════════════════════════════════════════════════════
# 8. BLOCK COMPRESSOR
#    Satu blok: pre-filter → LZ parse → serialize → pilih backend terbaik
#    Backend: zlib (cepat) atau lzma (rasio terbaik) tergantung level
# ═══════════════════════════════════════════════════════════════════════════════


# ─── Zlib wbits presets ────────────────────────────────────────────────────────
# wbits 15  = zlib wrapper  (header + adler32)
# wbits -15 = raw deflate   (no header, fastest for embedding)
# wbits 31  = gzip wrapper

def _zlib_compress(data: bytes, level: int) -> bytes:
    """zlib wrapper standar — cross-platform."""
    return zlib.compress(data, level)

def _zlib_decompress(data: bytes) -> bytes:
    return zlib.decompress(data)

def _try_all_and_pick(candidates: list[tuple[bytes, int]],
                      original: bytes) -> tuple[bytes, int]:
    """Pilih hasil terkecil. Jika semua lebih besar dari original -> store."""
    best_data, best_method = original, 0
    for c, method in candidates:
        if len(c) < len(best_data):
            best_data, best_method = c, method
    return best_data, best_method


def _worker_fn(args: tuple) -> tuple[int, bytes, int]:
    """Top-level picklable worker untuk ProcessPoolExecutor (Windows spawn)."""
    idx, blk, level, dtype_int, ftype_int = args
    dtype     = DataType(dtype_int)
    ftype     = FilterType(ftype_int)
    prefilter = PreFilter()
    c, method = compress_block(blk, level, dtype, ftype, prefilter)
    return idx, c, method


def compress_block(data: bytes, level: int, dtype: DataType,
                   ftype: FilterType, prefilter: PreFilter) -> tuple[bytes, int]:
    """
    Kompres satu blok.
      0 = store, 1 = zlib, 2 = lzma, 3 = lz+zlib (blok kecil saja)

      1    -> zlib L1
      2-3  -> zlib L2/L3
      4-5  -> zlib L6  (titik manis rasio/kecepatan)
      6-7  -> zlib L9  (no pure-Python LZ -- terlalu lambat file besar)
      8-12 -> lzma preset 1-5
    """
    if not data:
        return data, 0
    if dtype == DataType.COMPRESSED:
        return data, 0

    filtered = prefilter.apply(data, ftype)

    if level == 1:
        return _try_all_and_pick([(_zlib_compress(filtered, 1), 1)], data)
    if level <= 3:
        return _try_all_and_pick([(_zlib_compress(filtered, level), 1)], data)
    if level <= 5:
        return _try_all_and_pick([(_zlib_compress(filtered, 6), 1)], data)
    if level <= 7:
        return _try_all_and_pick([(_zlib_compress(filtered, 9), 1)], data)

    preset = min(level - 7, 5)
    try:
        c_lzma = lzma.compress(filtered, preset=preset)
    except Exception:
        c_lzma = filtered
    c_zlib = _zlib_compress(filtered, 9)
    return _try_all_and_pick([(c_lzma, 2), (c_zlib, 1)], data)


def decompress_block(data: bytes, method: int, original_size: int,
                     ftype: FilterType, prefilter: PreFilter) -> bytes:
    if method == 0:   result = data
    elif method == 1: result = _zlib_decompress(data)
    elif method == 2: result = lzma.decompress(data)
    elif method == 3:
        tokens = deserialize_tokens(_zlib_decompress(data))
        result = reconstruct(tokens)
    else:             result = data
    return prefilter.reverse(result, ftype)


# ═══════════════════════════════════════════════════════════════════════════════
# 9. AUTO BLOCK SIZER
#    Menentukan block size optimal secara otomatis dengan sampling adaptif
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ProbeResult:
    block_size_kb:  int
    block_size_bytes: int
    ratio:          float        # rasio kompresi (lebih kecil = lebih baik)
    sample_size_kb: int
    probe_time_ms:  float
    candidates:     list         # semua (kb, ratio) yang dievaluasi


class AutoBlockSizer:
    """
    Menentukan block size optimal secara otomatis.

    DUA strategi berbeda tergantung backend:

    ── zlib (level 1–7) ──────────────────────────────────────────────────
    zlib memiliki window size maksimum 32KB. Block > 256KB tidak meningkatkan
    rasio secara signifikan. Ada 'sweet spot' nyata yang bisa ditemukan dengan
    sampling → gunakan probe berbasis sample.

    ── LZMA (level 8–12) ─────────────────────────────────────────────────
    LZMA tidak memiliki batas window — makin besar block makin baik rasionya
    (kurva monoton turun, tidak ada sweet spot dari sample kecil).
    Sample kecil TIDAK BISA memprediksi performa block besar karena block
    besar tidak muncul dalam sample 2MB.

    Strategi LZMA:
      1. Quick measurement 3–4 titik dari full file (1 blok per titik, cepat)
      2. Fit model logaritmik: ratio ~ a + b·ln(block_kb)
      3. Cari block_kb yang memaksimalkan:
           score = (predicted_ratio) + penalty_parallelism
         di mana penalty_parallelism menghukum block yang terlalu besar
         sehingga CPU tidak terpakai semua
      4. Constraint: min block = 512KB, max block = file_size / min(4, cpu_count)
    """

    MIN_BLOCKS_ZLIB = 6    # minimum blok untuk statistik zlib valid
    MIN_BLOCKS_LZMA = 1    # cukup 1 blok untuk estimasi LZMA per titik

    def __init__(self, level: int = 6, probe_budget_mb: float = 2.0,
                 fine_search: bool = True, verbose: bool = False,
                 cpu_count: int = 1):
        self.level           = max(1, min(12, level))
        self.probe_budget_mb = probe_budget_mb
        self.fine_search     = fine_search
        self.verbose         = verbose
        self.cpu_count       = max(1, cpu_count)
        self._is_lzma        = (self.level >= 8)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _zlib_level(self) -> int:
        if self.level == 1:  return 1
        if self.level <= 3:  return self.level
        if self.level <= 5:  return 6
        return 9

    def _lzma_preset(self) -> int:
        return min(self.level - 7, 5)

    def _compress_one(self, data: bytes) -> int:
        """Kompres satu blok, return ukuran hasil (tidak lebih besar dari input)."""
        if self._is_lzma:
            try:
                c = lzma.compress(data, preset=self._lzma_preset())
            except Exception:
                c = zlib.compress(data, 9)
        else:
            c = zlib.compress(data, self._zlib_level())
        return min(len(c), len(data))

    def _sample_data(self, data: bytes, budget_bytes: int) -> bytes:
        n = len(data)
        if budget_bytes >= n:
            return data
        n_pos   = 8
        per_pos = max(budget_bytes // n_pos, 64 * 1024)
        return b"".join(data[int(n*i/n_pos) : int(n*i/n_pos) + per_pos]
                        for i in range(n_pos))

    # ── zlib strategy (level 1–7) ─────────────────────────────────────────────

    def _probe_zlib(self, data: bytes) -> ProbeResult:
        """
        Probe block size untuk zlib backend via sampling.
        zlib punya sweet spot nyata karena window 32KB — bisa diukur dari sample.
        """
        import math
        t0 = time.perf_counter()
        n  = len(data)
        budget = int(self.probe_budget_mb * 1024 * 1024)
        sample = self._sample_data(data, max(budget, 512*1024))

        candidates_kb = [8, 16, 32, 48, 64, 96, 128, 192, 256, 384, 512,
                         768, 1024, 2048, 4096]

        if self.verbose:
            print(f"  [AutoBlockSizer/zlib] sample={len(sample)//1024}KB  "
                  f"level={self.level}")
            print(f"  -- probing --")

        results = []
        for kb in candidates_kb:
            bs     = kb * 1024
            blocks = [sample[i:i+bs] for i in range(0, len(sample), bs)]
            if len(blocks) < self.MIN_BLOCKS_ZLIB:
                continue
            total  = sum(self._compress_one(b) for b in blocks)
            ratio  = total / len(sample)
            results.append((kb, ratio))
            if self.verbose:
                bar = "▓" * max(1, int((1-ratio)*60))
                print(f"    {kb:5d}KB  ratio={ratio*100:.4f}%  {bar}")

        if not results:
            return self._fallback(n, time.perf_counter()-t0)

        # Fine search di sekitar terbaik
        if self.fine_search:
            best_kb = min(results, key=lambda x: x[1])[0]
            lo = max(8, best_kb // 2)
            hi = min(4096, best_kb * 2)
            extra_set = set()
            kb = lo
            while kb <= hi:
                extra_set.add(kb)
                kb = max(kb+4, int(kb*1.2))
            extra_set -= {k for k,_ in results}

            if self.verbose and extra_set:
                print(f"  -- fine search --")
            for kb in sorted(extra_set):
                bs     = kb * 1024
                blocks = [sample[i:i+bs] for i in range(0, len(sample), bs)]
                if len(blocks) < self.MIN_BLOCKS_ZLIB:
                    continue
                total = sum(self._compress_one(b) for b in blocks)
                ratio = total / len(sample)
                results.append((kb, ratio))
                if self.verbose:
                    print(f"    {kb:5d}KB  ratio={ratio*100:.4f}%  (fine)")

        results_sorted = sorted(results, key=lambda x: x[1])
        best_kb, best_ratio = results_sorted[0]
        elapsed = (time.perf_counter()-t0)*1000

        if self.verbose:
            print(f"  [AutoBlockSizer/zlib] optimal={best_kb}KB "
                  f"ratio={best_ratio*100:.4f}% time={elapsed:.0f}ms")

        return ProbeResult(best_kb, best_kb*1024, best_ratio,
                           len(sample)//1024, elapsed, results_sorted)

    # ── LZMA strategy (level 8–12) ────────────────────────────────────────────

    def _probe_lzma(self, data: bytes) -> ProbeResult:
        """
        Probe block size untuk LZMA backend.

        LZMA tidak punya sweet spot dari sample kecil — kurva ratio vs block_size
        turun monoton (makin besar block makin kecil output). Karena itu kita:

        1. Ukur ratio untuk 4 titik dari FULL FILE (1 blok per titik, cepat)
        2. Fit model: ratio ~ a + b·ln(block_kb)
        3. Cari block_size yang meminimalkan combined score:
              score = ratio_predicted + lambda * parallelism_penalty
           di mana parallelism_penalty menghukum block yang membuat
           beberapa CPU menganggur
        4. Verifikasi dengan mengukur block_size yang dipilih secara aktual
        """
        import math
        t0  = time.perf_counter()
        n   = len(data)
        cpu = self.cpu_count

        # Titik pengukuran: spread logaritmik dari 512KB sampai file_size/8
        # Cap di file_size/8 agar tidak mengukur blok yang lebih besar dari 12.5% file
        max_probe_kb  = max(512, n // (8 * 1024))
        max_probe_kb  = min(max_probe_kb, 32 * 1024)   # cap 32MB per titik probe
        probe_points  = []
        kb = 512
        while kb <= max_probe_kb and len(probe_points) < 4:
            probe_points.append(kb)
            kb = max(int(kb * 3), kb + 1024)
        probe_points = sorted(set(probe_points))

        if self.verbose:
            print(f"  [AutoBlockSizer/lzma] file={n/1024/1024:.1f}MB  "
                  f"cpu={cpu}  preset={self._lzma_preset()}")
            print(f"  -- measuring {len(probe_points)} reference points --")

        measurements = []
        for kb in probe_points:
            blk   = data[:kb*1024]     # ambil dari awal — cukup representatif
            t_blk = time.perf_counter()
            sz    = self._compress_one(blk)
            ratio = sz / len(blk)
            measurements.append((kb, ratio))
            if self.verbose:
                ms = (time.perf_counter()-t_blk)*1000
                print(f"    {kb:6d}KB  ratio={ratio*100:.3f}%  t={ms:.0f}ms")

        if len(measurements) < 2:
            return self._fallback(n, time.perf_counter()-t0)

        # Fit model logaritmik: ratio = a + b*ln(kb)
        xs = [math.log(kb) for kb, _ in measurements]
        ys = [r for _, r in measurements]
        mx = sum(xs)/len(xs); my = sum(ys)/len(ys)
        denom = sum((x-mx)**2 for x in xs)
        if denom == 0:
            b_fit = 0.0
        else:
            b_fit = sum((xs[i]-mx)*(ys[i]-my) for i in range(len(xs))) / denom
        a_fit = my - b_fit * mx

        if self.verbose:
            print(f"  -- model: ratio = {a_fit:.5f} + {b_fit:.6f}·ln(kb) --")
            print(f"  -- scoring candidates --")

        # Score setiap kandidat block size
        # Kandidat: dari 512KB sampai file_size/cpu (maks 1 blok per CPU)
        max_block_kb = max(512, n // (max(1, cpu) * 1024))
        max_block_kb = min(max_block_kb, 128 * 1024)  # hard cap 128MB per blok
        scored = []
        kb = 512
        while kb <= max_block_kb:
            pred_ratio = a_fit + b_fit * math.log(kb)
            pred_ratio = max(0.1, min(1.0, pred_ratio))

            n_blocks      = max(1, -(-n // (kb*1024)))
            parallel_eff  = min(n_blocks, cpu) / cpu
            parallelism_penalty = (1 - parallel_eff) * 0.05

            score = pred_ratio + parallelism_penalty
            scored.append((kb, pred_ratio, parallelism_penalty, score, n_blocks))

            if self.verbose:
                print(f"    {kb:6d}KB  pred={pred_ratio*100:.2f}%  "
                      f"par={parallel_eff*100:.0f}%  score={score*100:.3f}%  "
                      f"nblk={n_blocks}")

            kb = max(int(kb * 1.4), kb + 256)

        if not scored:
            return self._fallback(n, time.perf_counter()-t0)

        # Pilih block size dengan score terendah
        scored.sort(key=lambda x: x[3])
        best_kb = scored[0][0]

        # Verifikasi aktual — hanya kalau block tidak terlalu besar (< 16MB)
        if best_kb <= 16 * 1024:
            blk_verify   = data[:best_kb*1024]
            actual_sz    = self._compress_one(blk_verify)
            actual_ratio = actual_sz / len(blk_verify)
        else:
            # Estimasi dari model saja untuk blok sangat besar
            actual_ratio = scored[0][1]

        if self.verbose:
            print(f"  [AutoBlockSizer/lzma] optimal={best_kb}KB "
                  f"actual_ratio={actual_ratio*100:.3f}% "
                  f"time={(time.perf_counter()-t0)*1000:.0f}ms")

        # Buat candidate list untuk output
        candidates_out = [(kb, a_fit + b_fit*math.log(kb)) for kb, *_ in scored]
        candidates_out = sorted(candidates_out, key=lambda x: x[1])

        elapsed = (time.perf_counter()-t0)*1000
        return ProbeResult(best_kb, best_kb*1024, actual_ratio,
                           0, elapsed, candidates_out)

    # ── Fallback & main entry ─────────────────────────────────────────────────

    def _fallback(self, file_size: int, elapsed_s: float) -> ProbeResult:
        kb = max(128, min(1024, file_size // (1024 * 16)))
        return ProbeResult(kb, kb*1024, 1.0, 0, elapsed_s*1000, [(kb, 1.0)])

    def probe(self, data: bytes) -> ProbeResult:
        """Entry point utama. Memilih strategi zlib atau lzma secara otomatis."""
        if self._is_lzma:
            return self._probe_lzma(data)
        else:
            return self._probe_zlib(data)

    def probe_file(self, path: str) -> ProbeResult:
        data = open(path, "rb").read()
        return self.probe(data)



# ═══════════════════════════════════════════════════════════════════════════════
# 10. ZXMA COMPRESSOR (public API)
#     Frame format: MAGIC(4) VERSION(1) FLAGS(1) HEADER(var) BLOCKS...
# ═══════════════════════════════════════════════════════════════════════════════

class ZXMACompressor:
    """
    API utama ZXMA.

    level      : 1–3  = fast (zlib backend)
                 4–7  = balanced (zlib-9)
                 8–12 = ultra (LZMA backend)

    threads    : 0/auto = semua CPU core, 1 = single-thread, N = tepat N proses

    block_size : ukuran blok dalam byte, atau 0 / 'auto' untuk deteksi otomatis
                 0 → AutoBlockSizer menentukan block size optimal via sampling

    auto_probe_mb : budget sampling untuk AutoBlockSizer (default 2 MB).
                    Lebih besar = lebih akurat, lebih lambat.
    """

    AUTO_BLOCK = 0    # sentinel untuk auto block size

    def __init__(self, level: int = 6, block_size: int = BLOCK_SIZE,
                 threads: int = 1, auto_probe_mb: float = 2.0):
        self.level          = max(1, min(12, level))
        self._block_size_raw = block_size       # simpan nilai asli (mungkin 0 = auto)
        self.block_size     = max(4096, block_size) if block_size > 0 else BLOCK_SIZE
        self.threads        = self._resolve_threads(threads)
        self.auto_probe_mb  = auto_probe_mb
        self._analyzer      = ContentAnalyzer()
        self._prefilter     = PreFilter()
        self._last_probe: ProbeResult | None = None   # simpan hasil probe terakhir

    @staticmethod
    def _resolve_threads(t: int) -> int:
        """
        Resolusi jumlah thread:
          0 atau negatif → auto (cpu_count)
          1              → single-thread
          N > cpu_count  → clamp ke cpu_count dengan warning
        """
        cpu = os.cpu_count() or 1
        if t <= 0:
            return cpu          # auto
        if t > cpu:
            return cpu          # clamp
        return t

    @staticmethod
    def cpu_count() -> int:
        return os.cpu_count() or 1

    def compress(self, data: bytes,
                 progress: bool = False) -> tuple[bytes, CompressionStats]:
        t0 = time.perf_counter()

        dtype, ftype, entropy = self._analyzer.analyze(data)
        checksum = hashlib.sha256(data).digest()

        # ── Auto block size detection ────────────────────────────
        effective_block = self.block_size
        probe_result    = None

        if self._block_size_raw == self.AUTO_BLOCK and len(data) >= 256 * 1024:
            if progress:
                print(f"  [AutoBlockSizer] sampling file untuk block size optimal...",
                      flush=True)
            sizer       = AutoBlockSizer(
                level          = self.level,
                probe_budget_mb = self.auto_probe_mb,
                fine_search    = True,
                verbose        = False,
                cpu_count      = self.threads,
            )
            probe_result    = sizer.probe(data)
            effective_block = probe_result.block_size_bytes
            self._last_probe = probe_result
            if progress:
                print(f"  [AutoBlockSizer] optimal={probe_result.block_size_kb}KB "
                      f"(probe={probe_result.probe_time_ms:.0f}ms, "
                      f"sample={probe_result.sample_size_kb}KB)", flush=True)

        # Bagi data menjadi blok-blok
        blocks = [data[i : i + effective_block]
                  for i in range(0, max(len(data), 1), effective_block)]
        n = len(blocks)


        compressed_blocks: list[tuple[bytes, int]] = [None] * n  # type: ignore

        # ── Progress tracking ───────────────────────────────────
        done_count = 0
        done_lock  = threading.Lock()

        def _report():
            nonlocal done_count
            with done_lock:
                done_count += 1
                if progress:
                    pct = done_count * 100 // n
                    bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                    print(f"\r  [{bar}] {pct:3d}%  blok {done_count}/{n} "
                          f"({'process' if self.threads > 1 else 'thread'}={self.threads})",
                          end="", flush=True)

        # ── Eksekusi ────────────────────────────────────────────
        # CPU-bound task → ProcessPoolExecutor (bypass GIL, true parallelism)
        # Single-thread → langsung di main process (tidak ada spawn overhead)
        if self.threads == 1:
            for i, blk in enumerate(blocks):
                c, method = compress_block(
                    blk, self.level, dtype, ftype, self._prefilter)
                compressed_blocks[i] = (c, method)
                _report()
        else:
            # Bagi blok menjadi chunk untuk mengurangi IPC overhead
            # chunksize optimal: cukup besar agar tidak terlalu banyak round-trip
            chunksize = max(1, n // (self.threads * 4))
            args_list = [
                (i, blk, self.level, int(dtype), int(ftype))
                for i, blk in enumerate(blocks)
            ]
            with ProcessPoolExecutor(max_workers=self.threads) as pool:
                futures = {
                    pool.submit(_worker_fn, args): args[0]
                    for args in args_list
                }
                for fut in as_completed(futures):
                    idx, c, method = fut.result()
                    compressed_blocks[idx] = (c, method)
                    _report()


        if progress:
            print()  # newline setelah progress bar

        # ── Serialisasi frame ───────────────────────────────────
        out = io.BytesIO()
        out.write(MAGIC)
        out.write(bytes([VERSION, self.level]))
        out.write(struct.pack(">BBQ I", int(dtype), int(ftype), len(data), n))
        out.write(checksum)

        for i, (c_data, method) in enumerate(compressed_blocks):
            blk_orig = len(blocks[i])
            out.write(struct.pack(">I I B", len(c_data), blk_orig, method))
            out.write(c_data)

        result  = out.getvalue()
        elapsed = (time.perf_counter() - t0) * 1000

        stats = CompressionStats(
            original_size    = len(data),
            compressed_size  = len(result),
            ratio            = len(result) / max(len(data), 1),
            time_compress_ms = elapsed,
            data_type        = dtype.name,
            filter_used      = ftype.name,
            blocks           = n,
            threads_used     = self.threads,
            block_size_kb    = effective_block // 1024,
            auto_detected    = (self._block_size_raw == self.AUTO_BLOCK),
            probe_time_ms    = probe_result.probe_time_ms if probe_result else 0.0,
        )
        return result, stats

    def decompress(self, data: bytes) -> tuple[bytes, CompressionStats]:
        t0 = time.perf_counter()
        buf = io.BytesIO(data)

        magic = buf.read(4)
        if magic != MAGIC:
            raise ValueError(f"Invalid ZXMA magic: {magic!r}")

        version, level = buf.read(1)[0], buf.read(1)[0]
        dtype_int, ftype_int, orig_size, n_blocks = struct.unpack(">BBQ I", buf.read(14))
        checksum = buf.read(32)
        dtype  = DataType(dtype_int)
        ftype  = FilterType(ftype_int)

        out = bytearray()
        for _ in range(n_blocks):
            c_size, o_size, method = struct.unpack(">I I B", buf.read(9))
            c_data  = buf.read(c_size)
            blk_out = decompress_block(c_data, method, o_size, ftype, self._prefilter)
            out.extend(blk_out)

        result = bytes(out[:orig_size])

        # Verifikasi checksum
        actual = hashlib.sha256(result).digest()
        if actual != checksum:
            raise ValueError("Checksum mismatch — data korup!")

        elapsed = (time.perf_counter() - t0) * 1000
        stats = CompressionStats(
            original_size      = orig_size,
            compressed_size    = len(data),
            ratio              = len(data) / max(orig_size, 1),
            time_decompress_ms = elapsed,
            data_type          = dtype.name,
            filter_used        = ftype.name,
            blocks             = n_blocks,
        )
        return result, stats


# ─── Convenience functions ────────────────────────────────────────────────────

def compress(data: bytes, level: int = 6, threads: int = 1,
             progress: bool = False) -> bytes:
    c = ZXMACompressor(level=level, threads=threads)
    compressed, _ = c.compress(data, progress=progress)
    return compressed

def decompress(data: bytes) -> bytes:
    c = ZXMACompressor()
    result, _ = c.decompress(data)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# 10. BENCHMARK & DEMO
# ═══════════════════════════════════════════════════════════════════════════════

def _hr(n: int) -> str:
    """Human-readable byte size."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def run_demo():
    print("=" * 62)
    print("  ZXMA Hybrid Compression — Demo & Benchmark")
    print("  Zstandard techniques × LZMA techniques")
    print("=" * 62)

    test_cases = {
        "Teks bahasa Indonesia (repetitif)": (
            ("Algoritma kompresi adalah metode untuk mereduksi ukuran data "
             "dengan memanfaatkan pola berulang dan redundansi statistik. "
             "Zstandard menggunakan FSE entropy coding yang sangat cepat, "
             "sementara LZMA menggunakan range coder dengan Markov model "
             "yang menghasilkan rasio kompresi lebih tinggi. "
             "ZXMA menggabungkan keduanya untuk efisiensi optimal. ") * 80
        ).encode(),

        "Data numerik / delta (simulasi sensor)": bytes(
            [(i * 3 + (i // 256) * 7 + 42) % 256 for i in range(32_768)]
        ),

        "Binary terstruktur (berulang)": bytes(
            [i % 64 for i in range(16_384)] * 2
        ),

        "JSON config (semi-terstruktur)": (
            '{"id": %d, "name": "sensor_%d", "value": %.3f, '
            '"unit": "celsius", "active": true, "tags": ["iot", "v2"]}\n'
        ).__mod__  # trick untuk generate tanpa f-string di definisi
        and b'',   # placeholder — akan di-generate di loop
    }

    # Generate JSON test case secara dinamis
    import math
    json_data = b""
    for i in range(500):
        val = 20.0 + 5.0 * math.sin(i * 0.1)
        line = (f'{{"id": {i}, "name": "sensor_{i % 20}", "value": {val:.3f}, '
                f'"unit": "celsius", "active": true, "tags": ["iot", "v2"]}}\n')
        json_data += line.encode()
    test_cases["JSON config (semi-terstruktur)"] = json_data

    levels_to_test = [3, 6, 10]

    for name, data in test_cases.items():
        if not data:
            continue
        print(f"\n{'─'*62}")
        print(f"  Dataset : {name}")
        print(f"  Ukuran  : {_hr(len(data))}")
        print(f"  {'Level':<8} {'Compressed':<14} {'Ratio':<10} "
              f"{'Compress':<14} {'Decompress':<12} {'Type'}")
        print(f"  {'─'*6:<8} {'─'*12:<14} {'─'*8:<10} "
              f"{'─'*12:<14} {'─'*10:<12} {'─'*10}")

        for lvl in levels_to_test:
            cmp = ZXMACompressor(level=lvl)
            compressed, s1 = cmp.compress(data)
            _, s2 = cmp.decompress(compressed)

            # Verifikasi integritas
            recovered, _ = cmp.decompress(compressed)
            ok = "✓" if recovered == data else "✗ GAGAL"

            print(f"  {lvl:<8} {_hr(len(compressed)):<14} "
                  f"{s1.ratio*100:.1f}%{'':<6} "
                  f"{s1.time_compress_ms:.1f}ms{'':<8} "
                  f"{s2.time_decompress_ms:.1f}ms{'':<6} "
                  f"{s1.data_type} {ok}")

    # Perbandingan dengan zlib dan lzma standar
    print(f"\n{'─'*62}")
    print("  Perbandingan rasio: ZXMA vs zlib vs lzma (pada data teks)")
    data = test_cases["Teks bahasa Indonesia (repetitif)"]
    print(f"  Original : {_hr(len(data))}")

    zlib_c  = zlib.compress(data, 9)
    lzma_c  = lzma.compress(data, preset=9)
    zxma_c  = compress(data, level=10)

    for label, c in [("zlib (level 9)", zlib_c),
                     ("lzma (preset 9)", lzma_c),
                     ("ZXMA (level 10)", zxma_c)]:
        ratio = len(c) / len(data) * 100
        print(f"  {label:<20} → {_hr(len(c)):<12} ({ratio:.1f}%)")

    print(f"\n{'─'*62}")
    print("  Uji integritas round-trip pada semua test case...")
    all_ok = True
    for name, data in test_cases.items():
        if not data:
            continue
        for lvl in [1, 6, 12]:
            c = ZXMACompressor(level=lvl)
            try:
                compressed, _ = c.compress(data)
                recovered, _  = c.decompress(compressed)
                assert recovered == data, "mismatch!"
            except Exception as e:
                print(f"  GAGAL [{name}, level={lvl}]: {e}")
                all_ok = False
    if all_ok:
        print("  Semua round-trip berhasil ✓")

    print("\n" + "=" * 62)
    print("  Demo selesai.")
    print("=" * 62)


def run_cli():
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="zxma",
        description="ZXMA — Hybrid Compression (Zstandard × LZMA)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Contoh pemakaian:
  python3 zxma.py compress foto.jpg
  python3 zxma.py compress laporan.txt -l 10 -o hasil.zxma
  python3 zxma.py decompress hasil.zxma -o laporan_restored.txt
  python3 zxma.py info arsip.zxma
  python3 zxma.py bench laporan.txt
  python3 zxma.py demo
        """
    )
    sub = parser.add_subparsers(dest="cmd", metavar="PERINTAH")

    # ── compress ──────────────────────────────────────────────
    p_c = sub.add_parser("compress", aliases=["c"], help="Kompres sebuah file")
    p_c.add_argument("input",  help="File yang akan dikompres")
    p_c.add_argument("-o", "--output", default=None,
                     help="File output (default: <input>.zxma)")
    p_c.add_argument("-l", "--level", type=int, default=6, metavar="1-12",
                     help="Level kompresi 1=cepat … 12=maksimal (default: 6)")
    p_c.add_argument("-t", "--threads", type=int, default=1, metavar="N",
                     help=(
                         "Jumlah worker thread (default: 1)\n"
                         "  0 atau 'auto' = deteksi otomatis (semua CPU core)\n"
                         "  1             = single-thread (deterministik)\n"
                         f"  N             = tepat N thread (CPU tersedia: {os.cpu_count() or 1})"
                     ))
    p_c.add_argument("--block-size", type=int, default=BLOCK_SIZE // 1024,
                     metavar="KB",
                     help=f"Ukuran blok dalam KB (default: {BLOCK_SIZE//1024} KB). "
                          "Blok lebih kecil = lebih efektif multi-thread.")
    p_c.add_argument("--auto-block", action="store_true",
                     help="Deteksi otomatis block size optimal via sampling "
                          "(mengabaikan --block-size). Direkomendasikan untuk file besar.")
    p_c.add_argument("--probe-budget", type=float, default=2.0, metavar="MB",
                     help="Budget sampling untuk auto block size detection (default: 2 MB). "
                          "Lebih besar = lebih akurat tapi lebih lambat.")
    p_c.add_argument("--progress", action="store_true",
                     help="Tampilkan progress bar saat kompresi")


    # ── decompress ────────────────────────────────────────────
    p_d = sub.add_parser("decompress", aliases=["d"], help="Dekompres file .zxma")
    p_d.add_argument("input",  help="File .zxma yang akan didekompres")
    p_d.add_argument("-o", "--output", default=None,
                     help="File output (default: nama asli tanpa .zxma)")

    # ── info ──────────────────────────────────────────────────
    p_i = sub.add_parser("info", aliases=["i"], help="Tampilkan info file .zxma")
    p_i.add_argument("input", help="File .zxma")

    # ── bench ─────────────────────────────────────────────────
    p_b = sub.add_parser("bench", aliases=["b"],
                         help="Benchmark semua level pada sebuah file")
    p_b.add_argument("input", help="File yang akan di-benchmark")

    # ── demo ──────────────────────────────────────────────────
    sub.add_parser("demo", help="Jalankan demo & benchmark built-in")

    # ── probe ─────────────────────────────────────────────────
    p_pr = sub.add_parser("probe", aliases=["p"],
                          help="Probe block size optimal untuk sebuah file tanpa mengompres")
    p_pr.add_argument("input", help="File yang akan dianalisis")
    p_pr.add_argument("-l", "--level", type=int, default=6, metavar="1-12",
                      help="Level kompresi yang akan digunakan (default: 6)")
    p_pr.add_argument("--budget", type=float, default=2.0, metavar="MB",
                      help="Budget sampling dalam MB (default: 2)")


    args = parser.parse_args()

    # ──────────────────────────────────────────────────────────

    if args.cmd in ("compress", "c"):
        if not os.path.isfile(args.input):
            print(f"[ERROR] File tidak ditemukan: {args.input}")
            sys.exit(1)
        if args.level < 1 or args.level > 12:
            print("[ERROR] Level harus antara 1–12")
            sys.exit(1)

        block_kb    = getattr(args, 'block_size', BLOCK_SIZE // 1024)
        show_prog   = getattr(args, 'progress', False)
        use_auto    = getattr(args, 'auto_block', False)
        probe_mb    = getattr(args, 'probe_budget', 2.0)
        block_bytes = 0 if use_auto else block_kb * 1024

        resolved_t = ZXMACompressor._resolve_threads(args.threads)
        cpu_n      = os.cpu_count() or 1

        out_path = args.output or (args.input + ".zxma")
        print(f"[ZXMA] Kompres  : {args.input}")
        print(f"       Output   : {out_path}")
        print(f"       Level    : {args.level}")
        print(f"       Threads  : {resolved_t}"
              f"{'  (auto dari ' + str(cpu_n) + ' core)' if args.threads <= 0 else ''}")
        if use_auto:
            print(f"       Block    : AUTO (probe budget={probe_mb} MB)")
        else:
            print(f"       Block    : {block_kb} KB")

        data = open(args.input, "rb").read()
        cmp  = ZXMACompressor(level=args.level, threads=args.threads,
                               block_size=block_bytes, auto_probe_mb=probe_mb)
        compressed, stats = cmp.compress(data, progress=show_prog)

        open(out_path, "wb").write(compressed)

        saved = len(data) - len(compressed)
        print(f"\n  Ukuran original  : {_hr(stats.original_size)}")
        print(f"  Ukuran compressed: {_hr(stats.compressed_size)}")
        print(f"  Rasio kompresi   : {stats.ratio*100:.2f}%")
        print(f"  Penghematan      : {_hr(max(saved,0))} ({max(0,100-stats.ratio*100):.1f}% lebih kecil)")
        print(f"  Tipe data        : {stats.data_type}")
        print(f"  Filter           : {stats.filter_used}")
        if stats.auto_detected:
            print(f"  Block size       : {stats.block_size_kb} KB  "
                  f"(auto-detected, probe={stats.probe_time_ms:.0f}ms)")
        else:
            print(f"  Block size       : {stats.block_size_kb} KB")
        print(f"  Jumlah blok      : {stats.blocks}")
        print(f"  Waktu kompresi   : {stats.time_compress_ms:.1f} ms")
        print(f"\n  Selesai → {out_path}")


    elif args.cmd in ("decompress", "d"):
        if not os.path.isfile(args.input):
            print(f"[ERROR] File tidak ditemukan: {args.input}")
            sys.exit(1)

        if args.output:
            out_path = args.output
        elif args.input.endswith(".zxma"):
            out_path = args.input[:-5]
        else:
            out_path = args.input + ".restored"

        print(f"[ZXMA] Dekompres : {args.input}")
        print(f"       Output    : {out_path}")

        data = open(args.input, "rb").read()
        cmp  = ZXMACompressor()
        try:
            result, stats = cmp.decompress(data)
        except ValueError as e:
            print(f"\n[ERROR] {e}")
            sys.exit(1)

        open(out_path, "wb").write(result)

        print(f"\n  Ukuran compressed: {_hr(len(data))}")
        print(f"  Ukuran original  : {_hr(stats.original_size)}")
        print(f"  Tipe data        : {stats.data_type}")
        print(f"  Waktu dekompres  : {stats.time_decompress_ms:.1f} ms")
        print(f"  Checksum         : OK ✓")
        print(f"\n  Selesai → {out_path}")

    elif args.cmd in ("info", "i"):
        if not os.path.isfile(args.input):
            print(f"[ERROR] File tidak ditemukan: {args.input}")
            sys.exit(1)

        raw = open(args.input, "rb").read()
        if raw[:4] != MAGIC:
            print("[ERROR] Bukan file ZXMA yang valid")
            sys.exit(1)

        buf = io.BytesIO(raw)
        buf.read(4)  # magic
        version, level = buf.read(1)[0], buf.read(1)[0]
        dtype_i, ftype_i, orig_size, n_blocks = struct.unpack(">BBQ I", buf.read(14))
        checksum = buf.read(32)

        print(f"[ZXMA] Info file: {args.input}")
        print(f"  Format versi   : {version}")
        print(f"  Level kompresi : {level}")
        print(f"  Ukuran original: {_hr(orig_size)}")
        print(f"  Ukuran file    : {_hr(len(raw))}")
        print(f"  Rasio          : {len(raw)/max(orig_size,1)*100:.2f}%")
        print(f"  Tipe data      : {DataType(dtype_i).name}")
        print(f"  Filter         : {FilterType(ftype_i).name}")
        print(f"  Jumlah blok    : {n_blocks}")
        print(f"  Checksum SHA256: {checksum.hex()[:32]}...")

        print(f"\n  Blok detail:")
        for i in range(n_blocks):
            try:
                c_size, o_size, method = struct.unpack(">I I B", buf.read(9))
                methods = {0:"store", 1:"zlib", 2:"lzma", 3:"lz+zlib"}
                buf.read(c_size)
                print(f"    Blok {i+1:2d}: {_hr(c_size):>10}  metode={methods.get(method, '?')}")
            except Exception:
                break

    elif args.cmd in ("bench", "b"):
        if not os.path.isfile(args.input):
            print(f"[ERROR] File tidak ditemukan: {args.input}")
            sys.exit(1)

        data  = open(args.input, "rb").read()
        cpu_n = os.cpu_count() or 1
        print(f"[ZXMA] Benchmark: {args.input}  ({_hr(len(data))})")
        print(f"       CPU core tersedia: {cpu_n}")

        print(f"\n  -- Benchmark level (threads=1) --")
        print(f"  {'Level':<8} {'Compressed':<14} {'Rasio':<10} {'Kompres':<14} {'Dekompres'}")
        print(f"  {'─'*6:<8} {'─'*12:<14} {'─'*8:<10} {'─'*12:<14} {'─'*10}")
        for lvl in [1, 3, 5, 7, 9, 10, 12]:
            c = ZXMACompressor(level=lvl, threads=1)
            comp, s1 = c.compress(data)
            _, s2    = c.decompress(comp)
            print(f"  {lvl:<8} {_hr(len(comp)):<14} {s1.ratio*100:.1f}%{'':<6} "
                  f"{s1.time_compress_ms:.1f}ms{'':<8} {s2.time_decompress_ms:.1f}ms")

        if cpu_n > 1 and len(data) >= BLOCK_SIZE:
            print(f"\n  -- Benchmark thread (level=6, block=64KB) --")
            print(f"  {'Threads':<10} {'Kompres':<14} {'Speedup'}")
            print(f"  {'─'*8:<10} {'─'*12:<14} {'─'*8}")
            ref_time = None
            thread_vals = sorted(set([1, 2] + ([4] if cpu_n >= 4 else []) +
                                      ([cpu_n] if cpu_n not in (1, 2, 4) else [])))
            for t in thread_vals:
                c = ZXMACompressor(level=6, threads=t, block_size=64*1024)
                _, s = c.compress(data)
                if ref_time is None:
                    ref_time = s.time_compress_ms
                speedup = ref_time / max(s.time_compress_ms, 0.01)
                label = f"{t} (auto)" if t == cpu_n else str(t)
                print(f"  {label:<10} {s.time_compress_ms:.1f}ms{'':<8} {speedup:.2f}×")
        else:
            print(f"\n  (Benchmark thread dilewati: file terlalu kecil atau CPU = 1 core)")

        print(f"\n  -- Pembanding --")
        zlib_c = zlib.compress(data, 9)
        lzma_c = lzma.compress(data, preset=9)
        print(f"  {'zlib lv9':<10} {_hr(len(zlib_c)):<14} {len(zlib_c)/len(data)*100:.1f}%")
        print(f"  {'lzma p9':<10} {_hr(len(lzma_c)):<14} {len(lzma_c)/len(data)*100:.1f}%")

    elif args.cmd == "demo":
        run_demo()

    elif args.cmd in ("probe", "p"):
        if not os.path.isfile(args.input):
            print(f"[ERROR] File tidak ditemukan: {args.input}")
            sys.exit(1)

        data = open(args.input, "rb").read()
        print(f"[ZXMA] Probe    : {args.input}  ({_hr(len(data))})")
        print(f"       Level    : {args.level}  |  Budget: {args.budget} MB")
        print()

        sizer  = AutoBlockSizer(level=args.level, probe_budget_mb=args.budget,
                                fine_search=True, verbose=True,
                                cpu_count=os.cpu_count() or 1)
        result = sizer.probe(data)

        print(f"\n  Hasil kandidat (diurutkan terbaik):")
        print(f"  {'Block':>8}  {'Ratio':>9}  {'Bar (lebih panjang = lebih kecil)'}")
        max_inv = max(1 - r for _, r in result.candidates)
        for kb, ratio in result.candidates[:10]:
            bar_len = int((1 - ratio) / max_inv * 40) if max_inv > 0 else 0
            marker  = " ◀ OPTIMAL" if kb == result.block_size_kb else ""
            bar     = "▓" * bar_len + "░" * (40 - bar_len)
            print(f"  {kb:>7}KB  {ratio*100:>8.4f}%  {bar}{marker}")

        print(f"\n  Block size optimal : {result.block_size_kb} KB")
        print(f"  Rasio prediksi     : {result.ratio*100:.4f}%")
        print(f"  Sample digunakan   : {result.sample_size_kb} KB")
        print(f"  Waktu probe        : {result.probe_time_ms:.0f} ms")
        print(f"\n  Command kompres optimal:")
        print(f"  python zxma.py compress {args.input} -l {args.level} "
              f"--block-size {result.block_size_kb} --progress")
        print(f"  -- atau gunakan --auto-block untuk deteksi otomatis --")
        print(f"  python zxma.py compress {args.input} -l {args.level} "
              f"--auto-block --progress")


    else:
        parser.print_help()


if __name__ == "__main__":
    import sys
    # Jika dipanggil tanpa argumen → jalankan demo
    if len(sys.argv) == 1:
        run_demo()
    else:
        run_cli()