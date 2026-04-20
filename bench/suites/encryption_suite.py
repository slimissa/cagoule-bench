"""
EncryptionSuite — benchmark chiffrement.

Compare CAGOULE, AES-256-GCM et ChaCha20-Poly1305
sur 5 tailles de messages. Collecte timing + mémoire + CPU.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from bench.metrics import TimeCollector, MemoryCollector, CpuCollector
from bench.suites.base import BaseSuite, BenchmarkResult

# TODO: Replace with real CAGOULE import when bindings are ready
try:
    from cagoule import encrypt as cagoule_encrypt
except ImportError:
    # Mock for testing the harness (NOT real crypto)
    def cagoule_encrypt(plaintext: bytes, password: bytes) -> bytes:
        key = password * (len(plaintext) // len(password) + 1)
        return bytes(p ^ k for p, k in zip(plaintext, key[:len(plaintext)]))


# Tailles canoniques (bytes)
DEFAULT_SIZES = [
    1_024,        # 1 KB
    8_192,        # 8 KB
    65_536,       # 64 KB
    1_048_576,    # 1 MB
    10_485_760,   # 10 MB
]

PASSWORD = b"cagoule-bench-reference-password"
AES_KEY = AESGCM.generate_key(bit_length=256)
CHACHA_KEY = os.urandom(32)


def _aes_encrypt(plaintext: bytes) -> bytes:
    """AES-256-GCM encryption with random nonce prepended."""
    aes = AESGCM(AES_KEY)
    nonce = os.urandom(12)
    return nonce + aes.encrypt(nonce, plaintext, None)


def _aes_decrypt(ciphertext: bytes) -> bytes:
    """AES-256-GCM decryption."""
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    aes = AESGCM(AES_KEY)
    return aes.decrypt(nonce, ct, None)


def _chacha_encrypt(plaintext: bytes) -> bytes:
    """ChaCha20-Poly1305 encryption with random nonce prepended."""
    chacha = ChaCha20Poly1305(CHACHA_KEY)
    nonce = os.urandom(12)
    return nonce + chacha.encrypt(nonce, plaintext, None)


def _chacha_decrypt(ciphertext: bytes) -> bytes:
    """ChaCha20-Poly1305 decryption."""
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    chacha = ChaCha20Poly1305(CHACHA_KEY)
    return chacha.decrypt(nonce, ct, None)


def _cagoule_decrypt(ciphertext: bytes, password: bytes) -> bytes:
    """CAGOULE decryption (assuming symmetric)."""
    # TODO: Replace with real CAGOULE decrypt when available
    return cagoule_encrypt(ciphertext, password)  # XOR is symmetric


class EncryptionSuite(BaseSuite):
    NAME = "encryption"
    DESCRIPTION = "CAGOULE vs AES-256-GCM vs ChaCha20-Poly1305 — chiffrement/déchiffrement"

    def __init__(
        self,
        iterations: int = 500,
        warmup: int = 10,
        sizes: list[int] | None = None,
    ):
        super().__init__(iterations=iterations, warmup=warmup)
        self.sizes = sizes or DEFAULT_SIZES
        self._timer = TimeCollector()
        self._mem = MemoryCollector()
        self._cpu = CpuCollector()

    def run(self) -> list[BenchmarkResult]:
        results: list[BenchmarkResult] = []

        for size in self.sizes:
            plaintext = os.urandom(size)
            size_label = self._fmt_size(size)

            # Encrypt first to get ciphertext for decryption tests
            cagoule_ct = cagoule_encrypt(plaintext, PASSWORD)
            aes_ct = _aes_encrypt(plaintext)
            chacha_ct = _chacha_encrypt(plaintext)

            # ── CAGOULE ENCRYPT ──────────────────────────────
            results.extend(self._benchmark_operation(
                name=f"encrypt-{size_label}",
                algorithm="CAGOULE",
                operation=lambda: cagoule_encrypt(plaintext, PASSWORD),
                data_size_bytes=size,
            ))

            # ── CAGOULE DECRYPT ──────────────────────────────
            results.extend(self._benchmark_operation(
                name=f"decrypt-{size_label}",
                algorithm="CAGOULE",
                operation=lambda: _cagoule_decrypt(cagoule_ct, PASSWORD),
                data_size_bytes=size,
            ))

            # ── AES-256-GCM ENCRYPT ──────────────────────────
            results.extend(self._benchmark_operation(
                name=f"encrypt-{size_label}",
                algorithm="AES-256-GCM",
                operation=lambda: _aes_encrypt(plaintext),
                data_size_bytes=size,
            ))

            # ── AES-256-GCM DECRYPT ──────────────────────────
            results.extend(self._benchmark_operation(
                name=f"decrypt-{size_label}",
                algorithm="AES-256-GCM",
                operation=lambda: _aes_decrypt(aes_ct),
                data_size_bytes=size,
            ))

            # ── ChaCha20-Poly1305 ENCRYPT ────────────────────
            results.extend(self._benchmark_operation(
                name=f"encrypt-{size_label}",
                algorithm="ChaCha20-Poly1305",
                operation=lambda: _chacha_encrypt(plaintext),
                data_size_bytes=size,
            ))

            # ── ChaCha20-Poly1305 DECRYPT ────────────────────
            results.extend(self._benchmark_operation(
                name=f"decrypt-{size_label}",
                algorithm="ChaCha20-Poly1305",
                operation=lambda: _chacha_decrypt(chacha_ct),
                data_size_bytes=size,
            ))

        return results

    def _benchmark_operation(
        self,
        name: str,
        algorithm: str,
        operation,
        data_size_bytes: int,
    ) -> list[BenchmarkResult]:
        """
        Measure time, memory, and CPU for a single operation.
        Returns a list with one BenchmarkResult.
        """
        results = []

        # Warmup memory collector (3 passes to stabilize)
        for _ in range(3):
            self._mem.measure(operation)

        # Measure memory (separate run to avoid tracemalloc overhead)
        _, mem = self._mem.measure(operation, label=f"{algorithm}-{name}")

        # Measure timing (N iterations with warmup)
        timing = self._timer.measure(
            operation,
            iterations=self.iterations,
            warmup=self.warmup,
            label=f"{algorithm}-{name}",
        )

        # Measure CPU
        _, cpu = self._cpu.measure(operation, label=f"{algorithm}-{name}")

        results.append(self._make_result(
            name=name,
            algorithm=algorithm,
            data_size_bytes=data_size_bytes,
            mean_ms=timing.mean_ms,
            stddev_ms=timing.stddev_ms,
            min_ms=timing.min_ms,
            max_ms=timing.max_ms,
            p95_ms=timing.p95_ms,
            p99_ms=timing.p99_ms,
            cv_percent=timing.cv_percent,  # Property, not method
            throughput_mbps=timing.throughput_mbps(data_size_bytes),
            peak_mb=mem.peak_mb,
            delta_mb=mem.delta_mb,
            cpu_mean_pct=cpu.cpu_mean_pct,
            cpu_peak_pct=cpu.cpu_peak_pct,
        ))

        return results

    @staticmethod
    def _fmt_size(size: int) -> str:
        if size < 1024:
            return f"{size}B"
        if size < 1_048_576:
            return f"{size // 1024}KB"
        return f"{size // 1_048_576}MB"