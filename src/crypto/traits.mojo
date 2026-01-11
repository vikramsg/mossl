"""Traits for cryptographic primitives."""

from collections import List, InlineArray
from memory import Span


trait AEAD:
    """Trait for Authenticated Encryption with Associated Data algorithms."""

    fn seal(
        self,
        key: Span[UInt8],
        iv: Span[UInt8],
        aad: Span[UInt8],
        plaintext: Span[UInt8],
    ) raises -> List[UInt8]: # Usually returns concatenated CT + Tag
        ...

    fn open(
        self,
        key: Span[UInt8],
        iv: Span[UInt8],
        aad: Span[UInt8],
        ciphertext: Span[UInt8],
    ) raises -> List[UInt8]: # Returns plaintext or raises on auth failure
        ...


trait Hash:
    """Trait for cryptographic hash functions."""

    fn hash(self, data: Span[UInt8]) raises -> InlineArray[UInt8, 32]:
        ...


struct KeyExchangeResult:
    """Result of a key exchange operation."""

    var public_key: InlineArray[UInt8, 32]
    var private_key: InlineArray[UInt8, 32]

    fn __init__(
        out self,
        public_key: InlineArray[UInt8, 32],
        private_key: InlineArray[UInt8, 32],
    ):
        self.public_key = public_key
        self.private_key = private_key


trait KeyExchange:
    """Trait for key exchange algorithms."""

    fn generate_keypair(self) raises -> KeyExchangeResult:
        ...

    fn compute_shared_secret(
        self, private_key: Span[UInt8], public_key: Span[UInt8]
    ) raises -> InlineArray[UInt8, 32]:
        ...