from collections import List, InlineArray
from memory import Span

# Result struct for opening an AEAD record
@value
struct OpenResult:
    var success: Bool
    var plaintext_len: Int

trait AEAD:
    fn seal(
        self,
        key: Span[UInt8],
        iv: Span[UInt8],
        aad: Span[UInt8],
        plaintext: Span[UInt8],
        mut ciphertext: List[UInt8],
        mut tag: InlineArray[UInt8, 16],
    ) raises:
        ...

    fn open(
        self,
        key: Span[UInt8],
        iv: Span[UInt8],
        aad: Span[UInt8],
        ciphertext: Span[UInt8],
        tag: InlineArray[UInt8, 16],
        mut plaintext: List[UInt8],
    ) raises -> Bool:
        ...

trait Hash:
    fn hash(self, data: Span[UInt8], mut digest: InlineArray[UInt8, 32]) raises:
        ...

trait KeyExchange:
    fn generate_keypair(self) raises -> (InlineArray[UInt8, 32], InlineArray[UInt8, 32]):
        ...

    fn compute_shared(
        self, private: Span[UInt8], peer_public: Span[UInt8], mut shared_secret: InlineArray[UInt8, 32]
    ) raises:
        ...
