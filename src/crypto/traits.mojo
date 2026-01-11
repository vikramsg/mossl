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
    ) raises -> List[UInt8]:
        """Encrypts and authenticates the plaintext.





        Args:


            key: The encryption key.


            iv: The initialization vector.


            aad: Additional authenticated data.


            plaintext: The data to protect.





        Returns:


            The combined ciphertext and authentication tag.





        Raises:


            Error: If encryption fails.


        """

        ...

    fn open(
        self,
        key: Span[UInt8],
        iv: Span[UInt8],
        aad: Span[UInt8],
        ciphertext: Span[UInt8],
    ) raises -> List[UInt8]:
        """Verifies and decrypts the ciphertext.





        Args:


            key: The encryption key.


            iv: The initialization vector.


            aad: Additional authenticated data.


            ciphertext: The data to verify and decrypt.





        Returns:


            The original plaintext.





        Raises:


            Error: If authentication fails or decryption error occurs.


        """

        ...


trait Hash:

    """Trait for cryptographic hash functions."""

    fn hash(self, data: Span[UInt8]) raises -> InlineArray[UInt8, 32]:
        """Computes the hash of the input data.





        Args:


            data: The data to hash.





        Returns:


            The computed message digest.


        """

        ...


struct KeyExchangeResult:

    """Result of a key exchange operation."""

    var public_key: InlineArray[UInt8, 32]

    """The public key produced."""

    var private_key: InlineArray[UInt8, 32]

    """The private key produced."""

    fn __init__(
        out self,
        public_key: InlineArray[UInt8, 32],
        private_key: InlineArray[UInt8, 32],
    ):
        """Initializes the result with public and private keys."""

        self.public_key = public_key

        self.private_key = private_key


trait KeyExchange:

    """Trait for key exchange algorithms."""

    fn generate_keypair(self) raises -> KeyExchangeResult:
        """Generates a new ephemeral keypair.





        Returns:


            A result containing both public and private keys.


        """

        ...

    fn compute_shared_secret(
        self, private_key: Span[UInt8], public_key: Span[UInt8]
    ) raises -> InlineArray[UInt8, 32]:
        """Computes a shared secret between a private key and a public key.





        Args:


            private_key: The local private key.


            public_key: The remote public key.





        Returns:


            The computed shared secret.


        """

        ...
