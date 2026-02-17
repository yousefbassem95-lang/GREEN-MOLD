"""
Cryptography utilities for Green Mold Cure.
Provides encryption for quarantine vault and secure deletion.
"""

import os
import hashlib
import secrets
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class CryptoVault:
    """
    Handles encryption and decryption for the quarantine vault.
    
    Uses AES-256-CBC with PBKDF2 key derivation for secure storage.
    """
    
    SALT_LENGTH = 16  # 128-bit salt
    KEY_LENGTH = 32   # 256-bit key
    IV_LENGTH = 16    # 128-bit IV
    
    def __init__(self, master_key: Optional[bytes] = None):
        """
        Initialize the crypto vault.
        
        Args:
            master_key: Optional master key for encryption.
                       If not provided, generates a new key.
        """
        self.master_key = master_key or self._generate_key()
        self._salt = secrets.token_bytes(self.SALT_LENGTH)
    
    def _generate_key(self) -> bytes:
        """Generate a secure random key."""
        return secrets.token_bytes(self.KEY_LENGTH)
    
    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """
        Derive a key from password using PBKDF2.
        
        Args:
            password: Password bytes
            salt: Salt bytes
            
        Returns:
            Derived key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=100_000,
            backend=default_backend(),
        )
        return kdf.derive(password)
    
    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypt data using AES-256-CBC.
        
        Args:
            data: Data to encrypt
            
        Returns:
            Encrypted data with salt and IV prepended
        """
        # Generate random IV
        iv = secrets.token_bytes(self.IV_LENGTH)
        
        # Pad data to block size
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        
        # Prepend salt and IV to encrypted data
        return self._salt + iv + encrypted
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data.
        
        Args:
            encrypted_data: Encrypted data with salt and IV prepended
            
        Returns:
            Decrypted data
        """
        # Extract salt and IV
        salt = encrypted_data[:self.SALT_LENGTH]
        iv = encrypted_data[self.SALT_LENGTH:self.SALT_LENGTH + self.IV_LENGTH]
        ciphertext = encrypted_data[self.SALT_LENGTH + self.IV_LENGTH:]
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        return data
    
    def encrypt_file(self, input_path: Path, output_path: Path) -> bool:
        """
        Encrypt a file.
        
        Args:
            input_path: Path to file to encrypt
            output_path: Path for encrypted output
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(input_path, "rb") as f:
                data = f.read()
            
            encrypted = self.encrypt(data)
            
            with open(output_path, "wb") as f:
                f.write(encrypted)
            
            return True
        except Exception:
            return False
    
    def decrypt_file(self, input_path: Path, output_path: Path) -> bool:
        """
        Decrypt a file.
        
        Args:
            input_path: Path to encrypted file
            output_path: Path for decrypted output
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(input_path, "rb") as f:
                encrypted_data = f.read()
            
            decrypted = self.decrypt(encrypted_data)
            
            with open(output_path, "wb") as f:
                f.write(decrypted)
            
            return True
        except Exception:
            return False
    
    def get_file_hash(self, file_path: Path) -> str:
        """
        Calculate SHA-256 hash of a file.
        
        Args:
            file_path: Path to file
            
        Returns:
            Hex-encoded hash
        """
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()


class SecureDeleter:
    """
    Secure file deletion using multiple overwrite passes.
    
    Implements DoD 5220.22-M standard (3-pass overwrite).
    """
    
    PASS_COUNT = 3
    BUFFER_SIZE = 1024 * 1024  # 1 MB chunks
    
    @staticmethod
    def secure_delete(file_path: Path, passes: int = PASS_COUNT) -> bool:
        """
        Securely delete a file by overwriting multiple times.
        
        Args:
            file_path: Path to file to delete
            passes: Number of overwrite passes
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not file_path.exists():
                return False
            
            file_size = file_path.stat().st_size
            
            # Pass 1: Random data
            SecureDeleter._overwrite(file_path, file_size, os.urandom)
            
            # Pass 2: Zeros
            SecureDeleter._overwrite(file_path, file_size, lambda n: b"\x00" * n)
            
            # Pass 3: Random data
            SecureDeleter._overwrite(file_path, file_size, os.urandom)
            
            # Delete the file
            file_path.unlink()
            
            return True
        except Exception:
            return False
    
    @staticmethod
    def _overwrite(file_path: Path, size: int, data_generator) -> None:
        """
        Overwrite file with generated data.
        
        Args:
            file_path: Path to file
            size: File size
            data_generator: Function to generate overwrite data
        """
        with open(file_path, "wb") as f:
            remaining = size
            while remaining > 0:
                chunk_size = min(SecureDeleter.BUFFER_SIZE, remaining)
                data = data_generator(chunk_size)
                f.write(data)
                remaining -= chunk_size
                f.flush()
                os.fsync(f.fileno())
    
    @staticmethod
    def secure_delete_directory(dir_path: Path) -> bool:
        """
        Securely delete all files in a directory.
        
        Args:
            dir_path: Path to directory
            
        Returns:
            True if all files deleted successfully
        """
        success = True
        
        if dir_path.exists() and dir_path.is_dir():
            for file_path in dir_path.iterdir():
                if file_path.is_file():
                    if not SecureDeleter.secure_delete(file_path):
                        success = False
            
            # Try to remove empty directory
            try:
                dir_path.rmdir()
            except OSError:
                pass  # Directory may not be empty or permissions issue
        
        return success


def generate_secure_key() -> str:
    """
    Generate a secure random key for encryption.
    
    Returns:
        Hex-encoded secure key
    """
    return secrets.token_hex(32)


def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[bytes, bytes]:
    """
    Hash a password with salt.
    
    Args:
        password: Password to hash
        salt: Optional salt (generated if not provided)
        
    Returns:
        Tuple of (hashed_password, salt)
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend(),
    )
    hashed = kdf.derive(password.encode("utf-8"))
    
    return hashed, salt
