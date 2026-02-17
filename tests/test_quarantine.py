"""
Tests for Green Mold Cure quarantine module.
"""

import pytest
import sys
from pathlib import Path
import tempfile
import json

# Add src to path for imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from quarantine.manager import QuarantineManager, QuarantineEntry
from utils.crypto import CryptoVault, SecureDeleter


class TestQuarantineManager:
    """Tests for the quarantine manager."""
    
    @pytest.fixture
    def quarantine_manager(self):
        """Create a quarantine manager for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_path = Path(tmpdir) / "quarantine"
            manager = QuarantineManager(vault_path)
            yield manager
    
    @pytest.fixture
    def test_file(self):
        """Create a test file for quarantine."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("This is a test file that simulates malware")
            path = Path(f.name)
        yield path
        # Cleanup original if it still exists
        if path.exists():
            path.unlink()
    
    def test_manager_initialization(self, quarantine_manager):
        """Test manager initializes correctly."""
        assert quarantine_manager is not None
        assert quarantine_manager.vault_path.exists()
        assert quarantine_manager.metadata_path.exists()
    
    def test_quarantine_file(self, quarantine_manager, test_file):
        """Test quarantining a file."""
        entry = quarantine_manager.quarantine_file(
            test_file,
            threat_name="Test.Malware",
            file_hash="a" * 64,
            encrypt=False,  # Don't encrypt for easier testing
        )
        
        assert entry is not None
        assert entry.id is not None
        assert entry.threat_name == "Test.Malware"
        assert Path(entry.quarantine_path).exists()
    
    def test_quarantine_encrypted_file(self, quarantine_manager, test_file):
        """Test quarantining a file with encryption."""
        entry = quarantine_manager.quarantine_file(
            test_file,
            threat_name="Test.Malware",
            file_hash="a" * 64,
            encrypt=True,
        )
        
        assert entry is not None
        assert entry.encrypted is True
        assert Path(entry.quarantine_path).exists()
    
    def test_quarantine_nonexistent_file(self, quarantine_manager):
        """Test quarantining nonexistent file."""
        entry = quarantine_manager.quarantine_file(
            Path("/nonexistent/file.txt"),
            threat_name="Test.Malware",
            file_hash="a" * 64,
        )
        
        assert entry is None
    
    def test_get_entry(self, quarantine_manager, test_file):
        """Test retrieving a quarantine entry."""
        # Quarantine a file
        entry = quarantine_manager.quarantine_file(
            test_file,
            threat_name="Test.Malware",
            file_hash="a" * 64,
            encrypt=False,
        )
        
        # Retrieve by ID
        retrieved = quarantine_manager.get_entry(entry.id)
        
        assert retrieved is not None
        assert retrieved.id == entry.id
        assert retrieved.threat_name == entry.threat_name
    
    def test_get_all_entries(self, quarantine_manager, test_file):
        """Test getting all quarantine entries."""
        # Quarantine multiple files
        for i in range(3):
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(f"Test content {i}")
                temp_path = Path(f.name)
            
            quarantine_manager.quarantine_file(
                temp_path,
                threat_name=f"Test.Malware.{i}",
                file_hash="a" * 64,
                encrypt=False,
            )
            temp_path.unlink()
        
        entries = quarantine_manager.get_all_entries()
        assert len(entries) == 3
    
    def test_restore_file(self, quarantine_manager, test_file):
        """Test restoring a file from quarantine."""
        # Quarantine the file
        entry = quarantine_manager.quarantine_file(
            test_file,
            threat_name="Test.Malware",
            file_hash="a" * 64,
            encrypt=False,
        )
        
        # Restore to new location
        with tempfile.TemporaryDirectory() as tmpdir:
            restore_path = Path(tmpdir) / "restored.txt"
            success = quarantine_manager.restore_file(entry.id, restore_path)
            
            assert success is True
            assert restore_path.exists()
            assert restore_path.read_text() == "This is a test file that simulates malware"
    
    def test_delete_from_quarantine(self, quarantine_manager, test_file):
        """Test deleting a file from quarantine."""
        # Quarantine the file
        entry = quarantine_manager.quarantine_file(
            test_file,
            threat_name="Test.Malware",
            file_hash="a" * 64,
            encrypt=False,
        )
        
        # Delete from quarantine
        success = quarantine_manager.delete_from_quarantine(entry.id, secure=False)
        
        assert success is True
        assert entry.id not in quarantine_manager.entries
        assert not Path(entry.quarantine_path).exists()
    
    def test_empty_quarantine(self, quarantine_manager, test_file):
        """Test emptying the entire quarantine."""
        # Quarantine multiple files
        for i in range(3):
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(f"Test content {i}")
                temp_path = Path(f.name)
            
            quarantine_manager.quarantine_file(
                temp_path,
                threat_name=f"Test.Malware.{i}",
                file_hash="a" * 64,
                encrypt=False,
            )
            temp_path.unlink()
        
        # Empty quarantine
        count = quarantine_manager.empty_quarantine(secure=False)
        
        assert count == 3
        assert len(quarantine_manager.entries) == 0
    
    def test_get_vault_stats(self, quarantine_manager, test_file):
        """Test getting vault statistics."""
        # Quarantine a file
        quarantine_manager.quarantine_file(
            test_file,
            threat_name="Test.Malware",
            file_hash="a" * 64,
            encrypt=False,
        )
        
        stats = quarantine_manager.get_vault_stats()
        
        assert stats["total_entries"] == 1
        assert stats["total_size_bytes"] > 0
        assert "threat_breakdown" in stats
    
    def test_metadata_persistence(self, quarantine_manager, test_file):
        """Test that metadata persists across instances."""
        # Quarantine a file
        entry = quarantine_manager.quarantine_file(
            test_file,
            threat_name="Test.Malware",
            file_hash="a" * 64,
            encrypt=False,
        )
        
        # Create new manager instance with same vault
        new_manager = QuarantineManager(quarantine_manager.vault_path)
        
        # Entry should be loaded from metadata
        assert entry.id in new_manager.entries
        assert new_manager.entries[entry.id].threat_name == "Test.Malware"


class TestCryptoVault:
    """Tests for the crypto vault."""
    
    @pytest.fixture
    def vault(self):
        """Create a crypto vault for testing."""
        return CryptoVault()
    
    def test_vault_initialization(self, vault):
        """Test vault initializes correctly."""
        assert vault is not None
        assert len(vault.master_key) == 32  # 256-bit key
    
    def test_encrypt_decrypt(self, vault):
        """Test encryption and decryption."""
        original = b"This is secret data"
        
        encrypted = vault.encrypt(original)
        assert encrypted != original
        assert len(encrypted) > len(original)  # Includes salt and IV
        
        decrypted = vault.decrypt(encrypted)
        assert decrypted == original
    
    def test_encrypt_decrypt_file(self, vault):
        """Test file encryption and decryption."""
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = Path(tmpdir) / "original.txt"
            encrypted_path = Path(tmpdir) / "encrypted.bin"
            decrypted_path = Path(tmpdir) / "decrypted.txt"
            
            # Create test file
            input_path.write_text("Secret file content")
            
            # Encrypt
            success = vault.encrypt_file(input_path, encrypted_path)
            assert success is True
            assert encrypted_path.exists()
            
            # Decrypt
            success = vault.decrypt_file(encrypted_path, decrypted_path)
            assert success is True
            assert decrypted_path.read_text() == "Secret file content"
    
    def test_get_file_hash(self, vault):
        """Test file hashing."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("Test content")
            path = Path(f.name)
        
        try:
            file_hash = vault.get_file_hash(path)
            
            assert file_hash is not None
            assert len(file_hash) == 64  # SHA256
        finally:
            path.unlink()


class TestSecureDeleter:
    """Tests for secure deletion."""
    
    def test_secure_delete(self):
        """Test secure file deletion."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("Sensitive data")
            path = Path(f.name)
        
        assert path.exists()
        
        success = SecureDeleter.secure_delete(path, passes=1)  # Use 1 pass for speed in tests
        
        assert success is True
        assert not path.exists()
    
    def test_secure_delete_nonexistent(self):
        """Test secure deletion of nonexistent file."""
        result = SecureDeleter.secure_delete(Path("/nonexistent/file.txt"))
        assert result is False
