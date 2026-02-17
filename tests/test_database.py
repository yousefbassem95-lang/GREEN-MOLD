"""
Tests for Green Mold Cure database module.
"""

import pytest
import sys
from pathlib import Path
import tempfile
import asyncio

# Add src to path for imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from database.updater import DatabaseUpdater
from scanner.signatures import SignatureDatabase


class TestDatabaseUpdater:
    """Tests for the database updater."""
    
    @pytest.fixture
    def updater(self):
        """Create a database updater instance."""
        return DatabaseUpdater()
    
    @pytest.fixture
    def signature_db(self):
        """Create a test signature database."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = Path(f.name)
        
        db = SignatureDatabase(db_path)
        yield db
        
        db_path.unlink()
    
    def test_updater_initialization(self, updater):
        """Test updater initializes correctly."""
        assert updater is not None
        assert isinstance(updater.sources, dict)
    
    def test_load_enabled_sources(self, updater):
        """Test loading enabled sources."""
        updater._load_enabled_sources()
        
        # Should have expected sources
        expected_sources = [
            "clamav",
            "abuse_ch",
            "virustotal",
            "hybrid_analysis",
            "anyrun",
            "alienvault",
            "phishtank",
            "tor_feeds",
        ]
        
        for source in expected_sources:
            assert source in updater.sources
    
    def test_set_progress_callback(self, updater):
        """Test setting progress callback."""
        def callback(source, status):
            pass
        
        updater.set_progress_callback(callback)
        assert updater.progress_callback is not None
    
    @pytest.mark.asyncio
    async def test_update_all_no_sources(self, updater):
        """Test update all with no sources enabled."""
        # Disable all sources
        original_sources = updater.sources.copy()
        updater.sources = {k: False for k in updater.sources}

        try:
            results = await updater.update_all()

            # Results should indicate no sources enabled
            assert results is not None
        finally:
            # Restore original sources
            updater.sources = original_sources
    
    def test_get_last_update_times(self, updater):
        """Test getting last update times."""
        times = updater.get_last_update_times()
        
        assert isinstance(times, dict)
        # All sources should have a time entry (even if "Never")
    
    def test_should_update(self, updater):
        """Test checking if update is due."""
        # Auto-update is typically disabled by default
        result = updater.should_update()
        assert isinstance(result, bool)


class TestSignatureDatabaseIntegration:
    """Integration tests for signature database."""
    
    @pytest.fixture
    def signature_db(self):
        """Create a test signature database."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = Path(f.name)
        
        db = SignatureDatabase(db_path)
        yield db
        
        db_path.unlink()
    
    def test_full_signature_workflow(self, signature_db):
        """Test complete signature workflow."""
        # Add signatures
        signature_db.add_signature("a" * 64, "Malware.A", source="test")
        signature_db.add_signature("b" * 64, "Malware.B", source="test")
        signature_db.add_signature("c" * 64, "Malware.C", source="test2")
        
        # Check count
        assert signature_db.get_signature_count() == 3
        
        # Check specific hash
        result = signature_db.check_hash("a" * 64)
        assert result is not None
        assert result["name"] == "Malware.A"
        
        # Check by source
        count = signature_db.get_signatures_by_source("test")
        assert count == 2
        
        # Clear specific source
        signature_db.clear_signatures("test")
        assert signature_db.get_signature_count() == 1
        
        # Clear all
        signature_db.clear_signatures()
        assert signature_db.get_signature_count() == 0
    
    def test_batch_operations(self, signature_db):
        """Test batch signature operations."""
        signatures = [
            {"hash_sha256": f"{i}" * 64, "threat_name": f"Threat.{i}", "threat_type": "malware", "severity": "medium"}
            for i in range(10)
        ]
        
        imported, failed = signature_db.add_signatures_batch(signatures, source="batch_test")
        
        assert imported == 10
        assert failed == 0
        assert signature_db.get_signature_count() == 10
        
        # Batch check
        hashes = [f"{i}" * 64 for i in range(10)]
        results = signature_db.check_hashes_batch(hashes)
        
        assert len(results) == 10
    
    def test_scan_logging(self, signature_db):
        """Test scan history logging."""
        # Log a scan
        signature_db.log_scan("quick", 100, 5, 30.5)
        
        # Get history
        history = signature_db.get_scan_history()
        
        assert len(history) >= 1
        assert history[0]["scan_type"] == "quick"
        assert history[0]["files_scanned"] == 100
        assert history[0]["threats_found"] == 5
    
    def test_quarantine_logging(self, signature_db):
        """Test quarantine logging."""
        # Log quarantine
        signature_db.log_quarantine(
            "/path/to/file",
            "/quarantine/file",
            "Test.Malware",
            "a" * 64,
            "quarantine",
        )
        
        # Get log
        log = signature_db.get_quarantine_log()
        
        assert len(log) >= 1
        assert log[0]["original_path"] == "/path/to/file"
        assert log[0]["threat_name"] == "Test.Malware"
    
    def test_source_info_tracking(self, signature_db):
        """Test source information tracking."""
        # Add signatures from a source (this also tracks source info)
        signature_db.add_signature("a" * 64, "Test.1", severity="high", source="test_source")
        signature_db.add_signature("b" * 64, "Test.2", severity="low", source="test_source")

        # Update source info explicitly
        signature_db.update_source_info("test_source", 2, '{"config": "value"}')

        # Get stats - by_source comes from signatures table
        stats = signature_db.get_database_stats()

        assert stats["total_signatures"] == 2
        assert "by_source" in stats
        # Source should be in by_source since we added signatures from it
        assert "test_source" in stats["by_source"]
        assert stats["by_source"]["test_source"] == 2
