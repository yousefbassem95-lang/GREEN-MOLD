"""
Tests for Green Mold Cure scanner module.
"""

import pytest
import sys
from pathlib import Path
import tempfile
import hashlib

# Add src to path for imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from scanner.engine import ScannerEngine, ScanStatus, ScanResult, Severity
from scanner.signatures import SignatureDatabase
from scanner.heuristics import HeuristicAnalyzer


class TestScannerEngine:
    """Tests for the scanner engine."""
    
    @pytest.fixture
    def scanner(self):
        """Create a scanner instance for testing."""
        return ScannerEngine()
    
    @pytest.fixture
    def temp_file(self):
        """Create a temporary file for testing."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("This is a test file content")
            path = Path(f.name)
        yield path
        path.unlink()
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory with files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dir_path = Path(tmpdir)
            
            # Create test files
            (dir_path / "file1.txt").write_text("Content 1")
            (dir_path / "file2.txt").write_text("Content 2")
            (dir_path / "subdir").mkdir()
            (dir_path / "subdir" / "file3.txt").write_text("Content 3")
            
            yield dir_path
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly."""
        assert scanner is not None
        assert scanner.signature_database is None
        assert scanner.excluded_patterns == []
    
    def test_get_file_hash(self, scanner, temp_file):
        """Test file hashing."""
        file_hash = scanner.get_file_hash(temp_file)
        
        assert file_hash is not None
        assert len(file_hash) == 64  # SHA256 hex length
        assert all(c in '0123456789abcdef' for c in file_hash)
    
    def test_get_file_hash_nonexistent(self, scanner):
        """Test hashing nonexistent file."""
        result = scanner.get_file_hash(Path("/nonexistent/file.txt"))
        assert result is None
    
    def test_should_skip_file_size(self, scanner, temp_file):
        """Test file skip based on size."""
        # Default max size is 100MB, our test file should not be skipped
        assert not scanner.should_skip_file(temp_file)
    
    def test_should_skip_file_exclusion(self, scanner, temp_file):
        """Test file skip based on exclusion pattern."""
        scanner.excluded_patterns = ["*.txt"]
        assert scanner.should_skip_file(temp_file)
    
    def test_traverse_file(self, scanner, temp_file):
        """Test traversing a single file."""
        files = list(scanner.traverse_path(temp_file))
        assert len(files) == 1
        assert files[0] == temp_file
    
    def test_traverse_directory(self, scanner, temp_dir):
        """Test traversing a directory."""
        files = list(scanner.traverse_path(temp_dir))
        assert len(files) == 3  # We created 3 files
    
    def test_scan_clean_file(self, scanner, temp_file):
        """Test scanning a clean file."""
        result = scanner.scan_file(temp_file)
        
        assert result.status == ScanStatus.CLEAN
        assert result.file_hash is not None
        assert result.threat_name is None
    
    def test_scan_nonexistent_file(self, scanner):
        """Test scanning nonexistent file."""
        result = scanner.scan_file(Path("/nonexistent/file.txt"))
        # Nonexistent files are skipped due to should_skip_file catching OSError
        assert result.status in (ScanStatus.ERROR, ScanStatus.SKIPPED)

    def test_scan_with_signature_match(self, scanner, temp_file):
        """Test scanning file with matching signature."""
        # Add signature to database
        file_hash = scanner.get_file_hash(temp_file)
        signature_db = scanner.signature_database
        if signature_db is None:
            from src.scanner.signatures import SignatureDatabase
            import tempfile
            with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
                db_path = Path(f.name)
            signature_db = SignatureDatabase(db_path)
            scanner.set_signature_database(signature_db)

        signature_db.add_signature(
            file_hash,
            "Test.Threat",
            threat_type="malware",
            severity="high",
            source="test",
        )

        # Scan should detect threat
        result = scanner.scan_file(temp_file)
        assert result.status == ScanStatus.INFECTED
        assert result.threat_name == "Test.Threat"
        assert result.severity == Severity.HIGH
    
    def test_quick_scan(self, scanner):
        """Test quick scan executes without error."""
        # Quick scan may find no paths on test system
        summary = scanner.quick_scan()
        assert summary is not None
        assert isinstance(summary.total_files, int)
    
    def test_scan_summary_properties(self, scanner, temp_dir):
        """Test scan summary properties."""
        summary = scanner.scan([temp_dir])
        
        assert summary.total_files >= 0
        assert summary.scanned_files >= 0
        assert summary.clean_files >= 0
        assert summary.duration >= 0
        assert summary.infection_rate >= 0


class TestSignatureDatabase:
    """Tests for the signature database."""
    
    @pytest.fixture
    def signature_db(self):
        """Create a test signature database."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = Path(f.name)
        
        db = SignatureDatabase(db_path)
        yield db
        
        # Cleanup
        db_path.unlink()
    
    def test_database_initialization(self, signature_db):
        """Test database initializes correctly."""
        assert signature_db is not None
        assert signature_db.db_path.exists()
    
    def test_add_signature(self, signature_db):
        """Test adding a signature."""
        result = signature_db.add_signature(
            "a" * 64,  # Test SHA256 hash
            "Test.Malware",
            threat_type="trojan",
            severity="high",
            source="test",
        )
        
        assert result is True
    
    def test_check_hash_match(self, signature_db):
        """Test checking a hash that matches."""
        # Add signature
        signature_db.add_signature(
            "b" * 64,
            "Test.Threat",
            threat_type="malware",
            severity="medium",
            source="test",
        )
        
        # Check hash
        result = signature_db.check_hash("b" * 64)
        
        assert result is not None
        assert result["name"] == "Test.Threat"
        assert result["severity"] == "medium"
    
    def test_check_hash_no_match(self, signature_db):
        """Test checking a hash with no match."""
        result = signature_db.check_hash("c" * 64)
        assert result is None
    
    def test_batch_add_signatures(self, signature_db):
        """Test batch adding signatures."""
        signatures = [
            {"hash_sha256": "d" * 64, "threat_name": "Test.1", "threat_type": "malware", "severity": "low"},
            {"hash_sha256": "e" * 64, "threat_name": "Test.2", "threat_type": "malware", "severity": "medium"},
            {"hash_sha256": "f" * 64, "threat_name": "Test.3", "threat_type": "malware", "severity": "high"},
        ]
        
        imported, failed = signature_db.add_signatures_batch(signatures, source="test")
        
        assert imported == 3
        assert failed == 0
    
    def test_get_signature_count(self, signature_db):
        """Test getting signature count."""
        assert signature_db.get_signature_count() == 0
        
        signature_db.add_signature("a" * 64, "Test.1", source="test")
        signature_db.add_signature("b" * 64, "Test.2", source="test")
        
        assert signature_db.get_signature_count() == 2
    
    def test_remove_signature(self, signature_db):
        """Test removing a signature."""
        signature_db.add_signature("a" * 64, "Test.Threat", source="test")
        assert signature_db.get_signature_count() == 1
        
        signature_db.remove_signature("a" * 64)
        assert signature_db.get_signature_count() == 0
    
    def test_clear_signatures(self, signature_db):
        """Test clearing signatures."""
        signature_db.add_signature("a" * 64, "Test.1", source="test")
        signature_db.add_signature("b" * 64, "Test.2", source="test2")
        
        # Clear specific source
        count = signature_db.clear_signatures("test")
        assert count == 1
        assert signature_db.get_signature_count() == 1
        
        # Clear all
        count = signature_db.clear_signatures()
        assert signature_db.get_signature_count() == 0
    
    def test_get_database_stats(self, signature_db):
        """Test getting database statistics."""
        signature_db.add_signature("a" * 64, "Test.1", severity="high", source="test")
        signature_db.add_signature("b" * 64, "Test.2", severity="low", source="test")
        
        stats = signature_db.get_database_stats()
        
        assert stats["total_signatures"] == 2
        assert "by_severity" in stats
        assert "by_source" in stats


class TestHeuristicAnalyzer:
    """Tests for the heuristic analyzer."""
    
    @pytest.fixture
    def analyzer(self):
        """Create a heuristic analyzer instance."""
        return HeuristicAnalyzer()
    
    def test_analyzer_initialization(self, analyzer):
        """Test analyzer initializes correctly."""
        assert analyzer is not None
        assert len(analyzer.compiled_patterns) > 0
    
    def test_analyze_clean_file(self, analyzer):
        """Test analyzing a clean file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("This is completely normal content")
            path = Path(f.name)
        
        try:
            result = analyzer.analyze_file(path)
            
            assert result.suspicion_level < 20
            assert "No significant indicators" in result.recommendation
        finally:
            path.unlink()
    
    def test_analyze_suspicious_extension(self, analyzer):
        """Test file with suspicious extension."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.exe') as f:
            f.write("Fake executable")
            path = Path(f.name)
        
        try:
            result = analyzer.analyze_file(path)
            
            assert "Suspicious extension" in str(result.indicators)
            assert result.suspicion_level >= 10
        finally:
            path.unlink()
    
    def test_analyze_nonexistent_file(self, analyzer):
        """Test analyzing nonexistent file."""
        result = analyzer.analyze_file(Path("/nonexistent/file.exe"))
        assert result.suspicion_level == 0
    
    def test_analyze_script_content(self, analyzer):
        """Test script content analysis."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.ps1') as f:
            f.write("""
            # Suspicious PowerShell
            DownloadString
            Invoke-Expression
            Bypass
            """)
            path = Path(f.name)
        
        try:
            result = analyzer.analyze_file(path)
            
            assert result.suspicion_level > 0
            assert "Suspicious script" in str(result.indicators)
        finally:
            path.unlink()
