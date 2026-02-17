"""
Tests for Green Mold Cure CLI module.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.cli.display import GMCConsole, DARK_GREEN, MEDIUM_GREEN
from src.cli.menu import MenuHandler, MAIN_MENU_OPTIONS


class TestGMCConsole:
    """Tests for the GMCConsole class."""

    @pytest.fixture
    def console(self):
        """Create a console instance for testing."""
        return GMCConsole()

    def test_console_initialization(self, console):
        """Test console initializes correctly."""
        assert console is not None
        assert console.console is not None

    def test_icon_loading(self, console):
        """Test icon loading."""
        # Icon should be loaded (or fallback prepared)
        assert hasattr(console, '_icon_loaded')
        assert hasattr(console, '_icon_text')

    def test_display_methods_exist(self, console):
        """Test that display methods exist."""
        assert hasattr(console, 'display_icon')
        assert hasattr(console, 'display_menu')
        assert hasattr(console, 'display_scan_result')
        assert hasattr(console, 'display_threat_action_prompt')
        assert hasattr(console, 'print_success')
        assert hasattr(console, 'print_error')
        assert hasattr(console, 'print_warning')
        assert hasattr(console, 'print_info')

    def test_color_scheme(self):
        """Test color scheme constants are defined."""
        assert DARK_GREEN is not None
        assert MEDIUM_GREEN is not None

    def test_create_progress(self, console):
        """Test progress bar creation."""
        progress = console.create_progress("Test progress...")
        assert progress is not None

    def test_confirm_method(self, console, monkeypatch):
        """Test confirmation prompt."""
        # Mock Rich's Confirm.ask to return True
        with patch('src.cli.display.Confirm.ask', return_value=True):
            result = console.confirm("Test?", default=False)
            assert result is True

        with patch('src.cli.display.Confirm.ask', return_value=False):
            result = console.confirm("Test?", default=False)
            assert result is False

    def test_ask_method(self, console, monkeypatch):
        """Test input prompt."""
        with patch('src.cli.display.Prompt.ask', return_value='test input'):
            result = console.ask("Enter something:")
            assert result == 'test input'


class TestMenuHandler:
    """Tests for the MenuHandler class."""

    @pytest.fixture
    def menu_handler(self):
        """Create a menu handler instance."""
        return MenuHandler()

    def test_menu_handler_initialization(self, menu_handler):
        """Test menu handler initializes correctly."""
        assert menu_handler is not None
        assert menu_handler.running is True
        assert menu_handler.current_menu == "main"

    def test_main_menu_options_defined(self):
        """Test main menu options are defined."""
        assert len(MAIN_MENU_OPTIONS) == 11  # Updated for Ultimate Edition with AI

        # Check structure
        for option, description in MAIN_MENU_OPTIONS:
            assert isinstance(option, str)
            assert isinstance(description, str)
            assert option.isdigit()

    def test_display_methods_exist(self, menu_handler):
        """Test that display methods exist."""
        assert hasattr(menu_handler, 'display_main_menu')
        assert hasattr(menu_handler, 'display_quarantine_menu')
        assert hasattr(menu_handler, 'display_settings_menu')
        assert hasattr(menu_handler, 'get_menu_choice')

    def test_menu_options_structure(self):
        """Test menu options have correct structure."""
        # Main menu
        for option, description in MAIN_MENU_OPTIONS:
            assert len(option) >= 1
            assert len(description) > 0

        # Verify expected options exist
        option_numbers = [opt[0] for opt in MAIN_MENU_OPTIONS]
        assert "1" in option_numbers  # Quick Scan
        assert "2" in option_numbers  # Full System Scan
        assert "8" in option_numbers  # Exit

    def test_handle_main_menu(self, menu_handler, monkeypatch):
        """Test handling main menu."""
        # Mock the get_menu_choice to return a valid choice
        with patch.object(menu_handler, 'get_menu_choice', return_value="8"):
            try:
                menu_handler.display_main_menu()
            except Exception as e:
                pytest.fail(f"display_main_menu raised {e}")

    def test_confirm_exit(self, menu_handler, monkeypatch):
        """Test exit confirmation."""
        # Mock Rich's Confirm.ask to return True
        with patch('src.cli.display.Confirm.ask', return_value=True):
            result = menu_handler.confirm_exit()
            assert result is True

        with patch('src.cli.display.Confirm.ask', return_value=False):
            result = menu_handler.confirm_exit()
            assert result is False

    def test_pause_and_continue(self, menu_handler, monkeypatch):
        """Test pause functionality."""
        # Mock the ask method to avoid actual input
        with patch.object(menu_handler.console, 'ask', return_value=''):
            try:
                menu_handler.pause_and_continue()
            except Exception as e:
                pytest.fail(f"pause_and_continue raised {e}")

    def test_display_header(self, menu_handler):
        """Test header display."""
        try:
            menu_handler.display_header("Test Header")
        except Exception as e:
            pytest.fail(f"display_header raised {e}")

    def test_get_menu_choice(self, menu_handler, monkeypatch):
        """Test getting menu choice."""
        # Mock the console.ask to return a valid choice
        with patch.object(menu_handler.console, 'ask', return_value="1"):
            choice = menu_handler.get_menu_choice(["1", "2", "3"])
            assert choice == "1"
