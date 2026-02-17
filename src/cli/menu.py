"""
Numbered menu system for Green Mold Cure.
Handles user input and menu navigation.
"""

from typing import Callable
from .display import console, DARK_GREEN, MEDIUM_GREEN


# Main menu options - Enhanced for Ultimate Edition with AI
MAIN_MENU_OPTIONS = [
    ("1", "Quick Scan - Scan common malware locations"),
    ("2", "Full System Scan - Comprehensive system-wide scan"),
    ("3", "Process & Memory Scan - Scan running processes"),
    ("4", "Sandbox Emulation - Analyze file behavior"),
    ("5", "Cloud Scan - Scan with multiple cloud engines"),
    ("6", "AI Threat Correlation - UNIQUE: AI-powered analysis"),
    ("7", "Real-time Protection - Configure background monitoring"),
    ("8", "Update Database - Fetch latest signatures"),
    ("9", "Quarantine - Manage quarantined files"),
    ("10", "Settings - Configure preferences"),
    ("11", "Exit - Close the application"),
]

# Submenu for quarantine management
QUARANTINE_MENU_OPTIONS = [
    ("1", "List Quarantined Files"),
    ("2", "Restore File"),
    ("3", "Delete from Quarantine"),
    ("4", "Empty Quarantine"),
    ("5", "Back to Main Menu"),
]

# Settings menu options
SETTINGS_MENU_OPTIONS = [
    ("1", "View Current Settings"),
    ("2", "Configure API Keys"),
    ("3", "Toggle Real-time Protection"),
    ("4", "Configure Scan Options"),
    ("5", "Manage Exclusions"),
    ("6", "Back to Main Menu"),
]


class MenuHandler:
    """Handles menu display and user input."""
    
    def __init__(self):
        self.console = console
        self.running = True
        self.current_menu = "main"
    
    def display_main_menu(self) -> None:
        """Display the main menu."""
        self.console.display_menu(MAIN_MENU_OPTIONS)
    
    def display_quarantine_menu(self) -> None:
        """Display the quarantine management menu."""
        self.console.display_menu(QUARANTINE_MENU_OPTIONS)
    
    def display_settings_menu(self) -> None:
        """Display the settings menu."""
        self.console.display_menu(SETTINGS_MENU_OPTIONS)
    
    def get_menu_choice(self, valid_choices: list[str]) -> str:
        """
        Get user's menu choice.
        
        Args:
            valid_choices: List of valid choice strings
            
        Returns:
            User's choice
        """
        while True:
            choice = self.console.ask(
                "[bold green]Enter your choice[/bold green]",
            )
            if choice in valid_choices:
                return choice
            self.console.print_error(f"Invalid choice. Please enter one of: {', '.join(valid_choices)}")
    
    def handle_main_menu(self, callbacks: dict[str, Callable]) -> str:
        """
        Handle main menu interaction.
        
        Args:
            callbacks: Dictionary mapping option numbers to callback functions
            
        Returns:
            The choice made by the user
        """
        self.display_main_menu()
        valid_choices = [opt[0] for opt in MAIN_MENU_OPTIONS]
        choice = self.get_menu_choice(valid_choices)
        
        # Execute callback if exists
        if choice in callbacks:
            callbacks[choice]()
        
        return choice
    
    def handle_quarantine_menu(self, callbacks: dict[str, Callable]) -> str:
        """
        Handle quarantine menu interaction.
        
        Args:
            callbacks: Dictionary mapping option numbers to callback functions
            
        Returns:
            The choice made by the user
        """
        self.display_quarantine_menu()
        valid_choices = [opt[0] for opt in QUARANTINE_MENU_OPTIONS]
        choice = self.get_menu_choice(valid_choices)
        
        # Execute callback if exists
        if choice in callbacks:
            callbacks[choice]()
        
        return choice
    
    def handle_settings_menu(self, callbacks: dict[str, Callable]) -> str:
        """
        Handle settings menu interaction.
        
        Args:
            callbacks: Dictionary mapping option numbers to callback functions
            
        Returns:
            The choice made by the user
        """
        self.display_settings_menu()
        valid_choices = [opt[0] for opt in SETTINGS_MENU_OPTIONS]
        choice = self.get_menu_choice(valid_choices)
        
        # Execute callback if exists
        if choice in callbacks:
            callbacks[choice]()
        
        return choice
    
    def confirm_exit(self) -> bool:
        """
        Ask user to confirm exit.
        
        Returns:
            True if user confirms exit, False otherwise
        """
        return self.console.confirm(
            "[bold yellow]Are you sure you want to exit Green Mold Cure?[/bold yellow]",
            default=False,
        )
    
    def pause_and_continue(self, message: str = "Press Enter to continue...") -> None:
        """
        Pause and wait for user to continue.
        
        Args:
            message: Message to display
        """
        self.console.ask(f"[gray]{message}[/gray]")
    
    def display_header(self, title: str) -> None:
        """
        Display a section header.
        
        Args:
            title: Header title
        """
        from rich.panel import Panel
        from rich.text import Text
        
        header = Panel(
            Text(title, style="bold bright_green"),
            border_style=MEDIUM_GREEN,
            padding=(0, 2),
        )
        self.console.console.print(header)
    
    def display_back_option(self) -> None:
        """Display back navigation hint."""
        self.console.console.print("[gray]Enter 'b' to go back[/gray]\n")
