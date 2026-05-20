"""
Rich UI display components for Green Mold Cure.
Dark green theme with icon display.
"""

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Prompt, Confirm
from rich.style import Style
from pathlib import Path

# Dark green color scheme
DARK_GREEN = "#006400"
MEDIUM_GREEN = "#228B22"
LIGHT_GREEN = "#32CD32"
BRIGHT_GREEN = "#00FF00"
WHITE = "#FFFFFF"
GRAY = "#808080"


class GMCConsole:
    """Custom console wrapper with Green Mold Cure branding."""
    
    def __init__(self):
        self.console = Console()
        self.icon_path = Path(__file__).parent.parent.parent / "ICON.txt"
        self._icon_loaded = False
        self._icon_text = ""
        self._load_icon()
    
    def _load_icon(self) -> None:
        """Load the ASCII art icon from file."""
        try:
            if self.icon_path.exists():
                with open(self.icon_path, "r", encoding="utf-8") as f:
                    self._icon_text = f.read()
                self._icon_loaded = True
        except Exception:
            self._icon_loaded = False
    
    def display_icon(self) -> None:
        """Display the Green Mold Cure icon at the top of the interface."""
        if self._icon_loaded and self._icon_text:
            # Color the icon with dark green theme
            icon_panel = Panel(
                Text(self._icon_text, style=Style(color=MEDIUM_GREEN)),
                border_style=DARK_GREEN,
                padding=(1, 2),
            )
            self.console.print(icon_panel)
        else:
            # Fallback text header if icon not available
            header = Panel(
                Text("🦠 GREEN MOLD CURE 🦠", style=Style(color=BRIGHT_GREEN, bold=True)),
                subtitle="Antivirus Scanner v4.0.1",
                border_style=MEDIUM_GREEN,
                padding=(1, 2),
            )
            self.console.print(header)
    
    def display_menu(self, menu_items: list[tuple[str, str]]) -> None:
        """
        Display the numbered menu.
        
        Args:
            menu_items: List of tuples (option_number, description)
        """
        table = Table(
            show_header=False,
            show_lines=False,
            border_style=DARK_GREEN,
            padding=(0, 2),
        )
        table.add_column("Option", style=BRIGHT_GREEN, width=6)
        table.add_column("Description", style=WHITE)
        
        for option, description in menu_items:
            table.add_row(f"[{option}]", description)
        
        menu_panel = Panel(
            table,
            title="[bold bright_green]Main Menu[/bold bright_green]",
            border_style=MEDIUM_GREEN,
        )
        self.console.print(menu_panel)
    
    def display_scan_result(
        self,
        file_path: str,
        threat_name: str | None = None,
        severity: str = "medium",
        status: str = "clean"
    ) -> None:
        """
        Display a scan result for a file.
        
        Args:
            file_path: Path to the scanned file
            threat_name: Name of detected threat (if any)
            severity: Threat severity (low, medium, high, critical)
            status: Scan status (clean, infected, error, skipped)
        """
        severity_colors = {
            "low": LIGHT_GREEN,
            "medium": "#FFA500",  # Orange
            "high": "#FF4500",    # Red-Orange
            "critical": "#FF0000", # Red
        }
        
        status_icons = {
            "clean": "✓",
            "infected": "✗",
            "error": "!",
            "skipped": "-",
        }
        
        icon = status_icons.get(status, "?")
        color = severity_colors.get(severity, WHITE)
        
        if status == "clean":
            text = f"[{LIGHT_GREEN}]{icon} CLEAN[/{LIGHT_GREEN}] {file_path}"
        elif status == "infected":
            text = f"[{color}]{icon} THREAT DETECTED[/{color}] {file_path}"
            if threat_name:
                text += f"\n  [bold {color}]Threat:[/bold {color}] {threat_name}"
                text += f"\n  [bold {color}]Severity:[/bold {color}] {severity.upper()}"
        elif status == "error":
            text = f"[{GRAY}]{icon} ERROR[/{GRAY}] {file_path}"
        else:
            text = f"[{GRAY}]{icon} SKIPPED[/{GRAY}] {file_path}"
        
        self.console.print(text)
    
    def display_threat_action_prompt(
        self,
        file_path: str,
        threat_name: str,
        severity: str
    ) -> str:
        """
        Prompt user for action on detected threat.
        
        Args:
            file_path: Path to the infected file
            threat_name: Name of detected threat
            severity: Threat severity level
            
        Returns:
            User's choice: 'quarantine', 'purge', or 'ignore'
        """
        severity_colors = {
            "low": LIGHT_GREEN,
            "medium": "#FFA500",
            "high": "#FF4500",
            "critical": "#FF0000",
        }
        color = severity_colors.get(severity, WHITE)
        
        panel = Panel(
            f"[bold white]File:[/bold white] {file_path}\n"
            f"[bold {color}]Threat:[/bold {color}] {threat_name}\n"
            f"[bold {color}]Severity:[/bold {color}] {severity.upper()}\n\n"
            f"[bold yellow]What action should be taken?[/bold yellow]",
            title="[bold red]⚠️  THREAT DETECTED ⚠️[/bold red]",
            border_style=color,
        )
        self.console.print(panel)
        
        self.console.print("\n[1] [bright_green]Quarantine[/bright_green] - Move to secure isolation vault")
        self.console.print("[2] [orange_red1]Purge[/orange_red1] - Securely delete (3-pass overwrite)")
        self.console.print("[3] [gray]Ignore[/gray] - Add to exclusion list (not recommended)\n")
        
        choice = Prompt.ask(
            "Enter your choice",
            choices=["1", "2", "3"],
            default="1",
            show_choices=False,
        )
        
        action_map = {"1": "quarantine", "2": "purge", "3": "ignore"}
        return action_map.get(choice, "quarantine")
    
    def create_progress(self, description: str = "Processing...") -> Progress:
        """
        Create a progress bar with dark green theme.
        
        Args:
            description: Description text for the progress bar
            
        Returns:
            Configured Progress instance
        """
        return Progress(
            SpinnerColumn(spinner_name="dots", style=MEDIUM_GREEN),
            TextColumn("[bold green]{task.description}"),
            BarColumn(bar_width=40, complete_style=MEDIUM_GREEN, finished_style=BRIGHT_GREEN),
            TextColumn("[green]{task.percentage:>3.1f}%"),
            console=self.console,
        )
    
    def print_success(self, message: str) -> None:
        """Print a success message."""
        self.console.print(f"[bold bright_green]✓ SUCCESS:[/bold bright_green] {message}")
    
    def print_error(self, message: str) -> None:
        """Print an error message."""
        self.console.print(f"[bold red]✗ ERROR:[/bold red] {message}")
    
    def print_warning(self, message: str) -> None:
        """Print a warning message."""
        self.console.print(f"[bold yellow]⚠ WARNING:[/bold yellow] {message}")
    
    def print_info(self, message: str) -> None:
        """Print an info message."""
        self.console.print(f"[bold cyan]ℹ INFO:[/bold cyan] {message}")
    
    def confirm(self, message: str, default: bool = False) -> bool:
        """
        Ask for user confirmation.
        
        Args:
            message: Confirmation message
            default: Default value if user just presses Enter
            
        Returns:
            True if confirmed, False otherwise
        """
        return Confirm.ask(message, default=default)
    
    def ask(self, message: str, default: str = "") -> str:
        """
        Ask user for input.
        
        Args:
            message: Prompt message
            default: Default value
            
        Returns:
            User input
        """
        return Prompt.ask(message, default=default) if default else Prompt.ask(message)
    
    def clear(self) -> None:
        """Clear the console screen."""
        self.console.clear()
    
    def print_table(self, title: str, headers: list[str], rows: list[list[str]]) -> None:
        """
        Print a formatted table.
        
        Args:
            title: Table title
            headers: Column headers
            rows: List of row data
        """
        table = Table(
            title=title,
            title_style="bold bright_green",
            border_style=MEDIUM_GREEN,
            show_header=True,
            header_style="bold green",
        )
        
        for header in headers:
            table.add_column(header, style=WHITE)
        
        for row in rows:
            table.add_row(*row)
        
        self.console.print(table)


# Global console instance
console = GMCConsole()
