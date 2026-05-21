"""
Green Mold Cure - Ultimate Edition
Complete Multi-Engine Antivirus with Real-time Protection

Features:
- 4 Detection Engines (Signature, YARA, Heuristic, PE)
- Process/Memory Scanning
- Sandbox Emulation
- Cloud Integration (VirusTotal, MetaDefender, Jotti's, Hybrid Analysis)
- Real-time File System Protection
- Archive Scanning
- Comprehensive Error Handling
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime

# Add src directory to path
if __name__ == "__main__":
    src_path = Path(__file__).parent
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))

from cli.display import console as ui_console, DARK_GREEN, MEDIUM_GREEN, BRIGHT_GREEN
from cli.menu import MenuHandler, MAIN_MENU_OPTIONS
from scanner.enhanced_engine import enhanced_scanner, ScanResult, ScanStatus, ScanSummary
from scanner.signatures import signature_db
from scanner.yara_scanner import yara_scanner
from scanner.process_scanner import process_scanner
from scanner.sandbox_emulator import sandbox_emulator, EmulationRisk
from scanner.cloud_scanner import cloud_scanner
from scanner.realtime_protection import realtime_protection, protection_daemon, ProtectionStatus
from ai_threat_correlator import ai_correlator, AIThreatAnalysis, ThreatCorrelation
from database.updater import db_updater
from quarantine.manager import quarantine_manager
from config.settings import settings
from utils.platform import platform_info
from utils.integrity import integrity_monitor
import subprocess
import os
import psutil
from utils.logger import logger


class GreenMoldCureUltimate:
    """Main application class for Green Mold Cure Ultimate Edition."""
    
    def __init__(self):
        """Initialize the application."""
        self.menu_handler = MenuHandler()
        self.running = True
        self.console = ui_console.console
        self.setup_self_defense()
        
        # Ensure directories exist
        platform_info.ensure_directories()
        
        # Load settings
        settings.load()
        
        # Set signature database for scanner
        enhanced_scanner.set_signature_database(signature_db)
        
        logger.info("Green Mold Cure Ultimate Edition initialized")
    

    def setup_self_defense(self):
        """Initialize integrity monitor and sentinel process."""
        # Check integrity first
        if not integrity_monitor.load_baseline():
            integrity_monitor.create_baseline()

        if not integrity_monitor.check_integrity():
            self.console.print("[red][bold]ALERT: System integrity breach detected! Auto-recovery initiated.[/bold][/red]")

        # Start real-time integrity monitoring
        integrity_monitor.start_monitoring()

        # Start sentinel process
        self.start_sentinel()

    def start_sentinel(self):
        """Starts the sentinel process to monitor this main process."""
        sentinel_script = Path(__file__).parent / "utils" / "sentinel.py"
        try:
            # Check if sentinel is already running
            sentinel_pid_file = platform_info.get_app_data_dir() / "sentinel.pid"
            if sentinel_pid_file.exists():
                with open(sentinel_pid_file, "r") as f:
                    try:
                        old_pid = int(f.read().strip())
                        if psutil.pid_exists(old_pid):
                            logger.info(f"Sentinel already running with PID {old_pid}")
                            return
                    except ValueError:
                        pass

            subprocess.Popen([sys.executable, str(sentinel_script), str(os.getpid())],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info("Sentinel process started.")
        except Exception as e:
            logger.error(f"Failed to start sentinel: {e}")
    def display_header(self) -> None:
        """Display the application header with icon and status."""
        self.console.clear()
        ui_console.display_icon()
        
        # Platform and privileges
        platform = platform_info.platform.value
        admin_status = " [bold yellow](Administrator)[/bold yellow]" if platform_info.is_admin() else " [dim](User)[/dim]"
        self.console.print(f"[bold green]Platform:[/bold green] {platform}{admin_status}")
        
        # Scanner status
        self.console.print(f"\n[bold green]Detection Engines:[/bold green]")
        
        # Signature database
        sig_count = signature_db.get_signature_count()
        self.console.print(f"  ✓ Signatures: {sig_count}")
        
        # YARA
        yara_info = yara_scanner.get_rules_info()
        if yara_info.get('available'):
            self.console.print(f"  ✓ YARA Rules: {yara_info.get('rules_count', 0)}")
        else:
            self.console.print(f"  ⚠ YARA: Not available")
        
        # Process scanning
        if process_scanner.is_available():
            self.console.print(f"  ✓ Process Scanner: Available")
        else:
            self.console.print(f"  ⚠ Process Scanner: psutil required")
        
        # Sandbox
        self.console.print(f"  ✓ Sandbox Emulator: Ready")
        
        # Cloud services
        cloud_services = sum(1 for s in ['virustotal', 'metadefender', 'hybrid_analysis'] if settings.get_api_key(s))
        self.console.print(f"  {'✓' if cloud_services > 0 else '⚠'} Cloud Services: {cloud_services} configured")

        # AI Correlator
        ai_status = ai_correlator.get_summary()
        if ai_status['available'] and ai_status['ollama_connected']:
            self.console.print(f"  ✓ AI Correlator: {ai_status['model']} (Connected)")
        elif ai_status['available']:
            self.console.print(f"  ⚠ AI Correlator: Ollama not running")
        else:
            self.console.print(f"  ⚠ AI Correlator: Install ollama")
        
        # Real-time protection status
        self.console.print(f"\n[bold green]Real-time Protection:[/bold green]")
        protection_status = realtime_protection.get_status()
        status_color = "green" if protection_status['status'] == 'running' else "yellow" if protection_status['status'] == 'paused' else "red"
        self.console.print(f"  [{status_color}]{protection_status['status'].upper()}[/{status_color}]")
        self.console.print(f"  Watch Paths: {len(protection_status['watch_paths'])}")
        
        self.console.print()
    
    def display_scan_result(self, result: ScanResult) -> None:
        """Display scan result with details."""
        if result.status == ScanStatus.CLEAN:
            self.console.print(f"[green]✓ CLEAN[/green] | {result.file_path}")
        
        elif result.status == ScanStatus.INFECTED:
            self.console.print(f"\n[bold red]✗ THREAT DETECTED[/bold red]")
            self.console.print(f"  File: {result.file_path}")
            self.console.print(f"  Threat: [red]{result.threat_name}[/red]")
            self.console.print(f"  Severity: [{result.severity.value}]{result.severity.value.upper()}[/{result.severity.value}]")
            
            if result.explanation:
                self.console.print(f"\n  [dim]{result.explanation[:300]}[/dim]")
            
            if result.recommendations:
                self.console.print(f"\n  [yellow]Recommendations:[/yellow]")
                for rec in result.recommendations[:3]:
                    self.console.print(f"    • {rec}")
        
        elif result.status == ScanStatus.SUSPICIOUS:
            self.console.print(f"\n[yellow]⚠ SUSPICIOUS[/yellow] | {result.file_path}")
            if result.heuristic_score > 0:
                self.console.print(f"  Heuristic Score: {result.heuristic_score}/100")
            if result.yara_matches:
                self.console.print(f"  YARA Matches: {len(result.yara_matches)}")
        
        elif result.status == ScanStatus.ACCESS_DENIED:
            self.console.print(f"[dim]⊘ ACCESS DENIED[/dim] | {result.file_path}")
            self.console.print(f"  [gray]{result.error_message}[/gray]")
        
        elif result.status == ScanStatus.ERROR:
            self.console.print(f"[gray]✗ ERROR[/gray] | {result.file_path}")
            self.console.print(f"  [gray]{result.error_message}[/gray]")
    
    def display_scan_summary(self, summary: ScanSummary) -> None:
        """Display comprehensive scan summary."""
        self.console.print("\n" + "═" * 70)
        self.console.print("[bold bright_green]📊 SCAN REPORT[/bold bright_green]")
        self.console.print("═" * 70)
        
        self.console.print(f"\nDuration: {summary.duration:.2f} seconds")
        self.console.print(f"Files: {summary.total_files} total, {summary.scanned_files} scanned ({summary.success_rate:.1f}%)")
        
        self.console.print(f"\n[green]✓ Clean: {summary.clean_files}[/green]")
        self.console.print(f"[bold red]✗ Infected: {summary.infected_files}[/bold red] ({summary.infection_rate:.1f}%)")
        self.console.print(f"[yellow]⚠ Suspicious: {summary.suspicious_files}[/yellow]")
        self.console.print(f"[gray]✗ Errors: {summary.error_files}[/gray]")
        self.console.print(f"[dim]⊘ Access Denied: {summary.access_denied_files}[/dim]")
        
        if summary.by_threat_type:
            self.console.print(f"\n[bold red]Threats by Type:[/bold red]")
            for tt, count in sorted(summary.by_threat_type.items(), key=lambda x: x[1], reverse=True):
                self.console.print(f"  • {tt}: {count}")
        
        if summary.error_files > 0:
            self.console.print(f"\n[yellow]⚠ Error Summary:[/yellow]")
            self.console.print(f"  {summary.error_files} files could not be scanned.")
            if summary.access_denied_files > summary.total_files * 0.3:
                self.console.print(f"  [bold yellow]⚠ High access denial rate - run as Administrator![/bold yellow]")
        
        self.console.print("\n" + "═" * 70)
    
    def handle_quick_scan(self) -> None:
        """Handle quick scan."""
        self.display_header()
        self.menu_handler.display_header("🔍 Quick Scan")
        
        self.console.print("\n[bold green]Scanning common malware locations...[/bold green]\n")
        
        def on_result(result: ScanResult) -> None:
            if result.status != ScanStatus.CLEAN:
                self.display_scan_result(result)
        
        summary = enhanced_scanner.quick_scan(result_callback=on_result)
        signature_db.log_scan("quick", summary.scanned_files, summary.infected_files, summary.duration)
        self.display_scan_summary(summary)
        self.menu_handler.pause_and_continue()
    
    def handle_full_scan(self) -> None:
        """Handle full system scan."""
        self.display_header()
        self.menu_handler.display_header("🔍 Full System Scan")
        
        self.console.print("\n[yellow]⚠ Running full system scan...[/yellow]")
        if not platform_info.is_admin():
            self.console.print("[yellow]⚠ Not running as Administrator - some files will be inaccessible[/yellow]\n")
        
        if not self.console.confirm("[bold]Start full system scan?[/bold]", default=False):
            return
        
        def on_result(result: ScanResult) -> None:
            if result.status != ScanStatus.CLEAN:
                self.display_scan_result(result)
        
        summary = enhanced_scanner.full_system_scan(result_callback=on_result)
        signature_db.log_scan("full", summary.scanned_files, summary.infected_files, summary.duration)
        self.display_scan_summary(summary)
        self.menu_handler.pause_and_continue()
    
    def handle_process_scan(self) -> None:
        """Handle process/memory scan - NEW FEATURE."""
        self.display_header()
        self.menu_handler.display_header("🧠 Process & Memory Scan")
        
        if not process_scanner.is_available():
            self.console.print("\n[red]Process scanning requires psutil library.[/red]")
            self.console.print("[yellow]Install with: pip install psutil[/yellow]")
            self.menu_handler.pause_and_continue()
            return
        
        self.console.print("\n[bold green]Scanning running processes...[/bold green]\n")
        
        # Get all processes
        processes = process_scanner.get_all_processes()
        self.console.print(f"Found {len(processes)} running processes\n")
        
        # Show suspicious processes
        suspicious = process_scanner.get_suspicious_processes()
        
        if suspicious:
            self.console.print(f"[bold red]⚠ {len(suspicious)} SUSPICIOUS PROCESSES DETECTED[/bold red]\n")
            
            for proc in suspicious:
                self.console.print(f"\n[bold red]Process: {proc.name} (PID: {proc.pid})[/bold red]")
                self.console.print(f"  Path: {proc.exe or 'Unknown'}")
                self.console.print(f"  User: {proc.username or 'Unknown'}")
                self.console.print(f"  Risk Score: {proc.suspicious_score}/100")
                
                if proc.suspicious_indicators:
                    self.console.print(f"  Indicators:")
                    for indicator in proc.suspicious_indicators[:5]:
                        self.console.print(f"    ⚠ {indicator}")
                
                # Offer to scan memory
                if self.console.confirm(f"  Scan memory of this process?", default=False):
                    mem_result = process_scanner.scan_process_memory(proc.pid)
                    self.console.print(f"\n  Memory Scan Result: {mem_result.status.upper()}")
                    if mem_result.explanation:
                        self.console.print(f"  [dim]{mem_result.explanation[:200]}[/dim]")
        else:
            self.console.print("[green]✓ No suspicious processes detected[/green]")
        
        # Scan summary
        scan_summary = process_scanner.get_scan_summary()
        self.console.print(f"\n[bold]Scan Summary:[/bold]")
        self.console.print(f"  Total Processes: {scan_summary['total_processes']}")
        self.console.print(f"  Suspicious: {scan_summary['suspicious']}")
        self.console.print(f"  With Code Injection: {scan_summary['processes_with_injection']}")
        
        self.menu_handler.pause_and_continue()
    
    def handle_sandbox_scan(self) -> None:
        """Handle sandbox emulation scan - NEW FEATURE."""
        self.display_header()
        self.menu_handler.display_header("🧪 Sandbox Emulation")
        
        self.console.print("\n[bold green]Enter file path to emulate:[/bold green]")
        self.console.print("[dim]Supports: Scripts (PS1, VBS, JS), Documents, Executables[/dim]\n")
        
        file_path = self.console.input("File path: ")
        path = Path(file_path.strip())
        
        if not path.exists():
            self.console.print("[red]File not found.[/red]")
            self.menu_handler.pause_and_continue()
            return
        
        self.console.print(f"\n[bold green]Emulating: {path.name}[/bold green]\n")
        
        result = sandbox_emulator.emulate_file(path)
        
        # Display result
        risk_colors = {
            'safe': 'green',
            'low': 'green',
            'medium': 'yellow',
            'high': 'orange_red1',
            'critical': 'red',
        }
        color = risk_colors.get(result.risk_level.value, 'white')
        
        self.console.print(f"\n[bold {color}]Risk Level: {result.risk_level.value.upper()}[/bold {color}]")
        self.console.print(f"Risk Score: {result.risk_score}/100")
        self.console.print(f"Safe to Execute: {'[green]Yes[/green]' if result.safe_to_execute else '[red]NO[/red]'}")
        
        if result.behaviors_detected:
            self.console.print(f"\n[bold]Behaviors Detected:[/bold]")
            for behavior in result.behaviors_detected[:10]:
                self.console.print(f"  ⚠ {behavior}")
        
        if result.explanation:
            self.console.print(f"\n[dim]{result.explanation}[/dim]")
        
        if result.recommendations:
            self.console.print(f"\n[yellow]Recommendations:[/yellow]")
            for rec in result.recommendations:
                self.console.print(f"  • {rec}")
        
        self.menu_handler.pause_and_continue()
    
    def handle_cloud_scan(self) -> None:
        """Handle cloud scanning."""
        self.display_header()
        self.menu_handler.display_header("☁️ Cloud Scan")

        self.console.print("\n[bold green]Enter file path for cloud scanning:[/bold green]")
        self.console.print("[dim]Uploads file hash to: VirusTotal, MetaDefender, Jotti's[/dim]\n")

        file_path = self.console.input("File path: ")
        path = Path(file_path.strip())

        if not path.exists():
            self.console.print("[red]File not found.[/red]")
            self.menu_handler.pause_and_continue()
            return

        self.console.print(f"\n[bold green]Scanning in cloud...[/bold green]\n")

        # Run async cloud scan
        file_hash = cloud_scanner._calculate_hash(path)
        self.console.print(f"File Hash (SHA256): [dim]{file_hash}[/dim]\n")

        try:
            result = asyncio.run(cloud_scanner.scan_all_services(path))

            if result.get('available'):
                self.console.print(f"[bold]Cloud Scan Results:[/bold]")
                self.console.print(f"  Services: {result['services_scanned']}")
                self.console.print(f"  Detections: {result['services_detected']}/{result['services_scanned']}")
                self.console.print(f"  Verdict: [bold {'red' if result['verdict'] == 'malicious' else 'green'}]{result['verdict']}[/bold {'red' if result['verdict'] == 'malicious' else 'green'}]")
                self.console.print(f"  Confidence: {result['confidence']}")

                if result.get('results'):
                    self.console.print(f"\n[bold]By Service:[/bold]")
                    for r in result['results']:
                        detected = "[red]DETECTED[/red]" if r['detected'] else "[green]Clean[/green]"
                        self.console.print(f"  {r['service']}: {detected} ({r['ratio']})")

                if result.get('permalinks'):
                    self.console.print(f"\n[dim]View detailed reports:[/dim]")
                    for link in result['permalinks'][:3]:
                        self.console.print(f"  {link}")
            else:
                self.console.print("[yellow]No cloud services configured.[/yellow]")
                self.console.print("[dim]Configure API keys in Settings for cloud scanning.[/dim]")

        except Exception as e:
            self.console.print(f"[red]Cloud scan failed: {e}[/red]")

        self.menu_handler.pause_and_continue()

    def handle_ai_correlation(self) -> None:
        """Handle AI threat correlation - UNIQUE FEATURE."""
        self.display_header()
        self.menu_handler.display_header("🤖 AI Threat Correlation")

        # Refresh available models
        ai_correlator._discover_models()
        ai_status = ai_correlator.get_summary()

        if not ai_status['available']:
            self.console.print("\n[red]AI correlation requires ollama library.[/red]")
            self.console.print("[yellow]Install with: pip install ollama[/yellow]")
            self.menu_handler.pause_and_continue()
            return

        if not ai_status['ollama_connected']:
            self.console.print("\n[yellow]⚠️  Ollama is not running[/yellow]")
            self.console.print("\n[dim]Setup instructions:[/dim]")
            self.console.print("  1. Install Ollama: https://ollama.com")
            self.console.print("  2. Pull a model: ollama pull phi3:mini")
            self.console.print("  3. Start Ollama: ollama serve")
            self.console.print("\n" + ai_correlator.get_setup_instructions())
            self.menu_handler.pause_and_continue()
            return

        # Show available models
        available_models = ai_correlator.get_available_models()

        self.console.print(f"\n[bold green]Current Model:[/bold green] {ai_correlator.model}")
        self.console.print(f"[bold green]Available Models:[/bold green] {len(available_models)}")

        if available_models:
            self.console.print("\n[bold]Installed Models:[/bold]")
            for i, model in enumerate(available_models, 1):
                # Check if it's a recommended lightweight model
                is_recommended = any(rec.split(':')[0] in model for rec in ai_correlator.RECOMMENDED_MODELS)
                marker = " [green](recommended)[/green]" if is_recommended else ""
                self.console.print(f"  {i}. {model}{marker}")
        else:
            self.console.print("\n[yellow]No models found. Pull a model with:[/yellow]")
            self.console.print("  ollama pull phi3:mini")

        self.console.print(f"\n[bold green]Previous Analyses:[/bold green] {ai_status['analyses_performed']}")

        self.console.print("\n[bold]AI Threat Correlation Options:[/bold]")
        self.console.print("  [1] Analyze Specific Threat")
        self.console.print("  [2] Correlate Recent Detections")
        self.console.print("  [3] Generate AI Report")
        self.console.print("  [4] Change AI Model")
        self.console.print("  [5] View AI Setup Instructions")
        self.console.print("  [6] Back")

        choice = self.menu_handler.get_menu_choice(["1", "2", "3", "4", "5", "6"])

        if choice == "1":
            asyncio.run(self._ai_analyze_threat())
        elif choice == "2":
            asyncio.run(self._ai_correlate_campaign())
        elif choice == "3":
            self._ai_export_report()
        elif choice == "4":
            self._ai_change_model()
        elif choice == "5":
            self.console.print(ai_correlator.get_setup_instructions())
            self.menu_handler.pause_and_continue()

    def _ai_change_model(self) -> None:
        """Let user select AI model from available models."""
        self.display_header()
        self.menu_handler.display_header("🤖 Select AI Model")

        # Get available models
        available_models = ai_correlator.get_available_models()

        if not available_models:
            self.console.print("\n[red]No models available on Ollama server.[/red]")
            self.console.print("[yellow]Pull a model first: ollama pull phi3:mini[/yellow]")
            self.menu_handler.pause_and_continue()
            return

        self.console.print("\n[bold]Available Models:[/bold]\n")

        for i, model in enumerate(available_models, 1):
            is_current = model == ai_correlator.model
            current_marker = " [green](current)[/green]" if is_current else ""
            is_recommended = any(rec.split(':')[0] in model for rec in ai_correlator.RECOMMENDED_MODELS)
            recommended_marker = " [bold](recommended)[/bold]" if is_recommended else ""
            self.console.print(f"  [{i}] {model}{current_marker}{recommended_marker}")

        self.console.print(f"\n  [0] Cancel")
        self.console.print(f"\n[dim]Recommended for speed: phi3:mini, tinyllama, stablelm2[/dim]\n")

        choice = self.menu_handler.get_menu_choice([str(i) for i in range(len(available_models) + 1)])

        if choice == "0":
            return

        try:
            model_index = int(choice) - 1
            if 0 <= model_index < len(available_models):
                selected_model = available_models[model_index]
                if ai_correlator.set_model(selected_model):
                    self.console.print(f"\n[green]✓ Model changed to: {selected_model}[/green]")
                    self.console.print(f"[dim]This model will be used for all AI threat analysis.[/dim]")
                else:
                    self.console.print(f"[red]Failed to set model: {selected_model}[/red]")
        except (ValueError, IndexError):
            self.console.print("[red]Invalid selection.[/red]")

        self.menu_handler.pause_and_continue()

    async def _ai_analyze_threat(self) -> None:
        """AI analyze a specific threat."""
        self.console.print("\n[bold green]Enter threat file path:[/bold green]")
        file_path = self.console.input("File path: ")
        path = Path(file_path.strip())

        if not path.exists():
            self.console.print("[red]File not found.[/red]")
            return

        self.console.print("\n[bold green]Analyzing with AI...[/bold green]")

        # Perform scan first
        result = enhanced_scanner.scan_file(path)

        # AI analysis
        analysis = await ai_correlator.analyze_threat(
            file_path=str(path),
            threat_name=result.threat_name or "Unknown",
            scan_results={
                'status': result.status.value,
                'file_type': result.file_type,
                'file_size': result.file_size,
                'engines': ['enhanced']
            },
            yara_matches=[m.rule_name for m in result.yara_matches],
            heuristic_score=result.heuristic_score
        )

        # Display results
        self.console.print(f"\n[bold]AI Analysis Results:[/bold]")
        self.console.print(f"  Correlation: {analysis.correlation.value}")
        self.console.print(f"  Confidence: {analysis.confidence}%")
        self.console.print(f"  Model: {analysis.model_used}")
        self.console.print(f"  Analysis Time: {analysis.analysis_time:.2f}s")

        if analysis.ai_summary:
            self.console.print(f"\n[bold green]AI Summary:[/bold green]")
            self.console.print(f"[dim]{analysis.ai_summary}[/dim]")

        if analysis.remediation_steps:
            self.console.print(f"\n[yellow]Remediation Steps:[/yellow]")
            for i, step in enumerate(analysis.remediation_steps[:5], 1):
                self.console.print(f"  {i}. {step}")

        self.menu_handler.pause_and_continue()

    async def _ai_correlate_campaign(self) -> None:
        """AI correlate threats into campaign."""
        self.console.print("\n[bold green]Correlating recent detections...[/bold green]")

        # Get recent scan results from database
        scan_history = signature_db.get_scan_history(limit=10)

        if not scan_history:
            self.console.print("[yellow]No recent detections to correlate.[/yellow]")
            return

        # Create mock analyses for correlation
        mock_analyses = []
        for scan in scan_history:
            if scan.get('threats_found', 0) > 0:
                analysis = AIThreatAnalysis(
                    threat_id=str(scan.get('id', 'unknown')),
                    file_path="unknown",
                    threat_name="Detected Threat",
                    correlation=ThreatCorrelation.ISOLATED,
                    confidence=50,
                    related_threats=[],
                    attack_pattern=None,
                    threat_actor=None,
                    ioc_indicators=[],
                    remediation_steps=[],
                    ai_summary="",
                    model_used=ai_correlator.model,
                    analysis_time=0
                )
                mock_analyses.append(analysis)

        if len(mock_analyses) < 2:
            self.console.print("[yellow]Need at least 2 detections for correlation.[/yellow]")
            return

        # Run AI correlation
        campaign = await ai_correlator.correlate_campaign(mock_analyses)

        if campaign:
            self.console.print(f"\n[bold]Campaign Analysis:[/bold]")
            self.console.print(f"  Campaign ID: {campaign.campaign_id}")
            self.console.print(f"  Threats Analyzed: {campaign.threats_analyzed}")
            self.console.print(f"  Confidence: {campaign.correlation_confidence}%")
            self.console.print(f"  Attack Vector: {campaign.attack_vector}")

            if campaign.ai_generated_report:
                self.console.print(f"\n[bold green]AI Report:[/bold green]")
                self.console.print(f"[dim]{campaign.ai_generated_report[:500]}...[/dim]")

        self.menu_handler.pause_and_continue()

    def _ai_export_report(self) -> None:
        """Export AI analysis report."""
        from datetime import datetime
        filename = f"ai_threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        report_path = Path.home() / filename

        if ai_correlator.export_ai_report(report_path):
            self.console.print(f"[green]AI report saved to: {report_path}[/green]")
        else:
            self.console.print("[red]Failed to export AI report.[/red]")

        self.menu_handler.pause_and_continue()
    
    def handle_realtime_protection(self) -> None:
        """Handle real-time protection settings."""
        self.display_header()
        self.menu_handler.display_header("🛡️ Real-time Protection")

        status = realtime_protection.get_status()

        # Check current status and prompt user
        if status['status'] == 'running':
            self.console.print(f"\n[bold green]✓ Real-time Protection is RUNNING[/bold green]")
            self.console.print("[dim]Your system is being actively monitored for threats.[/dim]\n")
        elif status['status'] == 'paused':
            self.console.print(f"\n[yellow]⚠ Real-time Protection is PAUSED[/yellow]")
            self.console.print("[dim]Monitoring is temporarily disabled.[/dim]\n")
        else:
            self.console.print(f"\n[bold red]✗ Real-time Protection is STOPPED[/bold red]")
            self.console.print("[dim]Your system is NOT being monitored.[/dim]\n")

            # Prompt user to start protection
            self.console.print("[yellow]⚠️  WARNING: Your system is unprotected![/yellow]\n")
            self.console.print("Real-time protection provides:")
            self.console.print("  • Automatic scanning of new files")
            self.console.print("  • Instant threat detection")
            self.console.print("  • Auto-quarantine of malware")
            self.console.print("  • Background monitoring\n")

            if self.console.confirm("[bold]Would you like to START real-time protection now?[/bold]", default=True):
                if realtime_protection.start(background=True):
                    self.console.print("\n[green]✓ Real-time protection started successfully![/green]")
                    status = realtime_protection.get_status()
                else:
                    self.console.print("\n[red]Failed to start real-time protection.[/red]")
            else:
                self.console.print("\n[yellow]Protection remains disabled. You can enable it later.[/yellow]")

        # Show watch paths
        self.console.print(f"\nWatch Paths ({len(status['watch_paths'])}):")
        for path in status['watch_paths'][:5]:
            self.console.print(f"  • {path}")
        if len(status['watch_paths']) > 5:
            self.console.print(f"  ... and {len(status['watch_paths']) - 5} more")

        # Show recent events
        if status['recent_events']:
            self.console.print(f"\nRecent Events ({len(status['events_count'])} total):")
            for event in status['recent_events'][-5:]:
                icon = "🚨" if event['action'] == 'quarantine' else "⚠️" if event['action'] == 'alert' else "ℹ️"
                self.console.print(f"  {icon} {event['type']}: {event['file'][-60:]}")

        self.console.print("\n[bold]Options:[/bold]")

        # Show relevant options based on current status
        if status['status'] == 'running':
            self.console.print("  [1] Stop Protection")
            self.console.print("  [2] Pause Protection")
        elif status['status'] == 'paused':
            self.console.print("  [1] Resume Protection")
            self.console.print("  [2] Stop Protection")
        else:
            self.console.print("  [1] Start Protection")

        self.console.print("  [3] Add Watch Path")
        self.console.print("  [4] Remove Watch Path")
        self.console.print("  [5] Toggle Auto-Quarantine")
        self.console.print("  [6] Start as Daemon/Service")
        self.console.print("  [7] View Event Log")
        self.console.print("  [8] Back")

        choice = self.menu_handler.get_menu_choice(["1", "2", "3", "4", "5", "6", "7", "8"])

        # Handle start/stop/pause based on current status
        if status['status'] == 'running':
            if choice == "1":
                if self.console.confirm("Stop real-time protection?", default=False):
                    realtime_protection.stop()
                    self.console.print("[yellow]Protection stopped.[/yellow]")
            elif choice == "2":
                realtime_protection.pause()
                self.console.print("[yellow]Protection paused.[/yellow]")
        elif status['status'] == 'paused':
            if choice == "1":
                realtime_protection.resume()
                self.console.print("[green]Protection resumed.[/green]")
            elif choice == "2":
                if self.console.confirm("Stop real-time protection?", default=False):
                    realtime_protection.stop()
                    self.console.print("[yellow]Protection stopped.[/yellow]")
        else:
            if choice == "1":
                if realtime_protection.start(background=True):
                    self.console.print("[green]Protection started.[/green]")

        # Other options
        if status['status'] != 'running' and choice in ["2"] and status['status'] in ['running', 'paused']:
            pass  # Already handled above
        elif choice == "3":
            path = self.console.input("Enter path to watch: ")
            if realtime_protection.add_watch_path(path):
                self.console.print("[green]Path added.[/green]")
        elif choice == "4":
            path = self.console.input("Enter path to remove: ")
            if realtime_protection.remove_watch_path(path):
                self.console.print("[green]Path removed.[/green]")
        elif choice == "5":
            current = settings.get("quarantine.auto_quarantine", False)
            settings.set("quarantine.auto_quarantine", not current)
            settings.save()
            self.console.print(f"Auto-quarantine {'enabled' if not current else 'disabled'}.")
        elif choice == "6":
            if protection_daemon.start_daemon():
                self.console.print("[green]Protection daemon started.[/green]")
                self.console.print(f"[dim]PID: {protection_daemon.get_pid()}[/dim]")
        elif choice == "7":
            events = realtime_protection.get_events(limit=20)
            if events:
                self.console.print(f"\n[bold]Recent Events ({len(events)}):[/bold]")
                for event in events:
                    self.console.print(f"  {event['timestamp'][:19]} - {event['type']}: {event['action']}")
            else:
                self.console.print("[dim]No events recorded.[/dim]")

        self.menu_handler.pause_and_continue()
    
    def handle_update_database(self) -> None:
        """Handle database update."""
        self.display_header()
        self.menu_handler.display_header("📡 Update Database")
        
        self.console.print("\n[bold green]Updating threat signatures...[/bold green]\n")
        
        def on_progress(source: str, status: str) -> None:
            icon = "[green]✓[/green]" if "complete" in status.lower() else "[red]✗[/red]"
            self.console.print(f"  {icon} {source}: {status}")
        
        db_updater.set_progress_callback(on_progress)
        asyncio.run(db_updater.update_all())
        
        stats = signature_db.get_database_stats()
        self.console.print(f"\n[bold green]Total signatures: {stats.get('total_signatures', 0)}[/bold green]")
        self.menu_handler.pause_and_continue()
    
    def handle_quarantine(self) -> None:
        """Handle quarantine management."""
        self.display_header()
        self.menu_handler.display_header("📦 Quarantine")
        
        entries = quarantine_manager.get_all_entries()
        
        if not entries:
            self.console.print("\n[yellow]Quarantine is empty.[/yellow]")
        else:
            self.console.print(f"\n[bold green]Quarantined: {len(entries)} files[/bold green]\n")
            for entry in entries[:10]:
                self.console.print(f"  [green]{entry.id}[/green] | {entry.threat_name}")
        
        self.console.print("\n[bold]Options:[/bold]")
        self.console.print("  [1] Restore")
        self.console.print("  [2] Delete")
        self.console.print("  [3] Empty All")
        self.console.print("  [4] Back")
        
        choice = self.menu_handler.get_menu_choice(["1", "2", "3", "4"])
        
        if choice == "1":
            entry_id = self.console.input("Entry ID: ")
            quarantine_manager.restore_file(entry_id)
        elif choice == "2":
            entry_id = self.console.input("Entry ID: ")
            quarantine_manager.delete_from_quarantine(entry_id)
        elif choice == "3":
            if self.console.confirm("[yellow]Empty all quarantine?[/yellow]", default=False):
                quarantine_manager.empty_quarantine()
        
        self.menu_handler.pause_and_continue()
    
    def handle_settings(self) -> None:
        """Handle settings."""
        self.display_header()
        self.menu_handler.display_header("⚙️ Settings")
        
        self.console.print("\n[bold]Current Settings:[/bold]")
        self.console.print(f"  Auto-update: {settings.get('updates.auto_update', False)}")
        self.console.print(f"  Scan Archives: {settings.get('scan.scan_archives', True)}")
        self.console.print(f"  Auto-Quarantine: {settings.get('quarantine.auto_quarantine', False)}")
        
        self.console.print("\n[bold]Options:[/bold]")
        self.console.print("  [1] Configure API Keys")
        self.console.print("  [2] Toggle Auto-Update")
        self.console.print("  [3] Manage Exclusions")
        self.console.print("  [4] Back")
        
        choice = self.menu_handler.get_menu_choice(["1", "2", "3", "4"])
        
        if choice == "1":
            self._configure_api_keys()
        elif choice == "2":
            current = settings.get("updates.auto_update", False)
            settings.set("updates.auto_update", not current)
            settings.save()
        elif choice == "3":
            self._manage_exclusions()
    
    def _configure_api_keys(self) -> None:
        """Configure API keys."""
        self.display_header()
        self.menu_handler.display_header("🔑 API Keys")
        
        self.console.print("\n[yellow]Configure API keys for cloud services:[/yellow]\n")
        
        vt = self.console.input("VirusTotal API Key: ")
        if vt.strip():
            settings.set_api_key("virustotal", vt.strip())
        
        ha = self.console.input("Hybrid Analysis API Key: ")
        if ha.strip():
            settings.set_api_key("hybrid_analysis", ha.strip())
        
        settings.save()
        self.console.print("[green]Keys saved.[/green]")
    
    def _manage_exclusions(self) -> None:
        """Manage exclusions."""
        self.display_header()
        self.menu_handler.display_header("🚫 Exclusions")
        
        exclusions = settings.get_excluded_patterns()
        
        if exclusions:
            for pattern in exclusions:
                self.console.print(f"  • {pattern}")
        
        self.console.print("\n[bold]Options:[/bold]")
        self.console.print("  [1] Add")
        self.console.print("  [2] Remove")
        self.console.print("  [3] Back")
        
        choice = self.menu_handler.get_menu_choice(["1", "2", "3"])
        
        if choice == "1":
            pattern = self.console.input("Pattern: ")
            settings.add_exclusion(pattern.strip())
            settings.save()
        elif choice == "2":
            pattern = self.console.input("Pattern to remove: ")
            settings.remove_exclusion(pattern.strip())
            settings.save()
    
    def run(self) -> None:
        """Run the main application loop."""
        logger.info("Green Mold Cure Ultimate with AI started")

        while self.running:
            self.display_header()
            self.menu_handler.display_main_menu()

            self.console.print("\n[dim]Enter number to select option[/dim]\n")

            choice = self.menu_handler.get_menu_choice([str(i) for i in range(1, 12)])

            match choice:
                case "1":
                    self.handle_quick_scan()
                case "2":
                    self.handle_full_scan()
                case "3":
                    self.handle_process_scan()
                case "4":
                    self.handle_sandbox_scan()
                case "5":
                    self.handle_cloud_scan()
                case "6":
                    self.handle_ai_correlation()
                case "7":
                    self.handle_realtime_protection()
                case "8":
                    self.handle_update_database()
                case "9":
                    self.handle_quarantine()
                case "10":
                    self.handle_settings()
                case "11":
                    if self.menu_handler.confirm_exit():
                        self.running = False

        logger.info("Green Mold Cure Ultimate with AI exited")
        self.console.print("\n[bold green]Stay protected with AI-powered security! Goodbye.[/bold green]\n")


def main():
    """Main entry point."""
    try:
        app = GreenMoldCureUltimate()
        app.run()
    except KeyboardInterrupt:
        print("\n\n[yellow]Interrupted.[/yellow]")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Application error: {e}")
        print(f"\n[red]Error: {e}[/red]")
        print("[yellow]Check logs: ~/.green_mold_cure/logs/[/yellow]")
        sys.exit(1)


if __name__ == "__main__":
    main()
