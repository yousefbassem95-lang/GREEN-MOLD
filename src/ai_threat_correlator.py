"""
AI Threat Correlation Engine for Green Mold Cure.
UNIQUE FEATURE: Local AI-powered threat intelligence correlation.

This feature uses local LLM models (Ollama, etc.) to:
- Correlate threats across multiple scan results
- Generate human-readable threat reports
- Identify attack patterns and campaigns
- Provide contextual threat intelligence
- Suggest remediation steps based on threat context

NO API KEYS REQUIRED - Runs 100% locally with small models (1-3B parameters)
"""

import json
import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    ollama = None

from utils.logger import logger
from utils.platform import platform_info


class ThreatCorrelation(Enum):
    """Threat correlation types."""
    ISOLATED = "isolated"  # Single threat, no connection
    RELATED = "related"  # Related to other threats
    CAMPAIGN = "campaign"  # Part of larger campaign
    APT = "apt"  # Advanced Persistent Threat indicators
    OPPORTUNISTIC = "opportunistic"  # Common malware


@dataclass
class AIThreatAnalysis:
    """AI-generated threat analysis."""
    threat_id: str
    file_path: str
    threat_name: str
    correlation: ThreatCorrelation
    confidence: float  # 0-100
    related_threats: List[str]
    attack_pattern: Optional[str]
    threat_actor: Optional[str]
    ioc_indicators: List[str]
    remediation_steps: List[str]
    ai_summary: str
    model_used: str
    analysis_time: float


@dataclass
class CampaignReport:
    """AI-generated campaign report."""
    campaign_id: str
    threats_analyzed: int
    correlation_confidence: float
    attack_vector: str
    threat_actor_profile: Optional[str]
    timeline: List[str]
    affected_systems: List[str]
    recommendations: List[str]
    ai_generated_report: str


class AIThreatCorrelator:
    """
    AI-powered threat correlation engine.
    
    UNIQUE FEATURE: Uses local LLM to correlate threats and generate
    intelligence reports that no other antivirus provides.
    
    Supported Local AI Backends:
    - Ollama (recommended) - phi3, tinyllama, stablelm2 (1-3B models)
    - LM Studio - Local API compatible with OpenAI
    - LocalAI - Self-hosted OpenAI-compatible API
    """
    
    # Lightweight models for local AI (1-3B parameters)
    RECOMMENDED_MODELS = [
        "phi3:mini",        # 3.8B - Microsoft's efficient model
        "tinyllama:1.1b",   # 1.1B - Very fast
        "stablelm2:1.6b",   # 1.6B - Stable AI
        "qwen2:1.5b",       # 1.5B - Alibaba's model
        "gemma:2b",         # 2B - Google's lightweight model
    ]
    
    # System prompt for threat analysis
    THREAT_ANALYSIS_PROMPT = """You are an expert cybersecurity threat analyst. Analyze the following threat detection data and provide a structured assessment.

THREAT DATA:
{threat_data}

Provide your analysis in JSON format with these fields:
{{
    "correlation": "isolated|related|campaign|apt|opportunistic",
    "confidence": 0-100,
    "related_threats": ["list of potentially related threats"],
    "attack_pattern": "description of attack pattern if identified",
    "threat_actor": "potential threat actor if identifiable, otherwise null",
    "ioc_indicators": ["list of IOCs to look for"],
    "remediation_steps": ["step 1", "step 2", ...],
    "summary": "2-3 sentence executive summary"
}}

Be concise and actionable. Focus on practical security guidance."""
    
    # Campaign correlation prompt
    CAMPAIGN_PROMPT = """You are a threat intelligence analyst. Analyze these multiple threat detections and determine if they are part of a coordinated campaign.

THREAT DETECTIONS:
{threats_data}

Provide your analysis in JSON format:
{{
    "is_campaign": true/false,
    "confidence": 0-100,
    "attack_vector": "initial infection vector",
    "threat_actor_profile": "description if identifiable",
    "timeline": ["event 1", "event 2", ...],
    "affected_systems": ["systems affected"],
    "recommendations": ["priority remediation steps"],
    "report": "detailed narrative report (3-4 paragraphs)"
}}

Look for patterns in:
- Timing of detections
- Common malware families
- Shared infrastructure
- Attack techniques (MITRE ATT&CK)"""
    
    def __init__(self, model: Optional[str] = None):
        """
        Initialize AI threat correlator.
        
        Args:
            model: Ollama model name (uses recommended if None)
        """
        self.model = model or "phi3:mini"
        self.available_models: List[str] = []
        self.analysis_results: List[AIThreatAnalysis] = []
        self.campaign_reports: List[CampaignReport] = []
        self._ollama_available = OLLAMA_AVAILABLE
        
        if self._ollama_available:
            self._discover_models()
    
    def _discover_models(self) -> None:
        """Discover available Ollama models."""
        try:
            models = ollama.list()
            self.available_models = [m['name'] for m in models.get('models', [])]
            logger.info(f"Found {len(self.available_models)} Ollama models: {self.available_models}")
        except Exception as e:
            logger.debug(f"Ollama model discovery failed: {e}")
            self.available_models = []

    def get_available_models(self) -> List[str]:
        """
        Get list of available models from Ollama server.

        Returns:
            List of model names
        """
        self._discover_models()
        return self.available_models

    def set_model(self, model_name: str) -> bool:
        """
        Set the model to use for AI correlation.

        Args:
            model_name: Name of the model to use

        Returns:
            True if model was set successfully
        """
        if model_name in self.available_models or model_name in self.RECOMMENDED_MODELS:
            self.model = model_name
            logger.info(f"AI model set to: {model_name}")
            return True
        return False
    
    def is_available(self) -> bool:
        """Check if AI correlation is available."""
        return self._ollama_available
    
    def check_ollama_connection(self) -> bool:
        """Check if Ollama is running and accessible."""
        if not self._ollama_available:
            return False
        
        try:
            ollama.list()
            return True
        except Exception:
            return False
    
    def get_setup_instructions(self) -> str:
        """Get instructions for setting up Ollama."""
        return """
╔═══════════════════════════════════════════════════════════════════╗
║     AI THREAT CORRELATION - SETUP INSTRUCTIONS                   ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║  This feature uses LOCAL AI - NO API KEYS REQUIRED!              ║
║                                                                   ║
║  Step 1: Install Ollama                                          ║
║  ─────────────────────────                                       ║
║  Linux:     curl -fsSL https://ollama.com/install.sh | sh        ║
║  Windows:   Download from https://ollama.com                     ║
║  macOS:     brew install ollama                                  ║
║                                                                   ║
║  Step 2: Pull a lightweight model (1-3B parameters)             ║
║  ─────────────────────────────────────────────                   ║
║  ollama pull phi3:mini        # Recommended (3.8B)              ║
║  ollama pull tinyllama:1.1b   # Fastest (1.1B)                   ║
║  ollama pull stablelm2:1.6b   # Balanced (1.6B)                  ║
║                                                                   ║
║  Step 3: Start Ollama (usually auto-starts)                     ║
║  ───────────────────────────────────────                         ║
║  ollama serve                                                      ║
║                                                                   ║
║  Step 4: Run AI Threat Correlation                              ║
║  ─────────────────────────────────────                           ║
║  Select option in Green Mold Cure menu                          ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"""
    
    async def analyze_threat(
        self,
        file_path: str,
        threat_name: str,
        scan_results: Dict[str, Any],
        yara_matches: List[str],
        heuristic_score: int
    ) -> AIThreatAnalysis:
        """
        Analyze a single threat using local AI.
        
        Args:
            file_path: Path to detected threat
            threat_name: Name of detected threat
            scan_results: Scan result details
            yara_matches: YARA rule matches
            heuristic_score: Heuristic analysis score
            
        Returns:
            AI-generated threat analysis
        """
        import time
        start_time = time.time()
        
        import uuid
        analysis_id = str(uuid.uuid4())[:8]
        
        # Prepare threat data for AI
        threat_data = {
            "file_path": file_path,
            "threat_name": threat_name,
            "scan_results": scan_results,
            "yara_matches": yara_matches[:10],  # Limit context
            "heuristic_score": heuristic_score,
            "detection_engines": scan_results.get('engines', []),
            "file_type": scan_results.get('file_type', 'unknown'),
            "file_size": scan_results.get('file_size', 0),
        }
        
        # Generate AI analysis
        if self._ollama_available and self.check_ollama_connection():
            ai_result = await self._query_ollama(threat_data)
        else:
            ai_result = self._fallback_analysis(threat_data)
        
        # Create analysis result
        analysis = AIThreatAnalysis(
            threat_id=analysis_id,
            file_path=file_path,
            threat_name=threat_name,
            correlation=ThreatCorrelation(ai_result.get('correlation', 'isolated')),
            confidence=float(ai_result.get('confidence', 50)),
            related_threats=ai_result.get('related_threats', []),
            attack_pattern=ai_result.get('attack_pattern'),
            threat_actor=ai_result.get('threat_actor'),
            ioc_indicators=ai_result.get('ioc_indicators', []),
            remediation_steps=ai_result.get('remediation_steps', []),
            ai_summary=ai_result.get('summary', 'AI analysis unavailable'),
            model_used=self.model,
            analysis_time=time.time() - start_time
        )
        
        self.analysis_results.append(analysis)
        return analysis
    
    async def _query_ollama(self, threat_data: Dict) -> Dict[str, Any]:
        """
        Query Ollama for threat analysis.
        
        Args:
            threat_data: Threat information
            
        Returns:
            AI analysis result
        """
        try:
            prompt = self.THREAT_ANALYSIS_PROMPT.format(
                threat_data=json.dumps(threat_data, indent=2)
            )
            
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: ollama.chat(
                    model=self.model,
                    messages=[{
                        'role': 'user',
                        'content': prompt
                    }]
                )
            )
            
            # Parse JSON from response
            content = response['message']['content']
            
            # Extract JSON from response (handle markdown code blocks)
            if '```json' in content:
                content = content.split('```json')[1].split('```')[0].strip()
            elif '```' in content:
                content = content.split('```')[1].split('```')[0].strip()
            
            result = json.loads(content)
            return result
            
        except Exception as e:
            logger.debug(f"Ollama analysis failed: {e}")
            return self._fallback_analysis(threat_data)
    
    def _fallback_analysis(self, threat_data: Dict) -> Dict[str, Any]:
        """
        Provide basic analysis when AI is unavailable.
        
        Args:
            threat_data: Threat information
            
        Returns:
            Basic analysis result
        """
        heuristic_score = threat_data.get('heuristic_score', 0)
        yara_count = len(threat_data.get('yara_matches', []))
        
        # Determine correlation based on rules
        if yara_count > 3 or heuristic_score > 70:
            correlation = "related"
            confidence = 60 + min(yara_count * 5, 20)
        elif yara_count > 1 or heuristic_score > 40:
            correlation = "opportunistic"
            confidence = 50
        else:
            correlation = "isolated"
            confidence = 40
        
        return {
            'correlation': correlation,
            'confidence': confidence,
            'related_threats': [],
            'attack_pattern': None,
            'threat_actor': None,
            'ioc_indicators': [threat_data.get('threat_name', 'Unknown')],
            'remediation_steps': [
                'Quarantine the detected file',
                'Run a full system scan',
                'Update threat database',
                'Monitor for reinfection'
            ],
            'summary': f"Detected {threat_data.get('threat_name', 'threat')} with {yara_count} YARA matches and heuristic score of {heuristic_score}/100."
        }
    
    async def correlate_campaign(
        self,
        threat_analyses: List[AIThreatAnalysis]
    ) -> Optional[CampaignReport]:
        """
        Correlate multiple threats to identify campaigns.
        
        Args:
            threat_analyses: List of threat analyses
            
        Returns:
            Campaign report if correlation found
        """
        if len(threat_analyses) < 2:
            return None
        
        import uuid
        campaign_id = str(uuid.uuid4())[:8]
        
        # Prepare data for AI
        threats_data = []
        for analysis in threat_analyses:
            threats_data.append({
                'threat_id': analysis.threat_id,
                'file_path': analysis.file_path,
                'threat_name': analysis.threat_name,
                'correlation': analysis.correlation.value,
                'confidence': analysis.confidence,
                'attack_pattern': analysis.attack_pattern,
            })
        
        if self._ollama_available and self.check_ollama_connection():
            ai_result = await self._query_campaign_ai(threats_data)
        else:
            ai_result = self._fallback_campaign(threat_analyses)
        
        report = CampaignReport(
            campaign_id=campaign_id,
            threats_analyzed=len(threat_analyses),
            correlation_confidence=float(ai_result.get('confidence', 50)),
            attack_vector=ai_result.get('attack_vector', 'Unknown'),
            threat_actor_profile=ai_result.get('threat_actor_profile'),
            timeline=ai_result.get('timeline', []),
            affected_systems=ai_result.get('affected_systems', []),
            recommendations=ai_result.get('recommendations', []),
            ai_generated_report=ai_result.get('report', ''),
        )
        
        self.campaign_reports.append(report)
        return report
    
    async def _query_campaign_ai(self, threats_data: List[Dict]) -> Dict[str, Any]:
        """Query Ollama for campaign correlation."""
        try:
            prompt = self.CAMPAIGN_PROMPT.format(
                threats_data=json.dumps(threats_data, indent=2)
            )
            
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: ollama.chat(
                    model=self.model,
                    messages=[{'role': 'user', 'content': prompt}]
                )
            )
            
            content = response['message']['content']
            
            # Extract JSON
            if '```json' in content:
                content = content.split('```json')[1].split('```')[0].strip()
            
            return json.loads(content)
            
        except Exception as e:
            logger.debug(f"Campaign AI analysis failed: {e}")
            return self._fallback_campaign([])
    
    def _fallback_campaign(self, analyses: List[AIThreatAnalysis]) -> Dict[str, Any]:
        """Fallback campaign correlation without AI."""
        if not analyses:
            return {
                'confidence': 0,
                'attack_vector': 'Unknown',
                'threat_actor_profile': None,
                'timeline': [],
                'affected_systems': [],
                'recommendations': ['Run full system scan'],
                'report': 'AI correlation unavailable.'
            }
        
        # Simple rule-based correlation
        threat_names = [a.threat_name for a in analyses]
        unique_threats = set(threat_names)
        
        if len(unique_threats) == 1:
            confidence = 80
            attack_vector = 'Single threat family detected across multiple files'
        elif len(unique_threats) <= 3:
            confidence = 60
            attack_vector = 'Multiple related threats detected'
        else:
            confidence = 40
            attack_vector = 'Multiple unrelated threats (opportunistic infections)'
        
        return {
            'confidence': confidence,
            'attack_vector': attack_vector,
            'threat_actor_profile': None,
            'timeline': [f"Detected {len(analyses)} threats"],
            'affected_systems': ['Local system'],
            'recommendations': [
                'Quarantine all detected threats',
                'Full system scan recommended',
                'Check for persistence mechanisms',
                'Monitor network traffic'
            ],
            'report': f"Analysis identified {len(unique_threats)} unique threat families across {len(analyses)} detections. {'This pattern suggests a coordinated infection.' if confidence > 60 else 'Threats appear to be opportunistic infections.'}"
        }
    
    def export_ai_report(self, output_path: Path) -> bool:
        """Export AI analysis report."""
        try:
            with open(output_path, 'w') as f:
                f.write("╔═══════════════════════════════════════════════════════════╗\n")
                f.write("║     GREEN MOLD CURE - AI THREAT INTELLIGENCE REPORT      ║\n")
                f.write("╚═══════════════════════════════════════════════════════════╝\n\n")
                f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
                f.write(f"Model Used: {self.model}\n")
                f.write(f"Total Analyses: {len(self.analysis_results)}\n")
                f.write(f"Campaign Reports: {len(self.campaign_reports)}\n\n")
                
                for analysis in self.analysis_results:
                    f.write("─" * 60 + "\n")
                    f.write(f"Threat ID: {analysis.threat_id}\n")
                    f.write(f"File: {analysis.file_path}\n")
                    f.write(f"Threat: {analysis.threat_name}\n")
                    f.write(f"Correlation: {analysis.correlation.value}\n")
                    f.write(f"Confidence: {analysis.confidence}%\n")
                    f.write(f"Model: {analysis.model_used}\n")
                    f.write(f"Analysis Time: {analysis.analysis_time:.2f}s\n\n")
                    f.write(f"AI Summary:\n{analysis.ai_summary}\n\n")
                    
                    if analysis.remediation_steps:
                        f.write("Remediation:\n")
                        for i, step in enumerate(analysis.remediation_steps, 1):
                            f.write(f"  {i}. {step}\n")
                        f.write("\n")
                
                if self.campaign_reports:
                    f.write("\n" + "═" * 60 + "\n")
                    f.write("CAMPAIGN ANALYSIS\n")
                    f.write("═" * 60 + "\n\n")
                    
                    for report in self.campaign_reports:
                        f.write(f"Campaign ID: {report.campaign_id}\n")
                        f.write(f"Threats Analyzed: {report.threats_analyzed}\n")
                        f.write(f"Confidence: {report.correlation_confidence}%\n")
                        f.write(f"Attack Vector: {report.attack_vector}\n\n")
                        f.write(f"AI Report:\n{report.ai_generated_report}\n\n")
            
            return True
        except Exception as e:
            logger.error(f"Failed to export AI report: {e}")
            return False
    
    def get_summary(self) -> Dict[str, Any]:
        """Get AI correlation summary."""
        return {
            'available': self.is_available(),
            'ollama_connected': self.check_ollama_connection(),
            'model': self.model,
            'available_models': self.available_models,
            'analyses_performed': len(self.analysis_results),
            'campaigns_identified': len(self.campaign_reports),
            'high_confidence_threats': len([
                a for a in self.analysis_results 
                if a.confidence >= 70
            ]),
        }


# Global AI threat correlator instance
ai_correlator = AIThreatCorrelator()
