"""
MITRE ATT&CK Technique Extraction Module v2.0

Features:
- P1: Deprecated and revoked technique filtering
- P1: Existence validation against current ATT&CK schema
- P2: Accurate sub-technique name resolution
- P3: Optional LLM-assisted context validation (requires anthropic package + API key)

LLM validation is opt-in via:
1. Issue template toggle (Enable LLM MITRE Validation: Yes)
2. Environment variable: PEAK_ENABLE_LLM_VALIDATION=true
3. API key: ANTHROPIC_API_KEY must be set

Without anthropic package or API key, gracefully falls back to P1+P2 only.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Check for LLM availability
try:
    import anthropic
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    logger.debug("anthropic package not installed - LLM validation disabled")


@dataclass
class MitreTechnique:
    """Single MITRE ATT&CK technique."""
    id: str
    name: str
    tactics: list[str] = field(default_factory=list)
    source: str = "extracted"  # extracted, llm_suggested
    confidence: str = ""  # For LLM-suggested techniques


@dataclass
class MitreWarning:
    """Warning about a technique that was filtered or flagged."""
    type: str  # deprecated, revoked, invalid, context_mismatch
    id: str
    name: str = ""
    message: str = ""
    suggested_replacement: str = ""


@dataclass
class MitreSection:
    """Complete MITRE extraction result."""
    enabled: bool
    source: str
    techniques: list[MitreTechnique]
    warnings: list[MitreWarning] = field(default_factory=list)
    llm_used: bool = False


class MITREExtractor:
    """
    Enhanced MITRE ATT&CK technique extractor with validation.
    
    Validates extracted techniques against the current ATT&CK Enterprise
    framework to filter deprecated, revoked, and invalid technique IDs.
    """
    
    def __init__(self, mitre_json_path: Optional[Path] = None):
        self.mitre_json_path = mitre_json_path
        self.attack_data = None
        self.valid_techniques: set[str] = set()
        self.deprecated_techniques: set[str] = set()
        self.revoked_techniques: set[str] = set()
        self.technique_names: dict[str, str] = {}
        self.technique_tactics: dict[str, list[str]] = {}
        
        if mitre_json_path and Path(mitre_json_path).exists():
            self._load_attack_data()
    
    def _load_attack_data(self):
        """Load and parse MITRE ATT&CK Enterprise JSON."""
        try:
            data = json.loads(self.mitre_json_path.read_text(encoding="utf-8"))
            self.attack_data = data
            
            for obj in data.get("objects", []):
                if obj.get("type") != "attack-pattern":
                    continue
                
                # Extract technique ID
                tech_id = None
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        tech_id = ref.get("external_id")
                        break
                
                if not tech_id:
                    continue
                
                # Categorize by status
                is_deprecated = obj.get("x_mitre_deprecated", False)
                is_revoked = obj.get("revoked", False)
                
                if is_deprecated:
                    self.deprecated_techniques.add(tech_id)
                elif is_revoked:
                    self.revoked_techniques.add(tech_id)
                else:
                    self.valid_techniques.add(tech_id)
                
                # Store name (sub-techniques have their own specific names)
                self.technique_names[tech_id] = obj.get("name", "")
                
                # Store tactics
                tactics = []
                for phase in obj.get("kill_chain_phases", []):
                    if phase.get("kill_chain_name") == "mitre-attack":
                        tactics.append(phase.get("phase_name", ""))
                self.technique_tactics[tech_id] = tactics
            
            logger.info(
                f"Loaded ATT&CK data: {len(self.valid_techniques)} valid, "
                f"{len(self.deprecated_techniques)} deprecated"
            )
            
        except Exception as e:
            logger.error(f"Failed to load ATT&CK data: {e}")
    
    def get_full_name(self, tech_id: str) -> str:
        """
        Get the full technique name, including parent for sub-techniques.
        
        P2: Returns actual sub-technique name (e.g., "Steganography")
        not the parent name (e.g., "Obfuscated Files or Information").
        """
        name = self.technique_names.get(tech_id, "")
        
        if "." in tech_id:
            # Sub-technique - include parent context
            parent_id = tech_id.split(".")[0]
            parent_name = self.technique_names.get(parent_id, "")
            if name and parent_name:
                return f"{parent_name}: {name}"
            return name
        
        return name
    
    def extract_ids_from_text(self, text: str) -> list[str]:
        """Extract technique IDs via regex."""
        ids: list[str] = []
        for tid in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text, flags=re.I):
            tid = tid.upper()
            if tid not in ids:
                ids.append(tid)
        return ids
    
    def extract_by_name(self, text: str, min_length: int = 8) -> list[str]:
        """Extract techniques by searching for technique names in text."""
        found = []
        text_lower = text.lower()
        
        for tech_id, name in self.technique_names.items():
            if not name or len(name) < min_length:
                continue
            
            # Skip deprecated/revoked
            if tech_id in self.deprecated_techniques:
                continue
            if tech_id in self.revoked_techniques:
                continue
            
            # Word boundary search
            pattern = rf"(?<![a-z0-9]){re.escape(name.lower())}(?![a-z0-9])"
            if re.search(pattern, text_lower):
                if tech_id not in found:
                    found.append(tech_id)
        
        return found
    
    def validate(self, technique_ids: list[str]) -> tuple[list[str], list[MitreWarning]]:
        """
        P1: Validate techniques against current ATT&CK schema.
        
        Returns:
            Tuple of (valid_ids, warnings)
        """
        valid = []
        warnings = []
        
        for tech_id in technique_ids:
            if tech_id in self.valid_techniques:
                valid.append(tech_id)
            elif tech_id in self.deprecated_techniques:
                warnings.append(MitreWarning(
                    type="deprecated",
                    id=tech_id,
                    name=self.technique_names.get(tech_id, ""),
                    message=f"{tech_id} is deprecated in current ATT&CK schema"
                ))
            elif tech_id in self.revoked_techniques:
                warnings.append(MitreWarning(
                    type="revoked",
                    id=tech_id,
                    name=self.technique_names.get(tech_id, ""),
                    message=f"{tech_id} has been revoked"
                ))
            else:
                warnings.append(MitreWarning(
                    type="invalid",
                    id=tech_id,
                    message=f"{tech_id} does not exist in ATT&CK schema"
                ))
        
        return valid, warnings
    
    def llm_validate_context(
        self,
        techniques: list[str],
        article_text: str,
        api_key: str = None
    ) -> tuple[list[str], list[MitreWarning], list[MitreTechnique]]:
        """
        P3: Use LLM to validate technique relevance to the attack narrative.
        
        Returns:
            Tuple of (validated_ids, new_warnings, suggested_techniques)
        """
        if not LLM_AVAILABLE:
            logger.debug("LLM not available - skipping context validation")
            return techniques, [], []
        
        api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            logger.debug("No API key - skipping LLM validation")
            return techniques, [], []
        
        # Build technique context for the prompt
        technique_details = []
        for tech_id in techniques:
            name = self.get_full_name(tech_id)
            tactics = self.technique_tactics.get(tech_id, [])
            technique_details.append(
                f"- {tech_id}: {name} (Tactics: {', '.join(tactics) or 'Unknown'})"
            )
        
        # Truncate article text to fit context window
        max_chars = 15000
        truncated_text = article_text[:max_chars]
        if len(article_text) > max_chars:
            truncated_text += "\n\n[Article truncated for analysis]"
        
        prompt = f"""Analyze this threat intelligence article and validate the extracted MITRE ATT&CK techniques.

ARTICLE TEXT:
{truncated_text}

EXTRACTED TECHNIQUES:
{chr(10).join(technique_details)}

TASK:
1. For each extracted technique, determine if it accurately describes behavior in the article
2. Flag techniques that are mentioned but do not match the actual attack chain described
3. Suggest any missing techniques that are clearly demonstrated but not extracted

Common issues to check:
- T1190 (Exploit Public-Facing Application) vs T1203 (Exploitation for Client Execution): T1190 is for server-side exploits, T1203 is for client-side (email attachments, documents)
- Reconnaissance tactics (T1592.x, T1589.x) should only apply if the article describes pre-attack intelligence gathering, not execution
- Process injection sub-techniques should match the specific method described

Respond in this exact JSON format only, no other text:
{{
    "validated": ["T1234", "T1567.001"],
    "flagged": [
        {{"id": "T1190", "reason": "Article describes client-side document exploitation, not server exploit", "suggested_replacement": "T1203"}}
    ],
    "suggested": [
        {{"id": "T1218.009", "reason": "Article describes RegAsm.exe abuse for payload execution", "confidence": "HIGH"}}
    ]
}}"""

        try:
            client = anthropic.Anthropic(api_key=api_key)
            
            response = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            response_text = response.content[0].text
            
            # Extract JSON from response
            json_match = re.search(r"\{[\s\S]*\}", response_text)
            if not json_match:
                logger.warning("Could not parse LLM response as JSON")
                return techniques, [], []
            
            result = json.loads(json_match.group())
            
            # Process results
            validated = result.get("validated", techniques)
            new_warnings = []
            suggested = []
            
            for flagged in result.get("flagged", []):
                new_warnings.append(MitreWarning(
                    type="context_mismatch",
                    id=flagged.get("id", ""),
                    message=flagged.get("reason", "May not match attack context"),
                    suggested_replacement=flagged.get("suggested_replacement", "")
                ))
            
            for sug in result.get("suggested", []):
                tech_id = sug.get("id", "")
                if tech_id and tech_id in self.valid_techniques:
                    suggested.append(MitreTechnique(
                        id=tech_id,
                        name=self.get_full_name(tech_id),
                        tactics=self.technique_tactics.get(tech_id, []),
                        source="llm_suggested",
                        confidence=sug.get("confidence", "MEDIUM")
                    ))
            
            return validated, new_warnings, suggested
            
        except Exception as e:
            logger.error(f"LLM validation failed: {e}")
            return techniques, [], []


def extract_mitre_techniques(
    article_text: str,
    ocr_results: list[dict],
    mitre_json_path: Optional[Path],
    max_techniques: int = 30,
) -> MitreSection:
    """
    Extract MITRE ATT&CK techniques with validation.
    
    This is the main entry point, maintaining backward compatibility
    while adding P1+P2+P3 validation.
    
    Args:
        article_text: Main article/document text
        ocr_results: List of OCR result dicts with 'text' key
        mitre_json_path: Path to enterprise-attack.json
        max_techniques: Maximum techniques to return
        
    Returns:
        MitreSection with techniques and warnings
    """
    combined_text = (article_text or "") + "\n\n" + "\n".join(
        [(r.get("text") or "") for r in (ocr_results or [])]
    )
    
    if not mitre_json_path:
        return MitreSection(
            enabled=False,
            source="(missing enterprise-attack.json)",
            techniques=[],
            warnings=[]
        )
    
    extractor = MITREExtractor(mitre_json_path)
    
    if not extractor.attack_data:
        return MitreSection(
            enabled=False,
            source="(failed to load enterprise-attack.json)",
            techniques=[],
            warnings=[]
        )
    
    # Stage 1: Extract technique IDs
    extracted_ids = extractor.extract_ids_from_text(combined_text)
    
    # Stage 2: Extract by technique name
    name_matches = extractor.extract_by_name(combined_text)
    for tech_id in name_matches:
        if tech_id not in extracted_ids:
            extracted_ids.append(tech_id)
    
    # Stage 3: P1 Validation (deprecated, revoked, invalid)
    valid_ids, warnings = extractor.validate(extracted_ids)
    
    # Stage 4: P3 LLM Validation (if enabled)
    llm_used = False
    suggested_techniques = []
    
    enable_llm = os.environ.get("PEAK_ENABLE_LLM_VALIDATION", "").lower() == "true"
    
    if enable_llm and LLM_AVAILABLE and valid_ids:
        logger.info("Running LLM context validation...")
        validated_ids, llm_warnings, suggested = extractor.llm_validate_context(
            valid_ids, combined_text
        )
        
        if validated_ids != valid_ids or llm_warnings or suggested:
            llm_used = True
            valid_ids = validated_ids
            warnings.extend(llm_warnings)
            suggested_techniques = suggested
    
    # Stage 5: P2 Build final technique list with proper names
    techniques = []
    for tech_id in valid_ids[:max_techniques]:
        techniques.append(MitreTechnique(
            id=tech_id,
            name=extractor.get_full_name(tech_id),
            tactics=extractor.technique_tactics.get(tech_id, [])
        ))
    
    # Add LLM-suggested techniques (if any)
    for sug in suggested_techniques:
        if len(techniques) < max_techniques:
            techniques.append(sug)
    
    return MitreSection(
        enabled=True,
        source=str(mitre_json_path),
        techniques=techniques,
        warnings=warnings,
        llm_used=llm_used
    )


def format_warnings_markdown(warnings: list[MitreWarning]) -> str:
    """
    Format warnings as markdown for report inclusion.
    
    Args:
        warnings: List of MitreWarning objects
        
    Returns:
        Markdown string (empty if no warnings)
    """
    if not warnings:
        return ""
    
    lines = [
        "",
        "### Extraction Warnings",
        "",
        "> The following techniques were flagged during validation. "
        "Review the source to verify accuracy.",
        ""
    ]
    
    for warn in warnings:
        if warn.type == "deprecated":
            if warn.name:
                lines.append(f"- **{warn.id}** ({warn.name}): Deprecated in current ATT&CK schema")
            else:
                lines.append(f"- **{warn.id}**: Deprecated in current ATT&CK schema")
        elif warn.type == "revoked":
            lines.append(f"- **{warn.id}**: Revoked (check ATT&CK for replacement)")
        elif warn.type == "invalid":
            lines.append(f"- **{warn.id}**: Does not exist in ATT&CK Enterprise")
        elif warn.type == "context_mismatch":
            msg = f"- **{warn.id}**: {warn.message}"
            if warn.suggested_replacement:
                msg += f" (consider **{warn.suggested_replacement}** instead)"
            lines.append(msg)
        else:
            lines.append(f"- **{warn.id}**: {warn.message}")
    
    return "\n".join(lines)
