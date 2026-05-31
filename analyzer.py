import math
import re
from urllib.parse import urlparse

class HeuristicNLPAnalyzer:

    # Pre-compiling static regex patterns at the class level for maximum thread speed
    _LINK_PATTERN = re.compile(r'<a\s+(?:[^>]*?\s+)?href="([^"]*)"[^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
    _HTTP_MATCH = re.compile(r'^https?://', re.IGNORECASE)
    _HTTP_SUB = re.compile(r'(?i)http')

    def __init__(self):
        # Phase 2: Lexical Threat Matrix
        self.threat_lexicon = {
            r'\b(urgent|immediate|action required|24 hours)\b': 3.0,
            r'\b(suspend|restricted|locked|terminated)\b': 3.5,
            r'\b(password|credentials|login details)\b': 2.0,
            r'\b(verify|validate|update your account)\b': 2.5,
            r'\b(invoice|payment receipt|transaction)\b': 1.5,
            r'\b(dear customer|dear user)\b': 1.0 
        }
        
        self.crypto_patterns = {
            'Bitcoin': r'\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b',
            'Ethereum': r'\b0x[a-fA-F0-9]{40}\b'
        }

    @classmethod
    def defang_observable(cls, text):
        """
        Sanitizes URLs and IPs to prevent accidental execution.
        Converts 'http' to 'hxxp' and '.' to '[.]'
        """
        if not isinstance(text, str):
            return text
            
        safe_text = cls._HTTP_SUB.sub('hxxp', text)
        return safe_text.replace('.', '[.]')

    def _calculate_entropy(self, text):
        if not text:
            return 0.0
        text_len = len(text)
        probabilities = [text.count(c) / text_len for c in set(text)]
        return -sum(p * math.log2(p) for p in probabilities)

    def _analyze_links(self, html_content):
        flags = []
        score = 0.0
        
        for match in self._LINK_PATTERN.finditer(html_content):
            actual_url = match.group(1).strip()
            visible_text = re.sub(r'<[^>]+>', '', match.group(2)).strip()

            if self._HTTP_MATCH.match(visible_text):
                visible_domain = urlparse(visible_text).netloc
                actual_domain = urlparse(actual_url).netloc
                
                if visible_domain and actual_domain and visible_domain != actual_domain:
                    score += 5.0
                    safe_visible = self.defang_observable(visible_domain)
                    safe_actual = self.defang_observable(actual_domain)
                    flags.append(f"Critical Structure: Link masking. Text says '{safe_visible}' but points to '{safe_actual}' (+5.0 pts).")
                    
        return score, flags

    def _analyze_html_evasion(self, html_content):
        flags = []
        score = 0.0
        evasion_patterns = [
            r'display\s*:\s*none',
            r'visibility\s*:\s*hidden',
            r'font-size\s*:\s*0\b',
            r'opacity\s*:\s*0\b',
            r'color\s*:\s*transparent'
        ]
        
        for pattern in evasion_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                score += 4.0
                flags.append("Critical Structure: Invisible HTML evasion tactics detected (e.g., 'display: none') (+4.0 pts).")
                break
                
        return score, flags

    def _generate_intent_summary(self, flags, risk_level):
        if risk_level == "Low":
            return "Payload appears benign. No definitive malicious intent detected."

        flags_text = " ".join(flags).lower()
        goals = []
        
        if any(w in flags_text for w in ['cryptocurrency', 'bitcoin', 'ethereum']):
            goals.append("extort cryptocurrency")
        if any(w in flags_text for w in ['password', 'credentials', 'login']):
            goals.append("harvest user credentials")
        elif any(w in flags_text for w in ['invoice', 'payment']):
            goals.append("commit financial fraud")
        if any(w in flags_text for w in ['urgent', 'suspend', 'immediate']):
            goals.append("manufacture artificial urgency")

        if not goals:
            goals.append("execute a generic social engineering attack")

        mechanisms = []
        if 'masking' in flags_text:
            mechanisms.append("deceptive routing via masked links")
        if 'header' in flags_text:
            mechanisms.append("spoofing trusted sender identities")
        if 'entropy' in flags_text:
            mechanisms.append("utilizing high-entropy obfuscation")
        if any(w in flags_text for w in ['evasion', 'invisible']):
            mechanisms.append("embedding invisible HTML to evade static spam filters")

        summary = "This payload attempts to " + " and ".join(goals)
        if mechanisms:
            summary += " by " + " and ".join(mechanisms) + "."
        else:
            summary += "."
            
        return summary[0].upper() + summary[1:]

    def process_email(self, headers, text_body, html_body=""):
        """Runs all phases and records sub-scores for telemetry tracking."""
        phase_1_score = 0.0
        phase_2_score = 0.0
        phase_3_score = 0.0
        phase_4_score = 0.0
        analysis_flags = []

        # Phase 1: Header Anomalies
        from_header = headers.get('From', 'N/A')
        reply_to = headers.get('Reply-To', 'N/A')
        auth_results = headers.get('Authentication-Results', '')
        auth_results_lower = auth_results.lower() if isinstance(auth_results, str) else str(auth_results).lower()

        if from_header != 'N/A' and reply_to != 'N/A':
            if from_header not in reply_to:
                phase_1_score += 4.5
                analysis_flags.append("Critical Header: 'From' and 'Reply-To' addresses do not match (+4.5 pts).")
        
        if 'fail' in auth_results_lower or 'softfail' in auth_results_lower:
            phase_1_score += 3.0
            analysis_flags.append("Warning Header: SPF, DKIM, or DMARC authentication failed (+3.0 pts).")

        # Phase 2: Lexical Scoring
        text_lower = text_body.lower()
        for pattern, weight in self.threat_lexicon.items():
            matches = len(re.findall(pattern, text_lower))
            if matches > 0:
                phase_2_score += (matches * weight)
                analysis_flags.append(f"Lexical hit: Matches '{pattern}' (+{matches * weight} pts).")
                
        # Phase 2.5: Cryptocurrency Hunter
        for crypto_type, pattern in self.crypto_patterns.items():
            if re.search(pattern, text_body):
                phase_2_score += 6.0
                analysis_flags.append(f"Critical Lexical: {crypto_type} wallet address detected. Highly indicative of extortion (+6.0 pts).")

        # Phase 3: Obfuscation / Entropy
        text_entropy = self._calculate_entropy(text_body)
        if text_entropy > 5.5:
            phase_3_score += 4.0
            analysis_flags.append(f"High text entropy ({text_entropy:.2f}): Likely base64 or obfuscated payload (+4.0 pts).")

        # Phase 4: Structural Phishing Indicators
        if html_body:
            link_score, link_flags = self._analyze_links(html_body)
            phase_4_score += link_score
            analysis_flags.extend(link_flags)
            
            evasion_score, evasion_flags = self._analyze_html_evasion(html_body)
            phase_4_score += evasion_score
            analysis_flags.extend(evasion_flags)

        total_score = phase_1_score + phase_2_score + phase_3_score + phase_4_score

        if total_score >= 8.0:
            risk_level = "High"
        elif total_score >= 4.0:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        safe_headers = {}
        for key, value in headers.items():
            safe_headers[key] = self.defang_observable(str(value))

        intent_summary = self._generate_intent_summary(analysis_flags, risk_level)

        return {
            "threat_score": total_score,
            "risk_level": risk_level,
            "flags": analysis_flags,  
            "headers": safe_headers,
            "ai_summary": intent_summary,
            "metrics": {
                "headers": phase_1_score,
                "lexical": phase_2_score,
                "obfuscation": phase_3_score,
                "structure": phase_4_score
            }
        }