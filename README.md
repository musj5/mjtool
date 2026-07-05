MJTOOL ELITE EDITION v2.6
Advanced URL & Phishing Forensic Analyzer with LIVE AI Threat Analysis
```
    ███╗   ███╗     ██╗████████╗ ██████╗  ██████╗ ██╗         ███████╗██████╗
    ████╗ ████║     ██║╚══██╔══╝██╔═══██╗██╔═══██╗██║         ██╔════╝╚════██╗
    ██╔████╔██║     ██║   ██║   ██║   ██║██║   ██║██║         ███████╗ █████╔╝
    ██║╚██╔╝██║██   ██║   ██║   ██║   ██║██║   ██║██║         ╚════██║██╔═══╝
    ██║ ╚═╝ ██║╚█████╔╝   ██║   ╚██████╔╝╚██████╔╝███████╗    ███████║███████╗
    ╚═╝     ╚═╝ ╚════╝    ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝    ╚══════╝╚══════╝
```
Author: mustafa jabir | Telegram: @mus_ja
Cross-Platform: Linux & Windows | Defense-Grade Threat Intelligence
---
What's New in v2.6 ELITE EDITION
1. LIVE AI-Powered Threat Analysis Engine (Google Gemini API)
MJTOOL v2.6 integrates a real, live AI cybersecurity analyst powered by Google's Gemini pro model. The AI analyzes all gathered forensic metrics and generates a concise, actionable threat assessment in your chosen language.
Real-time AI analysis of domain age, HTTPS status, redirects, VirusTotal flags, and more
Multi-language AI output - Gemini responds in English, Arabic, or Kurdish (Badini) based on your UI selection
Intelligent safety recommendations tailored to the actual threat profile
Zero-cost setup using Google's free Gemini API tier

2. Complete Kurdish (Badini - Duhok) Dictionary
Full, verified Kurdish translations for the entire UI using the Badini dialect with Arabic script:

3. Enhanced VirusTotal API v3 Multi-Key Rotation
Supports up to 5 API keys with automatic rotation on rate-limit (429) or invalid key (401/403)
Graceful degradation when all keys are exhausted
Detailed per-vendor malicious flag reporting in the terminal
---
Installation
Prerequisites
Python 3.8+
pip
Step 1: Install Python Dependencies
```bash
pip install colorama requests arabic-reshaper python-bidi google-generativeai
```
Or let the tool auto-install them on first run.
Step 2: Configure Your API Keys
Google Gemini API Key (FREE)
Visit https://aistudio.google.com/app/apikey
Click "Create API Key"
Copy your key and paste it in the script:
```python
GEMINI\_API\_KEY = "your-actual-api-key-here"
```
VirusTotal API Key (FREE)
Sign up at https://www.virustotal.com
Go to your profile settings
Copy your API key and paste it:
```python
VT\_API\_KEYS = \[
    "your-virustotal-api-key-here",
    "",  # Optional: add up to 5 keys for rotation
    "",
    "",
    "",
]
```
Step 3: Run MJTOOL
```bash
python mjtool.py
```
---
Features
Deep Forensic Analysis
Redirect Chain Analysis - Detects cross-domain redirects used to hide phishing destinations
Typosquatting Detection - 7-layer detection including homograph IDN attacks, Levenshtein distance, brand containment, and character substitution
TLD Risk Assessment - Flags 40+ suspicious TLDs commonly abused by phishing actors
URL Entropy Analysis - Shannon entropy calculation to detect algorithmically generated domains (DGA)
Security Headers Audit - Validates HSTS, CSP, X-Frame-Options, and more
VirusTotal v3 Integration - Multi-key rotation with per-vendor malicious flag details
AI Threat Analysis (NEW in v2.6)
Live Gemini 1.5 Flash analysis engine
Structured prompt with all scan metrics (VT flags, HTTPS, redirects, entropy, etc.)
Multi-language output - AI responds in English, Arabic, or Kurdish
Robust error handling - Falls back to local heuristic analysis if API is unavailable
Safety recommendations - Clear, actionable advice based on threat level
Multi-Language Support (3 Languages)
Language	Code	Script	Status
English	`en`	Latin	Full
Arabic	`ar`	Arabic	Full + RTL
Kurdish (Badini)	`ku`	Arabic	Full + RTL
Risk Scoring System (v2.6 Logic-Based)
Score Range	Color	Verdict	Action
90-100	Red	CRITICAL	Do NOT open - malware detected
70-89	Yellow	HIGH	Avoid - strong phishing indicators
40-69	Yellow	MODERATE	Be cautious - verify source
0-39	Green	LOW	Appears safe - remain vigilant
---
Usage
Main Menu
```
\[1] Execute Deep Scan
\[2] Persistent Scan History
\[3] Language Settings
\[4] Exit
```
Deep Scan Workflow
Enter a target URL (e.g., `https://example.com`)
MJTOOL automatically performs all forensic checks:
Fetches the URL and analyzes redirect chains
Checks for typosquatting against 20 major brands
Analyzes URL structure and entropy
Audits security headers
Queries VirusTotal API v3
Consults Gemini AI for threat analysis
View the comprehensive results report
Results are automatically saved to `history.json`
Scan History
Access up to 20 recent scans
View verdict, score, and timestamp for each scan
History persists between sessions
Language Settings
Switch between English, Arabic, and Kurdish (Badini) at any time. All UI elements, AI analysis, and threat explanations are fully translated.
---
Architecture
```
User Input URL
     |
     v
+----------------------------+
|  1. fetch\_url\_data()       |  <- HTTP session with redirect tracking
+----------------------------+
     |
     v
+----------------------------+
|  2. check\_typosquatting()  |  <- 7-layer brand impersonation detection
+----------------------------+
     |
     v
+----------------------------+
|  3. check\_redirect\_chain() |  <- Cross-domain redirect analysis
+----------------------------+
     |
     v
+----------------------------+
|  4. check\_tld()            |  <- Suspicious TLD detection
+----------------------------+
     |
     v
+----------------------------+
|  5. analyze\_url\_structure()|  <- Entropy, subdomains, patterns
+----------------------------+
     |
     v
+----------------------------+
|  6. check\_security\_headers|  <- HSTS, CSP, X-Frame, etc.
+----------------------------+
     |
     v
+----------------------------+
|  7. check\_virustotal\_v3()  |  <- Multi-key VT API with rotation
+----------------------------+
     |
     v
+----------------------------+
|  8. calculate\_risk\_score() |  <- LOGIC-BASED: VT malicious = CRITICAL
+----------------------------+
     |
     v
+----------------------------+
|  9. get\_ai\_threat\_analysis |  <- Gemini AI (with local fallback)
+----------------------------+
     |
     v
+----------------------------+
|  10. display\_results()     |  <- Full report with RTL support
+----------------------------+
```
---
File Structure
```
mjtool.py          # Main application (self-contained)
history.json       # Scan history (auto-generated)
```
---
API Reference
`get\_ai\_threat\_analysis(scan\_data, lang)`
Purpose: Generate live AI threat analysis using Google Gemini.
Parameters:
`scan\_data` (dict): All gathered scan metrics
`url`, `malicious\_count`, `suspicious\_count`, `https\_enabled`
`is\_typosquatting`, `is\_suspicious\_tld`, `has\_cross\_domain\_redirect`
`has\_ip\_in\_url`, `has\_at\_symbol`, `entropy`, `subdomain\_count`
`url\_length`, `redirect\_hop\_count`, `missing\_headers`, `risk\_score`
`typosquatting\_brand`
`lang` (str): Target language code (`'en'`, `'ar'`, or `'ku'`)
Returns: String containing 3-4 sentence analysis + recommendation in target language.
Fallback: If `GEMINI\_API\_KEY` is empty/invalid or API call fails, automatically falls back to `get\_local\_threat\_analysis()`.
`get\_local\_threat\_analysis(scan\_data, lang)`
Purpose: Rule-based heuristic analysis when Gemini API is unavailable.
Returns: Same format as AI analysis but generated using local logic rules.
`calculate\_risk\_score(results)`
Purpose: Calculate risk score (0-100) using logic-based priority system.
Priority Rules:
`malicious\_count > 0` -> 90-100 (CRITICAL)
`suspicious\_count > 0` (no malicious) -> 70-85 (HIGH)
Otherwise -> additive scoring from other indicators
`render\_rtl(text)` / `render\_rtl\_textonly(text)`
Purpose: Apply Arabic reshaping + bidi algorithm to RTL text.
Key Design: Processing happens on PURE translated text BEFORE injection into f-strings with English variables. This prevents the text reversal bug that plagued v2.3.
---
Troubleshooting
Gemini AI Not Working
```
\[!] Gemini AI not configured. Using local rule-based analysis.
```
Solution: Set your `GEMINI\_API\_KEY` at the top of the script.
VirusTotal Keys Exhausted
```
\[!] All 5 VirusTotal API keys exhausted or invalid. Skipping VT check.
```
Solution: Add valid VT API keys to `VT\_API\_KEYS` list.
RTL Text Not Displaying Correctly
Solution: Ensure `arabic-reshaper` and `python-bidi` are installed:
```bash
pip install arabic-reshaper python-bidi
```
Windows CMD Issues
The tool auto-detects Windows and uses Colorama for cross-platform color support.
---
Security Notes
SSL certificate verification is disabled for the initial fetch (`verify=False`) to allow analysis of misconfigured or self-signed sites. This is intentional for forensic analysis purposes.
API keys are stored in the script file. Keep your copy of `mjtool.py` secure.
The tool performs HEAD/GET requests only - it does not download or execute any content.
---
Changelog
v2.6 (Current) - ELITE EDITION
Added LIVE Google Gemini AI Threat Analysis Engine
Rewrote risk scoring with logic-based priority (malicious=CRITICAL)
Fixed RTL text rendering for Arabic/Kurdish mixed with English
Complete Kurdish (Badini) dictionary with verified translations
Enhanced multi-key VirusTotal API rotation
Added `render\_rtl\_textonly()` for external AI text processing
Added local heuristic fallback when AI is unavailable
v2.3
Initial Elite Edition with multi-language support
VirusTotal API v3 with key rotation
Typosquatting and homograph detection
URL entropy analysis
Security headers audit
---
License
This tool is provided as-is for educational and defensive cybersecurity purposes. Use responsibly and only on URLs you own or have explicit permission to analyze.
Author: mustafa jabir
Telegram: @mus_ja
---
Stay secure. Trust nothing. Verify everything.
