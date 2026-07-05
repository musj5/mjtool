#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    ███╗   ███╗     ██╗████████╗ ██████╗  ██████╗ ██╗         ███████╗██████╗
    ████╗ ████║     ██║╚══██╔══╝██╔═══██╗██╔═══██╗██║         ██╔════╝╚════██╗
    ██╔████╔██║     ██║   ██║   ██║   ██║██║   ██║██║         ███████╗ █████╔╝
    ██║╚██╔╝██║██   ██║   ██║   ██║   ██║██║   ██║██║         ╚════██║██╔═══╝
    ██║ ╚═╝ ██║╚█████╔╝   ██║   ╚██████╔╝╚██████╔╝███████╗    ███████║███████╗
    ╚═╝     ╚═╝ ╚════╝    ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝    ╚══════╝╚══════╝
================================================================================
    MJTOOL ELITE EDITION v2.6 - Advanced URL & Phishing Forensic Analyzer
    LIVE AI-POWERED: Google Gemini Threat Analysis Engine
    Author: mustafa jabir  |  Telegram: @mus_ja
    Cross-Platform: Linux & Windows  |  Defense-Grade Threat Intelligence
    VT API: v3 with Multi-Key Rotation  |  Languages: EN / AR / KU (Badini)
    NEW: AI Analyst  |  Logic-Based Risk Scoring  |  Flawless RTL
================================================================================
"""

import os
import sys
import re
import json
import time
import math
import hashlib
import base64
import itertools
from datetime import datetime
from urllib.parse import urlparse, unquote
from difflib import SequenceMatcher

# ---------------------------------------------------------------------------
# CROSS-PLATFORM TERMINAL COLORS
# ---------------------------------------------------------------------------
try:
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)
except ImportError:
    print("[!] colorama not found. Installing...")
    os.system(f"{sys.executable} -m pip install colorama -q")
    import colorama
    from colorama import Fore, Back, Style
    colorama.init(autoreset=True)

# ---------------------------------------------------------------------------
# NETWORKING LIBRARIES
# ---------------------------------------------------------------------------
try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
except ImportError:
    print("[!] requests not found. Installing...")
    os.system(f"{sys.executable} -m pip install requests -q")
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# RTL TEXT RENDERING (Arabic + Kurdish Badini support)
# ---------------------------------------------------------------------------
try:
    import arabic_reshaper
    from bidi.algorithm import get_display
    RTL_SUPPORT = True
except ImportError:
    print("[!] arabic-reshaper / python-bidi not found. Installing...")
    os.system(f"{sys.executable} -m pip install arabic-reshaper python-bidi -q")
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display
        RTL_SUPPORT = True
    except ImportError:
        RTL_SUPPORT = False

# ---------------------------------------------------------------------------
# GOOGLE AI INTEGRATION
# ---------------------------------------------------------------------------
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    print("[!] google-generativeai not found. Installing...")
    os.system(f"{sys.executable} -m pip install google-generativeai -q")
    try:
        import google.generativeai as genai
        GEMINI_AVAILABLE = True
    except ImportError:
        GEMINI_AVAILABLE = False

# ---------------------------------------------------------------------------
# CONFIGURATION & GLOBALS
# ---------------------------------------------------------------------------

# Google Gemini API Key - Configure for LIVE AI Threat Analysis
# Get your free API key at: https://aistudio.google.com/app/apikey
GEMINI_API_KEY = "YOUR_GEMINI_API_KEY_HERE"

# VirusTotal API v3 - Multi-Key Rotation System (up to 5 keys)
# Fill in your free VT API keys. The tool will auto-rotate on rate-limit.
VT_API_KEYS = [
    "77e4d375a08ca4c24e17e215f5fd9e865532b06465c41a6906b1fc8752bb2cf5",  # Slot 1
    "36b3e06f2332a07134693d0254cc7f57eac9f1b1e53532dab5f4979808ccfe38",  # Slot 2
    "",  # Slot 3
    "",  # Slot 4
    "",  # Slot 5
]

# VT API v3 Base URL
VT_API_BASE = "https://www.virustotal.com/api/v3"

HISTORY_FILE = "history.json"
VERSION = "2.6 (Elite Edition - AI Powered)"
AUTHOR = "mustafa jabir"
TELEGRAM = "@mus_ja"

# Suspicious TLDs frequently abused by phishing kits
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.click', '.buzz', '.zip',
    '.download', '.work', '.date', '.racing', '.win', '.bid', '.review',
    '.party', '.stream', '.gdn', '.men', '.loan', '.accountants', '.country',
    '.link', '.trade', '.webcam', '.science', '.space', '.club', '.online',
    '.site', '.icu', '.cyou', '.fit', '.cam', '.bar', '.rest', '.uno',
    '.miami', '.works', '.ninja', '.rocks', '.social', '.cc', '.su', '.pw',
    '.cm', '.om', '.co', '.ph', '.vn', '.bd', '.ng', '.ke', '.tz'
}

# Top 20 global brands for typosquatting detection
TOP_BRANDS = {
    'google': ['google.com', 'youtube.com', 'gmail.com', 'drive.google.com'],
    'facebook': ['facebook.com', 'fb.com', 'messenger.com', 'instagram.com'],
    'microsoft': ['microsoft.com', 'outlook.com', 'live.com', 'office.com', 'hotmail.com', 'microsoftonline.com', 'login.microsoftonline.com'],
    'apple': ['apple.com', 'icloud.com', 'me.com', 'mac.com'],
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp', 'primevideo.com'],
    'paypal': ['paypal.com', 'paypal.me'],
    'netflix': ['netflix.com'],
    'twitter': ['twitter.com', 'x.com'],
    'linkedin': ['linkedin.com'],
    'github': ['github.com'],
    'dropbox': ['dropbox.com'],
    'adobe': ['adobe.com'],
    'spotify': ['spotify.com'],
    'uber': ['uber.com'],
    'airbnb': ['airbnb.com'],
    'booking': ['booking.com'],
    'wellsfargo': ['wellsfargo.com'],
    'bankofamerica': ['bankofamerica.com', 'bofa.com'],
    'chase': ['chase.com'],
    'citibank': ['citibank.com'],
}

# Security headers to validate
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'required': True,
        'description_en': 'HSTS enforces HTTPS connections and prevents downgrade attacks.',
        'description_ar': 'HSTS يفرض اتصالات HTTPS ويمنع هجمات تخفيض بروتوكول.',
        'description_ku': 'HSTS پەیوەندی HTTPS دەسەپێنێت و بەرگری لە هێرشەکانی داوەند کردن دەکات.'
    },
    'X-Frame-Options': {
        'required': True,
        'description_en': 'Prevents clickjacking by blocking iframe embedding of your site.',
        'description_ar': 'يمنع هجمات النقر عبر حظر تضمين موقعك في iframe.',
        'description_ku': 'بەرگری لە کلیکجاکینگ دەکات بە بLOKکردنی ئیمبی‌دکردنی سایتەکەت لە iframe.'
    },
    'Content-Security-Policy': {
        'required': True,
        'description_en': 'CSP mitigates XSS and data injection attacks by defining approved content sources.',
        'description_ar': 'CSP يخفف من هجمات XSS وحقن البيانات عن طريق تحديد مصادر المحتوى المعتمدة.',
        'description_ku': 'CSP هێرشەکانی XSS ودزەکردنی داتا کەم دەکاتەوە بە دیاریکردنی سەرچاوە پەسەندکراوەکان.'
    },
    'X-Content-Type-Options': {
        'required': True,
        'description_en': 'Prevents MIME-type sniffing that could lead to drive-by download attacks.',
        'description_ar': 'يمنع استنشاق نوع MIME الذي قد يؤدي إلى هجمات التنزيل التلقائي.',
        'description_ku': 'بەرگری لە سنیفتی جۆری MIME دەکات کە دەتوانێت ببێتە هۆی هێرشەکانی داگرتنی ئۆتۆماتیکی.'
    },
    'X-XSS-Protection': {
        'required': False,
        'description_en': 'Legacy XSS filter. Modern browsers prefer CSP but this adds a layer.',
        'description_ar': 'فلتر XSS القديم. المتصفحات الحديثة تفضل CSP لكن هذا يضيف طبقة حماية.',
        'description_ku': 'فیلتەری XSSـی کۆن. براوسەرە نوێیەکان CSPـیان پەسەندترە بەڵام ئەمە چینێکی زیاد دەکات.'
    },
    'Referrer-Policy': {
        'required': False,
        'description_en': 'Controls referrer information leakage to third-party sites.',
        'description_ar': 'يتحكم في تسرب معلومات المرجع إلى مواقع الطرف الثالث.',
        'description_ku': 'کۆنترۆڵی ڕەوشتی دەرچوونی زانیاری ڕەوانە بۆ ماڵپەڕە دەرەکییەکان دەکات.'
    },
}

# Loading animation characters
SPINNER = itertools.cycle(['|', '/', '-', '\\'])

# ---------------------------------------------------------------------------
# TRANSLATION DICTIONARY (English / Arabic / Kurdish Badini)
# ---------------------------------------------------------------------------
LANG = {
    'en': {
        'banner_title': 'MJTOOL ELITE EDITION v{} - Advanced URL & Phishing Forensic Analyzer',
        'author': 'Author',
        'telegram': 'Telegram',
        'version': 'Version',
        'menu_title': ' MAIN MENU ',
        'option_scan': 'Execute Deep Scan',
        'option_history': 'Persistent Scan History',
        'option_language': 'Language Settings',
        'option_exit': 'Exit',
        'prompt_choice': 'Enter your choice',
        'prompt_url': 'Enter target URL (e.g., https://example.com)',
        'scanning': 'Initiating deep forensic scan',
        'scan_complete': 'Scan complete',
        'result_title': ' FORENSIC SCAN RESULTS ',
        'target_url': 'Target URL',
        'scan_time': 'Scan Timestamp',
        'verdict_clean': 'CLEAN',
        'verdict_suspicious': 'SUSPICIOUS',
        'verdict_malicious': 'MALICIOUS',
        'overall_risk': 'Overall Risk Verdict',
        'risk_score': 'Risk Score',
        'section_redirects': ' REDIRECT CHAIN ANALYSIS ',
        'section_typosquatting': ' TYPOSQUATTING & HOMOGRAPH DETECTION ',
        'section_tld': ' TLD RISK ASSESSMENT ',
        'section_entropy': ' URL ENTROPY & STRUCTURE ANALYSIS ',
        'section_headers': ' SECURITY HEADERS AUDIT ',
        'section_vt': ' VIRUSTOTAL REPUTATION CHECK ',
        'section_ai': ' AI THREAT ANALYSIS REPORT ',
        'redirect_chain': 'Redirect Chain',
        'final_destination': 'Final Destination',
        'no_redirects': 'No redirects detected',
        'suspicious_redirect': 'Suspicious cross-domain redirect detected',
        'typosquatting_detected': 'Typosquatting detected',
        'homograph_detected': 'Homograph attack (IDN spoofing) detected',
        'similarity_score': 'Brand Similarity Score',
        'suspicious_tld': 'Suspicious TLD detected',
        'tld_safe': 'TLD appears legitimate',
        'entropy_score': 'Shannon Entropy Score',
        'high_entropy': 'High entropy - possible algorithmically generated domain',
        'subdomain_analysis': 'Subdomain Analysis',
        'excessive_subdomains': 'Excessive subdomains - potential phishing structure',
        'url_length': 'URL Length',
        'long_url': 'Unusually long URL - common in phishing',
        'has_ip': 'IP Address in URL',
        'ip_detected': 'Raw IP detected in URL - high phishing indicator',
        'has_at_symbol': '@ Symbol in URL',
        'at_detected': '@ symbol detected - credential manipulation trick',
        'has_hex': 'Hexadecimal Obfuscation',
        'hex_detected': 'Hex encoding detected - obfuscation attempt',
        'header_present': 'Present',
        'header_missing': 'MISSING',
        'header_weak': 'WEAK',
        'vt_clean': 'No detections on VirusTotal',
        'vt_flagged': 'Flagged by security vendors on VirusTotal',
        'vt_error': 'VirusTotal check failed',
        'vt_stats_title': 'VirusTotal Analysis Statistics',
        'vt_malicious_vendors': 'Flagging Security Vendors',
        'vt_no_vendors': 'No vendors flagged this URL',
        'vt_all_keys_exhausted': 'All 5 VirusTotal API keys exhausted or invalid. Skipping VT check.',
        'vt_key_invalid': 'VirusTotal API key invalid or quota exceeded',
        'explanation_title': 'SECURITY ANALYSIS EXPLANATION',
        'no_explanations': 'No vulnerabilities detected. Target appears secure.',
        'history_title': ' SCAN HISTORY ',
        'history_empty': 'No scan history found.',
        'history_entry': 'Target: {} | Verdict: {} | Time: {}',
        'history_cleared': 'History cleared successfully.',
        'language_title': ' LANGUAGE SETTINGS ',
        'lang_en': 'English',
        'lang_ar': 'Arabic',
        'lang_ku': 'Kurdish (Badini)',
        'lang_current': 'Current language',
        'lang_switched': 'Language switched successfully.',
        'press_enter': 'Press Enter to continue...',
        'invalid_choice': 'Invalid choice. Please try again.',
        'invalid_url': 'Invalid URL format. Please enter a valid URL.',
        'network_error': 'Network error: Unable to reach target.',
        'timeout_error': 'Connection timed out. Target may be blocking scans.',
        'general_error': 'An error occurred during scanning',
        'goodbye': 'Thank you for using MJTOOL. Stay secure.',
        'save_error': 'Failed to save history',
        'load_error': 'Failed to load history',
        'warning_no_vt_key': 'VirusTotal API key not configured. Skipping VT check.',
        'vt_rotation_warning': 'VT Key {} quota exceeded/rate-limited. Rotating to backup Key {}...',
        'vt_scan_id_error': 'Failed to retrieve VirusTotal scan ID.',
        'ai_thinking': 'Consulting AI Threat Analyst...',
        'ai_error_fallback': 'AI analysis unavailable. Using local heuristic fallback.',
        'ai_offline': 'AI not configured. Using local rule-based analysis.',
        'ai_analysis_label': 'AI Threat Assessment',
        'ai_recommendation': 'Recommendation',
        'fallback_label': 'Local Heuristic Analysis',
        'threat_level_critical': 'CRITICAL THREAT DETECTED',
        'threat_level_high': 'HIGH RISK',
        'threat_level_medium': 'MODERATE RISK',
        'threat_level_low': 'LOW RISK',
        'status': 'Status',
        'domain_age': 'Domain Age',
        'server_info': 'Server Info',
        'ip_address': 'IP Address',
        'phishing': 'Phishing',
        'malware': 'Malware',
        'no_threats': 'No threats detected.',
        'high_risk': 'High risk detected!',
        'fetching_data': 'Fetching data...',
        'error': 'Error',
        'ai_analysis': 'AI Analysis',
        'threat_reasoning': 'Threat Reasoning (Deep Analysis)',
        'safe': 'Safe',
        'danger': 'Danger',
        'deep_scan': 'Deep Scan URL',
        'scan_history': 'Scan History',
        'language_settings': 'Language Settings',
        'exit': 'Exit',
        'main_menu': 'Main Menu',
        'enter_url': 'Enter URL to scan',
        'analyzing': 'Analyzing...',
        'vendors_flagged': 'Security vendors that detected malware',
        'vt_report': 'VirusTotal Report',
        'scan_results': 'Scan Results',
    },
    'ar': {
        'banner_title': 'MJTOOL الإصدار Elite v{} - محلل الطب الشرعي المتقدم للروابط والتصيد',
        'author': 'المؤلف',
        'telegram': 'تيليجرام',
        'version': 'الإصدار',
        'menu_title': ' القائمة الرئيسية ',
        'option_scan': 'تنفيذ فحص عميق',
        'option_history': 'سجل الفحوصات',
        'option_language': 'إعدادات اللغة',
        'option_exit': 'خروج',
        'prompt_choice': 'أدخل اختيارك',
        'prompt_url': 'أدخل رابط الهدف (مثال: https://example.com)',
        'scanning': 'جاري بدء الفحص الشرعي العميق',
        'scan_complete': 'اكتمل الفحص',
        'result_title': ' نتائج الفحص الشرعي ',
        'target_url': 'رابط الهدف',
        'scan_time': 'تاريخ ووقت الفحص',
        'verdict_clean': 'آمن',
        'verdict_suspicious': 'مشبوه',
        'verdict_malicious': 'ضار',
        'overall_risk': 'الحكم النهائي للمخاطر',
        'risk_score': 'درجة المخاطرة',
        'section_redirects': ' تحليل سلسلة إعادة التوجيه ',
        'section_typosquatting': ' كشف التصيد بالأحرف المشابهة ',
        'section_tld': ' تقييم مخاطر النطاق العلوي ',
        'section_entropy': ' تحليل الإنتروبيا وهيكل الرابط ',
        'section_headers': ' تدقيق رؤوس الأمان ',
        'section_vt': ' فحص سمعة VirusTotal ',
        'section_ai': ' تقرير تحليل الذكاء الاصطناعي للتهديدات ',
        'redirect_chain': 'سلسلة إعادة التوجيه',
        'final_destination': 'الوجهة النهائية',
        'no_redirects': 'لم يتم الكشف عن إعادات توجيه',
        'suspicious_redirect': 'تم الكشف عن إعادة توجيه مشبوهة بين النطاقات',
        'typosquatting_detected': 'تم الكشف عن محاكاة علامة تجارية',
        'homograph_detected': 'تم الكشف عن هجوم الحروف المتشابهة (انتحال IDN)',
        'similarity_score': 'درجة تشابه العلامة التجارية',
        'suspicious_tld': 'تم الكشف عن نطاق علوي مشبوه',
        'tld_safe': 'النطاق العلوي يبدو شرعياً',
        'entropy_score': 'درجة إنتروبيا شانون',
        'high_entropy': 'إنتروبيا عالية - نطاق مولد خوارزمياً محتمل',
        'subdomain_analysis': 'تحليل النطاقات الفرعية',
        'excessive_subdomains': 'نطاقات فرعية مفرطة - هيكل تصيد محتمل',
        'url_length': 'طول الرابط',
        'long_url': 'رابط غير عادي الطول - شائع في التصيد',
        'has_ip': 'عنوان IP في الرابط',
        'ip_detected': 'تم الكشف عن IP مباشر في الرابط - مؤشر تصيد عالي',
        'has_at_symbol': 'رمز @ في الرابط',
        'at_detected': 'تم الكشف عن رمز @ - خدعة التلاعب بالبيانات',
        'has_hex': 'التشويه الست عشري',
        'hex_detected': 'تم الكشف عن ترميز ست عشري - محاولة إخفاء',
        'header_present': 'موجود',
        'header_missing': 'مفقود',
        'header_weak': 'ضعيف',
        'vt_clean': 'لا توجد كشوفات على VirusTotal',
        'vt_flagged': 'تم التحذير من قبل مزودي الأمان على VirusTotal',
        'vt_error': 'فشل فحص VirusTotal',
        'vt_stats_title': 'إحصائيات تحليل VirusTotal',
        'vt_malicious_vendors': 'مزودو الأمان المحذرون',
        'vt_no_vendors': 'لم يحذر أي مزود من هذا الرابط',
        'vt_all_keys_exhausted': 'جميع مفاتيح VirusTotal الـ 5 استُنفدت أو غير صالحة. يتم تخطي الفحص.',
        'vt_key_invalid': 'مفتاح VirusTotal API غير صالح أو تجاوز الحصة',
        'explanation_title': 'توضيح تحليل الأمان',
        'no_explanations': 'لم يتم الكشف عن ثغرات. الهدف يبدو آمناً.',
        'history_title': ' سجل الفحوصات ',
        'history_empty': 'لم يتم العثور على سجل فحوصات.',
        'history_entry': 'الهدف: {} | الحكم: {} | الوقت: {}',
        'history_cleared': 'تم مسح السجل بنجاح.',
        'language_title': ' إعدادات اللغة ',
        'lang_en': 'الإنجليزية',
        'lang_ar': 'العربية',
        'lang_ku': 'الكردية (البديني)',
        'lang_current': 'اللغة الحالية',
        'lang_switched': 'تم تغيير اللغة بنجاح.',
        'press_enter': 'اضغط Enter للمتابعة...',
        'invalid_choice': 'اختيار غير صالح. يرجى المحاولة مرة أخرى.',
        'invalid_url': 'صيغة رابط غير صالحة. يرجى إدخال رابط صحيح.',
        'network_error': 'خطأ في الشبكة: تعذر الوصول إلى الهدف.',
        'timeout_error': 'انتهت مهلة الاتصال. الهدف قد يقوم بحظر الفحوصات.',
        'general_error': 'حدث خطأ أثناء الفحص',
        'goodbye': 'شكراً لاستخدام MJTOOL.ابقَ آمناً.',
        'save_error': 'فشل في حفظ السجل',
        'load_error': 'فشل في تحميل السجل',
        'warning_no_vt_key': 'مفتاح VirusTotal API غير مكون. يتم تخطي الفحص.',
        'vt_rotation_warning': 'مفتاح VT {} تجاوز الحصة/محدد بالمعدل. الانتقال إلى المفتاح الاحتياطي {}...',
        'vt_scan_id_error': 'فشل في استرداد معرف فحص VirusTotal.',
        'ai_thinking': 'جاري استشارة محلل AI للتهديدات...',
        'ai_error_fallback': 'تحليل AI غير متاح. استخدام التحليل البدني المحلي.',
        'ai_offline': 'لم يتم تكوين AI. استخدام التحليل القائم على القواعد المحلية.',
        'ai_analysis_label': 'تقييم تهديدات الذكاء الاصطناعي',
        'ai_recommendation': 'التوصية',
        'fallback_label': 'التحليل الإرشادي المحلي',
        'threat_level_critical': 'تم اكتشاف تهديد حرج',
        'threat_level_high': 'مخاطر عالية',
        'threat_level_medium': 'مخاطر متوسطة',
        'threat_level_low': 'مخاطر منخفضة',
        'status': 'الحالة',
        'domain_age': 'عمر النطاق',
        'server_info': 'معلومات الخادم',
        'ip_address': 'عنوان IP',
        'phishing': 'التصيد',
        'malware': 'البرمجيات الخبيثة',
        'no_threats': 'لم يتم اكتشاف تهديدات.',
        'high_risk': 'تم اكتشاف مخاطر عالية!',
        'fetching_data': 'جاري جلب البيانات...',
        'error': 'خطأ',
        'ai_analysis': 'تحليل الذكاء الاصطناعي',
        'threat_reasoning': 'تفسير التهديد (تحليل عميق)',
        'safe': 'آمن',
        'danger': 'خطر',
        'deep_scan': 'فحص عميق لرابط',
        'scan_history': 'سجل الفحوصات',
        'language_settings': 'إعدادات اللغة',
        'exit': 'خروج',
        'main_menu': 'القائمة الرئيسية',
        'enter_url': 'أدخل الرابط للفحص',
        'analyzing': 'جاري التحليل...',
        'vendors_flagged': 'مزودو الأمان الذين اكتشفوا البرمجيات الخبيثة',
        'vt_report': 'تقرير VirusTotal',
        'scan_results': 'نتائج الفحص',
    },
    'ku': {
        'banner_title': 'MJTOOL چاپی Elite v{} - شیکاری پێشکەتووی بەستەر و فیشینگ',
        'author': 'نووسەر',
        'telegram': 'تێلێگرام',
        'version': 'وەشان',
        'menu_title': ' پێڕستا سەرەکی ',
        'option_scan': 'پشکنینا کویر بۆ بەستەری (URL)',
        'option_history': 'مێژووا پشکنینان',
        'option_language': 'رێکخستنێن زمان',
        'option_exit': 'دەرکەوتن',
        'prompt_choice': 'هەلبژارتنا خۆ لێرە بنڤیسە',
        'prompt_url': 'بەستەري بنڤیسە بۆ پشکنینێ',
        'scanning': 'دئێتە شیکارکرن...',
        'scan_complete': 'پشکنین تەواو بوو',
        'result_title': ' ئەنجامێن پشکنینێ ',
        'target_url': 'بەستەری ئامانج',
        'scan_time': 'کات و بەرواری پشکنین',
        'verdict_clean': 'پاقژ',
        'verdict_suspicious': 'گومانلێکراو',
        'verdict_malicious': 'مەترسیدار',
        'overall_risk': 'بڕیاری کۆتایی مەترسی',
        'risk_score': 'رێژەیا مەترسیێ',
        'section_redirects': ' شیکاری زنجیرە ڕەوانەکردنەوە ',
        'section_typosquatting': ' دۆزینەوەی فیشینگی پیتی ',
        'section_tld': ' هەڵسەنگاندنی مەترسی دۆمەین ',
        'section_entropy': ' شیکاری ئێنتڕۆپیا و ساختاری بەستەر ',
        'section_headers': ' پشکنینی سەردێرەکانی ئاسایش ',
        'section_vt': ' پشکنینی ناوبانگی VirusTotal ',
        'section_ai': ' راپۆرتا شیکارکرنا زیرەکییا دەستکرد یێ مەترسیێن ',
        'redirect_chain': 'زنجیرە ڕەوانەکردنەوە',
        'final_destination': 'شوێنی کۆتایی',
        'no_redirects': 'هیچ ڕەوانەکردنەوەیەک نەدۆزرایەوە',
        'suspicious_redirect': 'ڕەوانەکردنەوەی گومانلێکراوی نێوان دۆمەین دۆزرایەوە',
        'typosquatting_detected': 'فیشینگی پیت دۆزرایەوە',
        'homograph_detected': 'هێرشی پیتی لەشی (IDN spoofing) دۆزرایەوە',
        'similarity_score': 'نمرەی هاوشێوەیی براند',
        'suspicious_tld': 'دۆمەینی گومانلێکراو دۆزرایەوە',
        'tld_safe': 'دۆمەین سەلامەتە',
        'entropy_score': 'نمرەی ئێنتڕۆپیای شانۆن',
        'high_entropy': 'ئێنتڕۆپیا بەرزە - دۆمەینی دەرهێنراو بە ئەلگۆریتم',
        'subdomain_analysis': 'شیکاری سەبدۆمەین',
        'excessive_subdomains': 'سەبدۆمەینی زۆر - ساختاری فیشینگی لەبەرچاوگیراو',
        'url_length': 'درێژی بەستەر',
        'long_url': 'بەستەری درێژی نائاسایی - باوە لە فیشینگ',
        'has_ip': 'ناونیشانی IP لە بەستەردا',
        'ip_detected': 'IPـی ڕەق دۆزرایەوە لە بەستەردا - نیشانەهێنەری فیشینگی بەرز',
        'has_at_symbol': 'نیشانەی @ لە بەستەردا',
        'at_detected': 'نیشانەی @ دۆزرایەوە - فێڵی گۆڕینی زانیاری',
        'has_hex': 'شاردراوەی هێگزادێسیمال',
        'hex_detected': 'هێگزادێسیمال دۆزرایەوە - هەوڵی شاردنەوە',
        'header_present': 'ئامادەیە',
        'header_missing': 'نەماوە',
        'header_weak': 'لاوە',
        'vt_clean': 'هیچ شتێک لەسەر VirusTotal نەدۆزرایەوە',
        'vt_flagged': 'لەلایەن دابینکەرانی ئاسایشەوە ئاگادارکرایەوە لەسەر VirusTotal',
        'vt_error': 'پشکنینی VirusTotal سەرکەوتوو نەبوو',
        'vt_stats_title': 'ئاماری شیکاری VirusTotal',
        'vt_malicious_vendors': 'کۆمپانیێن ئاسایشی یێن کو ڤایرۆس دیتین',
        'vt_no_vendors': 'هیچ دابینکەرێک ئەم بەستەرەی ئاگادار نەکردەوە',
        'vt_all_keys_exhausted': 'هەموو ٥ کلیلی VirusTotal بەکارهاتوون یان نادروستن. بەردەوامبوون بەبێ پشکنین.',
        'vt_key_invalid': 'کلیلی VirusTotal API نادروستە یان سنووری بەکارهێنان تێپەڕێنراوە',
        'explanation_title': 'هۆکارێ مەترسیێ (شیکارکرنا ژیری)',
        'no_explanations': 'چ مەترسی نەهاتنە دیتن.',
        'history_title': ' مێژووا پشکنینان ',
        'history_empty': 'هیچ مێژووی پشکنین نەدۆزرایەوە.',
        'history_entry': 'ئامانج: {} | بڕیار: {} | کات: {}',
        'history_cleared': 'مێژوو بە سەرکەوتوویی سڕایەوە.',
        'language_title': ' رێکخستنێن زمان ',
        'lang_en': 'ئینگلیزی',
        'lang_ar': 'عەرەبی',
        'lang_ku': 'کوردی (بەدینی)',
        'lang_current': 'زمانی ئێستا',
        'lang_switched': 'زمان بە سەرکەوتوویی گۆڕدرا.',
        'press_enter': 'ئینتەر (Enter) لێبدە بۆ بەردەوامبوونێ',
        'invalid_choice': 'هەڵبژاردن نادروستە. تکایە دووبارە هەوڵبدە.',
        'invalid_url': 'بەستەر نەدروستە، هيڤی دکەين دوبارە هەول بدە',
        'network_error': 'هەڵەی ڕایەڵە: نەتوانرا بگاتە ئامانج.',
        'timeout_error': 'دەمێ تەرخانکری ب دوماهی هات',
        'general_error': 'هەڵەیەک لە کاتی پشکنیندا ڕوویدا',
        'goodbye': 'سوپاس بۆ بکارئینانا ئامرازێ مە. ب خاترێ تە!',
        'save_error': 'پاشەکەوتکردنی مێژوو سەرکەوتوو نەبوو',
        'load_error': 'بارکردنی مێژوو سەرکەوتوو نەبوو',
        'warning_no_vt_key': 'کلیلی VirusTotal API ڕێکنەخراوە. پشکنین تێدەپەڕێنرێت.',
        'vt_rotation_warning': 'کلیلی VT {} سنووری تێپەڕاند/ڕەچاوکردن. گۆڕین بۆ کلیلی یەدەگ {}...',
        'vt_scan_id_error': 'نەتوانرا ناسنامەی پشکنینی VirusTotal بەدەست بهێنرێت.',
        'ai_thinking': 'دەت顾问ە لێکۆڵەری مەترسیێن AI...',
        'ai_error_fallback': 'شیکارکرنی AI بەردەست نییە. بەکارهێنانی شیکاری نێوخۆیی.',
        'ai_offline': 'AI چالاک نەکراوە. بەکارهێنانی شیکاری نێوخۆیی.',
        'ai_analysis_label': 'هەڵسەنگاندنی مەترسیێن AI',
        'ai_recommendation': 'پیشنیاز',
        'fallback_label': 'شیکاری نێوخۆیی',
        'threat_level_critical': 'مەترسییەکا کریتیکی هاتە دیتن',
        'threat_level_high': 'مەترسییەکا بەرز',
        'threat_level_medium': 'مەترسییەکا ناوەندی',
        'threat_level_low': 'مەترسییەکا کەم',
        'status': 'رەوش',
        'domain_age': 'ژیێ دۆمەینێ',
        'server_info': 'پێزانینێن سێرڤەري',
        'ip_address': 'ناڤونیشانێ (IP)',
        'phishing': 'فێلبازی (Phishing)',
        'malware': 'ڤایرۆس (Malware)',
        'no_threats': 'چ مەترسی نەهاتنە دیتن.',
        'high_risk': 'مەترسییەکا مەزن هەیە!',
        'fetching_data': 'داتا دئێتە وەرگرتن...',
        'error': 'خەلەتی',
        'ai_analysis': 'شیکارکرنا زیرەکییا دەستکرد (AI Analysis)',
        'threat_reasoning': 'هۆکارێ مەترسیێ (شیکارکرنا ژیری)',
        'safe': 'پاراستی (ئارام)',
        'danger': 'مەترسیدار',
        'deep_scan': 'پشکنینا کویر بۆ بەستەری (URL)',
        'scan_history': 'مێژووا پشکنینان',
        'language_settings': 'رێکخستنێن زمان',
        'exit': 'دەرکەوتن',
        'main_menu': 'پێڕستا سەرەکی',
        'enter_url': 'بەستەري بنڤیسە بۆ پشکنینێ',
        'analyzing': 'دئێتە شیکارکرن...',
        'vendors_flagged': 'کۆمپانیێن ئاسایشی یێن کو ڤایرۆس دیتین',
        'vt_report': 'راپۆرتا ڤایرۆس تۆتال',
        'scan_results': 'ئەنجامێن پشکنینێ',
    }
}

# Current language setting
current_lang = 'en'


def t(key, *args):
    """Get translated string for current language.
    For RTL languages (ar, ku), applies reshape + bidi to the pure translated
    text BEFORE any formatting, ensuring correct display when injected into
    f-strings with English variables and ANSI color codes."""
    text = LANG[current_lang].get(key, key)
    if args:
        text = text.format(*args)
    # For RTL languages, process the PURE translated text through reshape+bidi
    # BEFORE it gets mixed with English variables in f-strings
    if current_lang in ('ar', 'ku') and RTL_SUPPORT and text:
        try:
            reshaped = arabic_reshaper.reshape(text)
            displayed = get_display(reshaped)
            return displayed
        except Exception:
            pass
    return text


# =============================================================================
# RTL TEXT RENDERING HELPERS
# =============================================================================

def render_rtl(text):
    """
    Apply Arabic reshaping and bidi algorithm to RTL text chunks.
    CRITICAL: This is applied to PURE Arabic/Kurdish text BEFORE injection
    into f-strings with English variables and ANSI color codes.
    This ensures perfect right-to-left flow without breaking terminal formatting.
    """
    if not RTL_SUPPORT or not text:
        return text
    if current_lang not in ('ar', 'ku'):
        return text
    try:
        reshaped = arabic_reshaper.reshape(text)
        displayed = get_display(reshaped)
        return displayed
    except Exception:
        return text


def render_rtl_textonly(text):
    """
    Render RTL text that comes from EXTERNAL sources (like AI response).
    Use this for dynamically generated Arabic/Kurdish text that needs proper
    RTL display in the terminal.
    """
    return render_rtl(text)


def print_rtl(text, color=Fore.WHITE, end='\n'):
    """Print text with RTL rendering support for Arabic-script languages."""
    rendered = render_rtl(text)
    print(f"{color}{rendered}{Style.RESET_ALL}", end=end)


# =============================================================================
# VISUAL & UI COMPONENTS
# =============================================================================

def clear_screen():
    """Clear terminal screen cross-platform."""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    """Display the cyber-themed ASCII art banner."""
    banner = f"""
{Fore.CYAN}    ███╗   ███╗     ██╗████████╗ ██████╗  ██████╗ ██╗         ███████╗██████╗
    ████╗ ████║     ██║╚══██╔══╝██╔═══██╗██╔═══██╗██║         ██╔════╝╚════██╗
    ██╔████╔██║     ██║   ██║   ██║   ██║██║   ██║██║         ███████╗ █████╔╝
    ██║╚██╔╝██║██   ██║   ██║   ██║   ██║██║   ██║██║         ╚════██║██╔═══╝
    ██║ ╚═╝ ██║╚█████╔╝   ██║   ╚██████╔╝╚██████╔╝███████╗    ███████║███████╗
    ╚═╝     ╚═╝ ╚════╝    ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝    ╚══════╝╚══════╝
{Style.RESET_ALL}
{Fore.GREEN}════════════════════════════════════════════════════════════════════════════════{Style.RESET_ALL}
{Fore.YELLOW}    {t('banner_title', VERSION)}{Style.RESET_ALL}
{Fore.CYAN}    {t('author')}: {AUTHOR}  |  Telegram: {TELEGRAM}{Style.RESET_ALL}
{Fore.GREEN}    Defense-Grade URL Forensic Analysis  |  Cross-Platform: Linux & Windows{Style.RESET_ALL}
{Fore.MAGENTA}    [NEW] LIVE AI Threat Analyst  |  Logic-Based Risk Scoring{Style.RESET_ALL}
{Fore.GREEN}════════════════════════════════════════════════════════════════════════════════{Style.RESET_ALL}
    """
    print(banner)


def print_separator(char='=', width=80, color=Fore.CYAN):
    """Print a colored separator line."""
    print(f"{color}{char * width}{Style.RESET_ALL}")


def print_section(title, color=Fore.CYAN):
    """Print a formatted section header. Title is already RTL-processed via t()."""
    width = 80
    pad = (width - len(title)) // 2
    print(f"\n{color}{'=' * pad}{title}{'=' * (width - pad - len(title))}{Style.RESET_ALL}")


def print_row(label, value, color=Fore.WHITE, width_label=35, width_value=40):
    """Print a formatted table row. Label/value are already RTL-processed via t()."""
    print(f"  {Fore.CYAN}{label:<{width_label}}{Style.RESET_ALL} {color}{value:<{width_value}}{Style.RESET_ALL}")


def print_alert(message, level='warning'):
    """Print a color-coded alert message. Message is already RTL-processed via t()."""
    if level == 'critical':
        print(f"  {Fore.RED}[!!!] {message}{Style.RESET_ALL}")
    elif level == 'warning':
        print(f"  {Fore.YELLOW}[!] {message}{Style.RESET_ALL}")
    elif level == 'info':
        print(f"  {Fore.CYAN}[*] {message}{Style.RESET_ALL}")
    elif level == 'success':
        print(f"  {Fore.GREEN}[+] {message}{Style.RESET_ALL}")


def loading_animation(message, duration=2.0):
    """Display a loading animation."""
    end_time = time.time() + duration
    while time.time() < end_time:
        sys.stdout.write(f"\r  {Fore.CYAN}[{next(SPINNER)}] {message}...{Style.RESET_ALL}")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write(f"\r  {Fore.GREEN}[+] {message}... {t('scan_complete')}{Style.RESET_ALL}\n")
    sys.stdout.flush()


# =============================================================================
# GOOGLE AI THREAT ANALYSIS ENGINE
# =============================================================================

def get_local_threat_analysis(scan_data, lang):
    """
    LOCAL RULE-BASED HEURISTIC FALLBACK for when Gemini API is unavailable.
    Generates a logical threat analysis summary based on scan metrics.
    Never crashes - always returns a coherent analysis string.
    """
    indicators = []
    recommendations = []
    risk_level = 'low'

    # Extract key metrics
    malicious_count = scan_data.get('malicious_count', 0)
    suspicious_count = scan_data.get('suspicious_count', 0)
    is_typosquatting = scan_data.get('is_typosquatting', False)
    is_suspicious_tld = scan_data.get('is_suspicious_tld', False)
    has_cross_domain_redirect = scan_data.get('has_cross_domain_redirect', False)
    has_ip_in_url = scan_data.get('has_ip_in_url', False)
    has_at_symbol = scan_data.get('has_at_symbol', False)
    entropy = scan_data.get('entropy', 0)
    subdomain_count = scan_data.get('subdomain_count', 0)
    url_length = scan_data.get('url_length', 0)
    has_hex = scan_data.get('has_hex', False)
    https_enabled = scan_data.get('https_enabled', False)
    missing_headers = scan_data.get('missing_headers', 0)
    typosquatting_brand = scan_data.get('typosquatting_brand', None)

    # Determine risk level and build indicators
    if malicious_count > 0:
        risk_level = 'critical'
        if lang == 'ar':
            indicators.append(f"تم الإبلاغ عن هذا الرابط كضار من قبل {malicious_count} مزودي أمان على VirusTotal.")
        elif lang == 'ku':
            indicators.append(f"ئەم بەستەرە وەک مەترسیدار لەلایەن {malicious_count} دابینکەری ئاسایشەوە لەسەر VirusTotal ڕاپۆرت دراوە.")
        else:
            indicators.append(f"This URL is reported as malicious by {malicious_count} security vendors on VirusTotal.")
    elif suspicious_count > 0:
        risk_level = 'high'
        if lang == 'ar':
            indicators.append(f"أبلغ {suspicious_count} مزودي أمان عن نشاط مشبوه لهذا الرابط على VirusTotal.")
        elif lang == 'ku':
            indicators.append(f"{suspicious_count} دابینکەری ئاسایش چالاکییەکی گومانلێکراویان بۆ ئەم بەستەرە لەسەر VirusTotal ڕاپۆرت کردووە.")
        else:
            indicators.append(f"{suspicious_count} security vendors flagged suspicious activity for this URL on VirusTotal.")

    if is_typosquatting:
        risk_level = max(risk_level, 'high')
        brand = typosquatting_brand or 'a known brand'
        if lang == 'ar':
            indicators.append(f"اسم النطاق يحاكي علامة تجارية شرعية ({brand}) - تقنية تصيد شائعة.")
        elif lang == 'ku':
            indicators.append(f"ناوی دۆمەین تەڵەی براندێکی ناسراو دەکات ({brand}) - تەکنیکێکی باوە فیشینگ.")
        else:
            indicators.append(f"The domain name mimics a legitimate brand ({brand}) - a common phishing technique.")

    if is_suspicious_tld:
        risk_level = max(risk_level, 'medium')
        if lang == 'ar':
            indicators.append("النطاق العلوي (TLD) مرتبط بتسجيلات رخيصة تُستخدم غالباً في حملات التصيد.")
        elif lang == 'ku':
            indicators.append("دۆمەینە سەرەکییەکە (TLD) بە تۆمارکردنە هەرزانەکانەوە گرێدراوە کە زۆرجار لە هەمیشەیی فیشینگدا بەکاردەهێنرێن.")
        else:
            indicators.append("The top-level domain (TLD) is associated with cheap registrations often used in phishing campaigns.")

    if has_cross_domain_redirect:
        risk_level = max(risk_level, 'medium')
        if lang == 'ar':
            indicators.append("تم اكتشاف عمليات إعادة توجيه مشبوهة عبر نطاقات متعددة.")
        elif lang == 'ku':
            indicators.append("ڕەوانەکردنەوەی گومانلێکراو لە چەند دۆمەینێکدا دۆزرایەوە.")
        else:
            indicators.append("Suspicious cross-domain redirects were detected.")

    if has_ip_in_url:
        risk_level = max(risk_level, 'high')
        if lang == 'ar':
            indicators.append("يحتوي الرابط على عنوان IP خام - مؤشر تصيد قوي.")
        elif lang == 'ku':
            indicators.append("بەستەر ناونیشانی IPـی ڕەقی تێدایە - نیشانەهێنەری بەهێزی فیشینگ.")
        else:
            indicators.append("The URL contains a raw IP address - a strong phishing indicator.")

    if has_at_symbol:
        risk_level = max(risk_level, 'high')
        if lang == 'ar':
            indicators.append("يحتوي الرابط على رمز @ المستخدم في خدع سرقة بيانات الاعتماد.")
        elif lang == 'ku':
            indicators.append("بەستەر نیشانەی @ تێدایە کە لە فێڵەکانی دزرینی زانیاری چوونەژوورەویدا بەکاردێت.")
        else:
            indicators.append("The URL contains the @ symbol used in credential-harvesting tricks.")

    if entropy > 4.5:
        risk_level = max(risk_level, 'medium')
        if lang == 'ar':
            indicators.append("إنتروبيا الرابط عالية - قد يكون نطاقاً مولداً خوارزمياً (DGA).")
        elif lang == 'ku':
            indicators.append("ئێنتڕۆپیای بەستەر بەرزە - لەوانەیە دۆمەینێکی دەرهێنراو بێت بە ئەلگۆریتم (DGA).")
        else:
            indicators.append("The URL has high entropy - possibly an algorithmically generated domain (DGA).")

    if subdomain_count > 3:
        risk_level = max(risk_level, 'medium')
        if lang == 'ar':
            indicators.append("عدد النطاقات الفرعية مفرط - قد يكون هيكلاً تصيدياً.")
        elif lang == 'ku':
            indicators.append("ژمارەی سەبدۆمەین زۆرە - لەوانەیە ساختارێکی فیشینگ بێت.")
        else:
            indicators.append("Excessive subdomains detected - potential phishing structure.")

    if url_length > 100:
        risk_level = max(risk_level, 'low')
        if lang == 'ar':
            indicators.append("الرابط غير عادي الطول - شائع في رسائل التصيد.")
        elif lang == 'ku':
            indicators.append("بەستەر درێژی نائاساییە - باوە لە نامەکانی فیشینگ.")
        else:
            indicators.append("Unusually long URL - common in phishing emails.")

    if not https_enabled:
        risk_level = max(risk_level, 'medium')
        if lang == 'ar':
            indicators.append("الاتصال غير مشفر (HTTPS مفقود) - بيانات حساسة قد تتعرض للاعتراض.")
        elif lang == 'ku':
            indicators.append("پەیوەندی شێواندنەکراوە (HTTPS نییە) - زانیاری حساس لەوانەیە دەستبدرێت.")
        else:
            indicators.append("Connection is not encrypted (no HTTPS) - sensitive data may be intercepted.")

    if missing_headers >= 3:
        risk_level = max(risk_level, 'low')
        if lang == 'ar':
            indicators.append("رؤوس أمان مهمة مفقودة من الاستجابة.")
        elif lang == 'ku':
            indicators.append("سەردێرەکانی ئاسایشی گرنگ لە وەڵامەکەدا نەماون.")
        else:
            indicators.append("Important security headers are missing from the response.")

    # Build recommendations
    if risk_level == 'critical':
        if lang == 'ar':
            recommendations.append("لا تفتح هذا الرابط. تم اكتشاف برمجيات خبيثة فعلياً. إذا فتحته بالفعل، قم بفحص جهازك فوراً باستخدام برنامج مكافحة فيروسات محدث وغيّر كلمات المرور المهمة.")
        elif lang == 'ku':
            recommendations.append("ئەم بەستەرە مەکەوە. ڤایرۆس بە ڕاستی دۆزراوەتەوە. ئەگەر بێتوو کردتبێ، ئامرازەکەت فوراً بە ئەنتīvایرۆسێکی نوێیەوە بپشکنە و وشەی نهێنی گرنگ بگۆڕە.")
        else:
            recommendations.append("DO NOT open this link. Actual malware has been detected. If you already opened it, scan your device immediately with updated antivirus and change important passwords.")
    elif risk_level == 'high':
        if lang == 'ar':
            recommendations.append("تجنب هذا الرابط. هناك مؤشرات تصيد قوية. لا تُدخل أي بيانات اعتماد أو معلومات شخصية. تحقق من الرابط عبر قنوات رسمية.")
        elif lang == 'ku':
            recommendations.append("ئەم بەستەرە بپارێزە. نیشانەهێنەرە بەهێزەکانی فیشینگ هەیە. هیچ زانیاری چوونەژوورەوە یان تاکە کەسی تێدا بنێرە. بەستەرە لە ڕێگەی فەرمییەکانەوە بپشکنە.")
        else:
            recommendations.append("Avoid this link. Strong phishing indicators are present. Do not enter any credentials or personal information. Verify the link through official channels.")
    elif risk_level == 'medium':
        if lang == 'ar':
            recommendations.append("كن حذراً مع هذا الرابط. تحقق من المصدر قبل إدخال أي معلومات. تأكد من أن الموقع شرعي من خلال البحث عنه independently.")
        elif lang == 'ku':
            recommendations.append("لەگەڵ ئەم بەستەرە ئاگادار بە. سەرچاوەکە بپشکنە پێش ئەوەی هیچ زانیاریەک بنێری. دڵنیا بە لە ڕاستەقینەیی ماڵپەڕەکە لە ڕێگەی گەڕانێکی سەربەخۆوە.")
        else:
            recommendations.append("Be cautious with this link. Verify the source before entering any information. Confirm the site is legitimate by searching for it independently.")
    else:
        if lang == 'ar':
            recommendations.append("يبدو هذا الرابط آمناً نسبياً، لكن يجب الحفاظ على الحذر دائماً. تأكد من أنك تتوقع هذا الرابط قبل فتحه.")
        elif lang == 'ku':
            recommendations.append("ئەم بەستەرە نisbetan پاراستێ دیارە، بەڵام هەمیشە ئاگادار بە. دڵنیا بە لەوە کە چاوەڕێی ئەم بەستەرە دەکەیت پێش ئەوەی بیکەیتەوە.")
        else:
            recommendations.append("This link appears relatively safe, but always remain vigilant. Ensure you are expecting this link before opening it.")

    # Compose the analysis
    if not indicators:
        if lang == 'ar':
            analysis = "لم يتم اكتشاف مؤشرات تهديد واضحة في هذا الرابط. التحليل المحلي لا يجد أي علامات تصيد أو برمجيات خبيثة معروفة."
        elif lang == 'ku':
            analysis = "هیچ نیشانەهێنerekێکی مەترسیدار لەم بەستەرەدا نەدۆزراوەتەوە. شیکاری نێوخۆیی هیچ نیشانەیەکی فیشینگ یان ڤایرۆسی ناسراو نادۆزێتەوە."
        else:
            analysis = "No clear threat indicators were detected in this URL. The local analysis finds no known phishing signs or malware."
    else:
        if lang == 'ar':
            analysis = "تحليل المخاطر:\n" + "\n".join(f"  - {ind}" for ind in indicators)
            analysis += "\n\nالتوصية:\n" + "\n".join(f"  - {rec}" for rec in recommendations)
        elif lang == 'ku':
            analysis = "شیکاری مەترسی:\n" + "\n".join(f"  - {ind}" for ind in indicators)
            analysis += "\n\nپیشنیاز:\n" + "\n".join(f"  - {rec}" for rec in recommendations)
        else:
            analysis = "Risk Analysis:\n" + "\n".join(f"  - {ind}" for ind in indicators)
            analysis += "\n\nRecommendation:\n" + "\n".join(f"  - {rec}" for rec in recommendations)

    return analysis


def get_ai_threat_analysis(scan_data, lang):
    """
    LIVE AI-POWERED THREAT ANALYSIS using Google Gemini API.

    Args:
        scan_data: Dictionary containing all gathered scan metrics
        lang: Target language code ('en', 'ar', 'ku')

    Returns:
        A concise AI-generated threat analysis paragraph (max 3-4 sentences)
        in the requested language, OR falls back to local heuristic analysis
        if the API is unavailable, unconfigured, or rate-limited.
    """
    # Check if Gemini is available and configured
    if not GEMINI_AVAILABLE or not GEMINI_API_KEY or GEMINI_API_KEY.strip() == '' or GEMINI_API_KEY.strip() == 'YOUR_GEMINI_API_KEY_HERE':
        return get_local_threat_analysis(scan_data, lang)

    try:
        # Configure Gemini
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel('gemini-1.5-flash')

        # Build structured prompt with all metrics
        target_url = scan_data.get('url', 'Unknown')
        malicious_count = scan_data.get('malicious_count', 0)
        suspicious_count = scan_data.get('suspicious_count', 0)
        https_enabled = scan_data.get('https_enabled', False)
        is_typosquatting = scan_data.get('is_typosquatting', False)
        is_suspicious_tld = scan_data.get('is_suspicious_tld', False)
        has_cross_domain_redirect = scan_data.get('has_cross_domain_redirect', False)
        has_ip_in_url = scan_data.get('has_ip_in_url', False)
        has_at_symbol = scan_data.get('has_at_symbol', False)
        entropy = scan_data.get('entropy', 0)
        subdomain_count = scan_data.get('subdomain_count', 0)
        url_length = scan_data.get('url_length', 0)
        redirect_hop_count = scan_data.get('redirect_hop_count', 0)
        missing_headers = scan_data.get('missing_headers', 0)
        risk_score = scan_data.get('risk_score', 0)
        typosquatting_brand = scan_data.get('typosquatting_brand', 'None')

        # Language instruction
        if lang == 'ar':
            lang_instruction = (
                "اكتب التحليل باللغة العربية الفصحى. استخدم مصطلحات تقنية دقيقة. "
                "اكتب النص بشكل واضح ومختصر."
            )
        elif lang == 'ku':
            lang_instruction = (
                "ئەم شیکاریە بە زمانی کوردی (بادینی) بنووسە. "
                "زمانێکی ڕوون و کورت بەکاربهێنە."
            )
        else:
            lang_instruction = (
                "Write the analysis in clear, professional English. "
                "Use precise cybersecurity terminology."
            )

        prompt = f"""You are an Elite Cyber Security Forensic Analyst with 20+ years of experience.

Analyze the following URL scan data and generate a concise threat assessment (maximum 3-4 sentences) followed by one clear actionable safety recommendation.

URL SCANNED: {target_url}
RISK SCORE: {risk_score}/100

--- VIRUSTOTAL DATA ---
Malicious Flags: {malicious_count}
Suspicious Flags: {suspicious_count}

--- URL STRUCTURE ---
HTTPS Enabled: {https_enabled}
Typosquatting Detected: {is_typosquatting} (Brand: {typosquatting_brand})
Suspicious TLD: {is_suspicious_tld}
IP Address in URL: {has_ip_in_url}
@ Symbol in URL: {has_at_symbol}
URL Entropy: {entropy}
Excessive Subdomains: {subdomain_count}
URL Length: {url_length} characters

--- REDIRECTS ---
Redirect Hops: {redirect_hop_count}
Cross-Domain Redirects: {has_cross_domain_redirect}

--- SECURITY HEADERS ---
Missing Important Headers: {missing_headers}

{lang_instruction}

Provide ONLY the analysis text (3-4 sentences + 1 recommendation). No markdown, no bullet points, no headers.
"""

        # Generate with safety settings and timeout
        safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]

        response = model.generate_content(
            prompt,
            safety_settings=safety_settings,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=256,
                temperature=0.3,
            )
        )

        if response and response.text:
            analysis = response.text.strip()
            # Ensure it's not too long
            if len(analysis) > 800:
                analysis = analysis[:797] + "..."
            return analysis
        else:
            return get_local_threat_analysis(scan_data, lang)

    except Exception as e:
        # ALL API errors fall back to local analysis (no crash, no freeze)
        return get_local_threat_analysis(scan_data, lang)


# =============================================================================
# CORE ANALYSIS ENGINE
# =============================================================================

def create_session():
    """Create a robust requests session with retry logic."""
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0'
    })
    session.timeout = 15
    return session


def fetch_url_data(url):
    """Fetch URL data following redirects and collecting chain info."""
    session = create_session()
    try:
        response = session.get(url, allow_redirects=True, timeout=15, verify=False)
        redirect_chain = []
        if response.history:
            for resp in response.history:
                redirect_chain.append({
                    'url': resp.url,
                    'status': resp.status_code,
                    'headers': dict(resp.headers)
                })
        redirect_chain.append({
            'url': response.url,
            'status': response.status_code,
            'headers': dict(response.headers)
        })
        return {
            'success': True,
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'final_url': response.url,
            'redirect_chain': redirect_chain,
            'content_length': len(response.content),
            'response_time': response.elapsed.total_seconds()
        }
    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'timeout'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'error': 'connection'}
    except requests.exceptions.TooManyRedirects:
        return {'success': False, 'error': 'redirects'}
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': str(e)}
    finally:
        session.close()


def levenshtein_distance(s1, s2):
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def similarity_ratio(s1, s2):
    """Calculate similarity ratio between two strings (0.0 to 1.0)."""
    return SequenceMatcher(None, s1.lower(), s2.lower()).ratio()


def shannon_entropy(string):
    """Calculate Shannon entropy of a string."""
    if not string:
        return 0.0
    entropy = 0.0
    length = len(string)
    for char in set(string):
        p = string.count(char) / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _extract_registered_domain(domain):
    """Extract the registered domain (second-level + TLD) from a hostname."""
    parts = domain.lower().split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain.lower()


def _normalize_homoglyphs(text):
    """Replace common homoglyph characters with their ASCII equivalents."""
    homograph_chars = {
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
        '@': 'a', '$': 's', 'rn': 'm', '!': 'i',
        '|': 'l', '(': 'c', '+': 't', '7': 't', '8': 'b',
        '9': 'g', '2': 'z', '6': 'b'
    }
    normalized = text.lower()
    for bad, good in homograph_chars.items():
        normalized = normalized.replace(bad, good)
    return normalized


def check_typosquatting(domain):
    """
    Check if domain is typosquatting a known brand.
    Uses multi-layer detection: homograph IDN, Levenshtein distance,
    containment analysis, and character substitution normalization.
    Returns dict with findings.
    """
    results = {
        'is_typosquatting': False,
        'matched_brand': None,
        'similarity': 0.0,
        'method': None,
        'details': []
    }
    domain_lower = domain.lower()
    # Extract the registered domain (second-level + TLD)
    registered = _extract_registered_domain(domain)
    domain_no_tld = registered.split('.')[0] if '.' in registered else registered

    # Build comprehensive whitelist of all legitimate domains
    all_legit = set()
    for brand, domains in TOP_BRANDS.items():
        for d in domains:
            all_legit.add(d.lower())
            all_legit.add('www.' + d.lower())

    # Fast-path: exact match whitelist
    if domain_lower in all_legit or domain_lower.replace('www.', '') in all_legit:
        return results
    # Also whitelist: if the registered domain itself is legitimate
    if registered in all_legit:
        return results

    # Check for homograph attacks (IDN/punycode)
    if 'xn--' in domain_lower:
        results['is_typosquatting'] = True
        results['method'] = 'homograph'
        results['details'].append(t('homograph_detected'))
        return results

    # Normalize the domain for homoglyph detection
    normalized = _normalize_homoglyphs(domain_no_tld)
    was_modified = (normalized != domain_no_tld.lower())

    # Build comprehensive list of parts to check
    check_parts = set([domain_no_tld, normalized])
    if '-' in domain_no_tld:
        hyphen_parts = domain_no_tld.split('-')
        norm_hyphen_parts = normalized.split('-')
        check_parts.update(hyphen_parts)
        check_parts.update(norm_hyphen_parts)
        # Combine adjacent parts (catches pay-pal -> paypal)
        for i in range(len(hyphen_parts) - 1):
            combined = hyphen_parts[i] + hyphen_parts[i + 1]
            check_parts.add(combined)
            check_parts.add(_normalize_homoglyphs(combined))

    # Compare against top brands
    for brand, legitimate_domains in TOP_BRANDS.items():
        brand_lower = brand.lower()

        # Layer 1: Direct similarity (full registered domain vs brand)
        sim = similarity_ratio(domain_no_tld, brand_lower)
        if sim >= 0.75 and domain_no_tld != brand_lower:
            results['is_typosquatting'] = True
            results['matched_brand'] = brand
            results['similarity'] = round(sim, 3)
            results['method'] = 'similarity'
            results['details'].append(f"{t('typosquatting_detected')}: {domain} -> {brand}")
            return results

        # Layer 2: Domain contains brand with suspicious additions
        if brand_lower in domain_no_tld and domain_no_tld != brand_lower:
            is_legitimate = any(
                similarity_ratio(registered, legit.lower()) > 0.85
                for legit in legitimate_domains
            )
            if not is_legitimate:
                results['is_typosquatting'] = True
                results['matched_brand'] = brand
                results['similarity'] = round(similarity_ratio(domain_no_tld, brand_lower), 3)
                results['method'] = 'containment'
                results['details'].append(f"{t('typosquatting_detected')}: {domain} contains '{brand}'")
                return results

        # Layer 3: Check all parts (including hyphen-split and combined)
        for part in check_parts:
            if part and len(part) >= 3 and part != domain_no_tld:
                part_sim = similarity_ratio(part, brand_lower)
                if part_sim >= 0.80:
                    results['is_typosquatting'] = True
                    results['matched_brand'] = brand
                    results['similarity'] = round(part_sim, 3)
                    results['method'] = 'partial_match'
                    results['details'].append(f"{t('typosquatting_detected')}: {domain} (part: {part}) -> {brand}")
                    return results

        # Layer 4: Normalized exact match (catches g00gle->google)
        if was_modified and normalized == brand_lower:
            results['is_typosquatting'] = True
            results['matched_brand'] = brand
            results['similarity'] = 1.0
            results['method'] = 'homograph_substitution'
            results['details'].append(f"{t('typosquatting_detected')}: {domain} (normalized: {normalized}) -> {brand}")
            return results

        # Layer 5: Normalized fuzzy match
        norm_sim = similarity_ratio(normalized, brand_lower)
        if was_modified and norm_sim >= 0.80 and normalized != brand_lower:
            results['is_typosquatting'] = True
            results['matched_brand'] = brand
            results['similarity'] = round(norm_sim, 3)
            results['method'] = 'homograph_substitution'
            results['details'].append(f"{t('typosquatting_detected')}: {domain} (normalized: {normalized}) -> {brand}")
            return results

        # Layer 6: Levenshtein distance check (catches typos like gooogle)
        if len(domain_no_tld) >= 3 and len(brand_lower) >= 3:
            max_len = max(len(domain_no_tld), len(brand_lower))
            if max_len > 0:
                dist = levenshtein_distance(domain_no_tld, brand_lower)
                lev_sim = 1.0 - (dist / max_len)
                if lev_sim >= 0.75 and dist > 0:
                    results['is_typosquatting'] = True
                    results['matched_brand'] = brand
                    results['similarity'] = round(lev_sim, 3)
                    results['method'] = 'levenshtein'
                    results['details'].append(f"{t('typosquatting_detected')}: {domain} (Levenshtein: {dist}) -> {brand}")
                    return results

        # Layer 7: Subdomain brand check
        subdomain_parts = domain_lower.replace(registered, '').strip('.').split('.') if registered else []
        subdomain_text = ''.join(subdomain_parts)
        if subdomain_text and brand_lower in subdomain_text and len(brand_lower) >= 4:
            is_legitimate = any(
                similarity_ratio(registered, legit.lower()) > 0.85
                for legit in legitimate_domains
            )
            if not is_legitimate:
                results['is_typosquatting'] = True
                results['matched_brand'] = brand
                results['similarity'] = round(similarity_ratio(subdomain_text, brand_lower), 3)
                results['method'] = 'subdomain_brand'
                results['details'].append(f"{t('typosquatting_detected')}: {domain} (brand in subdomain: {brand}) -> {brand}")
                return results

    return results


def check_redirect_chain(redirect_chain, original_domain):
    """Analyze redirect chain for suspicious cross-domain jumps."""
    results = {
        'chain': [],
        'has_cross_domain': False,
        'suspicious_hops': [],
        'hop_count': len(redirect_chain) - 1 if len(redirect_chain) > 1 else 0
    }

    if not redirect_chain or len(redirect_chain) <= 1:
        return results

    original_domain_lower = original_domain.lower()

    for i, hop in enumerate(redirect_chain):
        try:
            hop_domain = urlparse(hop['url']).netloc.lower()
        except:
            hop_domain = hop['url']

        results['chain'].append({
            'hop': i + 1,
            'url': hop['url'],
            'status': hop['status'],
            'domain': hop_domain
        })

        # Check for cross-domain redirects (skip first hop)
        if i > 0:
            prev_domain = results['chain'][i-1]['domain']
            if hop_domain != prev_domain:
                results['has_cross_domain'] = True
                # Check if the new domain is suspicious
                is_suspicious = any(
                    tld in hop_domain for tld in SUSPICIOUS_TLDS
                )
                if is_suspicious:
                    results['suspicious_hops'].append({
                        'from': prev_domain,
                        'to': hop_domain,
                        'reason': 'cross_domain_suspicious_tld'
                    })

    return results


def check_tld(domain):
    """Check TLD risk level."""
    results = {
        'tld': None,
        'is_suspicious': False,
        'risk_level': 'low'
    }

    # Extract TLD
    parts = domain.lower().split('.')
    if len(parts) >= 2:
        tld = '.' + parts[-1]
        results['tld'] = tld
        if tld in SUSPICIOUS_TLDS:
            results['is_suspicious'] = True
            results['risk_level'] = 'high'

    return results


def analyze_url_structure(url):
    """Perform deep URL entropy and structure analysis."""
    results = {
        'entropy': 0.0,
        'length': len(url),
        'subdomain_count': 0,
        'has_ip': False,
        'has_at_symbol': '@' in url,
        'has_hex': bool(re.search(r'%[0-9a-fA-F]{2}', url)),
        'path_depth': 0,
        'suspicious_patterns': []
    }

    parsed = urlparse(url)
    domain_part = parsed.netloc
    path_part = parsed.path

    # Shannon entropy of full URL
    results['entropy'] = round(shannon_entropy(url), 3)

    # Subdomain count
    if domain_part:
        parts = domain_part.split('.')
        # Remove TLD and domain name
        if len(parts) > 2:
            results['subdomain_count'] = len(parts) - 2

    # Check for IP address in URL
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    results['has_ip'] = bool(ip_pattern.search(domain_part))

    # Path depth
    if path_part:
        results['path_depth'] = len([p for p in path_part.split('/') if p])

    # Check for suspicious keywords in path
    phishing_keywords = [
        'login', 'signin', 'verify', 'account', 'password', 'credential',
        'secure', 'auth', 'authenticate', 'wallet', 'banking', 'confirm',
        'update', 'security', 'identify', 'validation', 'billing', 'payment'
    ]
    url_lower = url.lower()
    found_keywords = [kw for kw in phishing_keywords if kw in url_lower]
    if found_keywords:
        results['suspicious_patterns'].extend(found_keywords)

    return results


def check_security_headers(headers):
    """Validate security headers presence and quality."""
    results = {}
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header, info in SECURITY_HEADERS.items():
        header_lower = header.lower()
        if header_lower in headers_lower:
            value = headers_lower[header_lower]
            status = 'present'

            # Check for weak configurations
            if header == 'X-Frame-Options':
                if value.upper() not in ['DENY', 'SAMEORIGIN']:
                    status = 'weak'
            elif header == 'X-Content-Type-Options':
                if 'nosniff' not in value.lower():
                    status = 'weak'
            elif header == 'Strict-Transport-Security':
                if 'max-age' not in value.lower():
                    status = 'weak'
            elif header == 'Content-Security-Policy':
                if len(value) < 10:
                    status = 'weak'

            results[header] = {
                'status': status,
                'value': value[:80] + '...' if len(value) > 80 else value
            }
        else:
            results[header] = {
                'status': 'missing',
                'value': None
            }

    return results


# =============================================================================
# VIRUSTOTAL API v3 - MULTI-KEY ROTATION SYSTEM
# =============================================================================

def _get_vt_headers(api_key):
    """Build VirusTotal API v3 headers with the given key."""
    return {
        'x-apikey': api_key,
        'User-Agent': 'MJTOOL/2.6',
        'Accept': 'application/json'
    }


def _encode_url_for_vt(url):
    """Encode URL for VT v3 URL ID (base64url without padding)."""
    url_bytes = url.encode('utf-8')
    b64 = base64.urlsafe_b64encode(url_bytes).decode('utf-8')
    return b64.rstrip('=')


def check_virustotal_v3(url):
    """
    Check URL reputation via VirusTotal API v3 with automatic key rotation.
    Tries up to 5 API keys with fallback on rate-limit (429), invalid key (401/403),
    or daily quota exhaustion.
    Returns detailed results including last_analysis_stats and per-vendor results.
    """
    results = {
        'checked': False,
        'positives': 0,
        'total': 0,
        'stats': {},
        'malicious_vendors': [],
        'permalink': None,
        'error': None,
        'all_keys_exhausted': False
    }

    # Check if any keys are configured
    valid_keys = [k.strip() for k in VT_API_KEYS if k and k.strip() and k.strip().lower() not in ('', 'your_key')]
    if not valid_keys:
        results['error'] = 'no_key'
        return results

    session = create_session()
    url_encoded = _encode_url_for_vt(url)

    # Try each key with automatic rotation
    for key_idx, api_key in enumerate(valid_keys):
        key_num = key_idx + 1
        try:
            headers = _get_vt_headers(api_key)

            # --- Step 1: Try to get existing analysis directly via URL ID ---
            lookup_endpoint = f"{VT_API_BASE}/urls/{url_encoded}"
            resp = session.get(lookup_endpoint, headers=headers, timeout=20)

            # Handle rate limiting (429) or auth errors (401/403) -> rotate key
            if resp.status_code in (401, 403):
                if key_idx < len(valid_keys) - 1:
                    print(f"  {Fore.YELLOW}[!] {t('vt_rotation_warning').format(key_num, key_num + 1)}{Style.RESET_ALL}")
                    time.sleep(0.5)
                    continue
                else:
                    results['error'] = 'all_keys_exhausted'
                    results['all_keys_exhausted'] = True
                    break

            if resp.status_code == 429:
                if key_idx < len(valid_keys) - 1:
                    print(f"  {Fore.YELLOW}[!] {t('vt_rotation_warning').format(key_num, key_num + 1)}{Style.RESET_ALL}")
                    time.sleep(1)
                    continue
                else:
                    results['error'] = 'all_keys_exhausted'
                    results['all_keys_exhausted'] = True
                    break

            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get('data', {}).get('attributes', {})

                # Extract analysis statistics
                last_analysis = attrs.get('last_analysis_stats', {})
                malicious = last_analysis.get('malicious', 0)
                suspicious = last_analysis.get('suspicious', 0)
                undetected = last_analysis.get('undetected', 0)
                harmless = last_analysis.get('harmless', 0)
                timeout_count = last_analysis.get('timeout', 0)

                total_vendors = malicious + suspicious + undetected + harmless + timeout_count

                results['checked'] = True
                results['positives'] = malicious + suspicious
                results['total'] = total_vendors if total_vendors > 0 else 0
                results['stats'] = last_analysis
                results['permalink'] = attrs.get('last_analysis_results', {}).get('permalink') or f"https://www.virustotal.com/gui/url/{url_encoded}"

                # Extract per-vendor malicious results
                vendor_results = attrs.get('last_analysis_results', {})
                malicious_vendors = []
                for vendor_name, vendor_data in vendor_results.items():
                    category = vendor_data.get('category', '')
                    if category in ('malicious', 'phishing', 'suspicious'):
                        malicious_vendors.append({
                            'engine': vendor_name,
                            'category': category,
                            'result': vendor_data.get('result', 'N/A')
                        })
                results['malicious_vendors'] = malicious_vendors
                session.close()
                return results

            # If URL not found (404), we need to submit it first
            if resp.status_code == 404:
                # --- Step 2: Submit URL for scanning ---
                submit_endpoint = f"{VT_API_BASE}/urls"
                submit_resp = session.post(
                    submit_endpoint,
                    headers=headers,
                    data={'url': url},
                    timeout=20
                )

                if submit_resp.status_code in (401, 403):
                    if key_idx < len(valid_keys) - 1:
                        print(f"  {Fore.YELLOW}[!] {t('vt_rotation_warning').format(key_num, key_num + 1)}{Style.RESET_ALL}")
                        time.sleep(0.5)
                        continue
                    else:
                        results['error'] = 'all_keys_exhausted'
                        results['all_keys_exhausted'] = True
                        break

                if submit_resp.status_code == 429:
                    if key_idx < len(valid_keys) - 1:
                        print(f"  {Fore.YELLOW}[!] {t('vt_rotation_warning').format(key_num, key_num + 1)}{Style.RESET_ALL}")
                        time.sleep(1)
                        continue
                    else:
                        results['error'] = 'all_keys_exhausted'
                        results['all_keys_exhausted'] = True
                        break

                if submit_resp.status_code in (200, 202):
                    # Wait for analysis to complete
                    time.sleep(3)

                    # Retry lookup
                    resp2 = session.get(lookup_endpoint, headers=headers, timeout=20)
                    if resp2.status_code == 200:
                        data = resp2.json()
                        attrs = data.get('data', {}).get('attributes', {})

                        last_analysis = attrs.get('last_analysis_stats', {})
                        malicious = last_analysis.get('malicious', 0)
                        suspicious = last_analysis.get('suspicious', 0)
                        undetected = last_analysis.get('undetected', 0)
                        harmless = last_analysis.get('harmless', 0)
                        timeout_count = last_analysis.get('timeout', 0)

                        total_vendors = malicious + suspicious + undetected + harmless + timeout_count

                        results['checked'] = True
                        results['positives'] = malicious + suspicious
                        results['total'] = total_vendors if total_vendors > 0 else 0
                        results['stats'] = last_analysis
                        results['permalink'] = f"https://www.virustotal.com/gui/url/{url_encoded}"

                        # Extract per-vendor malicious results
                        vendor_results = attrs.get('last_analysis_results', {})
                        malicious_vendors = []
                        for vendor_name, vendor_data in vendor_results.items():
                            category = vendor_data.get('category', '')
                            if category in ('malicious', 'phishing', 'suspicious'):
                                malicious_vendors.append({
                                    'engine': vendor_name,
                                    'category': category,
                                    'result': vendor_data.get('result', 'N/A')
                                })
                        results['malicious_vendors'] = malicious_vendors
                        session.close()
                        return results
                    else:
                        results['error'] = 'scan_pending'
                        session.close()
                        return results
                else:
                    results['error'] = f'submit_error_{submit_resp.status_code}'
                    session.close()
                    return results

            # Any other error -> try next key if available
            if key_idx < len(valid_keys) - 1:
                print(f"  {Fore.YELLOW}[!] {t('vt_rotation_warning').format(key_num, key_num + 1)}{Style.RESET_ALL}")
                time.sleep(0.5)
                continue
            else:
                results['error'] = f'api_error_{resp.status_code}'
                break

        except requests.exceptions.Timeout:
            if key_idx < len(valid_keys) - 1:
                print(f"  {Fore.YELLOW}[!] {t('vt_rotation_warning').format(key_num, key_num + 1)}{Style.RESET_ALL}")
                time.sleep(0.5)
                continue
            else:
                results['error'] = 'timeout'
                break
        except requests.exceptions.ConnectionError:
            if key_idx < len(valid_keys) - 1:
                print(f"  {Fore.YELLOW}[!] {t('vt_rotation_warning').format(key_num, key_num + 1)}{Style.RESET_ALL}")
                time.sleep(0.5)
                continue
            else:
                results['error'] = 'connection'
                break
        except Exception:
            if key_idx < len(valid_keys) - 1:
                print(f"  {Fore.YELLOW}[!] {t('vt_rotation_warning').format(key_num, key_num + 1)}{Style.RESET_ALL}")
                time.sleep(0.5)
                continue
            else:
                results['error'] = 'unknown_exception'
                break

    # If we exhausted all keys
    if results.get('all_keys_exhausted'):
        print(f"  {Fore.YELLOW}[!] {t('vt_all_keys_exhausted')}{Style.RESET_ALL}")

    session.close()
    return results


# =============================================================================
# RISK SCORING ENGINE (LOGIC-BASED v2.6)
# =============================================================================

def calculate_risk_score(results):
    """
    Calculate overall risk score from 0 (safe) to 100 (critical).
    v2.6 LOGIC-BASED APPROACH:
    - If VirusTotal malicious_count > 0: AUTO 90-100 (CRITICAL)
    - If VirusTotal suspicious_count > 0 (no malicious): AUTO 70-85 (HIGH)
    - Otherwise: use additive scoring from other indicators
    A URL with even ONE malicious flag is NEVER classified as 'Safe'.
    """
    # Extract VT counts
    vt_stats = results.get('virustotal', {}).get('stats', {})
    malicious_count = vt_stats.get('malicious', 0)
    suspicious_count = vt_stats.get('suspicious', 0)

    # =================================================================
    # CRITICAL RULE: VT MALICIOUS FLAGS = IMMEDIATE MAXIMUM RISK
    # =================================================================
    if malicious_count > 0:
        # Base score of 90, up to 100 based on how many vendors flagged it
        # Even 1 malicious flag = minimum 90 (CRITICAL)
        score = 90 + min((malicious_count * 2), 10)
        # Cap at 100
        score = min(score, 100)
        # Ensure minimum 90 even with just 1 flag
        score = max(score, 90)
        return score

    # =================================================================
    # HIGH RULE: VT SUSPICIOUS FLAGS = HIGH RISK
    # =================================================================
    if suspicious_count > 0:
        # Base score of 70, up to 85 based on suspicious count
        score = 70 + min((suspicious_count * 3), 15)
        score = min(score, 85)
        score = max(score, 70)
        return score

    # =================================================================
    # ADDITIVE SCORING (only when VT is clean)
    # =================================================================
    score = 0

    # Typosquatting (up to 30 points)
    if results['typosquatting']['is_typosquatting']:
        score += 30

    # Suspicious TLD (up to 15 points)
    if results['tld']['is_suspicious']:
        score += 15

    # Redirect chain issues (up to 15 points)
    if results['redirects']['has_cross_domain']:
        score += 10
    if len(results['redirects']['suspicious_hops']) > 0:
        score += 5

    # URL entropy and structure (up to 20 points)
    entropy = results['url_structure']['entropy']
    if entropy > 4.5:
        score += 10
    elif entropy > 4.0:
        score += 5

    if results['url_structure']['subdomain_count'] > 3:
        score += 5
    if results['url_structure']['has_ip']:
        score += 5
    if results['url_structure']['has_at_symbol']:
        score += 5
    if results['url_structure']['has_hex']:
        score += 3
    if results['url_structure']['length'] > 100:
        score += 3
    if len(results['url_structure']['suspicious_patterns']) > 2:
        score += 5

    # Security headers (up to 10 points)
    missing_headers = sum(
        1 for h in results['headers'].values()
        if h['status'] == 'missing' and SECURITY_HEADERS.get(next(
            (k for k in SECURITY_HEADERS if k.lower() == next(
                (hk for hk in SECURITY_HEADERS if hk.lower() ==
                 [kk for kk in SECURITY_HEADERS][0].lower()), ''
            )), ''
        ), {}).get('required', False)
    )
    score += min(missing_headers * 3, 10)

    return min(score, 100)


def determine_verdict(score):
    """Determine risk verdict based on score.
    v2.6 Thresholds:
    - 90-100: CRITICAL / MALICIOUS (RED)
    - 70-89:  HIGH / SUSPICIOUS (YELLOW)
    - 40-69:  MODERATE / SUSPICIOUS (YELLOW)
    - 0-39:   LOW / CLEAN (GREEN)
    """
    if score >= 90:
        return 'malicious', Fore.RED
    elif score >= 70:
        return 'suspicious', Fore.YELLOW
    elif score >= 40:
        return 'suspicious', Fore.YELLOW
    else:
        return 'clean', Fore.GREEN


# =============================================================================
# REPORT GENERATION
# =============================================================================

def generate_explanations(results):
    """Generate detailed educational explanations for all findings."""
    explanations = []

    # Determine description key based on current language
    if current_lang == 'en':
        desc_key = 'description_en'
    elif current_lang == 'ar':
        desc_key = 'description_ar'
    else:
        desc_key = 'description_ku'

    # Typosquatting explanation
    if results['typosquatting']['is_typosquatting']:
        if results['typosquatting']['method'] == 'homograph':
            explanations.append({
                'severity': 'critical',
                'title': t('homograph_detected'),
                'explanation': (
                    "IDN homograph attacks use visually similar Unicode characters to spoof legitimate domains. "
                    "For example, '\\u0430' (Cyrillic) looks identical to 'a' (Latin). Attackers register these domains "
                    "to trick users into entering credentials on fake login pages that look exactly like the real site."
                    if current_lang == 'en' else
                    "هجمات الحروف المتشابهة IDN تستخدم أحرف Unicode متشابهة بصرياً لانتحال النطاقات الشرعية. "
                    "على سبيل المثال، '\\u0430' (السيريلية) تبدو مطابقة لـ 'a' (اللاتينية). المهاجمون يسجلون هذه النطاقات "
                    "لخداع المستخدمين لإدخال بيانات الاعتماد على صفحات وهمية تبدو تماماً كالموقع الحقيقي."
                    if current_lang == 'ar' else
                    "هێرشەکانی هاوشێوەی پیتی IDN کاراکتەری Unicodeـی نزیك لە یەکتر بەکاردێنن بۆ گومڕاكردنی دۆمەینە ڕاستەقینەکان. "
                    "بۆ نموونە، '\\u0430' (سیریلی) وەك 'a' (لاتینی) دەردەکەوێت. هێرشبەران ئەم دۆمەینانە تۆمار دەکەن "
                    "بۆ فێڵکردنی بەکارهێنەران بۆ نووسینی زانیاری چوونەژوورەوە لەسەر پەڕە ساختەکان."
                )
            })
        else:
            explanations.append({
                'severity': 'critical',
                'title': t('typosquatting_detected'),
                'explanation': (
                    f"Typosquatting domains mimic legitimate brands to deceive users. The domain '{results['target_domain']}' "
                    f"is {results['typosquatting']['similarity']*100:.1f}% similar to '{results['typosquatting']['matched_brand']}'. "
                    "Attackers rely on typos or visual deception to drive traffic to phishing pages."
                    if current_lang == 'en' else
                    f"دومينات التصيد تحاكي العلامات التجارية الشرعية لخداع المستخدمين. النطاق '{results['target_domain']}' "
                    f"متشابه بنسبة {results['typosquatting']['similarity']*100:.1f}% مع '{results['typosquatting']['matched_brand']}'. "
                    "يعتمد المهاجمون على الأخطاء الإملائية أو الخداع البصري لتوجيه الزيارات إلى صفحات التصيد."
                    if current_lang == 'ar' else
                    f"دۆمەینە فیشەرەکان براندی ڕاستەقینە تەڵە دەکەن بۆ فێڵکردنی بەکارهێنەران. دۆمەین '{results['target_domain']}' "
                    f"بە {results['typosquatting']['similarity']*100:.1f}% هاوشێوەی '{results['typosquatting']['matched_brand']}'. "
                    "هێرشبەران پشت بە هەڵەکانی ڕێنووس یان فێڵی بینراو دەبەستن بۆ ڕەوانەکردنی ترافیک بۆ پەڕەکانی فیشینگ."
                )
            })

    # Redirect explanation
    if results['redirects']['has_cross_domain']:
        hop_info = " -> ".join([
            f"{h['domain']}" for h in results['redirects']['chain']
        ])
        explanations.append({
            'severity': 'warning',
            'title': t('suspicious_redirect'),
            'explanation': (
                f"Cross-domain redirects detected: {hop_info}. Phishing campaigns often chain multiple redirects "
                "through compromised or burner domains to hide the final destination from security filters and analysts."
                if current_lang == 'en' else
                f"تم الكشف عن إعادات توجيه بين النطاقات: {hop_info}. حملات التصيد غالباً ما تخلق سلاسل "
                "من إعادات التوجيه عبر نطاقات مخترقة أو مؤقتة لإخفاء الوجهة النهائية عن مرشحات الأمان."
                if current_lang == 'ar' else
                f"ڕەوانەکردنەوەی نێوان دۆمەین دۆزرایەوە: {hop_info}. هەمیشەیی فیشینگ زنجیرەیەکی زۆر "
                "ڕەوانەکردنەوە دروست دەکەن لە ڕێگەی دۆمەینەکانی تێکشکاو یان کاتییەوە بۆ شاردنەوەی شوێنی کۆتایی."
            )
        })

    # TLD explanation
    if results['tld']['is_suspicious']:
        explanations.append({
            'severity': 'warning',
            'title': t('suspicious_tld'),
            'explanation': (
                f"The TLD '{results['tld']['tld']}' is frequently abused by phishing actors because these domains are "
                "cheap or free to register, offer WHOIS privacy, and lack reputation monitoring. Legitimate services rarely "
                "use these TLDs for authentication or payment pages."
                if current_lang == 'en' else
                f"النطاق العلوي '{results['tld']['tld']}' يُساء استخدامه بكثرة من قبل مرتكبي التصيد لأن هذه النطاقات "
                "رخيصة أو مجانية للتسجيل، توفر خصوصية WHOIS، وتفتقر لمراقبة السمعة. الخدمات الشرعية نادراً ما "
                "تستخدم هذه النطاقات لصفحات المصادقة أو الدفع."
                if current_lang == 'ar' else
                f"دۆمەینە سەرەکییەکە '{results['tld']['tld']}' زۆرجار لەلایەن فیشەرانەوە بەدرۆ بەکاردەهێنرێت چونکە ئەم دۆمەینانە "
                "ارزان یان بێبەرامبەرن بۆ تۆمارکردن، تایبەتی WHOIS دابین دەکەن، و چاودێری ناوبانگیان نییە. خزمەتگوزارییە ڕاستەقینەکان "
                "کەم و کات ئەم دۆمەینانە بەکاردەهێنن بۆ پەڕەکانی دڵنیاکردنەوە یان پارەدان."
            )
        })

    # Entropy explanation
    if results['url_structure']['entropy'] > 4.5:
        explanations.append({
            'severity': 'warning',
            'title': t('high_entropy'),
            'explanation': (
                f"Shannon Entropy = {results['url_structure']['entropy']}. High entropy indicates randomness, which is "
                "characteristic of algorithmically generated domains (DGA) used by malware and phishing kits to evade "
                "blacklist-based detection systems."
                if current_lang == 'en' else
                f"إنتروبيا شانون = {results['url_structure']['entropy']}. الإنتروبيا العالية تشير إلى العشوائية، وهي "
                "سمة من سمات النطاقات المولدة خوارزمياً (DGA) التي يستخدمها البرمجيات الخبيثة وعدد التصيد لتجنب "
                "أنظمة الكشف القائمة على القوائم السوداء."
                if current_lang == 'ar' else
                f"ئێنتڕۆپیای شانۆن = {results['url_structure']['entropy']}. ئێنتڕۆپیای بەرز دەڵێتەوە لە هەڕەمەكی، کە "
                "تایبەتمەندی دۆمەینە دروستکراوەکانە بە ئەلگۆریتم (DGA) کە نەرمەواڵە زیانبەخشەکان و کۆمەڵە فیشینگەکان بەکاریان دێنن بۆ خۆپاراستن "
                "لە سیستەمەکانی دۆزینەوە ئەوانەی لەسەر لیستی ڕەش دان."
            )
        })

    # Subdomain explanation
    if results['url_structure']['subdomain_count'] > 3:
        explanations.append({
            'severity': 'warning',
            'title': t('excessive_subdomains'),
            'explanation': (
                f"Detected {results['url_structure']['subdomain_count']} subdomains. Phishers create deep subdomain chains "
                "like 'login.secure.auth.target.com.evil.com' to make the URL look legitimate at a quick glance. "
                "Always verify the actual registered domain (the last two parts before the path)."
                if current_lang == 'en' else
                f"تم الكشف عن {results['url_structure']['subdomain_count']} نطاقات فرعية. يقوم مرتكبو التصيد بإنشاء سلاسل نطاقات فرعية عميقة "
                "لجعل الرابط يبدو شرعياً عند النظر السريع. "
                "تحقق دائماً من النطاق المسجل الفعلي (الجزآن الأخيران قبل المسار)."
                if current_lang == 'ar' else
                f"{results['url_structure']['subdomain_count']} سەبدۆمەین دۆزرایەوە. فیشەران زنجیرە سەبدۆمەینی قووڵ دروست دەکەن "
                "وەک 'login.secure.auth.target.com.evil.com' بۆ ئەوەی بەستەر لە سەرەتاوە ڕاستەقینە دەربخات. "
                "هەمیشە دۆمەینی تۆمارکراوی ڕاستەقینە بپشکنە (دوو بەشی کۆتایی پێش ڕێچکە)."
            )
        })

    # IP in URL explanation
    if results['url_structure']['has_ip']:
        explanations.append({
            'severity': 'critical',
            'title': t('ip_detected'),
            'explanation': (
                "Legitimate websites use domain names, not raw IP addresses. Phishers use IPs to bypass DNS-based "
                "filtering and quickly rotate infrastructure before detection. This is a strong phishing indicator."
                if current_lang == 'en' else
                "المواقع الشرعية تستخدم أسماء النطاقات، وليس عناوين IP الخام. يستخدم مرتكبو التصيد عناوين IP لتجاوز "
                "الفلترة القائمة على DNS وتدوير البنية التحتية بسرعة قبل الاكتشاف. هذا مؤشر تصيد قوي."
                if current_lang == 'ar' else
                "ماڵپەڕە ڕاستەقینەکان ناوی دۆمەین بەکاردەهێنن، نەک ناونیشانی IPـی ڕەق. فیشەران IP بەکاردەهێنن بۆ تێپەڕین لە "
                "فیلتەری DNS و خێرا گۆڕینی بنەمایەتی پێش دۆزینەوە. ئەمە نیشانەهێنەری بەهێزی فیشینگە."
            )
        })

    # @ symbol explanation
    if results['url_structure']['has_at_symbol']:
        explanations.append({
            'severity': 'critical',
            'title': t('at_detected'),
            'explanation': (
                "The '@' symbol in URLs is used for authentication but attackers abuse it as a visual trick: "
                "'https://google.com@evil.com' actually navigates to 'evil.com', but users may only see 'google.com'. "
                "Modern browsers block this, but it's still used in phishing emails and documents."
                if current_lang == 'en' else
                "رمز '@' في الروابط يُستخدم للمصادقة لكن المهاجمين يسيئون استخدامه كخدعة بصرية: "
                "'https://google.com@evil.com' يتجه فعلياً إلى 'evil.com'، لكن المستخدمين قد يرون فقط 'google.com'. "
                "المتصفحات الحديثة تحظر هذا، لكنه لا يزال يُستخدم في رسائل التصيد والمستندات."
                if current_lang == 'ar' else
                "نیشانەی '@' لە بەستەردا بۆ دڵنیاکردنەوە بەکاردێت بەڵام هێرشبەران بە درۆ بەکاریدەهێنن وەک فێڵی بینراو: "
                "'https://google.com@evil.com' لە ڕاستیدا دەڕوات بۆ 'evil.com'، بەڵام بەکارهێنەران لەوانەیە تەنها 'google.com' ببینن. "
                "براوسەرە نوێیەکان ئەمە قەدەغە دەکەن، بەڵام هێشتا لە ئیمەیلی فیشینگ و بەڵگەنامەکاندا بەکاردێت."
            )
        })

    # Hex obfuscation explanation
    if results['url_structure']['has_hex']:
        explanations.append({
            'severity': 'warning',
            'title': t('hex_detected'),
            'explanation': (
                "Hexadecimal URL encoding (e.g., '%20', '%2F') is normal for special characters, but excessive "
                "hex encoding is a common obfuscation technique to hide malicious URLs from email filters and "
                "security scanners that perform simple string matching."
                if current_lang == 'en' else
                "الترميز الست عشري للروابط أمر طبيعي للأحرف الخاصة، لكن الترميز الست عشري المفرط هو "
                "تقنية إخفاء شائعة لإخفاء الروابط الضارة عن مرشحات البريد وماسحات الأمان التي تقوم بمطابقة النصوص البسيطة."
                if current_lang == 'ar' else
                "کۆدکردنی هێگزادێسیمالی بەستەر بۆ کاراکتەرە تایبەتەکان ئاساییە، بەڵام کۆدکردنی زۆر "
                "تەکنیکێکی باوە بۆ شاردنەوەی بەستەری زیانبەخش لە فیلتەری ئیمەیل و سکانەرە ئاسایشەکان."
            )
        })

    # Missing security headers explanations
    for header, info in results['headers'].items():
        if info['status'] == 'missing' and SECURITY_HEADERS.get(header, {}).get('required', False):
            header_desc = SECURITY_HEADERS[header].get(desc_key, '')
            explanations.append({
                'severity': 'warning',
                'title': f"Missing {header}" if current_lang == 'en' else f"{header} مفقود" if current_lang == 'ar' else f"{header} نەماوە",
                'explanation': header_desc + (
                    " Without this header, the site is vulnerable to related attacks. "
                    "Phishers specifically target sites missing these protections for embedding and content injection."
                    if current_lang == 'en' else
                    " بدون هذا الرأس، الموقع عرضة للهجمات ذات الصلة. يستهدف مرتكبو التصيد على وجه التحديد "
                    "المواقع التي تفتقر إلى هذه الحمايات للتضمين وحقن المحتوى."
                    if current_lang == 'ar' else
                    " بەبێ ئەم سەردێرە، ماڵپەڕ ئاسانکاری بۆ هێرشە پەیوەندیدارەکان. فیشەران بەتایبەتی ئەو ماڵپەرانە دەکەنە ئامانج "
                    "کە ونبوونی ئەم پاراستنانە لەسەرە بۆ ئیمبێدکردن و دزەکردنی ناوەڕۆک."
                )
            })

    # VirusTotal explanation (detailed)
    if results['virustotal']['checked'] and results['virustotal']['positives'] > 0:
        vendor_count = len(results['virustotal']['malicious_vendors'])
        explanations.append({
            'severity': 'critical',
            'title': t('vt_flagged'),
            'explanation': (
                f"VirusTotal reports {results['virustotal']['positives']}/{results['virustotal']['total']} security vendors "
                f"flagged this URL as malicious. {vendor_count} vendors identified specific threats. "
                "This is a definitive reputation-based detection from multiple independent "
                "antivirus and security companies. Exercise extreme caution."
                if current_lang == 'en' else
                f"يبلغ VirusTotal أن {results['virustotal']['positives']}/{results['virustotal']['total']} من مزودي الأمان "
                f"حذروا من هذا الرابط كضار. {vendor_count} مزودين حددوا تهديدات محددة. "
                "هذا كشف نهائي قائم على السمعة من عدة شركات أمان ومكافحة فيروسات مستقلة. كن حذراً للغاية."
                if current_lang == 'ar' else
                f"VirusTotal ڕاپۆرت دەدات کە {results['virustotal']['positives']}/{results['virustotal']['total']} دابینکەری ئاسایش "
                f"ئەم بەستەرەیان وەک زیانبەخش نیشانەکردووە. {vendor_count} دابینکەر مەترسی دیاریکراویان دیاریکردووە. "
                "ئەمە دۆزینەوەی کۆتاییە لەسەر بنەمای ناوبانگ لە چەندین کۆمپانیای سەربەخۆی ئەنتی ڤایرۆس و ئاسایش. زۆر ئاگادار بە."
            )
        })

    return explanations


def display_results(url, results):
    """Display comprehensive scan results in a formatted table."""
    risk_score = calculate_risk_score(results)
    verdict, verdict_color = determine_verdict(risk_score)

    # Map verdict to translated string
    verdict_key = f"verdict_{verdict}"
    verdict_text = t(verdict_key)

    # Get explanations
    explanations = generate_explanations(results)

    # Prepare AI scan data
    missing_headers_count = sum(
        1 for h in results['headers'].values()
        if h['status'] == 'missing' and SECURITY_HEADERS.get(next(
            (k for k in SECURITY_HEADERS if k.lower() == next(
                (hk for hk in SECURITY_HEADERS if hk.lower() ==
                 [kk for kk in SECURITY_HEADERS][0].lower()), ''
            )), ''
        ), {}).get('required', False)
    )

    scan_data_for_ai = {
        'url': url,
        'malicious_count': results['virustotal'].get('stats', {}).get('malicious', 0),
        'suspicious_count': results['virustotal'].get('stats', {}).get('suspicious', 0),
        'https_enabled': url.startswith('https://'),
        'is_typosquatting': results['typosquatting']['is_typosquatting'],
        'is_suspicious_tld': results['tld']['is_suspicious'],
        'has_cross_domain_redirect': results['redirects']['has_cross_domain'],
        'has_ip_in_url': results['url_structure']['has_ip'],
        'has_at_symbol': results['url_structure']['has_at_symbol'],
        'entropy': results['url_structure']['entropy'],
        'subdomain_count': results['url_structure']['subdomain_count'],
        'url_length': results['url_structure']['length'],
        'redirect_hop_count': results['redirects']['hop_count'],
        'missing_headers': missing_headers_count,
        'risk_score': risk_score,
        'typosquatting_brand': results['typosquatting'].get('matched_brand', 'None'),
    }

    clear_screen()
    print_banner()

    # Main results section
    print_section(t('result_title'), Fore.CYAN)
    print()
    print_row(t('target_url'), url, Fore.YELLOW)
    print_row(t('scan_time'), datetime.now().strftime('%Y-%m-%d %H:%M:%S'), Fore.CYAN)
    print_row(t('overall_risk'), verdict_text, verdict_color)
    print_row(t('risk_score'), f"{risk_score}/100", verdict_color)
    print()

    # Redirect chain section
    print_section(t('section_redirects'), Fore.CYAN)
    if results['redirects']['hop_count'] > 0:
        for hop in results['redirects']['chain']:
            hop_color = Fore.YELLOW if hop.get('hop', 0) > 1 else Fore.GREEN
            print_row(f"  Hop {hop['hop']}", f"[{hop['status']}] {hop['url'][:55]}", hop_color)
        if results['redirects']['has_cross_domain']:
            print_alert(t('suspicious_redirect'), 'warning')
    else:
        print_row('', t('no_redirects'), Fore.GREEN)
    print()

    # Typosquatting section
    print_section(t('section_typosquatting'), Fore.CYAN)
    if results['typosquatting']['is_typosquatting']:
        print_row(t('similarity_score'), f"{results['typosquatting']['similarity']*100:.1f}%", Fore.RED)
        for detail in results['typosquatting']['details']:
            print_alert(detail, 'critical')
    else:
        negative_text = t('typosquatting_detected') + ': Negative'
        print_row('', negative_text, Fore.GREEN)
    print()

    # TLD section
    print_section(t('section_tld'), Fore.CYAN)
    tld_info = f"{results['tld']['tld']} ({results['tld']['risk_level'].upper()})"
    tld_color = Fore.RED if results['tld']['is_suspicious'] else Fore.GREEN
    if results['tld']['is_suspicious']:
        print_row('', f"{t('suspicious_tld')}: {tld_info}", Fore.RED)
    else:
        print_row('', f"{t('tld_safe')}: {tld_info}", Fore.GREEN)
    print()

    # URL structure analysis
    print_section(t('section_entropy'), Fore.CYAN)
    entropy_color = Fore.RED if results['url_structure']['entropy'] > 4.5 else Fore.GREEN
    print_row(t('entropy_score'), str(results['url_structure']['entropy']), entropy_color)

    length_color = Fore.RED if results['url_structure']['length'] > 100 else Fore.GREEN
    print_row(t('url_length'), f"{results['url_structure']['length']} chars", length_color)

    sub_color = Fore.RED if results['url_structure']['subdomain_count'] > 3 else Fore.GREEN
    print_row(t('subdomain_analysis'), f"{results['url_structure']['subdomain_count']} subdomains", sub_color)

    ip_color = Fore.RED if results['url_structure']['has_ip'] else Fore.GREEN
    ip_status = t('ip_detected') if results['url_structure']['has_ip'] else 'No IP detected'
    print_row(t('has_ip'), ip_status, ip_color)

    at_color = Fore.RED if results['url_structure']['has_at_symbol'] else Fore.GREEN
    at_status = t('at_detected') if results['url_structure']['has_at_symbol'] else 'No @ symbol'
    print_row(t('has_at_symbol'), at_status, at_color)

    hex_color = Fore.RED if results['url_structure']['has_hex'] else Fore.GREEN
    hex_status = t('hex_detected') if results['url_structure']['has_hex'] else 'No hex encoding'
    print_row(t('has_hex'), hex_status, hex_color)
    print()

    # Security headers section
    print_section(t('section_headers'), Fore.CYAN)
    for header, info in results['headers'].items():
        if info['status'] == 'present':
            print_row(f"  {header}", t('header_present') + f" ({info['value']})", Fore.GREEN)
        elif info['status'] == 'weak':
            print_row(f"  {header}", t('header_weak') + f" ({info['value']})", Fore.YELLOW)
        else:
            req = SECURITY_HEADERS.get(header, {}).get('required', False)
            color = Fore.RED if req else Fore.YELLOW
            print_row(f"  {header}", t('header_missing'), color)
    print()

    # =================================================================
    # VIRUSTOTAL API v3 - DETAILED IN-TERMINAL REPORT
    # =================================================================
    print_section(t('section_vt'), Fore.CYAN)

    if not results['virustotal']['checked']:
        if results['virustotal'].get('error') == 'no_key':
            print_row('', t('warning_no_vt_key'), Fore.YELLOW)
        elif results['virustotal'].get('all_keys_exhausted'):
            print_row('', t('vt_all_keys_exhausted'), Fore.YELLOW)
        else:
            error_msg = results['virustotal'].get('error', 'unknown')
            print_row('', f"{t('vt_error')}: {error_msg}", Fore.YELLOW)
    else:
        # --- Summary Statistics Table ---
        stats = results['virustotal'].get('stats', {})
        malicious_count = stats.get('malicious', 0)
        suspicious_count = stats.get('suspicious', 0)
        undetected_count = stats.get('undetected', 0)
        harmless_count = stats.get('harmless', 0)
        timeout_count = stats.get('timeout', 0)

        print()
        print(f"  {Fore.CYAN}{t('vt_stats_title')}:{Style.RESET_ALL}")
        print(f"  {Fore.RED}    {'─' * 50}{Style.RESET_ALL}")

        # Print stats in a grid format
        mal_color = Fore.RED if malicious_count > 0 else Fore.GREEN
        sus_color = Fore.YELLOW if suspicious_count > 0 else Fore.GREEN
        und_color = Fore.GREEN
        harm_color = Fore.GREEN

        print(f"  {mal_color}    {'Malicious:':<15} {malicious_count:>5}{Style.RESET_ALL}  |  {sus_color}{'Suspicious:':<15} {suspicious_count:>5}{Style.RESET_ALL}")
        print(f"  {und_color}    {'Undetected:':<15} {undetected_count:>5}{Style.RESET_ALL}  |  {harm_color}{'Harmless:':<15} {harmless_count:>5}{Style.RESET_ALL}")
        if timeout_count > 0:
            print(f"  {Fore.YELLOW}    {'Timeout:':<15} {timeout_count:>5}{Style.RESET_ALL}")
        print(f"  {Fore.RED}    {'─' * 50}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}    {'TOTAL VENDORS:':<15} {results['virustotal']['total']:>5}{Style.RESET_ALL}")
        print()

        # --- Flagging Security Vendors (Bright Red) ---
        malicious_vendors = results['virustotal'].get('malicious_vendors', [])
        if malicious_vendors:
            print(f"  {Fore.RED}{t('vt_malicious_vendors')}:{Style.RESET_ALL}")
            print(f"  {Fore.RED}    {'─' * 50}{Style.RESET_ALL}")

            # Display vendors in columns
            for i, vendor in enumerate(malicious_vendors, 1):
                vendor_name = vendor['engine']
                vendor_cat = vendor['category']
                vendor_result = vendor['result']
                cat_tag = f"[{vendor_cat.upper()}]"
                print(f"  {Fore.RED}    {i:2d}. {vendor_name:<25} {cat_tag:<12} {vendor_result}{Style.RESET_ALL}")

            print(f"  {Fore.RED}    {'─' * 50}{Style.RESET_ALL}")
            print(f"  {Fore.RED}    [!] {len(malicious_vendors)} vendor(s) flagged this URL as malicious/phishing{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}    [+] {t('vt_no_vendors')}{Style.RESET_ALL}")

        # VT Link
        if results['virustotal'].get('permalink'):
            print()
            print(f"  {Fore.CYAN}    VT Report: {results['virustotal']['permalink'][:60]}{Style.RESET_ALL}")

    print()

    # =================================================================
    # AI THREAT ANALYSIS REPORT (v2.6 - LIVE GEMINI OR LOCAL FALLBACK)
    # =================================================================
    print_separator('=', 80, Fore.MAGENTA)
    ai_title = t('section_ai')
    print(f"{Fore.MAGENTA}{' ' * 15}{ai_title}{Style.RESET_ALL}")
    print_separator('=', 80, Fore.MAGENTA)

    # Show status message
    if GEMINI_AVAILABLE and GEMINI_API_KEY and GEMINI_API_KEY.strip() not in ('', 'YOUR_GEMINI_API_KEY_HERE'):
        print(f"\n  {Fore.CYAN}[*] {t('ai_thinking')}{Style.RESET_ALL}")
    else:
        print(f"\n  {Fore.YELLOW}[!] {t('ai_offline')}{Style.RESET_ALL}")

    # Get AI analysis (Gemini if available, local fallback otherwise)
    ai_analysis_text = get_ai_threat_analysis(scan_data_for_ai, current_lang)

    # For RTL languages, process the AI text through the RTL pipeline
    if current_lang in ('ar', 'ku') and RTL_SUPPORT:
        ai_analysis_text = render_rtl_textonly(ai_analysis_text)

    # Determine if we're using Gemini or fallback
    is_fallback = GEMINI_API_KEY.strip() in ('', 'YOUR_GEMINI_API_KEY_HERE') or not GEMINI_AVAILABLE

    if is_fallback:
        label = t('fallback_label')
        label_color = Fore.YELLOW
    else:
        label = t('ai_analysis_label')
        label_color = Fore.MAGENTA

    print(f"\n  {label_color}[{label}]{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}{ai_analysis_text}{Style.RESET_ALL}")

    print()
    print_separator('=', 80, Fore.CYAN)

    # Explanations section
    print_separator('=', 80, Fore.MAGENTA)
    expl_title = t('explanation_title')
    print(f"{Fore.MAGENTA}{' ' * 20}{expl_title}{Style.RESET_ALL}")
    print_separator('=', 80, Fore.MAGENTA)

    if explanations:
        for i, exp in enumerate(explanations, 1):
            sev_color = Fore.RED if exp['severity'] == 'critical' else Fore.YELLOW
            exp_title = exp['title']
            exp_text = exp['explanation']
            # Process explanation text through RTL if needed
            if current_lang in ('ar', 'ku') and RTL_SUPPORT:
                exp_text = render_rtl_textonly(exp_text)
            print(f"\n  {sev_color}[{i}] {exp_title}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}{exp_text}{Style.RESET_ALL}")
    else:
        no_exp = t('no_explanations')
        print(f"\n  {Fore.GREEN}{no_exp}{Style.RESET_ALL}")

    print()
    print_separator('=', 80, Fore.CYAN)

    return {
        'verdict': verdict,
        'score': risk_score,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'url': url,
        'explanations_count': len(explanations)
    }


# =============================================================================
# HISTORY MANAGEMENT
# =============================================================================

def load_history():
    """Load scan history from JSON file."""
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
    except Exception as e:
        print_alert(f"{t('load_error')}: {e}", 'warning')
        return []


def save_history(history):
    """Save scan history to JSON file."""
    try:
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print_alert(f"{t('save_error')}: {e}", 'warning')


def add_to_history(entry):
    """Add a scan entry to history."""
    history = load_history()
    history.append(entry)
    save_history(history)


def display_history():
    """Display scan history."""
    clear_screen()
    print_banner()
    print_section(t('history_title'), Fore.CYAN)

    history = load_history()
    if not history:
        print(f"\n  {Fore.YELLOW}{t('history_empty')}{Style.RESET_ALL}")
    else:
        print()
        for i, entry in enumerate(reversed(history[-20:]), 1):
            verdict_colors = {
                'clean': Fore.GREEN,
                'suspicious': Fore.YELLOW,
                'malicious': Fore.RED
            }
            v_color = verdict_colors.get(entry.get('verdict', 'clean'), Fore.WHITE)
            verdict_translated = t(f"verdict_{entry.get('verdict', 'clean')}")
            print(f"  {Fore.CYAN}{i:2d}.{Style.RESET_ALL} {t('history_entry', entry['url'], v_color + verdict_translated + Style.RESET_ALL, entry['timestamp'])}")

    print()
    print_separator('-', 80, Fore.CYAN)
    input(f"\n  {t('press_enter')}")


# =============================================================================
# MAIN SCAN WORKFLOW
# =============================================================================

def validate_url(url):
    """Validate URL format."""
    pattern = re.compile(
        r'^(https?://)?'
        r'([\w.-]+)'
        r'(\.[a-zA-Z]{2,})'
        r'(/[\w./?%&=-]*)?$'
    )
    return bool(pattern.match(url))


def normalize_url(url):
    """Normalize URL to ensure protocol prefix."""
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def execute_deep_scan():
    """Execute the full forensic scan workflow."""
    clear_screen()
    print_banner()

    # Get URL from user
    url = input(f"\n  {Fore.CYAN}[?] {t('prompt_url')}: {Style.RESET_ALL}").strip()

    if not url:
        print_alert(t('invalid_url'), 'warning')
        input(f"\n  {t('press_enter')}")
        return

    if not validate_url(url):
        print_alert(t('invalid_url'), 'warning')
        input(f"\n  {t('press_enter')}")
        return

    url = normalize_url(url)
    parsed = urlparse(url)
    target_domain = parsed.netloc

    # Loading animation
    print()
    loading_animation(t('scanning'), duration=3.0)
    print()

    # Perform all checks
    print(f"  {Fore.CYAN}[*] Analyzing redirects...{Style.RESET_ALL}")
    fetch_data = fetch_url_data(url)

    if not fetch_data['success']:
        error_map = {
            'timeout': t('timeout_error'),
            'connection': t('network_error'),
            'redirects': 'Too many redirects - possible redirect loop'
        }
        error_msg = error_map.get(fetch_data['error'], f"{t('general_error')}: {fetch_data['error']}")
        print_alert(error_msg, 'critical')
        input(f"\n  {t('press_enter')}")
        return

    print(f"  {Fore.CYAN}[*] Checking typosquatting...{Style.RESET_ALL}")
    typosquatting_result = check_typosquatting(target_domain)

    print(f"  {Fore.CYAN}[*] Analyzing redirect chain...{Style.RESET_ALL}")
    redirect_result = check_redirect_chain(
        fetch_data.get('redirect_chain', []),
        target_domain
    )

    print(f"  {Fore.CYAN}[*] Checking TLD risk...{Style.RESET_ALL}")
    tld_result = check_tld(target_domain)

    print(f"  {Fore.CYAN}[*] Computing URL entropy...{Style.RESET_ALL}")
    url_structure = analyze_url_structure(url)

    print(f"  {Fore.CYAN}[*] Auditing security headers...{Style.RESET_ALL}")
    headers_result = check_security_headers(fetch_data.get('headers', {}))

    # VirusTotal v3 check with multi-key rotation
    print(f"  {Fore.CYAN}[*] Querying VirusTotal API v3...{Style.RESET_ALL}")
    vt_result = check_virustotal_v3(url)

    # Compile all results
    results = {
        'target_domain': target_domain,
        'typosquatting': typosquatting_result,
        'redirects': redirect_result,
        'tld': tld_result,
        'url_structure': url_structure,
        'headers': headers_result,
        'virustotal': vt_result,
        'fetch_data': {
            'status_code': fetch_data.get('status_code'),
            'response_time': fetch_data.get('response_time'),
            'content_length': fetch_data.get('content_length')
        }
    }

    # Display results
    summary = display_results(url, results)

    # Save to history
    add_to_history(summary)

    input(f"\n  {t('press_enter')}")


# =============================================================================
# LANGUAGE SETTINGS (3 Languages: EN / AR / KU)
# =============================================================================

def language_settings():
    """Handle language settings menu with RTL support."""
    global current_lang

    while True:
        clear_screen()
        print_banner()
        print_section(t('language_title'), Fore.CYAN)
        print()

        # Show language options
        lang_labels = {
            'en': LANG['en']['lang_en'],
            'ar': LANG['ar']['lang_ar'],
            'ku': LANG['ku']['lang_ku']
        }

        print(f"  {Fore.CYAN}1.{Style.RESET_ALL} {lang_labels['en']}")
        print(f"  {Fore.CYAN}2.{Style.RESET_ALL} {lang_labels['ar']}")
        print(f"  {Fore.CYAN}3.{Style.RESET_ALL} {lang_labels['ku']}")
        print(f"  {Fore.CYAN}4.{Style.RESET_ALL} {t('option_exit')}")
        print()

        print(f"  {Fore.YELLOW}{t('lang_current')}: {lang_labels.get(current_lang, current_lang)}{Style.RESET_ALL}")
        print()

        choice = input(f"  {Fore.CYAN}[?] {t('prompt_choice')}: {Style.RESET_ALL}").strip()

        if choice == '1':
            current_lang = 'en'
            print_alert(t('lang_switched'), 'success')
            time.sleep(1)
            break
        elif choice == '2':
            current_lang = 'ar'
            print_alert(t('lang_switched'), 'success')
            time.sleep(1)
            break
        elif choice == '3':
            current_lang = 'ku'
            print_alert(t('lang_switched'), 'success')
            time.sleep(1)
            break
        elif choice == '4':
            break
        else:
            print_alert(t('invalid_choice'), 'warning')
            time.sleep(1)


# =============================================================================
# MAIN MENU & APPLICATION LOOP
# =============================================================================

def print_menu():
    """Display the main menu. Menu items are already RTL-processed via t()."""
    print_section(t('menu_title'), Fore.CYAN)
    print()

    print(f"  {Fore.CYAN}[1]{Style.RESET_ALL}  {Fore.WHITE}{t('option_scan')}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}[2]{Style.RESET_ALL}  {Fore.WHITE}{t('option_history')}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}[3]{Style.RESET_ALL}  {Fore.WHITE}{t('option_language')}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}[4]{Style.RESET_ALL}  {Fore.RED}{t('option_exit')}{Style.RESET_ALL}")
    print()
    print_separator('-', 80, Fore.CYAN)


def main():
    """Main application entry point."""
    # Suppress SSL warnings
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except:
        pass

    while True:
        clear_screen()
        print_banner()
        print_menu()

        choice = input(f"  {Fore.CYAN}[?] {t('prompt_choice')}: {Style.RESET_ALL}").strip()

        if choice == '1':
            execute_deep_scan()
        elif choice == '2':
            display_history()
        elif choice == '3':
            language_settings()
        elif choice == '4':
            clear_screen()
            print_banner()
            print(f"\n  {Fore.GREEN}{t('goodbye')}{Style.RESET_ALL}")
            print()
            break
        else:
            print_alert(t('invalid_choice'), 'warning')
            time.sleep(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        clear_screen()
        print_banner()
        print(f"\n  {Fore.GREEN}{t('goodbye')}{Style.RESET_ALL}")
        print()
        sys.exit(0)
    except Exception as e:
        clear_screen()
        print(f"\n  {Fore.RED}[!!!] Critical Error: {e}{Style.RESET_ALL}")
        print()
        sys.exit(1)
