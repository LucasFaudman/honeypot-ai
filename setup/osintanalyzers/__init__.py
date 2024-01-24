from .ipanalyzer import IPAnalyzer
from .malwareanalyzer import MalwareAnalyzer


class OSINTAnalyzer(IPAnalyzer, MalwareAnalyzer):
    """
    Class combining all OSINT analyzers to collect data on IPs, URLs, and Malware from OSINT sources.
    """
