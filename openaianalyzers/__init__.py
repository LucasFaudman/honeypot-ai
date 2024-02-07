from .completions import OpenAICompletionsAnalyzer
from .assistant import OpenAIAssistantAnalyzer


class OpenAIAnalyzer(OpenAIAssistantAnalyzer, OpenAICompletionsAnalyzer):
    "Class using OpenAI Completion and Assistant APIs to analyze Attack objects"
