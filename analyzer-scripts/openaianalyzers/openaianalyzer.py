from .aibase import OPENAI_API_KEY
from .completions import OpenAICompletionsAnalyzer
from .assistant import OpenAIAssistantAnalyzer

class OpenAIAnalyzer(OpenAIAssistantAnalyzer, OpenAICompletionsAnalyzer):
    "Class using OpenAI Completion and Assistant APIs to analyze Attack objects"

    pass
    


























