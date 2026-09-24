class AgentError(Exception):
    """Safe diagnostic message only: never include raw API bodies or target contents."""


class ProviderError(AgentError):
    pass


class DeadlineError(AgentError):
    pass


class AnalysisError(AgentError):
    pass


class OutputLimitError(AnalysisError):
    pass


class BudgetError(DeadlineError):
    pass
