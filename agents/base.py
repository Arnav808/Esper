from abc import ABC, abstractmethod
from typing import Any


class BaseAgent(ABC):
    """Abstract base class for all Esper agents.

    Each agent wraps a single responsibility in the security scan pipeline.
    Subclasses must implement ``run()``, which receives the current
    orchestration state and returns a dictionary of updates to merge in.
    """

    name: str = "base_agent"

    @abstractmethod
    def run(self, state: dict[str, Any]) -> dict[str, Any]:
        """Execute the agent's task.

        Args:
            state: The current LangGraph state dictionary.

        Returns:
            A dictionary of state updates to be merged into the graph state.
        """
        ...
