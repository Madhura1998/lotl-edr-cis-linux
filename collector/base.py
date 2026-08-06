from abc import ABC, abstractmethod
from typing import Callable, Dict, Any, Optional

class BaseCollector(ABC):
    def __init__(self, name: str, config: Dict[str, Any], callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.name = name
        self.config = config
        self.callback = callback
        self.running = False

    @abstractmethod
    def start(self) -> None:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass

    def emit(self, raw_event: Dict[str, Any]) -> None:
        if self.callback:
            raw_event["_collector"] = self.name
            self.callback(raw_event)
