from abc import abstractmethod, ABC
from typing import TypeAlias, Literal

Scope: TypeAlias = Literal["uri", "origin"]

class ModuleExport(ABC):
    @abstractmethod
    async def run(self, domains: list[str]) -> None:
        ...

    @abstractmethod
    def results(self) -> dict:
        ...

    @abstractmethod
    def scope(self) -> Scope:
        ...

    