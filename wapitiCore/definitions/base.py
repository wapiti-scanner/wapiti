from abc import ABC, abstractmethod
from typing import List


class FindingBase(ABC):
    @classmethod
    @abstractmethod
    def name(cls) -> str:
        pass

    @classmethod
    @abstractmethod
    def description(cls) -> str:
        pass

    @classmethod
    @abstractmethod
    def references(cls) -> List[str]:
        pass

    @classmethod
    @abstractmethod
    def short_name(cls) -> str:
        pass

    @classmethod
    @abstractmethod
    def solution(cls) -> str:
        pass

    @classmethod
    @abstractmethod
    def type(cls) -> str:
        pass

    @classmethod
    @abstractmethod
    def wstg_code(cls) -> List[str]:
        pass

    def __str__(cls) -> str:  # pylint: disable=no-self-argument
        return cls.name()
