from abc import ABC, abstractmethod
from typing import List


class FindingBase(ABC):
    """Base abstract class for all security findings (vulnerabilities, anomalies, additional info)"""

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


class Vulnerability(FindingBase):
    """Abstract class for security vulnerabilities that can be exploited"""

    @classmethod
    def type(cls) -> str:
        return "vulnerability"


class Anomaly(FindingBase):
    """Abstract class for anomalies or suspicious behaviors that may indicate issues"""

    @classmethod
    def type(cls) -> str:
        return "anomaly"


class Additional(FindingBase):
    """Abstract class for additional information findings (e.g., fingerprinting)"""

    @classmethod
    def type(cls) -> str:
        return "additional"
