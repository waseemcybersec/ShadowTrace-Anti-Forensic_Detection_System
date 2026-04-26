from abc import ABC, abstractmethod


class AnalysisEngine(ABC):
    module_id = ""
    module_name = ""

    @abstractmethod
    def analyze(self, evidence_path, case_name, examiner):
        raise NotImplementedError
