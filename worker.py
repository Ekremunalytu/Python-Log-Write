import subprocess
from PyQt6.QtCore import QThread, pyqtSignal

class CommandWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, command, parser_func, input_data=None):
        super().__init__()
        self.command = command         # e.g. ["last"]
        self.parser_func = parser_func # function to parse the command output
        self.input_data = input_data   # optional input (e.g. sudo password)

    def run(self):
        try:
            result = subprocess.run(
                self.command,
                input=self.input_data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode != 0:
                self.error.emit(result.stderr)
                return
            data = self.parser_func(result.stdout)
            self.finished.emit(data)
        except Exception as e:
            self.error.emit(str(e))
