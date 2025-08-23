import sys, subprocess, platform
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (QWidget, QLabel, QLineEdit, QGridLayout,
                            QApplication, QPushButton, QTextEdit)

class PingThread(QThread):
    result_signal = pyqtSignal(str)

    def __init__(self, host, count):
        super().__init__()
        self.host = host
        self.count = count

    def run(self):
        parameter = '-n' if platform.system().lower()=='windows' else '-c'
        process = subprocess.run(["ping", parameter, self.count, self.host], capture_output=True, text=True)
        self.result_signal.emit(process.stdout)

class Pingster(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        #create labels, line edit, button, text editor
        AddressLabel = QLabel('Ping Address: ')
        CountLabel = QLabel('Ping Count: ')

        self.PingAddress = QLineEdit()
        self.PingCount = QLineEdit()

        self.ping_button = QPushButton(parent=self, text="Ping")
        self.ping_button.clicked.connect(self.run_ping)

        self.ping_output = QTextEdit(self)
        self.ping_output.setReadOnly(True)

        #grid layouts go here
        grid = QGridLayout()
        grid.addWidget(AddressLabel, 0, 0)
        grid.addWidget(CountLabel, 1, 0)
        grid.addWidget(self.PingAddress, 0,1)
        grid.addWidget(self.PingCount, 1,1)
        grid.addWidget(self.ping_button, 2,1)
        grid.addWidget(self.ping_output, 3, 1)

        self.setLayout(grid)
        self.resize(500, 350)
        self.setWindowTitle('Pingster GUI')
        self.show()

    def run_ping(self):
        address = self.PingAddress.text()
        count = self.PingCount.text()
        self.thread = PingThread(address, count)
        self.thread.result_signal.connect(self.ping_result)
        self.thread.start()

    def ping_result(self, output):
        self.ping_output.setText(output)

if __name__=='__main__':
    app = QApplication(sys.argv)
    Pingster2 = Pingster()
    sys.exit(app.exec())
    main()