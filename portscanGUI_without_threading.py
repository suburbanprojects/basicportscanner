import sys, time
from scapy.all import IP, TCP, sr1
from PyQt6.QtWidgets import(QWidget, QLabel, QLineEdit, QGridLayout,
                            QApplication, QPushButton, QTextEdit)

class portscanGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        #create labels, line edit, button, text editor
        AddressLabel = QLabel('Address: ')
        StartPortLabel = QLabel('Starting Port: ')
        EndPortLabel = QLabel('Final Port: ')

        self.AddressEdit = QLineEdit()
        self.StartPortEdit = QLineEdit()
        self.EndPortEdit = QLineEdit()

        self.scan_button = QPushButton(parent=self, text="Scan")
        #connect to the start_scan function
        self.scan_button.clicked.connect(self.start_scan)
        self.scan_output = QTextEdit(self)
        self.scan_output.setReadOnly(True)

        #grid layouts go here
        grid = QGridLayout()
        grid.addWidget(AddressLabel, 0, 0)
        grid.addWidget(StartPortLabel, 1, 0)
        grid.addWidget(EndPortLabel, 2, 0)

        grid.addWidget(self.AddressEdit, 0,1)
        grid.addWidget(self.StartPortEdit, 1,1)
        grid.addWidget(self.EndPortEdit, 2,1)

        grid.addWidget(self.scan_button, 3,1)
        grid.addWidget(self.scan_output, 4, 1)

        self.setLayout(grid)
        self.resize(500, 350)
        self.setWindowTitle('Portscan GUI')
        self.show()

    def start_scan(self):
        self.scan_output.clear()
        address = self.AddressEdit.text()
        try:
            #set ports as integer 
            startport = int(self.StartPortEdit.text())
            endport = int(self.EndPortEdit.text())
            #set ports to ensure valid ports are used
            if startport < 0 or endport > 65535 or startport > endport:
                raise ValueError
        except ValueError:
            self.scan_output.append("enter valid port range(0 to 65535) and start port < end port ")
            return
        
        for port in range(startport, endport + 1):
            pkt = IP(dst = address)/TCP(dport=port, flags="S") 
            response = sr1(pkt, timeout=1, verbose=0)

            if response:
                #interpret response SYN-ACK  → Port is open.
                if response.haslayer(TCP) and response.getlayer(TCP).flags == "SA": 
                    self.scan_output.append(f"Port {port} is OPEN")
                    # Send RST to close connection and avoid half-open connections
                    sr1(IP(dst=address)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                    #interpret response Reset → Port is closed.
                elif response.haslayer(TCP) and response.getlayer(TCP).flags == "RA": 
                    self.scan_output.append(f"Port{port} is CLOSED")
            else:
                self.scan_output.append(f"Port {port} is FILTERED or no response")

if __name__=='__main__':
    app = QApplication(sys.argv)
    portscanGUI2=portscanGUI()
    sys.exit(app.exec())
    main()

