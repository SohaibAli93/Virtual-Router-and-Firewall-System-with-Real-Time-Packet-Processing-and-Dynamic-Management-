# Virtual Router and Firewall System with Real-Time Packet Processing and Dynamic Management

This project implements a **Virtual Router and Firewall System** built using Python. It is designed to process network packets in real-time and provide dynamic firewall rule management with a graphical interface.

> ⚠️ **For Educational Purposes Only** – This tool is intended for students and cybersecurity professionals to explore packet routing and firewall logic in a safe and controlled environment.

---

## 🚀 Features

- 🔄 **Packet Forwarding & Filtering** using raw sockets and Scapy
- 🔥 **Custom Firewall Rules** with allow/block logic for IPs, ports, and protocols
- 📊 **Real-Time Packet Monitoring** using live traffic graphs
- 🖥️ **Graphical User Interface (GUI)** for dynamic control via Tkinter
- 📁 **Logging of Packet Data** for inspection and analysis

---

## 🛠️ Technologies Used

- **Python 3**
- [`scapy==2.5.0`](https://pypi.org/project/scapy/)
- [`matplotlib==3.7.1`](https://pypi.org/project/matplotlib/)
- `tkinter` (for GUI — included with most Python distributions)

---

## 📦 Requirements

Install the required Python packages:

```bash
pip install scapy==2.5.0 matplotlib==3.7.1
```

> `tkinter` is included with standard Python installations. If it's missing:
- On **Ubuntu/Debian**: `sudo apt install python3-tk`
- On **Windows/macOS**: Ensure you installed Python from the official source (https://python.org)

---

## 💻 How to Run

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/virtual-router-firewall.git
   cd virtual-router-firewall
   ```

2. **Run the Application**
   ```bash
   python main.py
   ```

> Make sure to run the script with **administrator/root privileges**, as packet sniffing and raw sockets may require elevated permissions:
```bash
sudo python main.py
```

---

## 📂 Project Structure

```
📦virtual-router-firewall
 ┣ 📜main.py
 ┣ 📜README.md
 ┣ 📜firewall_rules.json
 ┣ 📜packet_log.txt
 ┗ 📜requirements.txt
```

---

## ⚙️ Functionality Overview

| Component           | Description                                      |
|---------------------|--------------------------------------------------|
| Packet Processor    | Captures packets using Scapy and processes them |
| Firewall Engine     | Evaluates custom rules (IP, port, protocol)      |
| GUI Manager         | Allows rule toggling and live packet visualization |
| Packet Logger       | Saves allowed/blocked packet metadata to file   |

---

## 📌 Use Cases

- Cybersecurity course labs
- Network security simulations
- Understanding packet flows
- Testing firewall logic safely

---

## 🔐 Disclaimer

This project is intended for **educational and research use only**. Do **not** deploy it in live production networks or use it to intercept unauthorized traffic. Ensure all testing is done on networks where you have proper permission.

---

## 🧠 Author

**Sohaib Ali Khan**  
Student, BS Cybersecurity  
National University of Computer and Emerging Sciences (FAST)

---

## 📄 License

Licensed under the [MIT License](LICENSE). Free to use for learning, modification, and educational projects.
