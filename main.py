import nmap
import sys
import os
from docx import Document
from docx.shared import Pt, RGBColor
from datetime import datetime

class TZSSHVUN:
    """
    Author: Japhet Munisi
    Email: munisi.japhet@gmail.com
    WhatsApp: +255784121281
    Tool: TZSSHVUN V1
    """
    def __init__(self, target):
        self.target = target
        self.tool_name = "TZSSHVUN V1"
        self.author = "Japhet Munisi"
        self.results = {}

    def banner(self):
        print(f"""
        ==================================================
        [+] Tool   : {self.tool_name}
        [+] Author : {self.author}
        [+] Status : Ethical Hacking Vulnerability Scanner
        ==================================================
        Scanning Target: {self.target}
        """)

    def check_nmap(self):
        try:
            nmap.PortScanner()
        except Exception:
            print("[-] Error: Nmap is not installed or not in PATH.")
            print("[!] Install Nmap: https://nmap.org/download.html")
            sys.exit(1)

    def scan(self):
        print(f"[*] Initializing deep scan on {self.target}...")
        nm = nmap.PortScanner()
        # Performs service versioning and runs default vulnerability scripts
        nm.scan(self.target, arguments='-sV --script=vuln')
        
        if self.target in nm.all_hosts():
            self.results = nm[self.target]
        else:
            print("[-] Target host unreachable.")
            sys.exit(1)

    def generate_report(self):
        filename = f"Report_{self.target.replace('.', '_')}.docx"
        doc = Document()

        # Title Section
        header = doc.add_heading(f'{self.tool_name} Assessment Report', 0)
        doc.add_paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        doc.add_paragraph(f"Target: {self.target}")
        doc.add_paragraph(f"Auditor: {self.author}")

        # Executive Summary
        doc.add_heading('1. Executive Summary', level=1)
        doc.add_paragraph(
            "This document provides a technical security assessment of the target host. "
            "The scan identified open ports, service versions, and potential vulnerabilities."
        )

        # Technical Evidence
        doc.add_heading('2. Technical Evidence', level=1)
        if 'tcp' in self.results:
            for port, info in self.results['tcp'].items():
                p = doc.add_paragraph()
                run = p.add_run(f"Port {port} | Service: {info['name']}")
                run.bold = True
                doc.add_paragraph(f"Version: {info['product']} {info['version']}")
                
                if 'script' in info:
                    doc.add_heading('Vulnerability Data Found:', level=2)
                    for script_name, output in info['script'].items():
                        # Create a "code block" look for evidence
                        table = doc.add_table(rows=1, cols=1)
                        table.style = 'Light List Accent 1'
                        cell = table.rows[0].cells[0]
                        cell.text = f"Script ID: {script_name}\n\n{output}"

        # Solutions
        doc.add_heading('3. Solutions & Recommendations', level=1)
        table = doc.add_table(rows=1, cols=3)
        table.style = 'Table Grid'
        headers = table.rows[0].cells
        headers[0].text = 'Issue Found'
        headers[1].text = 'Recommended Fix'
        headers[2].text = 'Severity'

        if 'tcp' in self.results:
            for port, info in self.results['tcp'].items():
                row = table.add_row().cells
                row[0].text = f"Open Port {port} ({info['name']})"
                row[1].text = f"Update {info['product']} to the latest version or close port if not needed."
                row[2].text = "High" if 'script' in info else "Low"

        doc.save(filename)
        print(f"[+] Success! Professional report saved as: {filename}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <target_ip>")
        sys.exit(1)
    
    target = sys.argv[1]
    engine = TZSSHVUN(target)
    engine.banner()
    engine.check_nmap()
    engine.scan()
    engine.generate_report()
