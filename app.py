from flask import Flask, render_template, request
import subprocess
import xml.etree.ElementTree as ET

app = Flask(__name__)

def run_nmap(target, scan_type):
    command = ["nmap", "-oX", "scan.xml"]

    if scan_type == "ping":
        command += ["-sn"]
    elif scan_type == "port":
        command += ["-sS"]
    elif scan_type == "os":
        command += ["-O"]

    command.append(target)
    try:
        subprocess.run(command, check=True)
        return parse_results("scan.xml")
    except Exception as e:
        return f"Error: {e}"

def parse_results(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    output = ""

    for host in root.findall("host"):
        addr = host.find("address").attrib["addr"]
        output += f"<strong>Host:</strong> {addr}<br>"
        for port in host.findall(".//port"):
            portid = port.attrib["portid"]
            state = port.find("state").attrib["state"]
            service = port.find("service").attrib.get("name", "unknown")
            output += f"Port {portid} ({service}): {state}<br>"
        output += "<hr>"
    return output

@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    if request.method == "POST":
        target = request.form["target"]
        scan_type = request.form["scan_type"]
        result = run_nmap(target, scan_type)
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=81)
