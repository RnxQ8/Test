from flask import Flask, request, render_template_string
from scapy.all import ARP, Ether, srp

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Wifi Eye By RNX</title>
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        h1 { color: #2c3e50; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #f4f4f4; }
    </style>
</head>
<body>
    <h1>Wifi Eye By RNX</h1>
    <form method="POST">
        <label>IP Range (e.g. 192.168.1.0/24):</label><br>
        <input type="text" name="ip_range" required>
        <button type="submit">Scan</button>
    </form>
    {% if devices %}
    <h2>Devices Found</h2>
    <table>
        <tr><th>IP Address</th><th>MAC Address</th></tr>
        {% for device in devices %}
        <tr><td>{{ device.ip }}</td><td>{{ device.mac }}</td></tr>
        {% endfor %}
    </table>
    {% endif %}
</body>
</html>
"""

def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    result = srp(packet, timeout=2, verbose=0)[0]
    devices = [{'ip': rcv.psrc, 'mac': rcv.hwsrc} for _, rcv in result]
    return devices

@app.route("/", methods=["GET", "POST"])
def index():
    devices = []
    if request.method == "POST":
        ip_range = request.form["ip_range"]
        devices = scan_network(ip_range)
    return render_template_string(HTML_TEMPLATE, devices=devices)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
