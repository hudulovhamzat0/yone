from flask import Blueprint, request, redirect, url_for, flash, jsonify
from flask_login import login_required
from .. import mongo
import subprocess
import datetime

scans_bp = Blueprint('scans', __name__)

PORT_SEVERITY_RULES = {
    "21": "medium",  # FTP
    "22": "medium",  # SSH
    "23": "high",    # Telnet
    "25": "low",     # SMTP
    "53": "low",     # DNS
    "80": "low",     # HTTP
    "110": "low",    # POP3
    "135": "high",   # MS RPC
    "139": "high",   # NetBIOS
    "143": "low",    # IMAP
    "443": "low",    # HTTPS
    "445": "medium", # SMB
    "3306": "medium",# MySQL
    "3389": "high",  # RDP
    "5900": "high",  # VNC
    "8080": "low"     # HTTP-alt
}

def detect_os_leak(nmap_output, target_url):
    details = []
    for line in nmap_output.splitlines():
        if line.strip().startswith("OS details:") or line.strip().startswith("Aggressive OS guesses:"):
            details.append(line.strip())

    if details:
        return {
            "title": "OS Fingerprinting Detected",
            "description": f"OS fingerprinting succeeded for target {target_url}. Details:\n" + "\n".join(details),
            "severity": "low",
            "status": "unresolved",
            "timestamp": datetime.datetime.utcnow()
        }
    return None

@scans_bp.route("/start_custom_scan", methods=["POST"])
@login_required
def start_custom_scan():
    print(request.form)
    target = request.form.get("target")
    scan_type = request.form.get("scan_type", "basic")
    speed = request.form.get("speed", "T4")
    ports = request.form.get("ports", "top")
    custom_ports = request.form.get("custom_ports")
    os_detect = request.form.get("os_detect") == "on"
    script_scan = request.form.get("script_scan") == "on"

    if not target:
        flash("Hedef belirtilmedi!", "danger")
        return redirect(url_for("dashboard.overview"))

    command = ["nmap"]

    scan_type_map = {
        "aggressive": "-A",
        "stealth": "-sS",
        "udp": "-sU",
        "basic": "-sV"
    }
    command.append(scan_type_map.get(scan_type, "-sV"))

    if speed in ["T1", "T2", "T3", "T4", "T5"]:
        command.append(f"-{speed}")

    if ports == "top":
        command += ["--top-ports", "100"]
    elif ports == "all":
        command.append("-p-")
    elif ports == "custom" and custom_ports:
        command += ["-p", custom_ports]

    if os_detect:
        command.append("-O")
    if script_scan:
        command.append("-sC")

    command.append(target)

    try:
        print(f"[+] Komut: {' '.join(command)}")
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=180, text=True)

        with open("terminal.txt", "w") as f:
            f.write(output)

        # OS fingerprinting varsa düşük seviye açık olarak ekle
        os_vuln = detect_os_leak(output, target)
        if os_vuln:
            existing = mongo.db.vulnerabilities.find_one({
                "title": os_vuln["title"],
                "description": {"$regex": target}
            })
            if not existing:
                mongo.db.vulnerabilities.insert_one(os_vuln)

        # Portlardan açık çıkarımı
        for line in output.splitlines():
            if "/tcp" in line and ("open" in line or "filtered" in line):
                port = line.split("/")[0].strip()
                severity = PORT_SEVERITY_RULES.get(port, "low")
                title = f"Açık Port: {line.strip()}"

                existing_vuln = mongo.db.vulnerabilities.find_one({
                    "title": title,
                    "description": target
                })

                if not existing_vuln:
                    mongo.db.vulnerabilities.insert_one({
                        "title": title,
                        "description": target,
                        "severity": severity,
                        "status": "unresolved",
                        "timestamp": datetime.datetime.utcnow()
                    })

        # Scan kaydını veritabanına ekle
        mongo.db.scans.insert_one({
            "name": f"{scan_type.title()} Tarama - {target}",
            "type": scan_type,
            "status": "completed",
            "target": target,
            "command": " ".join(command),
            "output": output,
            "timestamp": datetime.datetime.utcnow()
        })

        flash("Tarama başarıyla tamamlandı.", "success")

    except subprocess.TimeoutExpired:
        flash("Taramada zaman aşımı.", "danger")
    except subprocess.CalledProcessError as e:
        flash(f"Nmap hatası: {e.output}", "danger")
    except Exception as e:
        flash(f"Hata: {str(e)}", "danger")

    return redirect(url_for("dashboard.overview"))

@scans_bp.route("/list")
@login_required
def list_scans():
    scans = list(mongo.db.scans.find().sort("timestamp", -1))
    for scan in scans:
        scan["_id"] = str(scan["_id"])
    return jsonify(scans)
