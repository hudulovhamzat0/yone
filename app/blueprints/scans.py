from flask import Blueprint, request, redirect, url_for, flash, jsonify
from flask_login import login_required
from .. import mongo
import subprocess
import datetime

scans_bp = Blueprint('scans', __name__)

@scans_bp.route("/start-nmap", methods=["POST"])
@login_required
def start_nmap():
    ip = request.form.get("target")
    if not ip:
        flash("Hedef IP girilmedi!", "danger")
        return redirect(url_for("dashboard.overview"))

    try:
        print(f"[+] Nmap başlatılıyor: {ip}")
        output = subprocess.check_output(
            ["nmap", "-sV", "-T4", "--top-ports", "10", ip],
            stderr=subprocess.STDOUT,
            timeout=60,
            text=True
        )

        # Write output to terminal.txt file
        with open("terminal.txt", "w") as f:
            f.write(output)

        # Add open and filtered ports to vulnerabilities
        for line in output.splitlines():
            if "/tcp" in line and ("open" in line or "filtered" in line):
                mongo.db.vulnerabilities.insert_one({
                    "title": f"Açık Port: {line.strip()}",
                    "description": f"Nmap çıktısı: {line.strip()}",
                    "severity": "low",
                    "timestamp": datetime.datetime.utcnow()
                })

        # Save scan to database
        mongo.db.scans.insert_one({
            "name": f"Nmap Scan {ip}",
            "type": "port-scan",
            "status": "completed",
            "target": ip,
            "output": output,
            "timestamp": datetime.datetime.utcnow()
        })

        flash("Nmap taraması tamamlandı. Açık ve filtreli portlar eklendi.", "success")

    except subprocess.TimeoutExpired:
        flash("Nmap taraması zaman aşımına uğradı.", "danger")
    except subprocess.CalledProcessError as e:
        flash(f"Nmap hatası: {e.output}", "danger")

    return redirect(url_for("dashboard.overview"))

@scans_bp.route("/list")
@login_required
def list_scans():
    """API endpoint to get all scans"""
    scans = list(mongo.db.scans.find({}, {"_id": 0}))
    return jsonify(scans)

@scans_bp.route("/start-custom", methods=["POST"])
@login_required
def start_custom_scan():
    """Start a custom scan with different parameters"""
    target = request.form.get("target")
    scan_type = request.form.get("scan_type", "basic")
    
    if not target:
        flash("Hedef belirtilmedi!", "danger")
        return redirect(url_for("dashboard.overview"))
    
    # Define scan commands based on type
    scan_commands = {
        "basic": ["nmap", "-sV", "-T4", "--top-ports", "100", target],
        "aggressive": ["nmap", "-A", "-T4", target],
        "stealth": ["nmap", "-sS", "-T2", target],
        "udp": ["nmap", "-sU", "--top-ports", "50", target]
    }
    
    command = scan_commands.get(scan_type, scan_commands["basic"])
    
    try:
        print(f"[+] Starting {scan_type} scan on: {target}")
        output = subprocess.check_output(
            command,
            stderr=subprocess.STDOUT,
            timeout=120,
            text=True
        )
        
        # Write output to terminal.txt
        with open("terminal.txt", "w") as f:
            f.write(output)
        
        # Save scan to database
        mongo.db.scans.insert_one({
            "name": f"{scan_type.title()} Scan - {target}",
            "type": scan_type,
            "status": "completed",
            "target": target,
            "output": output,
            "timestamp": datetime.datetime.utcnow()
        })
        
        flash(f"{scan_type.title()} taraması tamamlandı.", "success")
        
    except subprocess.TimeoutExpired:
        flash("Tarama zaman aşımına uğradı.", "danger")
    except subprocess.CalledProcessError as e:
        flash(f"Tarama hatası: {str(e)}", "danger")
    except Exception as e:
        flash(f"Beklenmeyen hata: {str(e)}", "danger")
    
    return redirect(url_for("dashboard.overview"))