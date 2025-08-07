from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, logout_user, login_required
from .models import User
from . import mongo, login_manager, bcrypt
import subprocess
import datetime
import os

main = Blueprint('main', __name__)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@main.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.get_by_username(username)

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("main.dashboard"))
        flash("Kullanıcı adı veya şifre yanlış", "danger")

    return render_template("login.html")

@main.route("/dashboard")
@login_required
def dashboard():
    total_goals = mongo.db.goals.count_documents({})
    active_scans = mongo.db.scans.count_documents({"status": "active"})
    found_vulns = mongo.db.vulnerabilities.count_documents({})
    critical_vulns = mongo.db.vulnerabilities.count_documents({"severity": "critical"})

    goals = list(mongo.db.goals.find())
    scans = list(mongo.db.scans.find())
    vulnerabilities = list(mongo.db.vulnerabilities.find())

    # terminal.txt'yi oku
    terminal_output = "Henüz çıktı yok..."
    if os.path.exists("terminal.txt"):
        with open("terminal.txt", "r") as f:
            terminal_output = f.read()

    return render_template("dashboard.html",
                           total_goals=total_goals,
                           active_scans=active_scans,
                           found_vulns=found_vulns,
                           critical_vulns=critical_vulns,
                           goals=goals,
                           scans=scans,
                           vulnerabilities=vulnerabilities,
                           terminal_output=terminal_output)

@main.route("/add-goal", methods=["POST"])
@login_required
def add_goal():
    url = request.form.get("url")
    note = request.form.get("note")

    if url:
        mongo.db.goals.insert_one({
            "name": note or "Not Yok",
            "ip": url,
            "note": note,
            "status": "active",
        })
        flash("Hedef başarıyla eklendi.", "success")
    else:
        flash("Hedef URL boş bırakılamaz.", "danger")

    return redirect(url_for("main.dashboard"))

@main.route("/start-nmap", methods=["POST"])
@login_required
def start_nmap():
    ip = request.form.get("target")
    if not ip:
        flash("Hedef IP girilmedi!", "danger")
        return redirect(url_for("main.dashboard"))

    try:
        print(f"[+] Nmap başlatılıyor: {ip}")
        output = subprocess.check_output(
            ["nmap", "-sV", "-T4", "--top-ports", "10", ip],
            stderr=subprocess.STDOUT,
            timeout=60,
            text=True
        )

        # Çıktıyı terminal.txt dosyasına yaz
        with open("terminal.txt", "w") as f:
            f.write(output)

        # open ve filtered portlar açıklar kısmına eklenir
        for line in output.splitlines():
            if "/tcp" in line and ("open" in line or "filtered" in line):
                mongo.db.vulnerabilities.insert_one({
                    "title": f"Açık Port: {line.strip()}",
                    "description": f"Nmap çıktısı: {line.strip()}",
                    "severity": "low",
                    "timestamp": datetime.datetime.utcnow()
                })

        # Taramayı DB'ye kaydet
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

    return redirect(url_for("main.dashboard"))


@main.route("/terminal", methods=["POST"])
@login_required
def terminal():
    command = request.form.get("command")
    allowed = ["ls", "whoami", "id", "pwd", "uname", "uptime"]

    if not command.split()[0] in allowed:
        output = "⚠️ Bu komuta izin verilmiyor."
    else:
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=10, text=True)
        except subprocess.CalledProcessError as e:
            output = f"Hata:\n{e.output}"
        except subprocess.TimeoutExpired:
            output = "⚠️ Komut zaman aşımına uğradı."

    with open("terminal.txt", "w") as f:
        f.write(output)

    return redirect(url_for("main.dashboard"))

@main.route("/terminal-output")
@login_required
def terminal_output():
    try:
        with open("terminal.txt", "r") as f:
            content = f.read()
    except FileNotFoundError:
        content = "Henüz çıktı yok..."
    return jsonify({"output": content})

@main.route("/api/vulnerabilities")
@login_required
def api_vulnerabilities():
    severity = request.args.get("severity")
    query = {}
    if severity:
        query["severity"] = severity

    data = list(mongo.db.vulnerabilities.find(query, {"_id": 0}))
    return jsonify(data)

@main.route("/api/scans")
@login_required
def api_scans():
    data = list(mongo.db.scans.find({}, {"_id": 0}))
    return jsonify(data)

@main.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.login"))
