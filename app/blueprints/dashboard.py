from flask import Blueprint, render_template
from flask_login import login_required
from .. import mongo
import os

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route("/")
@login_required
def overview():
    # Get statistics
    total_goals = mongo.db.goals.count_documents({})
    active_scans = mongo.db.scans.count_documents({"status": "active"})
    found_vulns = mongo.db.vulnerabilities.count_documents({})
    critical_vulns = mongo.db.vulnerabilities.count_documents({"severity": "critical"})

    # Get all data for the dashboard
    goals = list(mongo.db.goals.find())
    scans = list(mongo.db.scans.find())
    vulnerabilities = list(mongo.db.vulnerabilities.find())

    # Read terminal output
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