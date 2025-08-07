from flask import Blueprint, request, jsonify
from flask_login import login_required
from .. import mongo

api_bp = Blueprint('api', __name__)

@api_bp.route("/vulnerabilities")
@login_required
def get_vulnerabilities():
    """Get vulnerabilities with optional severity filter"""
    severity = request.args.get("severity")
    query = {}
    if severity:
        query["severity"] = severity

    data = list(mongo.db.vulnerabilities.find(query, {"_id": 0}))
    return jsonify(data)

@api_bp.route("/scans")
@login_required
def get_scans():
    """Get all scans"""
    data = list(mongo.db.scans.find({}, {"_id": 0}))
    return jsonify(data)

@api_bp.route("/goals")
@login_required
def get_goals():
    """Get all goals/targets"""
    data = list(mongo.db.goals.find({}, {"_id": 0}))
    return jsonify(data)

@api_bp.route("/stats")
@login_required
def get_stats():
    """Get dashboard statistics"""
    total_goals = mongo.db.goals.count_documents({})
    active_scans = mongo.db.scans.count_documents({"status": "active"})
    found_vulns = mongo.db.vulnerabilities.count_documents({})
    critical_vulns = mongo.db.vulnerabilities.count_documents({"severity": "critical"})
    
    # Vulnerability breakdown by severity
    vuln_breakdown = {}
    severities = ["critical", "high", "medium", "low"]
    for severity in severities:
        count = mongo.db.vulnerabilities.count_documents({"severity": severity})
        vuln_breakdown[severity] = count
    
    # Scan status breakdown
    scan_breakdown = {}
    statuses = ["active", "completed", "pending", "failed"]
    for status in statuses:
        count = mongo.db.scans.count_documents({"status": status})
        scan_breakdown[status] = count
    
    return jsonify({
        "total_goals": total_goals,
        "active_scans": active_scans,
        "found_vulns": found_vulns,
        "critical_vulns": critical_vulns,
        "vulnerability_breakdown": vuln_breakdown,
        "scan_breakdown": scan_breakdown
    })

@api_bp.route("/vulnerabilities/<vuln_id>", methods=["DELETE"])
@login_required
def delete_vulnerability(vuln_id):
    """Delete a specific vulnerability"""
    from bson import ObjectId
    try:
        result = mongo.db.vulnerabilities.delete_one({"_id": ObjectId(vuln_id)})
        if result.deleted_count:
            return jsonify({"success": True, "message": "Açık başarıyla silindi"})
        else:
            return jsonify({"success": False, "error": "Açık bulunamadı"}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@api_bp.route("/vulnerabilities", methods=["POST"])
@login_required
def add_vulnerability():
    """Add a new vulnerability manually"""
    data = request.get_json()
    
    required_fields = ["title", "description", "severity"]
    if not all(field in data for field in required_fields):
        return jsonify({"success": False, "error": "Missing required fields"}), 400
    
    if data["severity"] not in ["critical", "high", "medium", "low"]:
        return jsonify({"success": False, "error": "Invalid severity level"}), 400
    
    vuln_data = {
        "title": data["title"],
        "description": data["description"],
        "severity": data["severity"],
        "timestamp": data.get("timestamp", None)
    }
    
    try:
        result = mongo.db.vulnerabilities.insert_one(vuln_data)
        return jsonify({"success": True, "id": str(result.inserted_id)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500