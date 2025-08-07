from flask import Blueprint, request, redirect, url_for, flash, jsonify
from flask_login import login_required
from .. import mongo
from bson import ObjectId

goals_bp = Blueprint('goals', __name__)

# 📌 Hedef Ekleme
@goals_bp.route("/add", methods=["POST"])
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

    return redirect(url_for("dashboard.overview"))


# 📌 Tüm Hedefleri Listele (JSON API)
@goals_bp.route("/list")
@login_required
def list_goals():
    """API endpoint to get all goals"""
    goals = list(mongo.db.goals.find({}, {"_id": 0}).sort("timestamp", -1))
    return jsonify(goals)


# 📌 Hedef Silme + Açık + Scan Silme
@goals_bp.route("/delete/<goal_id>", methods=["POST"])
@login_required
def delete_goal(goal_id):
    """Delete a specific goal and its related vulnerabilities and scans"""
    try:
        # Hedefi bul
        goal = mongo.db.goals.find_one({"_id": ObjectId(goal_id)})
        if goal:
            ip = goal.get("ip")

            # İlgili açıkları sil (description domain'e eşit)
            mongo.db.vulnerabilities.delete_many({"description": ip})

            # İlgili scan sonuçlarını sil (ip eşleşmesi)
            mongo.db.scans.delete_many({"ip": ip})

            # Hedefi sil
            result = mongo.db.goals.delete_one({"_id": ObjectId(goal_id)})

            if result.deleted_count:
                flash("Hedef, açıklar ve scan verileri başarıyla silindi.", "success")
            else:
                flash("Hedef silinemedi.", "danger")
        else:
            flash("Hedef bulunamadı.", "warning")

    except Exception as e:
        flash(f"Geçersiz hedef ID: {e}", "danger")

    return redirect(url_for("dashboard.overview"))


# 📌 Hedef Güncelleme (Not ve Durum)
@goals_bp.route("/update/<goal_id>", methods=["POST"])
@login_required
def update_goal(goal_id):
    """Update a specific goal (note and/or status)"""
    try:
        status = request.form.get("status")
        note = request.form.get("note")

        update_data = {}
        if status:
            update_data["status"] = status
        if note:
            update_data["note"] = note

        result = mongo.db.goals.update_one(
            {"_id": ObjectId(goal_id)},
            {"$set": update_data}
        )

        if result.modified_count:
            flash("Hedef başarıyla güncellendi.", "success")
        else:
            flash("Güncellenecek veri bulunamadı.", "info")
    except Exception as e:
        flash(f"Geçersiz hedef ID: {e}", "danger")

    return redirect(url_for("dashboard.overview"))
@goals_bp.route("/clear-scans", methods=["POST"])
@login_required
def clear_scans():
    try:
        result = mongo.db.scans.delete_many({})
        flash(f"{result.deleted_count} scan geçmişi silindi.", "success")
    except Exception as e:
        flash(f"Scan geçmişi silinemedi: {e}", "danger")
    
    return redirect(url_for("dashboard.overview"))
