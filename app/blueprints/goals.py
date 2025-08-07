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
    goals = list(mongo.db.goals.find({}, {"_id": 0}))
    return jsonify(goals)


# 📌 Hedef Silme
@goals_bp.route("/delete/<goal_id>", methods=["POST"])
@login_required
def delete_goal(goal_id):
    """Delete a specific goal"""
    try:
        result = mongo.db.goals.delete_one({"_id": ObjectId(goal_id)})
        if result.deleted_count:
            flash("Hedef başarıyla silindi.", "success")
        else:
            flash("Hedef bulunamadı.", "danger")
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
