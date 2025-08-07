# app/blueprints/vuln.py

from flask import Blueprint, request, jsonify
from bson import ObjectId
from app import mongo  # mongo bağlantın burada olmalı

vuln_bp = Blueprint('vuln', __name__)  # Blueprint adı "vuln"

@vuln_bp.route('/update-status', methods=['POST'])
def update_status():
    data = request.get_json()
    vuln_id = data.get('id')
    resolved = data.get('resolved')

    if not vuln_id:
        return jsonify({'error': 'Eksik ID'}), 400

    try:
        result = mongo.db.vulnerabilities.update_one(
            {'_id': ObjectId(vuln_id)},
            {'$set': {'resolved': resolved}}
        )
        return jsonify({'message': 'Durum güncellendi', 'matched': result.matched_count}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
