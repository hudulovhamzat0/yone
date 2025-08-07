from flask import Blueprint, request, redirect, url_for, jsonify
from flask_login import login_required
import subprocess

terminal_bp = Blueprint('terminal', __name__)

@terminal_bp.route("/execute", methods=["POST"])
@login_required
def execute_command():
    command = request.form.get("command")
    allowed = ["ls", "whoami", "id", "pwd", "uname", "uptime", "ps", "df", "free"]

    if not command:
        output = "⚠️ Komut girilmedi."
    elif not command.split()[0] in allowed:
        output = f"⚠️ Bu komuta izin verilmiyor. İzin verilen komutlar: {', '.join(allowed)}"
    else:
        try:
            output = subprocess.check_output(
                command, 
                shell=True, 
                stderr=subprocess.STDOUT, 
                timeout=10, 
                text=True
            )
        except subprocess.CalledProcessError as e:
            output = f"Hata:\n{e.output}"
        except subprocess.TimeoutExpired:
            output = "⚠️ Komut zaman aşımına uğradı."
        except Exception as e:
            output = f"⚠️ Beklenmeyen hata: {str(e)}"

    # Write output to terminal.txt
    with open("terminal.txt", "w") as f:
        f.write(output)

    return redirect(url_for("dashboard.overview"))

@terminal_bp.route("/output")
@login_required
def get_terminal_output():
    """Get current terminal output"""
    try:
        with open("terminal.txt", "r") as f:
            content = f.read()
    except FileNotFoundError:
        content = "Henüz çıktı yok..."
    return jsonify({"output": content})

@terminal_bp.route("/clear", methods=["POST"])
@login_required
def clear_terminal():
    """Clear terminal output"""
    try:
        with open("terminal.txt", "w") as f:
            f.write("Terminal temizlendi...")
        return jsonify({"success": True, "message": "Terminal temizlendi"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@terminal_bp.route("/history")
@login_required
def get_command_history():
    """Get command history (if implemented)"""
    # This could be expanded to store command history in database
    return jsonify({"history": []})