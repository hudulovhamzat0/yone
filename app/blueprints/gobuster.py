from flask import Blueprint, request, redirect, url_for, flash, jsonify
from flask_login import login_required
from .. import mongo
import subprocess
import datetime
import os

gobuster_bp = Blueprint('gobuster', __name__)

# Wordlist functions
def create_wordlists():
    """Tüm wordlist'leri oluştur"""
    os.makedirs('wordlists', exist_ok=True)
    
    # Default wordlist
    wordlist_path = os.path.join('wordlists', 'wordlist.txt')
    if not os.path.exists(wordlist_path):
        default_words = [
            'admin', 'administrator', 'login', 'test', 'demo', 'backup',
            'config', 'data', 'db', 'files', 'images', 'img', 'js',
            'css', 'assets', 'uploads', 'download', 'downloads', 'docs',
            'documentation', 'api', 'v1', 'v2', 'old', 'new', 'temp',
            'tmp', 'cache', 'logs', 'log', 'statistics', 'stats', 'info',
            'phpinfo', 'phpmyadmin', 'mysql', 'sql', 'database', 'wp-admin',
            'wp-content', 'wp-includes', 'wordpress', 'cms', 'control',
            'panel', 'dashboard', 'user', 'users', 'account', 'accounts',
            'profile', 'profiles', 'settings', 'configuration',
            'setup', 'install', 'installation', 'update', 'upgrade',
            'maintenance', 'dev', 'development', 'staging', 'production',
            'beta', 'alpha', 'private', 'public', 'secure', 'security'
        ]
        with open(wordlist_path, 'w') as f:
            f.write('\n'.join(default_words))
    
    # Common wordlist
    common_path = os.path.join('wordlists', 'common.txt')
    if not os.path.exists(common_path):
        common_words = [
            'admin', 'login', 'dashboard', 'panel', 'control', 'api',
            'test', 'demo', 'backup', 'config', 'uploads', 'files',
            'images', 'assets', 'js', 'css', 'docs', 'download'
        ]
        with open(common_path, 'w') as f:
            f.write('\n'.join(common_words))
    
    # Small wordlist
    small_path = os.path.join('wordlists', 'small.txt')
    if not os.path.exists(small_path):
        small_words = ['admin', 'login', 'test', 'api', 'backup', 'config', 'uploads', 'files']
        with open(small_path, 'w') as f:
            f.write('\n'.join(small_words))
    
    # Big wordlist
    big_path = os.path.join('wordlists', 'big.txt')
    if not os.path.exists(big_path):
        big_words = [
            'admin', 'administrator', 'login', 'signin', 'signup', 'register',
            'dashboard', 'panel', 'control', 'manage', 'manager', 'api',
            'v1', 'v2', 'v3', 'rest', 'graphql', 'test', 'testing',
            'demo', 'example', 'sample', 'backup', 'backups', 'old',
            'new', 'config', 'configuration', 'settings', 'setup',
            'install', 'installation', 'update', 'upgrade', 'maintenance',
            'uploads', 'upload', 'files', 'file', 'documents', 'docs',
            'images', 'img', 'pictures', 'photos', 'assets', 'static',
            'js', 'javascript', 'css', 'styles', 'fonts', 'media',
            'download', 'downloads', 'export', 'import', 'data',
            'database', 'db', 'sql', 'mysql', 'postgres', 'mongodb',
            'cache', 'temp', 'tmp', 'logs', 'log', 'debug', 'error',
            'info', 'statistics', 'stats', 'analytics', 'reports',
            'phpinfo', 'phpmyadmin', 'adminer', 'wp-admin', 'wp-content',
            'wp-includes', 'wordpress', 'cms', 'drupal', 'joomla',
            'user', 'users', 'account', 'accounts', 'profile', 'profiles',
            'member', 'members', 'client', 'clients', 'customer', 'customers',
            'private', 'public', 'secure', 'security', 'auth', 'oauth',
            'dev', 'development', 'staging', 'production', 'beta', 'alpha',
            'mobile', 'app', 'application', 'service', 'services'
        ]
        with open(big_path, 'w') as f:
            f.write('\n'.join(big_words))

# Initialize wordlists when blueprint loads
create_wordlists()

def detect_directory_vulnerabilities(gobuster_output, target_url):
    """Gobuster çıktısından potansiyel güvenlik açıklarını tespit et"""
    vulnerabilities = []
    
    for line in gobuster_output.splitlines():
        line = line.strip()
        if line and '(Status:' in line:
            # Extract path and status code
            parts = line.split('(Status:')
            if len(parts) >= 2:
                path = parts[0].strip()
                status_part = parts[1].split(')')[0].strip()
                
                # Check for sensitive directories/files
                sensitive_paths = {
                    'admin': 'high',
                    'phpmyadmin': 'high',
                    'config': 'medium',
                    'backup': 'medium',
                    'logs': 'medium',
                    'test': 'low',
                    'dev': 'medium',
                    'staging': 'medium'
                }
                
                for sensitive, severity in sensitive_paths.items():
                    if sensitive in path.lower():
                        vuln = {
                            "title": f"Sensitive Directory/File Found: {path}",
                            "description": f"Found potentially sensitive path: {target_url}{path} (Status: {status_part})",
                            "severity": severity,
                            "status": "unresolved",
                            "timestamp": datetime.datetime.utcnow()
                        }
                        
                        # Check if this vulnerability already exists
                        existing = mongo.db.vulnerabilities.find_one({
                            "title": vuln["title"],
                            "description": vuln["description"]
                        })
                        
                        if not existing:
                            vulnerabilities.append(vuln)
    
    return vulnerabilities

@gobuster_bp.route("", methods=["POST"])
@login_required
def gobuster():
    print("[DEBUG] Function started")
    print(f"[DEBUG] Request form: {request.form}")
    
    target = request.form.get("target")
    wordlist = request.form.get("wordlist", "wordlist.txt")
    threads = request.form.get("threads", "10")
    extensions = request.form.get("extensions", "")
    follow_redirects = request.form.get("follow_redirects")
    show_length = request.form.get("show_length")

    print(f"[DEBUG] Target: {target}")
    print(f"[DEBUG] Wordlist: {wordlist}")
    print(f"Gobuster request: {request.form}")

    if not target:
        print("[DEBUG] No target provided")
        flash("Hedef belirtilmedi!", "danger")
        return redirect(url_for("dashboard.overview"))

    print("[DEBUG] Target validation...")
    # Auto-add http:// if no protocol specified (like Nmap does)
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
        print(f"[DEBUG] Added http:// prefix. New target: {target}")
    else:
        print("[DEBUG] Target already has protocol")

    print("[DEBUG] Wordlist validation...")
    # Wordlist dosyasının varlığını kontrol et
    wordlist_path = os.path.join("wordlists", wordlist)
    print(f"[DEBUG] Checking wordlist at: {wordlist_path}")
    
    if not os.path.exists(wordlist_path):
        print(f"[DEBUG] Wordlist not found: {wordlist_path}")
        flash(f"Wordlist dosyası bulunamadı: {wordlist}", "danger")
        return redirect(url_for("dashboard.overview"))

    print("[DEBUG] Building command...")
    # Gobuster komutunu oluştur
    command = ["gobuster", "dir"]
    command += ["-u", target]
    command += ["-w", wordlist_path]
    command += ["-t", threads]
    command += ["--timeout", "30s"]

    # Extensions ekle
    if extensions:
        clean_extensions = ",".join([ext.strip() for ext in extensions.split(",") if ext.strip()])
        if clean_extensions:
            command += ["-x", clean_extensions]

    # Follow redirects
    if follow_redirects:
        command.append("-r")

    # Show content length
    if show_length:
        command.append("-l")

    # Status codes - disable default blacklist first, then set whitelist
    command += ["-b", ""]  # Disable default blacklist (empty string)
    command += ["-s", "200,204,301,302,307,401,403"]
    
    print(f"[DEBUG] Final command: {' '.join(command)}")
    print("[DEBUG] About to enter try block...")

    try:
        print(f"[+] Komut: {' '.join(command)}")
        print(f"[+] Wordlist path: {wordlist_path}")
        print(f"[+] Wordlist exists: {os.path.exists(wordlist_path)}")
        
        # Debug: Check if gobuster is available using 'gobuster version'
        try:
            version_output = subprocess.check_output(["gobuster", "version"], stderr=subprocess.STDOUT, text=True, timeout=10)
            print(f"[+] Gobuster version: {version_output.strip()}")
        except subprocess.CalledProcessError as e:
            print(f"[-] Gobuster version failed with return code {e.returncode}: {e.output}")
            flash(f"Gobuster version hatası: {e.output}", "danger")
            return redirect(url_for("dashboard.overview"))
        except FileNotFoundError:
            print("[-] Gobuster command not found")
            flash("Gobuster kurulu değil! 'gobuster' komutu bulunamadı.", "danger")
            return redirect(url_for("dashboard.overview"))
        except Exception as e:
            print(f"[-] Gobuster version check failed: {e}")
            flash(f"Gobuster kontrol hatası: {str(e)}", "danger")
            return redirect(url_for("dashboard.overview"))
        
        print("[+] Starting gobuster scan...")
        print(f"[+] Full command: {' '.join(command)}")
        
        # Run the actual scan
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=300, text=True)
        print(f"[+] Gobuster completed successfully!")
        print(f"[+] Output length: {len(output)}")
        
        if output.strip():
            print(f"[+] Output preview: {output[:500]}...")
        else:
            print("[-] Warning: Gobuster returned empty output")

        with open("terminal.txt", "w") as f:
            f.write(output)
            
        print("[+] Terminal.txt written")

        # Bulunan yollardan güvenlik açıklarını tespit et
        vulnerabilities = detect_directory_vulnerabilities(output, target)
        print(f"[+] Found {len(vulnerabilities)} vulnerabilities")
        
        # Tespit edilen açıkları veritabanına ekle
        if vulnerabilities:
            result = mongo.db.vulnerabilities.insert_many(vulnerabilities)
            print(f"[+] Inserted {len(result.inserted_ids)} vulnerabilities to DB")

        # Scan kaydını veritabanına ekle
        scan_result = mongo.db.scans.insert_one({
            "name": f"Gobuster - {target}",
            "type": "gobuster",
            "status": "completed",
            "target": target,
            "command": " ".join(command),
            "output": output,
            "timestamp": datetime.datetime.utcnow()
        })
        print(f"[+] Scan inserted to DB with ID: {scan_result.inserted_id}")

        flash("Gobuster taraması başarıyla tamamlandı.", "success")

    except subprocess.TimeoutExpired:
        print("[-] Gobuster scan timed out")
        flash("Taramada zaman aşımı.", "danger")
    except subprocess.CalledProcessError as e:
        print(f"[-] Gobuster failed with return code {e.returncode}")
        print(f"[-] Error output: {e.output}")
        flash(f"Gobuster hatası: {e.output}", "danger")
    except FileNotFoundError:
        print("[-] Gobuster executable not found")
        flash("Gobuster kurulu değil!", "danger")
    except Exception as e:
        print(f"[-] Unexpected error: {str(e)}")
        print(f"[-] Error type: {type(e)}")
        flash(f"Hata: {str(e)}", "danger")

    return redirect(url_for("dashboard.overview"))


@gobuster_bp.route("/list")
@login_required
def list_scans():
    """Gobuster taramalarını listele"""
    try:
        # Sadece gobuster taramalarını getir (Nmap pattern'i taklit et)
        scans = list(mongo.db.scans.find({"type": "gobuster"}).sort("timestamp", -1))
        
        # ObjectId'leri string'e çevir
        for scan in scans:
            scan["_id"] = str(scan["_id"])
            
        return jsonify(scans)
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@gobuster_bp.route("/scan/<scan_id>")
@login_required
def get_scan_details(scan_id):
    """Belirli bir taramanın detaylarını getir"""
    try:
        from bson import ObjectId
        
        scan = mongo.db.scans.find_one({"_id": ObjectId(scan_id), "type": "gobuster"})
        
        if not scan:
            return jsonify({
                "success": False,
                "error": "Tarama bulunamadı"
            }), 404
            
        scan["_id"] = str(scan["_id"])
        
        # Çıktıyı parse et (bulunan path'leri ayır)
        if scan.get("output"):
            lines = scan["output"].split('\n')
            found_paths = []
            for line in lines:
                line = line.strip()
                if line and not line.startswith('=') and '(Status:' in line:
                    found_paths.append(line)
            scan["parsed_paths"] = found_paths
        
        return jsonify({
            "success": True,
            "scan": scan
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@gobuster_bp.route("/scan/<scan_id>/delete", methods=["POST"])
@login_required
def delete_scan(scan_id):
    """Tarama kaydını sil"""
    try:
        from bson import ObjectId
        
        result = mongo.db.scans.delete_one({"_id": ObjectId(scan_id), "type": "gobuster"})
        
        if result.deleted_count > 0:
            flash("🗑️ Tarama kaydı silindi.", "success")
        else:
            flash("❌ Tarama kaydı bulunamadı.", "danger")
            
    except Exception as e:
        flash(f"❌ Silme hatası: {str(e)}", "danger")
    
    return redirect(url_for("dashboard.overview"))


@gobuster_bp.route("/wordlists")
@login_required
def get_wordlists():
    """Mevcut wordlist'leri getir"""
    try:
        wordlists_dir = "wordlists"
        wordlists = []
        
        if os.path.exists(wordlists_dir):
            for file in os.listdir(wordlists_dir):
                if file.endswith('.txt'):
                    file_path = os.path.join(wordlists_dir, file)
                    file_size = os.path.getsize(file_path)
                    
                    # Dosya boyutunu human readable format'a çevir
                    if file_size < 1024:
                        size_str = f"{file_size} B"
                    elif file_size < 1024 * 1024:
                        size_str = f"{file_size // 1024} KB"
                    else:
                        size_str = f"{file_size // (1024 * 1024)} MB"
                    
                    wordlists.append({
                        "filename": file,
                        "size": file_size,
                        "size_formatted": size_str
                    })
        
        return jsonify({
            "success": True,
            "wordlists": wordlists
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500