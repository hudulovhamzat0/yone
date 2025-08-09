# app/routes.py
from .blueprints.auth import auth_bp
from .blueprints.dashboard import dashboard_bp
from .blueprints.goals import goals_bp
from .blueprints.scans import scans_bp
from .blueprints.terminal import terminal_bp
from .blueprints.api import api_bp
from app.blueprints.vuln import vuln_bp  # DİKKAT: doğru import yolu!
from app.blueprints.gobuster import gobuster_bp  # DİKKAT: doğru import yolu!
from datetime import datetime

def register_blueprints(app):
    """Tüm blueprint'leri app'e register et"""
    
    # Ana blueprint'ler
    app.register_blueprint(auth_bp, url_prefix='/')
    app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
    app.register_blueprint(goals_bp, url_prefix='/goals')
    app.register_blueprint(scans_bp, url_prefix='/scans')
    app.register_blueprint(terminal_bp, url_prefix='/terminal')
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Security-related blueprint'ler
    app.register_blueprint(vuln_bp, url_prefix='/vuln')  # Bu çok önemli
    app.register_blueprint(gobuster_bp, url_prefix='/gobuster')  # Bu da önemli
    
    print("✅ Tüm blueprint'ler başarıyla register edildi!")

def get_registered_routes(app):
    """Register edilmiş route'ları listele (debug için)"""
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'methods': list(rule.methods),
            'rule': str(rule)
        })
    return routes

def setup_error_handlers(app):
    """Error handler'ları setup et"""
    
    @app.errorhandler(404)
    def not_found_error(error):
        from flask import render_template, request
        
        # AJAX request'lerse JSON döndür
        if request.is_json or 'application/json' in request.headers.get('Accept', ''):
            return {
                'success': False,
                'error': 'Endpoint bulunamadı',
                'status_code': 404
            }, 404
        
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_server_error(error):
        from flask import render_template, request
        
        # AJAX request'lerse JSON döndür  
        if request.is_json or 'application/json' in request.headers.get('Accept', ''):
            return {
                'success': False,
                'error': 'Sunucu hatası',
                'status_code': 500
            }, 500
        
        return render_template('errors/500.html'), 500
    
    @app.errorhandler(403)
    def forbidden_error(error):
        from flask import render_template, request
        
        if request.is_json or 'application/json' in request.headers.get('Accept', ''):
            return {
                'success': False,
                'error': 'Erişim reddedildi',
                'status_code': 403
            }, 403
        
        return render_template('errors/403.html'), 403

def init_app_context(app):
    """Uygulama context'ini initialize et"""
    
    # Template globals (tüm template'lerde kullanılabilir)
    @app.context_processor
    def inject_globals():
        from flask_login import current_user
        return {
            'current_user': current_user,
            'app_name': 'Security Dashboard',
            'version': '1.0.0'
        }
    
    # Before request handler
    @app.before_request
    def before_request():
        from flask import request, g
        from flask_login import current_user
        
        g.start_time = datetime.datetime.utcnow()
        
        # Debug için request log'la (development'ta)
        if app.debug:
            print(f"🌐 {request.method} {request.path} - User: {current_user.get_id() if current_user.is_authenticated else 'Anonymous'}")
    
    # After request handler  
    @app.after_request
    def after_request(response):
        from flask import g
        
        if hasattr(g, 'start_time'):
            duration = datetime.datetime.utcnow() - g.start_time
            response.headers['X-Response-Time'] = f"{duration.total_seconds():.3f}s"
        
        return response

# Convenience function - tüm setup'ı bir arada yapmak için
def setup_app_routes(app):
    """Tüm route setup'ını yap"""
    register_blueprints(app)
    setup_error_handlers(app)
    init_app_context(app)
    print("🚀 App routes ve handlers setup tamamlandı!")