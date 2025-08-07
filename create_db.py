# seed.py

from app import create_app, mongo

app = create_app()
app.app_context().push()

# 🧹 Önce tüm koleksiyonları temizle
mongo.db.goals.delete_many({})
mongo.db.scans.delete_many({})
mongo.db.vulnerabilities.delete_many({})

# 🎯 Hedefler (goals) koleksiyonu
goals_data = [
    {"name": "Web Sunucusu Taraması", "ip": "192.168.1.100", "status": "active"},
    {"name": "Veritabanı Güvenlik Kontrolü", "ip": "10.0.0.50", "status": "pending"},
    {"name": "Ağ Altyapısı Analizi", "ip": "172.16.0.0/24", "status": "completed"},
    {"name": "Mail Sunucusu Denetimi", "ip": "mail.example.com", "status": "active"}
]
mongo.db.goals.insert_many(goals_data)

# 🔍 Taramalar (scans) koleksiyonu
scans_data = [
    {"name": "Zamanlanmış Tarama #001", "type": "otomatik", "status": "active"},
    {"name": "Manuel Tarama #045", "type": "manuel", "status": "completed"},
    {"name": "Acil Durum Taraması", "type": "acil", "status": "pending"}
]
mongo.db.scans.insert_many(scans_data)

# 🔐 Güvenlik Açıkları (vulnerabilities) koleksiyonu
vulnerabilities_data = [
    {
        "title": "SQL Injection Açığı",
        "description": "Web uygulamasında kritik SQL injection açığı tespit edildi",
        "severity": "critical"
    },
    {
        "title": "Zayıf Şifre Politikası",
        "description": "Kullanıcı hesaplarında zayıf şifre kullanımı tespit edildi",
        "severity": "high"
    },
    {
        "title": "Güncel Olmayan Yazılım",
        "description": "Sistem üzerinde güvenlik güncellemeleri eksik",
        "severity": "medium"
    },
    {
        "title": "Açık Portlar",
        "description": "Firewall kuralları gevşek, dışa açık portlar tespit edildi",
        "severity": "low"
    }
]
mongo.db.vulnerabilities.insert_many(vulnerabilities_data)

print("✅ MongoDB koleksiyonları başarıyla oluşturuldu ve dolduruldu.")
