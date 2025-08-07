document.addEventListener('DOMContentLoaded', function () {
    // Sidebar Navigation
    const navItems = document.querySelectorAll('.nav-item');
    const contentSections = document.querySelectorAll('.content-section');

    navItems.forEach(item => {
        item.addEventListener('click', function () {
            const targetSection = this.dataset.section;
            navItems.forEach(nav => nav.classList.remove('active'));
            contentSections.forEach(section => section.classList.remove('active'));
            this.classList.add('active');
            document.getElementById(targetSection).classList.add('active');
        });
    });

    // Hover Animations for Cards
    const cards = document.querySelectorAll('.card');
    cards.forEach(card => {
        card.addEventListener('mouseenter', function () {
            this.style.transform = 'translateY(-10px) scale(1.02)';
        });
        card.addEventListener('mouseleave', function () {
            this.style.transform = 'translateY(0) scale(1)';
        });
    });

    // Animated Stats
    const statNumbers = document.querySelectorAll('.stat-number');
    statNumbers.forEach(stat => {
        const finalValue = parseInt(stat.textContent);
        let currentValue = 0;
        const increment = finalValue / 50;
        const counter = setInterval(() => {
            currentValue += increment;
            if (currentValue >= finalValue) {
                stat.textContent = finalValue;
                clearInterval(counter);
            } else {
                stat.textContent = Math.floor(currentValue);
            }
        }, 30);
    });

    // Vuln Chart from API
    fetch("/api/vulnerabilities")
        .then(res => res.json())
        .then(data => {
            const counts = { critical: 0, high: 0, medium: 0, low: 0 };
            data.forEach(v => {
                if (counts[v.severity] !== undefined) {
                    counts[v.severity]++;
                }
            });

            const ctx = document.getElementById("vulnChart").getContext("2d");
            new Chart(ctx, {
                type: "doughnut",
                data: {
                    labels: ["Kritik", "Yüksek", "Orta", "Düşük"],
                    datasets: [{
                        data: [counts.critical, counts.high, counts.medium, counts.low],
                        backgroundColor: ["#f44336", "#FF9800", "#FFC107", "#4CAF50"]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { position: "bottom" }
                    }
                }
            });
        });

    // Nmap Modal Logic
    const modal = document.getElementById("nmapModal");
    const trigger = document.getElementById("nmap-scan-trigger");

    if (trigger && modal) {
        trigger.addEventListener("click", function () {
            modal.style.display = "block";
        });

        window.addEventListener("click", function (e) {
            if (e.target === modal) {
                closeModal();
            }
        });
    }

    // Custom Scan Modal Logic
    const customModal = document.getElementById("customScanModal");
    const customTrigger = document.getElementById("custom-scan-trigger");

    if (customTrigger && customModal) {
        customTrigger.addEventListener("click", function () {
            customModal.style.display = "block";
        });

        window.addEventListener("click", function (e) {
            if (e.target === customModal) {
                closeCustomScanModal();
            }
        });
    }
});

// Modal functions
function closeModal() {
    document.getElementById("nmapModal").style.display = "none";
}

function closeCustomScanModal() {
    document.getElementById("customScanModal").style.display = "none";
}

// Terminal functions
function loadTerminalOutput() {
    fetch("/terminal/output")
        .then(res => res.json())
        .then(data => {
            document.getElementById("terminal-content").textContent = data.output;
        })
        .catch(error => {
            console.error('Error loading terminal output:', error);
        });
}

function clearTerminal() {
    fetch("/terminal/clear", { method: "POST" })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                document.getElementById("terminal-content").textContent = "Terminal temizlendi...";
            }
        })
        .catch(error => {
            console.error('Error clearing terminal:', error);
        });
}

// Auto-refresh terminal output when on terminal section
function startTerminalRefresh() {
    setInterval(() => {
        const terminalSection = document.getElementById("terminal");
        if (terminalSection && terminalSection.classList.contains("active")) {
            loadTerminalOutput();
        }
    }, 3000); // Refresh every 3 seconds
}

// Terminal sekmesine geçildiğinde çıktıyı göster
document.querySelector('[data-section="terminal"]').addEventListener("click", function() {
    loadTerminalOutput();
    startTerminalRefresh();
});

// Refresh stats periodically
function refreshStats() {
    fetch("/api/stats")
        .then(res => res.json())
        .then(data => {
            // Update stat numbers
            const statCards = document.querySelectorAll('.stat-card .stat-number');
            if (statCards.length >= 4) {
                statCards[0].textContent = data.total_goals;
                statCards[1].textContent = data.active_scans;
                statCards[2].textContent = data.found_vulns;
                statCards[3].textContent = data.critical_vulns;
            }
        })
        .catch(error => {
            console.error('Error refreshing stats:', error);
        });
}
document.addEventListener("DOMContentLoaded", function() {
  const severityFilter = document.getElementById("severityFilter");
  const listItems = document.querySelectorAll(".list-item");

  severityFilter.addEventListener("change", function() {
    const selected = this.value;

    listItems.forEach(item => {
      const itemSeverity = item.dataset.severity;
      if (selected === "all" || itemSeverity === selected) {
        item.style.display = "";
      } else {
        item.style.display = "none";
      }
    });
  });
});

function toggleResolved(vulnId, isChecked) {
    fetch('/vuln/update-status', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            id: vulnId,
            resolved: isChecked
        })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('Sunucu hatası');
        }
        return response.json();
    })
    .then(data => {
        console.log('Durum güncellendi:', data);
    })
    .catch(error => {
        console.error('Hata oluştu:', error);
        alert('Güncelleme başarısız oldu.');
    });
}


// Refresh stats every 30 seconds
setInterval(refreshStats, 30000);