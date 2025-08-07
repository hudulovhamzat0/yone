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

        function closeModal() {
            modal.style.display = "none";
        }

        window.addEventListener("click", function (e) {
            if (e.target === modal) {
                closeModal();
            }
        });

        // Close button inside modal
        const closeBtn = modal.querySelector(".close-button");
        if (closeBtn) {
            closeBtn.addEventListener("click", closeModal);
        }
    }
});

function loadTerminalOutput() {
    fetch("/terminal-output")
        .then(res => res.json())
        .then(data => {
            document.getElementById("terminal-content").textContent = data.output;
        });
}

// Terminal sekmesine geçildiğinde çıktıyı göster
document.querySelector('[data-section="terminal"]').addEventListener("click", loadTerminalOutput);