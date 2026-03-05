document.addEventListener('DOMContentLoaded', () => {
    const driverList = document.getElementById('driver-list');
    const searchInput = document.getElementById('search-input');
    const riskFilter = document.getElementById('risk-filter');
    const modal = document.getElementById('driver-modal');
    const modalBody = document.getElementById('modal-body');
    const closeBtn = document.querySelector('.close-btn');

    let driversData = [];

    // Fetch the JSON data
    fetch('../triage_results.json')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            driversData = data.sort((a, b) => b.score - a.score);
            updateStats(driversData);
            renderDrivers(driversData);
        })
        .catch(error => {
            console.error('Error fetching data:', error);
            driverList.innerHTML = `<div class="loading" style="color:#ef4444">Error loading triage_results.json<br><small>Make sure you are running a local web server (e.g., python -m http.server).</small></div>`;
        });

    function cleanString(str) {
        if (!str) return 'Unknown';
        return str.replace(/^u"/, '').replace(/"$/, '').trim();
    }

    function updateStats(drivers) {
        document.getElementById('stat-total').textContent = drivers.length;

        let high = 0, med = 0, low = 0;
        drivers.forEach(d => {
            if (d.priority === 'CRITICAL' || d.priority === 'HIGH') high++;
            else if (d.priority === 'MEDIUM') med++;
            else low++;
        });

        document.getElementById('stat-high').textContent = high;
        document.getElementById('stat-medium').textContent = med;
        document.getElementById('stat-low').textContent = low;
    }

    function renderDrivers(drivers) {
        driverList.innerHTML = '';

        if (drivers.length === 0) {
            driverList.innerHTML = '<div style="grid-column: 1/-1; text-align: center; color: var(--text-secondary); padding: 3rem;">No drivers found matching your criteria.</div>';
            return;
        }

        drivers.forEach((driver, index) => {
            const card = document.createElement('div');
            card.className = 'driver-card';
            card.setAttribute('data-risk', driver.priority);
            card.style.animationDelay = `${min(index * 0.05, 0.5)}s`;

            const vendor = driver.vendor_info ? cleanString(driver.vendor_info.vendor_name) : 'Unknown Vendor';
            const isCna = driver.vendor_info && driver.vendor_info.is_cna;

            // Limit findings for preview
            const topFindings = driver.findings ? driver.findings.slice(0, 3) : [];
            const findingsHtml = topFindings.map(f => `<li>${f.detail.split(':')[0]} <span class="score" style="color:var(--risk-high)">+${f.score}</span></li>`).join('');

            const driverClass = driver.driver_class ? driver.driver_class.category : 'Unknown';

            card.innerHTML = `
                <div class="driver-header">
                    <div class="driver-name">${driver.driver.name}</div>
                    <div class="driver-score">${driver.score}</div>
                </div>
                <div class="driver-meta">
                    <div>Class: ${driverClass}</div>
                    <div class="vendor-badge ${isCna ? 'cna-badge' : ''}">${vendor} ${isCna ? '🛡️ (CNA)' : ''}</div>
                </div>
                ${topFindings.length > 0 ? `
                <div class="findings-summary">
                    <strong>Top Indicators:</strong>
                    <ul>${findingsHtml}</ul>
                </div>` : ''}
            `;

            card.addEventListener('click', () => openModal(driver));
            driverList.appendChild(card);
        });
    }

    function openModal(driver) {
        const vendor = driver.vendor_info ? cleanString(driver.vendor_info.vendor_name) : 'Unknown Vendor';
        const versionInfo = driver.driver.version_info || {};

        let findingsHtml = '';
        if (driver.findings && driver.findings.length > 0) {
            findingsHtml = driver.findings.sort((a, b) => b.score - a.score).map(f => `
                <div class="finding-item">
                    <span class="score">+${f.score}</span>
                    <strong>${f.check}</strong><br>
                    <span style="color: var(--text-secondary)">${f.detail}</span>
                </div>
            `).join('');
        }

        modalBody.innerHTML = `
            <div class="detail-header">
                <h2>${driver.driver.name}</h2>
                <div>
                    <span class="tag" style="background: var(--risk-${driver.priority.toLowerCase()})">${driver.priority} RISK</span>
                    <span class="tag">Score: ${driver.score}</span>
                    <span class="tag">${driver.driver_class ? driver.driver_class.category : 'Unknown Class'}</span>
                </div>
            </div>
            
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-bottom: 2rem;">
                <div>
                    <h3>File Information</h3>
                    <div class="code-block">
Path: ${driver.driver.path}
Size: ${(driver.driver.size / 1024).toFixed(2)} KB
Functions: ${driver.driver.function_count}
Strings: ${driver.string_count}
Imports: ${driver.import_count}
Language: ${driver.driver.language}
                    </div>
                </div>
                <div>
                    <h3>Version Manifest</h3>
                    <div class="code-block">
Product: ${cleanString(versionInfo.ProductName)}
Version: ${cleanString(versionInfo.FileVersion)}
Company: ${cleanString(versionInfo.CompanyName)}
Description: ${cleanString(versionInfo.FileDescription)}
                    </div>
                </div>
            </div>

            ${driver.vendor_info && driver.vendor_info.is_cna ? `
                <div style="margin-bottom: 2rem; border-left: 4px solid #ffd700; padding-left: 1rem; background: rgba(255, 215, 0, 0.1); padding: 1rem;">
                    <strong>🛡️ Verified CNA Vendor: ${vendor}</strong><br>
                    This vendor has a vulnerability disclosure program.<br>
                    <a href="${driver.vendor_info.bounty_url}" target="_blank" style="color: #38bdf8; text-decoration: none;">View Bounty Program ↗</a>
                </div>
            ` : ''}

            <h3>Vulnerability Findings (${driver.findings_count || 0})</h3>
            <div style="margin-top: 1rem;">
                ${findingsHtml || '<p>No specific vulnerability indicators triggered.</p>'}
            </div>
        `;

        modal.classList.add('active');
        document.body.style.overflow = 'hidden'; // Prevent background scrolling
    }

    closeBtn.addEventListener('click', () => {
        modal.classList.remove('active');
        document.body.style.overflow = 'auto';
    });

    window.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.remove('active');
            document.body.style.overflow = 'auto';
        }
    });

    // Filtering logic
    function filterDrivers() {
        const term = searchInput.value.toLowerCase();
        const risk = riskFilter.value;

        const filtered = driversData.filter(d => {
            const matchName = d.driver.name.toLowerCase().includes(term);
            const vendorName = d.vendor_info ? d.vendor_info.vendor_name.toLowerCase() : '';
            const matchVendor = vendorName.includes(term);

            const matchRisk = risk === 'ALL' || d.priority === risk;

            return (matchName || matchVendor) && matchRisk;
        });

        renderDrivers(filtered);
    }

    searchInput.addEventListener('input', filterDrivers);
    riskFilter.addEventListener('change', filterDrivers);

    // Helper
    function min(a, b) { return a < b ? a : b; }
});
