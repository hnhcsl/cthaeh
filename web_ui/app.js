document.addEventListener('DOMContentLoaded', () => {
    const driverList = document.getElementById('driver-list');
    const searchInput = document.getElementById('search-input');
    const riskFilter = document.getElementById('risk-filter');
    const modal = document.getElementById('driver-modal');
    const modalBody = document.getElementById('modal-body');
    const closeBtn = document.querySelector('.close-btn');

    let driversData = [];

    // Fetch the JSON data
    fetch('/triage_results.json')
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
        const analyzableFindings = [];

        if (driver.findings && driver.findings.length > 0) {
            findingsHtml = driver.findings.sort((a, b) => b.score - a.score).map((f, index) => {
                // Determine if finding has a recognizable IOCTL to analyze
                let ioctlCode = "Unknown";
                const match = f.detail.match(/0x[0-9a-fA-F]+/);
                if (match) {
                    ioctlCode = match[0];
                }

                // Show button for all findings except purely informative ones
                const skipChecks = ['vendor_cna_bounty', 'whql_signed_inbox', 'driver_class_info'];
                const canAnalyze = !skipChecks.includes(f.check);

                if (canAnalyze) {
                    analyzableFindings.push({ index, ioctlCode, check: f.check });
                }

                return `
                <div class="finding-item" style="position: relative;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div>
                            <span class="score">+${f.score}</span>
                            <strong>${f.check}</strong><br>
                            <span style="color: var(--text-secondary)">${f.detail}</span>
                        </div>
                        ${canAnalyze ? `<button class="ai-btn-small" id="btn-analyze-${index}" data-ioctl="${ioctlCode}">🧠 Analyze</button>` : ''}
                    </div>
                    
                    <!-- Per-finding AI Results Container (Hidden by default) -->
                    <div id="ai-container-${index}" class="ai-analysis-section" style="display: none; margin-top: 1rem; padding: 1rem; border-color: rgba(168, 85, 247, 0.2);">
                        <div id="ai-loading-${index}" class="ai-loading-container" style="display: none; padding: 1rem 0;">
                            <div class="spinner"></div>
                            <p id="ai-status-${index}" style="margin: 0; font-size: 0.9rem;">Waking agents for ${ioctlCode}...</p>
                        </div>
                        <div id="ai-results-${index}" style="display: none;">
                            <div class="ai-reverser-box" style="margin-bottom: 0.5rem;">
                                <h3 style="font-size: 0.9rem; margin-top: 0;">🕵️ Reverser Analysis</h3>
                                <pre id="reverser-output-${index}" style="font-size: 0.8rem; padding: 0.5rem;"></pre>
                            </div>
                            <div class="ai-exploiter-box">
                                <h3 style="font-size: 0.9rem; margin-top: 0;">💣 Exploiter PoC</h3>
                                <pre id="exploiter-output-${index}" class="code-block" style="font-size: 0.8rem; padding: 0.5rem;"></pre>
                            </div>
                        </div>
                    </div>
                </div>
                `;
            }).join('');
        }

        modalBody.innerHTML = `
            <div class="detail-header" style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div>
                    <h2 style="display: flex; align-items: center; gap: 1rem; flex-wrap: wrap;">
                        ${driver.driver.name}
                        ${analyzableFindings.length > 0 ? `<button id="ai-analyze-all-btn" class="ai-btn" style="font-size: 0.85rem; padding: 0.5rem 1rem;">⚡ Analyze All (${analyzableFindings.length})</button>` : ''}
                    </h2>
                    <div style="margin-top: 0.5rem;">
                        <span class="tag" style="background: var(--risk-${driver.priority.toLowerCase()})">${driver.priority} RISK</span>
                        <span class="tag">Score: ${driver.score}</span>
                        <span class="tag">${driver.driver_class ? driver.driver_class.category : 'Unknown Class'}</span>
                    </div>
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

        // Function to run analysis for a specific finding
        const runAnalysis = async (finding) => {
            const btn = document.getElementById(`btn-analyze-${finding.index}`);
            const container = document.getElementById(`ai-container-${finding.index}`);
            const loading = document.getElementById(`ai-loading-${finding.index}`);
            const statusTxt = document.getElementById(`ai-status-${finding.index}`);
            const results = document.getElementById(`ai-results-${finding.index}`);
            const revOut = document.getElementById(`reverser-output-${finding.index}`);
            const expOut = document.getElementById(`exploiter-output-${finding.index}`);

            if (btn) {
                btn.disabled = true;
                btn.textContent = '⏳ Analyzing...';
            }

            container.style.display = 'block';
            loading.style.display = 'flex';
            results.style.display = 'none';
            statusTxt.textContent = `Extracting & Analyzing ${finding.ioctlCode}...`;

            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        driver_path: driver.driver.path,
                        ioctl_code: finding.ioctlCode
                    })
                });

                const result = await response.json();

                loading.style.display = 'none';
                results.style.display = 'block';

                if (result.status === 'error') {
                    revOut.innerHTML = `<span style="color:red">Error: ${result.error}</span>`;
                    expOut.textContent = 'Aborted.';
                    if (btn) btn.textContent = '❌ Failed';
                    return;
                }

                revOut.textContent = result.reverser_analysis;

                if (result.vuln_exists) {
                    expOut.textContent = result.poc_code;
                    if (btn) btn.textContent = '🔥 Vuln Found';
                } else {
                    expOut.innerHTML = `<span style="color:var(--text-secondary)">False Positive. No actionable PoC generated.</span>`;
                    if (btn) btn.textContent = '🛡️ Safe';
                }

            } catch (err) {
                loading.style.display = 'none';
                if (btn) {
                    btn.disabled = false;
                    btn.textContent = '🔄 Retry';
                }
                alert("Backend error during analysis of " + finding.ioctlCode + ": " + err.message);
            }
        };

        // Attach event listeners to individual analyze buttons
        analyzableFindings.forEach(finding => {
            const btn = document.getElementById(`btn-analyze-${finding.index}`);
            if (btn) {
                btn.addEventListener('click', () => runAnalysis(finding));
            }
        });

        // Setup the Analyze All button
        const analyzeAllBtn = document.getElementById('ai-analyze-all-btn');
        if (analyzeAllBtn) {
            analyzeAllBtn.addEventListener('click', async () => {
                analyzeAllBtn.disabled = true;
                analyzeAllBtn.textContent = '⚡ Running Batch...';

                // Run them sequentially to avoid killing local GPU/CPU or hitting rate limits too hard
                for (const finding of analyzableFindings) {
                    const btn = document.getElementById(`btn-analyze-${finding.index}`);
                    // Only run if it hasn't been run yet (checking disabled state)
                    if (btn && !btn.disabled) {
                        await runAnalysis(finding);
                    }
                }

                analyzeAllBtn.textContent = '✅ Batch Complete';
            });
        }

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
