document.addEventListener('DOMContentLoaded', () => {
    const driverList = document.getElementById('driver-list');
    const searchInput = document.getElementById('search-input');
    const riskFilter = document.getElementById('risk-filter');
    const modal = document.getElementById('driver-modal');
    const modalBody = document.getElementById('modal-body');
    const closeBtn = document.querySelector('.close-btn');
    const langToggleBtn = document.getElementById('lang-toggle-btn');
    const settingsBtn = document.getElementById('settings-btn');
    const settingsModal = document.getElementById('settings-modal');
    const settingsCloseBtn = document.querySelector('.settings-close-btn');

    // Settings elements
    const aiProviderSelect = document.getElementById('ai-provider-select');
    const aiModelSelect = document.getElementById('ai-model-select');
    const aiApikeyInput = document.getElementById('ai-apikey-input');
    const settingsSaveBtn = document.getElementById('settings-save-btn');

    let driversData = [];
    let aiCache = {}; // Phase 4: In-memory cache for AI results

    // --- AI Configuration ---
    const defaultAiConfig = { provider: 'gemini', model: 'gemini-2.5-flash', apiKey: '' };
    let currentAiConfig = JSON.parse(localStorage.getItem('cthaeh_ai_config')) || defaultAiConfig;

    const providerModels = {
        gemini: [
            { id: 'gemini-2.5-flash', name: 'Gemini 2.5 Flash' },
            { id: 'gemini-2.5-pro', name: 'Gemini 2.5 Pro' }
        ],
        deepseek: [
            { id: 'deepseek-chat', name: 'DeepSeek V3 (Chat)' },
            { id: 'deepseek-reasoner', name: 'DeepSeek R1 (Reasoner)' }
        ],
        openai: [
            { id: 'gpt-4o', name: 'GPT-4o' },
            { id: 'gpt-4o-mini', name: 'GPT-4o Mini' }
        ]
    };

    // --- i18n Dictionary ---
    const translations = {
        en: {
            app_title: "🌳 Cthaeh <span>Driver Triage Dashboard</span>",
            app_subtitle: "Automated vulnerability assessment for Windows Kernel Drivers",
            stat_total: "Total Drivers",
            stat_high: "High Risk",
            stat_medium: "Medium Risk",
            stat_low: "Low Risk",
            search_placeholder: "Search by driver name, vendor, or path...",
            filter_all: "All Risk Levels",
            filter_critical: "Critical",
            filter_high: "High Risk",
            filter_medium: "Medium Risk",
            filter_low: "Low Risk",
            loading_results: "Loading triage results...",
            lang_toggle: "🌐 切换至中文",
            settings_btn: "⚙️ Settings",
            settings_title: "⚙️ AI Configuration",
            settings_provider: "AI Provider",
            settings_model: "Model",
            settings_apikey: "API Key",
            settings_save: "💾 Save Configuration",
            settings_saved_alert: "AI Configuration Saved!",
            modal_file_info: "File Information",
            modal_version_mani: "Version Manifest",
            modal_vuln_findings: "Vulnerability Findings",
            modal_no_indicators: "No specific vulnerability indicators triggered.",
            modal_verified_cna: "🛡️ Verified CNA Vendor: ",
            modal_bounty_prog: "This vendor has a vulnerability disclosure program.",
            modal_view_bounty: "View Bounty Program ↗",
            btn_analyze: "🧠 Analyze",
            btn_analyzing: "⏳ Analyzing...",
            btn_analyzed: "✅ Analyzed",
            btn_failed: "❌ Failed",
            waking_agents: "Waking agents for ",
            reverser_title: "🕵️ Reverser Analysis",
            exploiter_title: "💣 Exploiter PoC"
        },
        zh: {
            app_title: "🌳 Cthaeh <span>驱动漏洞分析看板</span>",
            app_subtitle: "Windows 内核驱动漏洞自动化评估工具",
            stat_total: "驱动总数",
            stat_high: "高危风险",
            stat_medium: "中度风险",
            stat_low: "低度风险",
            search_placeholder: "搜索驱动名称、厂商或路径...",
            filter_all: "所有风险等级",
            filter_critical: "极危",
            filter_high: "高风险",
            filter_medium: "中等风险",
            filter_low: "低风险",
            loading_results: "正在加载分诊结果...",
            lang_toggle: "🌐 Switch to English",
            settings_btn: "⚙️ 设置",
            settings_title: "⚙️ AI 模型配置",
            settings_provider: "AI 供应商",
            settings_model: "具体模型",
            settings_apikey: "API 密钥 (Key)",
            settings_save: "💾 保存配置",
            settings_saved_alert: "AI 配置已成功保存！",
            modal_file_info: "文件信息",
            modal_version_mani: "版本清单",
            modal_vuln_findings: "漏洞特征发现",
            modal_no_indicators: "未触发特定的漏洞特征指标。",
            modal_verified_cna: "🛡️ 认证的 CNA 厂商：",
            modal_bounty_prog: "该厂商拥有漏洞悬赏披露计划。",
            modal_view_bounty: "查看漏洞悬赏计划 ↗",
            btn_analyze: "🧠 AI分析",
            btn_analyzing: "⏳ 分析中...",
            btn_analyzed: "✅ 已分析",
            btn_failed: "❌ 分析失败",
            waking_agents: "正在唤醒AI Agent处理 ",
            reverser_title: "🕵️ 逆向Agent分析",
            exploiter_title: "💣 利用Agent生成PoC"
        }
    };

    let currentLang = localStorage.getItem('cthaeh_lang') || 'en';

    function setLanguage(lang) {
        currentLang = lang;
        localStorage.setItem('cthaeh_lang', lang);

        // Update all data-i18n elements
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            if (translations[lang][key]) {
                el.innerHTML = translations[lang][key];
            }
        });

        // Update placeholders
        document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
            const key = el.getAttribute('data-i18n-placeholder');
            if (translations[lang][key]) {
                el.setAttribute('placeholder', translations[lang][key]);
            }
        });

        // Update the toggle button text itself (special case)
        if (langToggleBtn) {
            langToggleBtn.innerHTML = translations[lang]['lang_toggle'];
        }
    }

    if (langToggleBtn) {
        langToggleBtn.addEventListener('click', () => {
            setLanguage(currentLang === 'en' ? 'zh' : 'en');
        });
    }

    // Initialize language on startup
    setLanguage(currentLang);

    // --- Settings Modal Logic ---
    function updateModelDropdown(provider, selectedModel) {
        aiModelSelect.innerHTML = '';
        const models = providerModels[provider] || [];
        models.forEach(m => {
            const opt = document.createElement('option');
            opt.value = m.id;
            opt.textContent = m.name;
            if (m.id === selectedModel) {
                opt.selected = true;
            }
            aiModelSelect.appendChild(opt);
        });
    }

    aiProviderSelect.addEventListener('change', (e) => {
        updateModelDropdown(e.target.value, null);
    });

    if (settingsBtn) {
        settingsBtn.addEventListener('click', () => {
            // Load current config into modal
            aiProviderSelect.value = currentAiConfig.provider;
            updateModelDropdown(currentAiConfig.provider, currentAiConfig.model);
            aiApikeyInput.value = currentAiConfig.apiKey;

            settingsModal.classList.add('active');
            document.body.style.overflow = 'hidden';
            setLanguage(currentLang); // Ensure translating dynamically generated items
        });
    }

    if (settingsCloseBtn) {
        settingsCloseBtn.addEventListener('click', () => {
            settingsModal.classList.remove('active');
            document.body.style.overflow = 'auto';
        });
    }

    if (settingsSaveBtn) {
        settingsSaveBtn.addEventListener('click', () => {
            currentAiConfig = {
                provider: aiProviderSelect.value,
                model: aiModelSelect.value,
                apiKey: aiApikeyInput.value.trim()
            };
            localStorage.setItem('cthaeh_ai_config', JSON.stringify(currentAiConfig));
            settingsModal.classList.remove('active');
            document.body.style.overflow = 'auto';
            alert(translations[currentLang]['settings_saved_alert'] || "AI Configuration Saved!");
        });
    }

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

                const cacheKey = `${driver.driver.path}_${ioctlCode}`;
                const cachedResult = aiCache[cacheKey];

                let analyzeBtnHtml = '';
                let containerStyle = 'display: none;';
                let initialResultsStyle = 'display: none;';
                let initialLoadingStyle = 'display: none;';

                if (canAnalyze) {
                    if (cachedResult) {
                        containerStyle = 'display: block;';
                        if (cachedResult.status === 'pending') {
                            analyzeBtnHtml = `<button id="btn-analyze-${index}" class="ai-btn-small" disabled style="margin-left: 1rem; opacity: 0.7; cursor: not-allowed;" data-i18n="btn_analyzing">⏳ Analyzing...</button>`;
                            initialLoadingStyle = 'display: flex;';

                            // We need a script to trigger translating the dynamic IOCTL text right away
                            setTimeout(() => {
                                const statusTxt = document.getElementById(`ai-status-${index}`);
                                if (statusTxt) {
                                    const displayName = ioctlCode === 'Unknown' ? f.check : ioctlCode;
                                    statusTxt.innerHTML = `<span data-i18n="waking_agents">${translations[currentLang]['waking_agents']}</span>${displayName}...`;
                                }
                            }, 0);

                        } else if (!cachedResult.error && cachedResult.status !== 'error') {
                            analyzeBtnHtml = `<button id="btn-analyze-${index}" class="ai-btn-small" title="Force Re-Analyze" style="margin-left: 1rem;" data-i18n="btn_analyzed">✅ Analyzed 🔄</button>`;
                            initialResultsStyle = 'display: block;';
                        } else {
                            analyzeBtnHtml = `<button id="btn-analyze-${index}" class="ai-btn-small" title="Retry Analysis" style="margin-left: 1rem;" data-i18n="btn_failed">❌ Failed</button>`;
                        }
                    } else {
                        analyzeBtnHtml = `<button id="btn-analyze-${index}" class="ai-btn-small" data-i18n="btn_analyze" style="margin-left: 1rem;">🧠 Analyze</button>`;
                    }
                }

                return `
                <div class="finding-item" style="position: relative;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                        <div>
                            <span class="score">+${f.score}</span>
                            <strong>${f.check}</strong><br>
                            <span style="color: var(--text-secondary)">${f.detail}</span>
                        </div>
                        ${analyzeBtnHtml}
                    </div>
                    
                    <!-- AI Analysis Container -->
                    <div id="ai-container-${index}" class="ai-analysis-section" style="${containerStyle} margin-top: 1rem; padding: 1rem; border-color: rgba(168, 85, 247, 0.2);">
                        <div id="ai-loading-${index}" class="ai-loading-container" style="${initialLoadingStyle} padding: 1rem 0;">
                            <div class="spinner"></div>
                            <p id="ai-status-${index}" style="margin: 0; font-size: 0.9rem;"><span data-i18n="waking_agents">Waking agents for </span>${ioctlCode}...</p>
                        </div>
                        <div id="ai-results-${index}" style="${initialResultsStyle}">
                            <div class="ai-reverser-box" style="margin-bottom: 0.5rem;">
                                <h3 style="font-size: 0.9rem; margin-top: 0;" data-i18n="reverser_title">🕵️ Reverser Analysis</h3>
                                <pre id="reverser-output-${index}" style="font-size: 0.8rem; padding: 0.5rem;">${cachedResult ? (cachedResult.reverser_analysis || '') : ''}</pre>
                            </div>
                            <div class="ai-exploiter-box">
                                <h3 style="font-size: 0.9rem; margin-top: 0;" data-i18n="exploiter_title">💣 Exploiter PoC</h3>
                                <pre id="exploiter-output-${index}" class="code-block" style="font-size: 0.8rem; padding: 0.5rem;">${cachedResult ? (cachedResult.poc_code || '') : ''}</pre>
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
                    <h3 data-i18n="modal_file_info">File Information</h3>
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
                    <h3 data-i18n="modal_version_mani">Version Manifest</h3>
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
                    <strong><span data-i18n="modal_verified_cna">🛡️ Verified CNA Vendor: </span>${vendor}</strong><br>
                    <span data-i18n="modal_bounty_prog">This vendor has a vulnerability disclosure program.</span><br>
                    ${driver.vendor_info.bounty_url && driver.vendor_info.bounty_url.startsWith('http') ? `<a href="${driver.vendor_info.bounty_url}" target="_blank" style="color: #38bdf8; text-decoration: none;" data-i18n="modal_view_bounty">View Bounty Program ↗</a>` : ''}
                </div>
            ` : ''}

            <h3><span data-i18n="modal_vuln_findings">Vulnerability Findings</span> (${driver.findings_count || 0})</h3>
            <div style="margin-top: 1rem;">
                ${findingsHtml || `<p data-i18n="modal_no_indicators">No specific vulnerability indicators triggered.</p>`}
            </div>
        `;

        // Function to run analysis for a specific finding
        const runAnalysis = async (finding, force = false) => {
            const cacheKey = `${driver.driver.path}_${finding.ioctlCode}`;

            // Re-query elements so closures don't hold stale DOM references
            const getFreshElements = () => {
                return {
                    btn: document.getElementById(`btn-analyze-${finding.index}`),
                    container: document.getElementById(`ai-container-${finding.index}`),
                    loading: document.getElementById(`ai-loading-${finding.index}`),
                    statusTxt: document.getElementById(`ai-status-${finding.index}`),
                    results: document.getElementById(`ai-results-${finding.index}`),
                    revOut: document.getElementById(`reverser-output-${finding.index}`),
                    expOut: document.getElementById(`exploiter-output-${finding.index}`)
                };
            };

            let els = getFreshElements();

            if (els.btn) {
                els.btn.disabled = true;
                els.btn.textContent = translations[currentLang]['btn_analyzing'];
            }

            if (els.container) els.container.style.display = 'block';
            if (els.loading) els.loading.style.display = 'flex';
            if (els.results) els.results.style.display = 'none';

            // UI Polish: Use finding check name if IOCTL is unknown
            const displayName = finding.ioctlCode === 'Unknown' ? finding.check : finding.ioctlCode;

            // Translate the static part, keeping the dynamic IOCTL code
            if (els.statusTxt) {
                els.statusTxt.innerHTML = `<span data-i18n="waking_agents">${translations[currentLang]['waking_agents']}</span>${displayName}...`;
            }

            try {
                // Check Cache first, unless force retry
                let result = force ? null : aiCache[cacheKey];

                if (!result || result.status === 'pending') {
                    // Lock state strictly in cache immediately
                    aiCache[cacheKey] = { status: 'pending' };

                    const response = await fetch('/api/analyze', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            driver_path: driver.driver.path,
                            ioctl_code: finding.ioctlCode,
                            language: currentLang,
                            ai_config: currentAiConfig
                        })
                    });
                    result = await response.json();
                }

                // VERY IMPORTANT: The modal might have been closed and re-opened while fetch was awaiting!
                // We MUST re-query the DOM IDs to get the currently appended ones.
                els = getFreshElements();

                // Store successful results
                if (!result.error && result.status !== "error") {
                    aiCache[cacheKey] = result;
                } else if (result.error || result.status === "error") {
                    // Update cache with error so UI knows it failed
                    aiCache[cacheKey] = result;
                }

                if (!els.container) return; // User closed modal and hasn't re-opened it, UI is gone but cache is saved.

                els.loading.style.display = 'none';
                els.results.style.display = 'block';

                if (result.error || result.status === "error") {
                    els.results.innerHTML = `<div style="color: #ef4444; padding: 1rem; border: 1px solid #7f1d1d; border-radius: 4px;">Backend error during analysis of ${finding.ioctlCode}: ${result.error || 'Unknown error'}</div>`;
                    if (els.btn) {
                        els.btn.disabled = false;
                        els.btn.textContent = translations[currentLang]['btn_failed'];
                    }
                } else {
                    els.revOut.innerHTML = marked.parse(result.reverser_analysis || "No analysis generated.");

                    if (result.vuln_exists && result.poc_code) {
                        els.expOut.parentElement.style.display = 'block';
                        els.expOut.textContent = result.poc_code;
                        hljs.highlightElement(els.expOut);
                    } else {
                        els.expOut.parentElement.style.display = 'none';
                    }

                    if (els.btn) {
                        els.btn.disabled = false;
                        els.btn.textContent = translations[currentLang]['btn_analyzed']; // Indicate done and clickable
                    }
                }

            } catch (err) {
                console.error("AI Analysis failed:", err);

                // Save error state so the user can retry later
                aiCache[cacheKey] = { status: 'error', error: err.message };

                els = getFreshElements();
                if (els.results) {
                    els.loading.style.display = 'none';
                    els.results.style.display = 'block';
                    els.results.innerHTML = `<div style="color: #ef4444; padding: 1rem; border: 1px solid #7f1d1d; border-radius: 4px;">Backend error during analysis of ${finding.ioctlCode}: ${err.message}</div>`;
                }
                if (els.btn) {
                    els.btn.disabled = false;
                    els.btn.textContent = translations[currentLang]['btn_failed'];
                }
            }
        };

        // Attach event listeners to individual analyze buttons
        analyzableFindings.forEach(finding => {
            const btn = document.getElementById(`btn-analyze-${finding.index}`);
            if (btn) {
                // If the user clicks manually, force a fresh request (bypass cache)
                btn.addEventListener('click', () => runAnalysis(finding, true));
            }
        });

        // Setup the Analyze All button
        const analyzeAllBtn = document.getElementById('ai-analyze-all-btn');
        if (analyzeAllBtn) {
            analyzeAllBtn.addEventListener('click', async () => {
                analyzeAllBtn.disabled = true;
                analyzeAllBtn.textContent = '⚡ Running Batch...';

                // Run them sequentially to avoid hitting rate limits too hard
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

        // Translate the newly injected modal content
        setLanguage(currentLang);

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
