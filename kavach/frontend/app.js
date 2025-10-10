document.addEventListener('DOMContentLoaded', () => {
    const loginContainer = document.getElementById('login-container');
    const dashboardContainer = document.getElementById('dashboard-container');
    const tokenInput = document.getElementById('token-input');
    const loginButton = document.getElementById('login-button');
    const loginError = document.getElementById('login-error');
    const tokenChip = document.getElementById('token-chip');
    const systemInfo = document.getElementById('system-info');
    const navLinks = document.querySelectorAll('.nav-link');
    const copyrightYear = document.getElementById('copyright-year');

    const toast = document.getElementById('toast');
    const logoutButton = document.getElementById('logout-button');
    const refreshStatusButton = document.getElementById('refresh-status');
    const editRulesButton = document.getElementById('edit-rules');
    const startHardeningButton = document.getElementById('start-hardening');
    const feedbackButton = document.getElementById('feedback-button');
    const viewReportsButton = document.getElementById('view-reports');
    const generateReportButton = document.getElementById('generate-report');
    const saveRulesButton = document.getElementById('save-rules');
    const importRulesButton = document.getElementById('import-rules');
    const importFileInput = document.getElementById('import-file');
    const submitFeedbackButton = document.getElementById('submit-feedback');

    // Hardening section buttons
    const levelButtons = document.querySelectorAll('.level-button');
    const startHardeningJobButton = document.getElementById('start-hardening-job');
    const dryRunHardeningButton = document.getElementById('dry-run-hardening');
    const previewChangesButton = document.getElementById('preview-changes');
    
    // Rollback section buttons
    const rollbackLatestButton = document.getElementById('rollback-latest');
    const rollbackSelectedButton = document.getElementById('rollback-selected');
    const previewRollbackButton = document.getElementById('preview-rollback');

    const sections = document.querySelectorAll('[data-section]');
    const rulesTableBody = document.getElementById('rule-table-body');
    const reportsList = document.getElementById('reports-list');

    let apiToken = '';
    let lastRulesPayload = '';
    let cachedCheckpoints = [];

    copyrightYear.textContent = new Date().getFullYear().toString();

    // Helper function to make authenticated API calls
    function apiFetch(url, options = {}) {
        const defaultHeaders = {
            'X-Kavach-Token': apiToken
        };
        
        const mergedOptions = {
            ...options,
            headers: {
                ...defaultHeaders,
                ...(options.headers || {})
            }
        };
        
        return fetch(url, mergedOptions);
    }

    loginButton.addEventListener('click', () => {
        const token = tokenInput.value.trim();
        if (!token) {
            loginError.textContent = 'Please provide an access token.';
            return;
        }

        authenticate(token)
            .then(() => {
                apiToken = token;
                activateDashboard();
                loadDashboard();
                displayToast('Session established successfully.');
            })
            .catch((err) => {
                console.error('Authentication failed:', err);
                loginError.textContent = 'Invalid or expired token. Request a new token from the TUI.';
            });
    });

    logoutButton?.addEventListener('click', () => {
        apiToken = '';
        tokenInput.value = '';
        tokenChip.textContent = '';
        dashboardContainer.classList.add('hidden');
        loginContainer.classList.remove('hidden');
        displayToast('Signed out. Your session has been cleared.');
    });

    refreshStatusButton?.addEventListener('click', () => loadSystemStatus());

    editRulesButton?.addEventListener('click', () => {
        openModal('rules-modal');
        const rulesTextarea = document.getElementById('rules-json');
        if (!rulesTextarea) return;

        rulesTextarea.value = 'Loading current rules...';
        apiFetch('/api/rules')
            .then(response => {
                if (!response.ok) throw new Error('Failed to load rules');
                return response.json();
            })
            .then(rulesets => {
                // Pretty-print the JSON
                rulesTextarea.value = JSON.stringify(rulesets, null, 2);
                lastRulesPayload = rulesTextarea.value;
            })
            .catch(err => {
                console.error(err);
                rulesTextarea.value = 'Error: Could not load rules. Please check the console.';
                displayToast('Failed to load rules for editing.', 'error');
            });
    });
    feedbackButton?.addEventListener('click', () => openModal('feedback-modal'));

    startHardeningButton?.addEventListener('click', () => {
        // Navigate to hardening section where the user can select level and launch
        selectSection('hardening');
        displayToast('Select a hardening level and click "Launch Hardening" to begin.');
    });

    viewReportsButton?.addEventListener('click', () => selectSection('reports'));
    
    generateReportButton?.addEventListener('click', () => {
        const statusEl = document.getElementById('reports-status');
        statusEl.innerHTML = 'Generating compliance report...';
        displayToast('Generating PDF report. This may take a moment.', 'info');

        apiFetch('/api/reports/generate', {
            method: 'POST'
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => {
                    throw new Error(err.detail || 'Failed to generate report');
                });
            }
            return response.blob();
        })
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            // Name the file
            const date = new Date().toISOString().split('T')[0];
            const filename = `Kavach-Compliance-Report-${date}.pdf`;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            
            // Store report info in localStorage
            localStorage.setItem('kavach_last_report', filename);
            localStorage.setItem('kavach_last_report_time', new Date().toISOString());
            
            statusEl.innerHTML = 'Report generated and download started.';
            displayToast('Report downloaded successfully.', 'success');
            hydrateReports(); // Refresh the list
        })
        .catch(err => {
            console.error('Report generation failed', err);
            statusEl.innerHTML = `Failed to generate report: ${err.message}`;
            displayToast(`Error: ${err.message}`, 'error');
        });
    });

    saveRulesButton?.addEventListener('click', () => {
        const rulesTextarea = document.getElementById('rules-json');
        if (!rulesTextarea) return;

        const newRulesPayload = rulesTextarea.value.trim();
        try {
            // Validate JSON before sending
            JSON.parse(newRulesPayload);
        } catch (e) {
            displayToast('Invalid JSON format. Please correct and try again.', 'error');
            return;
        }

        if (newRulesPayload === lastRulesPayload) {
            displayToast('No changes detected in the rules.', 'info');
            closeAllModals();
            return;
        }

        displayToast('Saving updated rules...', 'info');

        apiFetch('/api/rules', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: newRulesPayload
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => {
                    throw new Error(err.detail || 'Failed to save rules');
                });
            }
            return response.json();
        })
        .then(data => {
            displayToast(data.message || 'Rules saved successfully.', 'success');
            lastRulesPayload = newRulesPayload;
            loadRules(); // Refresh the rules table
            closeAllModals();
        })
        .catch(err => {
            displayToast(`Error: ${err.message}`, 'error');
        });
    });

    importRulesButton?.addEventListener('click', () => importFileInput?.click());

    importFileInput?.addEventListener('change', (event) => {
        const file = event.target?.files?.[0];
        if (!file) return;

        file.text()
            .then((content) => {
                const textarea = document.getElementById('rules-json');
                if (textarea) {
                    textarea.value = content;
                    displayToast(`Imported ${file.name}`);
                }
            })
            .catch((err) => {
                console.error('Failed to read file', err);
                displayToast('Could not read the selected file.', true);
            });
    });

    submitFeedbackButton?.addEventListener('click', () => {
        const feedbackText = document.getElementById('feedback-text');
        if (feedbackText && feedbackText.value.trim()) {
            displayToast('Thank you for your feedback! We will review it shortly.');
            feedbackText.value = '';
            closeAllModals();
        } else {
            displayToast('Please provide feedback before submitting.', true);
        }
    });

    // Hardening section button handlers
    levelButtons.forEach(button => {
        button.addEventListener('click', () => {
            // Remove 'selected' class from all buttons
            levelButtons.forEach(btn => btn.classList.remove('selected'));
            // Add 'selected' class only to the clicked button
            button.classList.add('selected');
            const level = button.getAttribute('data-level');
            displayToast(`Selected ${level} hardening level`);
        });
    });

    startHardeningJobButton?.addEventListener('click', () => {
        const selectedLevel = document.querySelector('.level-button.selected');
        const level = selectedLevel?.getAttribute('data-level') || 'moderate';
        const statusEl = document.getElementById('hardening-status');
        statusEl.innerHTML = `Starting ${level} hardening job...`;
        apiFetch('/api/apply', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ level, dry_run: false })
        })
        .then(res => res.ok ? res.json() : Promise.reject(res))
        .then(data => {
            statusEl.innerHTML = data?.message || `Hardening job triggered (${level}).`;
            displayToast(`Launched ${level} hardening job.`);
            loadCheckpoints();
        })
        .catch(err => {
            console.error('Apply failed', err);
            statusEl.innerHTML = 'Failed to start hardening.';
            displayToast('Failed to start hardening.', true);
        });
    });

    dryRunHardeningButton?.addEventListener('click', () => {
        const selectedLevel = document.querySelector('.level-button.selected');
        const level = selectedLevel?.getAttribute('data-level') || 'moderate';
        const statusEl = document.getElementById('hardening-status');
        statusEl.innerHTML = `Running ${level} hardening dry-run...`;
        apiFetch('/api/apply', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ level, dry_run: true })
        })
        .then(res => res.ok ? res.json() : Promise.reject(res))
        .then(data => {
            statusEl.innerHTML = data?.message || `Dry-run completed for ${level}.`;
            displayToast(`Dry-run started for ${level}.`);
        })
        .catch(err => {
            console.error('Dry-run failed', err);
            statusEl.innerHTML = 'Dry-run failed.';
            displayToast('Dry-run failed.', true);
        });
    });

    previewChangesButton?.addEventListener('click', () => {
        const selectedLevel = document.querySelector('.level-button.selected');
        const level = selectedLevel?.getAttribute('data-level') || 'moderate';
        
        displayToast(`Loading preview for ${level} level...`, 'info');
        
        // Fetch rules and filter by level to show what will be affected
        apiFetch('/api/rules')
            .then(response => response.json())
            .then(rulesets => {
                let affectedRules = [];
                const levelPriority = { 'basic': 0, 'moderate': 1, 'strict': 2 };
                const targetPriority = levelPriority[level];
                
                rulesets.forEach(ruleset => {
                    ruleset.rules.forEach(rule => {
                        if (levelPriority[rule.level] <= targetPriority) {
                            affectedRules.push({
                                id: rule.id,
                                title: rule.title,
                                level: rule.level,
                                description: rule.description
                            });
                        }
                    });
                });
                
                // Create preview modal content
                const previewContent = `
                    <div style="max-height: 400px; overflow-y: auto;">
                        <p><strong>${affectedRules.length} rules</strong> will be evaluated and applied at <strong>${level}</strong> level:</p>
                        <ul style="list-style: none; padding: 0;">
                            ${affectedRules.map(rule => `
                                <li style="padding: 8px; margin: 4px 0; background: var(--surface-muted); border-radius: 4px;">
                                    <strong>${rule.id}</strong> (${rule.level})<br>
                                    <small>${rule.title}</small>
                                </li>
                            `).join('')}
                        </ul>
                        <p style="margin-top: 16px; color: var(--text-muted);">
                            <strong>Note:</strong> Checkpoints will be created before applying changes. You can rollback if needed.
                        </p>
                    </div>
                `;
                
                // Show in a simple alert (you can enhance this with a proper modal later)
                const previewDiv = document.createElement('div');
                previewDiv.innerHTML = previewContent;
                previewDiv.style.cssText = 'position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: var(--surface); padding: 24px; border-radius: 16px; box-shadow: var(--shadow-lg); z-index: 1001; max-width: 600px; width: 90%;';
                
                const backdrop = document.createElement('div');
                backdrop.style.cssText = 'position: fixed; inset: 0; background: rgba(15, 23, 42, 0.6); z-index: 1000;';
                backdrop.onclick = () => {
                    document.body.removeChild(previewDiv);
                    document.body.removeChild(backdrop);
                };
                
                const closeBtn = document.createElement('button');
                closeBtn.textContent = 'Close';
                closeBtn.className = 'primary';
                closeBtn.style.marginTop = '16px';
                closeBtn.onclick = backdrop.onclick;
                previewDiv.appendChild(closeBtn);
                
                document.body.appendChild(backdrop);
                document.body.appendChild(previewDiv);
            })
            .catch(err => {
                console.error('Failed to load preview', err);
                displayToast('Failed to load change preview.', 'error');
            });
    });

    // Rollback section button handlers
    rollbackLatestButton?.addEventListener('click', () => {
        const statusEl = document.getElementById('rollback-status');
        statusEl.innerHTML = 'Fetching latest checkpoint...';
        
        // First, get the list of checkpoints to find the latest one
        apiFetch('/api/checkpoints')
            .then(res => res.ok ? res.json() : Promise.reject(res))
            .then(checkpoints => {
                if (!checkpoints || checkpoints.length === 0) {
                    statusEl.innerHTML = 'No checkpoints available for rollback.';
                    displayToast('No checkpoints found.', 'error');
                    return;
                }
                
                // Get the latest checkpoint (last in the array)
                const latestCheckpoint = checkpoints[checkpoints.length - 1];
                statusEl.innerHTML = `Initiating rollback to latest checkpoint (${latestCheckpoint.id})...`;
                
                // Now rollback using the checkpoint ID
                return apiFetch(`/api/rollback/${latestCheckpoint.id}`, { method: 'POST' });
            })
            .then(res => {
                if (!res) return; // No checkpoint case
                return res.ok ? res.json() : Promise.reject(res);
            })
            .then(data => {
                if (!data) return; // No checkpoint case
                statusEl.innerHTML = data?.message || 'Rollback to latest checkpoint completed.';
                displayToast('Rollback to latest checkpoint successful.', 'success');
                loadCheckpoints(); // Refresh the list
            })
            .catch(err => {
                console.error('Rollback failed', err);
                statusEl.innerHTML = 'Rollback failed.';
                displayToast('Rollback to latest checkpoint failed.', 'error');
            });
    });

    // This is handled by the global window.selectCheckpoint function now
    // rollbackSelectedButton?.addEventListener('click', () => {
    //     displayToast('Please select a checkpoint first.');
    // });

    previewRollbackButton?.addEventListener('click', () => {
        displayToast('Loading rollback preview...', 'info');
        
        // Fetch checkpoints and show details
        apiFetch('/api/checkpoints')
            .then(response => response.json())
            .then(checkpoints => {
                if (!checkpoints || checkpoints.length === 0) {
                    displayToast('No checkpoints available to preview.', 'error');
                    return;
                }
                
                // Create preview modal content
                const previewContent = `
                    <div style="max-height: 400px; overflow-y: auto;">
                        <p><strong>${checkpoints.length} checkpoint(s)</strong> available for rollback:</p>
                        <ul style="list-style: none; padding: 0;">
                            ${checkpoints.map((cp, idx) => `
                                <li style="padding: 12px; margin: 8px 0; background: var(--surface-muted); border-radius: 8px; ${idx === checkpoints.length - 1 ? 'border: 2px solid var(--primary);' : ''}">
                                    <div style="display: flex; justify-content: space-between; align-items: center;">
                                        <div>
                                            <strong>${cp.id}</strong>
                                            ${idx === checkpoints.length - 1 ? '<span style="color: var(--primary); margin-left: 8px;">(Latest)</span>' : ''}
                                            <br>
                                            <small>Rule: ${cp.rule_id}</small><br>
                                            <small>Time: ${cp.timestamp || 'N/A'}</small>
                                        </div>
                                    </div>
                                </li>
                            `).join('')}
                        </ul>
                        <p style="margin-top: 16px; color: var(--text-muted);">
                            <strong>Note:</strong> Rolling back will restore system state to when the checkpoint was created. Manual verification is recommended after rollback.
                        </p>
                    </div>
                `;
                
                // Show in a preview modal
                const previewDiv = document.createElement('div');
                previewDiv.innerHTML = previewContent;
                previewDiv.style.cssText = 'position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: var(--surface); padding: 24px; border-radius: 16px; box-shadow: var(--shadow-lg); z-index: 1001; max-width: 600px; width: 90%;';
                
                const backdrop = document.createElement('div');
                backdrop.style.cssText = 'position: fixed; inset: 0; background: rgba(15, 23, 42, 0.6); z-index: 1000;';
                backdrop.onclick = () => {
                    document.body.removeChild(previewDiv);
                    document.body.removeChild(backdrop);
                };
                
                const closeBtn = document.createElement('button');
                closeBtn.textContent = 'Close';
                closeBtn.className = 'primary';
                closeBtn.style.marginTop = '16px';
                closeBtn.onclick = backdrop.onclick;
                previewDiv.appendChild(closeBtn);
                
                document.body.appendChild(backdrop);
                document.body.appendChild(previewDiv);
            })
            .catch(err => {
                console.error('Failed to load rollback preview', err);
                displayToast('Failed to load rollback preview.', 'error');
            });
    });

    document.querySelectorAll('[data-close-modal]').forEach((btn) => {
        btn.addEventListener('click', () => closeAllModals());
    });

    navLinks.forEach((link) => {
        link.addEventListener('click', () => {
            const section = link.getAttribute('data-section');
            if (!section) return;
            selectSection(section);
        });
    });

    function authenticate(token) {
        return apiFetch('/api/status', {
            headers: { 'X-Kavach-Token': token }
        }).then((response) => {
            if (!response.ok) {
                throw new Error(`Status ${response.status}`);
            }
            return response.json();
        });
    }

    function activateDashboard() {
        loginContainer.classList.add('hidden');
        dashboardContainer.classList.remove('hidden');
        tokenChip.textContent = formatToken(apiToken);
        selectSection('overview');
    }

    function loadDashboard() {
        loadSystemStatus();
        loadRules();
        loadCheckpoints();
        hydrateReports();
        updateSummaryPlaceholders();
    }

    function loadSystemStatus() {
        if (!apiToken) return;
        apiFetch('/api/status')
            .then((response) => response.json())
            .then((data) => renderSystemInfo(data.system_info))
            .catch((err) => {
                console.error('Failed to load system status', err);
                systemInfo.innerHTML = '<div class="placeholder">Unable to retrieve host details.</div>';
            });
    }

    function loadRules() {
        if (!apiToken) return;
        apiFetch('/api/rules')
            .then((response) => {
                if (!response.ok) {
                    throw new Error(`Status ${response.status}`);
                }
                return response.json();
            })
            .then((rulesets) => {
                renderRulesTable(rulesets);
                updateSummaryFromRules(rulesets);
            })
            .catch(() => {
                renderRulesTable();
            });
    }

    function loadCheckpoints() {
        if (!apiToken) return;
        apiFetch('/api/checkpoints')
            .then((response) => {
                if (!response.ok) {
                    throw new Error('Failed to load checkpoints');
                }
                return response.json();
            })
            .then((checkpoints) => {
                cachedCheckpoints = Array.isArray(checkpoints) ? checkpoints : [];
                renderRollbackCheckpointList(checkpoints);
            })
            .catch(() => {
                const rollbackCheckpointList = document.getElementById('rollback-checkpoint-list');
                if (rollbackCheckpointList) {
                    rollbackCheckpointList.innerHTML = '<div class="placeholder">Unable to load checkpoints.</div>';
                }
            });
    }

    function hydrateReports() {
        const reportsListEl = document.getElementById('reports-list');
        if (!reportsListEl) return;
        
        // Show loading state
        reportsListEl.innerHTML = '<div class="placeholder">Loading reports...</div>';
        
        // Get the report output directory from backend
        // Since the backend doesn't expose a list endpoint, we'll show instructions
        // and the last generated report info from localStorage if available
        
        const lastReport = localStorage.getItem('kavach_last_report');
        const lastReportTime = localStorage.getItem('kavach_last_report_time');
        
        if (lastReport && lastReportTime) {
            const reportDate = new Date(lastReportTime);
            reportsListEl.innerHTML = `
                <div class="card" style="margin-bottom: 12px;">
                    <h3>Recent Report</h3>
                    <p><strong>Last Generated:</strong> ${reportDate.toLocaleString()}</p>
                    <p><strong>Filename:</strong> ${lastReport}</p>
                    <p style="color: var(--text-muted); font-size: 0.9rem;">
                        Reports are saved to <code>~/.kavach/reports/</code> directory.
                    </p>
                </div>
                <div class="placeholder" style="margin-top: 16px;">
                    Click "Generate PDF" to create a new compliance report. The report will be downloaded automatically.
                </div>
            `;
        } else {
            reportsListEl.innerHTML = `
                <div class="placeholder">
                    No reports generated yet. Click "Generate PDF" to create your first compliance report.
                    Reports are saved to <code>~/.kavach/reports/</code> and will be downloaded automatically.
                </div>
            `;
        }
    }

    function updateSummaryPlaceholders() {
        document.getElementById('compliance-score').textContent = '0%';
        document.getElementById('compliance-trend').textContent = 'Loading compliance data...';
        document.getElementById('ruleset-count').textContent = '--';
        document.getElementById('ruleset-detail').textContent = 'Loading rule packs...';
        document.getElementById('last-hardened').textContent = '--';
        document.getElementById('last-hardened-detail').textContent = 'No jobs recorded';
        document.getElementById('open-actions').textContent = '0';
        document.getElementById('open-actions-detail').textContent = 'No pending follow-ups';
    }

    function updateSummaryFromRules(rulesets = []) {
        if (!Array.isArray(rulesets) || rulesets.length === 0) return;
        const totalRules = rulesets.reduce((count, set) => count + (set.rules?.length || 0), 0);
        document.getElementById('ruleset-count').textContent = rulesets.length.toString();
        document.getElementById('ruleset-detail').textContent = `${totalRules} rules across ${rulesets.length} modules`;
        
        // Calculate compliance by fetching rule statuses
        apiFetch('/api/rules/status')
            .then(response => response.json())
            .then(statuses => {
                const appliedRules = Object.values(statuses).filter(status => status).length;
                const compliancePercent = totalRules > 0 ? Math.round((appliedRules / totalRules) * 100) : 0;
                document.getElementById('compliance-score').textContent = `${compliancePercent}%`;
                document.getElementById('compliance-trend').textContent = totalRules > 0 ? 
                    `${appliedRules} of ${totalRules} rules compliant` : 'No rules loaded';
            })
            .catch(() => {
                document.getElementById('compliance-score').textContent = 'Error';
                document.getElementById('compliance-trend').textContent = 'Could not load compliance status';
            });
    }

    function renderSystemInfo(info = {}) {
        const system = (info.system || '').toLowerCase();

        const base = [
            { label: 'Operating system', value: info.system || 'Unknown' },
            { label: 'Release', value: info.release || '—' },
            { label: 'Version', value: info.version || '—' }
        ];

        const extras = [];
        if (system === 'linux') {
            if (info.distro_name || info.distro_id) {
                extras.push({ label: 'Distribution', value: info.distro_name || info.distro_id });
            }
            if (info.distro_version) {
                extras.push({ label: 'Distro version', value: info.distro_version });
            }
        } else if (system === 'windows') {
            if (info.windows_edition) {
                extras.push({ label: 'Windows edition', value: info.windows_edition });
            }
            if (info.windows_version) {
                extras.push({ label: 'Windows version', value: info.windows_version });
            }
        }

        const entries = [...base, ...extras];
        systemInfo.innerHTML = entries
            .map((entry) => `
                <div>
                    <div class="metric-label">${entry.label}</div>
                    <div class="metric-value" style="font-size:1.2rem">${entry.value}</div>
                </div>
            `)
            .join('');
    }

    function renderRulesTable(rulesets) {
        if (!rulesets || rulesets.length === 0) {
            rulesTableBody.innerHTML = `
                <tr>
                    <td colspan="4" class="placeholder">
                        No rule packs loaded. Upload a JSON pack from the CLI or APIs.
                    </td>
                </tr>
            `;
            return;
        }

        // Fetch rule statuses and then render
        apiFetch('/api/rules/status')
            .then(response => response.json())
            .then(statuses => {
                const rows = [];
                rulesets.forEach((set) => {
                    (set.rules || []).forEach((rule) => {
                        const isCompliant = statuses[rule.id] || false;
                        const statusClass = isCompliant ? 'status-chip--success' : 'status-chip--pending';
                        const statusText = isCompliant ? 'Compliant' : 'Pending';
                        
                        rows.push(`
                            <tr>
                                <td>${rule.id}</td>
                                <td>${rule.title}</td>
                                <td>${rule.level}</td>
                                <td><span class="status-chip ${statusClass}">${statusText}</span></td>
                            </tr>
                        `);
                    });
                });
                rulesTableBody.innerHTML = rows.join('');
            })
            .catch(err => {
                console.error('Failed to fetch rule statuses', err);
                // Fallback to showing pending status
                const rows = [];
                rulesets.forEach((set) => {
                    (set.rules || []).forEach((rule) => {
                        rows.push(`
                            <tr>
                                <td>${rule.id}</td>
                                <td>${rule.title}</td>
                                <td>${rule.level}</td>
                                <td><span class="status-chip status-chip--pending">Unknown</span></td>
                            </tr>
                        `);
                    });
                });
                rulesTableBody.innerHTML = rows.join('');
            });
    }

    function renderRollbackCheckpointList(checkpoints = []) {
        const rollbackCheckpointList = document.getElementById('rollback-checkpoint-list');
        if (!rollbackCheckpointList) return;

        if (!Array.isArray(checkpoints) || checkpoints.length === 0) {
            rollbackCheckpointList.innerHTML = '<div class="placeholder">No checkpoints available. Checkpoints are created automatically when hardening rules are applied.</div>';
            return;
        }

        rollbackCheckpointList.innerHTML = checkpoints
            .map((checkpoint, index) => `
                <div class="card checkpoint-item" style="margin-bottom: 12px; cursor: pointer; border: 2px solid var(--border);" 
                     data-checkpoint-id="${checkpoint.id}" onclick="selectCheckpoint(this, '${checkpoint.id}')">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <div class="metric-label">${index === 0 ? 'Latest Checkpoint' : `Checkpoint #${checkpoints.length - index}`}</div>
                            <div class="metric-value" style="font-size: 1.1rem;">${checkpoint.id}</div>
                            <div class="metric-trend">${checkpoint.timestamp || 'Timestamp pending'}</div>
                        </div>
                        <div class="status-chip ${index === 0 ? 'status-chip--success' : ''}">${index === 0 ? 'Latest' : 'Available'}</div>
                    </div>
                </div>
            `)
            .join('');
    }

    function openModal(id) {
        const modal = document.getElementById(id);
        if (modal) {
            modal.classList.remove('hidden');
        }
    }

    function closeAllModals() {
        document.querySelectorAll('.modal').forEach((modal) => modal.classList.add('hidden'));
    }

    function selectSection(activeSection) {
        navLinks.forEach((link) => {
            const section = link.getAttribute('data-section');
            link.classList.toggle('active', section === activeSection);
        });

        sections.forEach((section) => {
            const sectionId = section.getAttribute('data-section');
            if (sectionId === activeSection) {
                section.removeAttribute('hidden');
                
                // Initialize section-specific defaults
                if (activeSection === 'hardening') {
                    const moderateButton = document.querySelector('.level-button[data-level="moderate"]');
                    if (moderateButton && !document.querySelector('.level-button.selected')) {
                        moderateButton.classList.add('selected');
                    }
                }
            } else if (section.hasAttribute('hidden') === false) {
                section.setAttribute('hidden', 'true');
            }
        });
    }

    function displayToast(message, type = 'info') { // type: 'info', 'success', 'error'
        if (!toast) return;
        toast.textContent = message;
        
        const colors = {
            info: 'var(--border)',
            success: 'rgba(34, 197, 94, 0.4)',
            error: 'rgba(220, 38, 38, 0.4)'
        };

        toast.style.borderColor = colors[type] || colors.info;
        toast.classList.remove('hidden');
        
        setTimeout(() => {
            toast.classList.add('hidden');
        }, 3800);
    }

    function formatToken(token) {
        if (!token || token.length < 8) return 'Session active';
        return `${token.slice(0, 4)}…${token.slice(-4)}`;
    }

    // Allow dismissing modals by clicking the backdrop
    document.querySelectorAll('.modal').forEach((modal) => {
        modal.addEventListener('click', (event) => {
            if (event.target === modal) {
                closeAllModals();
            }
        });
    });

    // Global function for checkpoint selection
    window.selectCheckpoint = function(element, checkpointId) {
        document.querySelectorAll('.checkpoint-item').forEach(item => {
            item.style.borderColor = 'var(--border)';
            item.style.backgroundColor = 'var(--surface)';
        });
        
        element.style.borderColor = 'var(--primary)';
        element.style.backgroundColor = 'var(--primary-soft)';
        
        const rollbackSelectedButton = document.getElementById('rollback-selected');
        if (rollbackSelectedButton) {
            rollbackSelectedButton.disabled = false;
            rollbackSelectedButton.onclick = () => {
                const statusEl = document.getElementById('rollback-status');
                statusEl.innerHTML = `Initiating rollback to checkpoint ${checkpointId}...`;
                
                apiFetch(`/api/rollback/${checkpointId}`, { method: 'POST' })
                    .then(res => res.ok ? res.json() : Promise.reject(res))
                    .then(data => {
                        statusEl.innerHTML = data?.message || `Rollback to ${checkpointId} completed.`;
                        displayToast(`Rollback to ${checkpointId} successful.`, 'success');
                        loadCheckpoints(); // Refresh list
                    })
                    .catch(err => {
                        console.error('Rollback failed', err);
                        statusEl.innerHTML = 'Rollback failed.';
                        displayToast(`Rollback to ${checkpointId} failed.`, 'error');
                    });
            };
        }
    };
});
