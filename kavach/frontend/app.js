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
    const rollbackButton = document.getElementById('rollback');
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
    const checkpointList = document.getElementById('checkpoint-list');

    let apiToken = '';
    let lastRulesPayload = '';

    copyrightYear.textContent = new Date().getFullYear().toString();

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

    editRulesButton?.addEventListener('click', () => openModal('rules-modal'));
    feedbackButton?.addEventListener('click', () => openModal('feedback-modal'));

    startHardeningButton?.addEventListener('click', () => {
        displayToast('Hardening jobs can be launched from the CLI or upcoming backend workflows.');
    });

    rollbackButton?.addEventListener('click', () => {
        displayToast('Rollback requires selecting a checkpoint. This action will be available soon.');
    });

    viewReportsButton?.addEventListener('click', () => selectSection('reports'));
    generateReportButton?.addEventListener('click', () => {
        displayToast('Report generation is queued. Check the Reports tab for updates.');
    });

    saveRulesButton?.addEventListener('click', () => {
        const rulesTextarea = document.getElementById('rules-json');
        if (!rulesTextarea) return;

        lastRulesPayload = rulesTextarea.value.trim();
        displayToast('Rule pack updates captured locally. Submit via CLI/API to persist.');
        closeAllModals();
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
            levelButtons.forEach(btn => btn.classList.remove('selected'));
            button.classList.add('selected');
            const level = button.getAttribute('data-level');
            displayToast(`Selected ${level} hardening level`);
        });
    });

    startHardeningJobButton?.addEventListener('click', () => {
        const selectedLevel = document.querySelector('.level-button.selected');
        const level = selectedLevel?.getAttribute('data-level') || 'moderate';
        document.getElementById('hardening-status').innerHTML = `Starting ${level} hardening job...`;
        displayToast(`Launching ${level} hardening job. Check CLI for detailed progress.`);
    });

    dryRunHardeningButton?.addEventListener('click', () => {
        const selectedLevel = document.querySelector('.level-button.selected');
        const level = selectedLevel?.getAttribute('data-level') || 'moderate';
        document.getElementById('hardening-status').innerHTML = `Running ${level} hardening dry-run...`;
        displayToast(`Starting ${level} dry-run. No changes will be applied.`);
    });

    previewChangesButton?.addEventListener('click', () => {
        displayToast('Change preview will show affected rules and system modifications.');
    });

    // Rollback section button handlers  
    rollbackLatestButton?.addEventListener('click', () => {
        document.getElementById('rollback-status').innerHTML = 'Initiating rollback to latest checkpoint...';
        displayToast('Rolling back to the most recent checkpoint.');
    });

    rollbackSelectedButton?.addEventListener('click', () => {
        displayToast('Please select a checkpoint first.');
    });

    previewRollbackButton?.addEventListener('click', () => {
        displayToast('Rollback preview will show what changes will be reverted.');
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
        return fetch('/api/status', {
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
        fetch('/api/status', {
            headers: { 'X-Kavach-Token': apiToken }
        })
            .then((response) => response.json())
            .then((data) => renderSystemInfo(data.system_info))
            .catch((err) => {
                console.error('Failed to load system status', err);
                systemInfo.innerHTML = '<div class="placeholder">Unable to retrieve host details.</div>';
            });
    }

    function loadRules() {
        if (!apiToken) return;
        fetch('/api/rules', {
            headers: { 'X-Kavach-Token': apiToken }
        })
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
        fetch('/api/checkpoints', {
            headers: { 'X-Kavach-Token': apiToken }
        })
            .then((response) => {
                if (!response.ok) {
                    throw new Error('Failed to load checkpoints');
                }
                return response.json();
            })
            .then((checkpoints) => {
                renderCheckpointList(checkpoints);
                renderRollbackCheckpointList(checkpoints);
            })
            .catch(() => {
                checkpointList.innerHTML = '<div class="placeholder">Unable to load checkpoints.</div>';
                const rollbackCheckpointList = document.getElementById('rollback-checkpoint-list');
                if (rollbackCheckpointList) {
                    rollbackCheckpointList.innerHTML = '<div class="placeholder">Unable to load checkpoints.</div>';
                }
            });
    }

    function hydrateReports() {
        reportsList.innerHTML = `
            <div class="placeholder">
                Reports will appear here once generated. Use the CLI or future backend workflows to export compliance PDFs.
            </div>
        `;
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
        
        // Calculate compliance - for now, assume 0% since no rules have been applied yet
        // In real implementation, this would check rule status from backend
        const appliedRules = 0; // TODO: Get from actual rule status API
        const compliancePercent = totalRules > 0 ? Math.round((appliedRules / totalRules) * 100) : 0;
        document.getElementById('compliance-score').textContent = `${compliancePercent}%`;
        document.getElementById('compliance-trend').textContent = totalRules > 0 ? 
            `${totalRules} rules loaded, ready for hardening` : 'No rules loaded';
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

        const rows = [];
        rulesets.forEach((set) => {
            (set.rules || []).forEach((rule) => {
                rows.push(`
                    <tr>
                        <td>${rule.id}</td>
                        <td>${rule.title}</td>
                        <td>${rule.level}</td>
                        <td><span class="status-chip status-chip--pending">Pending</span></td>
                    </tr>
                `);
            });
        });

        rulesTableBody.innerHTML = rows.join('');
    }

    function renderCheckpointList(checkpoints = []) {
        if (!Array.isArray(checkpoints) || checkpoints.length === 0) {
            checkpointList.innerHTML = '<div class="placeholder">No checkpoints available yet.</div>';
            return;
        }

        checkpointList.innerHTML = checkpoints
            .map((checkpoint) => `
                <div class="card" style="margin-bottom: 16px;">
                    <div class="metric-label">Checkpoint ID</div>
                    <div class="metric-value" style="font-size:1.4rem">${checkpoint.id}</div>
                    <div class="metric-trend">${checkpoint.timestamp || 'Timestamp pending'}</div>
                </div>
            `)
            .join('');
    }

    function renderRollbackCheckpointList(checkpoints = []) {
        const rollbackCheckpointList = document.getElementById('rollback-checkpoint-list');
        if (!rollbackCheckpointList) return;

        if (!Array.isArray(checkpoints) || checkpoints.length === 0) {
            rollbackCheckpointList.innerHTML = '<div class="placeholder">No checkpoints available for rollback.</div>';
            return;
        }

        rollbackCheckpointList.innerHTML = checkpoints
            .map((checkpoint, index) => `
                <div class="card checkpoint-item" style="margin-bottom: 12px; cursor: pointer; border: 2px solid var(--border);" 
                     data-checkpoint-id="${checkpoint.id}" onclick="selectCheckpoint(this, '${checkpoint.id}')">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <div class="metric-label">${index === 0 ? 'Latest Checkpoint' : 'Checkpoint'}</div>
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

    function displayToast(message, isError = false) {
        if (!toast) return;
        toast.textContent = message;
        toast.style.borderColor = isError ? 'rgba(220, 38, 38, 0.3)' : 'var(--border)';
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
                document.getElementById('rollback-status').innerHTML = `Initiating rollback to checkpoint ${checkpointId}...`;
                displayToast(`Rolling back to checkpoint: ${checkpointId}`);
            };
        }
    };
});
