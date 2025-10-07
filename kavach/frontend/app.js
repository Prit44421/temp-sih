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
            .then((checkpoints) => renderCheckpointList(checkpoints))
            .catch(() => {
                checkpointList.innerHTML = '<div class="placeholder">Unable to load checkpoints.</div>';
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
        document.getElementById('compliance-score').textContent = '—%';
        document.getElementById('compliance-trend').textContent = 'Pending initial assessment';
        document.getElementById('ruleset-count').textContent = '--';
        document.getElementById('ruleset-detail').textContent = 'Awaiting rule pack';
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
    }

    function renderSystemInfo(info = {}) {
        const entries = [
            { label: 'Operating system', value: info.system || 'Unknown' },
            { label: 'Release', value: info.release || '—' },
            { label: 'Version', value: info.version || '—' },
            { label: 'Distribution', value: info.distro_name || info.distro_id || '—' },
            { label: 'Distro version', value: info.distro_version || '—' }
        ];

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
});
