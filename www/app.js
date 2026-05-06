import init, { analyze_descriptor, validate_checksum } from './pkg/miniscript_analyzer.js';

let wasmReady = false;

async function initWasm() {
    try {
        await init();
        wasmReady = true;
        document.getElementById('analyze-btn').disabled = false;
        console.log('WASM initialized successfully');
    } catch (e) {
        console.error('Failed to initialize WASM:', e);
        showError('Failed to load WebAssembly module. Please refresh the page.');
    }
}

// Initialize on load
initWasm();

// Make analyzeDescriptor available globally for the onclick handler
window.analyzeDescriptor = analyzeDescriptor;

function analyzeDescriptor() {
    if (!wasmReady) {
        showError('WebAssembly module is still loading. Please wait...');
        return;
    }

    const descriptor = document.getElementById('descriptor').value.trim();
    if (!descriptor) {
        showError('Please enter a descriptor.');
        return;
    }

    const index = parseInt(document.getElementById('index').value) || 0;
    const network = document.getElementById('network').value;

    // Show loading
    hideError();
    hideResults();
    showLoading();

    // Use setTimeout to allow UI to update before heavy computation
    setTimeout(() => {
        try {
            const resultJson = analyze_descriptor(descriptor, index, network);
            const result = JSON.parse(resultJson);

            hideLoading();

            if (!result.valid && result.error) {
                showError(result.error);
                return;
            }

            displayResults(result, descriptor);
        } catch (e) {
            hideLoading();
            showError('Analysis failed: ' + e.message);
            console.error(e);
        }
    }, 50);
}

function displayResults(result, originalDescriptor) {
    const resultsEl = document.getElementById('results');
    resultsEl.classList.remove('hidden');

    // Checksum validation
    const checksumEl = document.getElementById('checksum-result');
    if (originalDescriptor.includes('#')) {
        try {
            const checkResult = JSON.parse(validate_checksum(originalDescriptor));
            if (checkResult.valid) {
                checksumEl.innerHTML = '<span class="valid-badge">✓ Checksum valid</span>';
            } else {
                checksumEl.innerHTML = `<span class="invalid-badge">✗ ${escapeHtml(checkResult.message)}</span>`;
            }
        } catch (e) {
            checksumEl.innerHTML = '<span class="invalid-badge">✗ Could not validate checksum</span>';
        }
    } else {
        checksumEl.innerHTML = '<span class="valid-badge">✓ Descriptor parsed successfully</span> <span style="color: var(--text-muted); font-size: 0.8rem; margin-left: 0.5rem;">(no checksum provided)</span>';
    }

    // Descriptor type
    document.getElementById('desc-type').textContent = result.descriptor_type || 'Unknown';

    // Policy
    const policyEl = document.getElementById('policy-content');
    if (result.policy) {
        policyEl.textContent = result.policy;
        document.getElementById('policy-section').classList.remove('hidden');
    } else {
        document.getElementById('policy-section').classList.add('hidden');
    }

    // Timelocks
    const timelockSection = document.getElementById('timelock-section');
    const timelockList = document.getElementById('timelock-list');
    if (result.timelock_info && result.timelock_info.length > 0) {
        timelockSection.classList.remove('hidden');
        timelockList.innerHTML = result.timelock_info.map(t =>
            `<div class="timelock-item">⏰ ${escapeHtml(t)}</div>`
        ).join('');
    } else {
        timelockSection.classList.add('hidden');
    }

    // Path results
    const pathResultsEl = document.getElementById('path-results');
    pathResultsEl.innerHTML = '';

    if (result.paths && result.paths.length > 0) {
        result.paths.forEach((pathResult) => {
            const analysis = pathResult.analysis;
            const card = document.createElement('section');
            card.className = 'result-card';

            let html = '';

            // Path label
            if (result.paths.length > 1) {
                html += `<div class="path-label">${escapeHtml(pathResult.label)}</div>`;
            }

            // Keys table
            if (analysis.keys && analysis.keys.length > 0) {
                html += '<h2>🔑 Derived Keys (Index: ' + document.getElementById('index').value + ')</h2>';
                html += '<div style="overflow-x: auto;">';
                html += '<table class="key-table">';
                html += '<thead><tr><th>#</th><th>Fingerprint</th><th>Origin Path</th><th>Full Derivation</th><th>Derived Public Key</th></tr></thead>';
                html += '<tbody>';
                analysis.keys.forEach((key, i) => {
                    html += `<tr>
                        <td>${i + 1}</td>
                        <td><span class="fingerprint">${escapeHtml(key.fingerprint)}</span></td>
                        <td>${escapeHtml(key.derivation_path)}</td>
                        <td style="font-size: 0.7rem; max-width: 200px; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(key.full_derivation)}</td>
                        <td>${escapeHtml(key.derived_pubkey)}</td>
                    </tr>`;
                });
                html += '</tbody></table></div>';
            }

            // Address
            if (analysis.address) {
                html += `
                    <div style="margin-top: 1rem;">
                        <h2>📫 Address</h2>
                        <div class="info-item">
                            <span class="info-label">Derived Address</span>
                            <span class="info-value" style="font-size: 0.9rem;">${escapeHtml(analysis.address)}</span>
                        </div>
                    </div>`;
            }

            // Script
            if (analysis.script_hex) {
                html += `
                    <div style="margin-top: 1rem;">
                        <h2>📝 Script</h2>
                        <div class="info-item" style="margin-bottom: 0.75rem;">
                            <span class="info-label">Hex</span>
                            <div class="script-wrapper">
                                <div class="code-block">${escapeHtml(analysis.script_hex)}</div>
                            </div>
                        </div>`;

                if (analysis.script_asm) {
                    html += `
                        <div class="info-item">
                            <span class="info-label">ASM</span>
                            <div class="script-wrapper">
                                <div class="code-block">${escapeHtml(analysis.script_asm)}</div>
                            </div>
                        </div>`;
                }
                html += '</div>';
            }

            card.innerHTML = html;
            pathResultsEl.appendChild(card);
        });
    }
}

function showLoading() {
    document.getElementById('loading').classList.remove('hidden');
}

function hideLoading() {
    document.getElementById('loading').classList.add('hidden');
}

function showError(msg) {
    const errorSection = document.getElementById('error-section');
    document.getElementById('error-message').textContent = msg;
    errorSection.classList.remove('hidden');
}

function hideError() {
    document.getElementById('error-section').classList.add('hidden');
}

function hideResults() {
    document.getElementById('results').classList.add('hidden');
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}

// Allow Ctrl+Enter to analyze
document.getElementById('descriptor').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
        analyzeDescriptor();
    }
});
