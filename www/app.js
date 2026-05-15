import init, { analyze_descriptor, validate_checksum } from './pkg/miniscript_analyzer.js';

let wasmReady = false;

async function initWasm() {
    try {
        await init();
        wasmReady = true;
        document.getElementById('analyze-btn').disabled = false;
        console.log('WASM initialized successfully');

        // Check for URL parameters and auto-load
        loadFromUrlParams();
    } catch (e) {
        console.error('Failed to initialize WASM:', e);
        showError('Failed to load WebAssembly module. Please refresh the page.');
    }
}

// Initialize on load
initWasm();

// Make functions available globally for the onclick handlers
window.analyzeDescriptor = analyzeDescriptor;
window.shareDescriptor = shareDescriptor;

/**
 * Read descriptor, index, and network from URL parameters.
 * If a descriptor is present, populate the form and auto-analyze.
 */
function loadFromUrlParams() {
    const params = new URLSearchParams(window.location.search);

    const desc = params.get('desc') || params.get('descriptor');
    const index = params.get('index');
    const network = params.get('network');

    if (desc) {
        document.getElementById('descriptor').value = desc;
    }
    if (index !== null && index !== '') {
        document.getElementById('index').value = index;
    }
    if (network) {
        const networkSelect = document.getElementById('network');
        // Only set if it's a valid option
        const validNetworks = ['bitcoin', 'testnet', 'signet', 'regtest'];
        if (validNetworks.includes(network)) {
            networkSelect.value = network;
        }
    }

    // Auto-analyze if a descriptor was provided
    if (desc) {
        analyzeDescriptor();
    }
}

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

/**
 * Build a shareable URL with the current descriptor, index, and network as parameters.
 * Copies it to the clipboard and shows a brief confirmation.
 */
function shareDescriptor() {
    const descriptor = document.getElementById('descriptor').value.trim();
    if (!descriptor) {
        showError('Please enter a descriptor before sharing.');
        return;
    }

    const index = document.getElementById('index').value;
    const network = document.getElementById('network').value;

    const url = new URL(window.location.href.split('?')[0]);
    url.searchParams.set('desc', descriptor);
    if (index && index !== '0') {
        url.searchParams.set('index', index);
    }
    if (network && network !== 'bitcoin') {
        url.searchParams.set('network', network);
    }

    const shareUrl = url.toString();

    navigator.clipboard.writeText(shareUrl).then(() => {
        const btn = document.getElementById('share-btn');
        const originalText = btn.textContent;
        btn.textContent = 'Copied! ✓';
        btn.classList.add('share-btn-copied');
        setTimeout(() => {
            btn.textContent = originalText;
            btn.classList.remove('share-btn-copied');
        }, 2000);
    }).catch(() => {
        // Fallback: select a prompt with the URL
        prompt('Copy this shareable URL:', shareUrl);
    });
}

// Allow Ctrl+Enter to analyze
document.getElementById('descriptor').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
        analyzeDescriptor();
    }
});
