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
                const network = document.getElementById('network').value;
                const mempoolUrl = getMempoolAddressUrl(analysis.address, network);
                const mempoolLink = mempoolUrl
                    ? `<a href="${mempoolUrl}" target="_blank" rel="noopener noreferrer" class="mempool-link" title="View on mempool.space">🔍 mempool.space</a>`
                    : '';
                html += `
                    <div style="margin-top: 1rem;">
                        <h2>📫 Address</h2>
                        <div class="info-item">
                            <span class="info-label">Derived Address</span>
                            <span class="info-value address-row" style="font-size: 0.9rem;">${escapeHtml(analysis.address)} ${mempoolLink}</span>
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

        // Add Address Explorer section after all path results
        const descriptor = document.getElementById('descriptor').value.trim();
        const network = document.getElementById('network').value;
        const currentIndex = parseInt(document.getElementById('index').value) || 0;
        if (network !== 'regtest') {
            const explorerCard = document.createElement('section');
            explorerCard.className = 'result-card';
            explorerCard.id = 'address-explorer';

            let explorerHtml = '<h2>🗺️ Address Explorer</h2>';
            explorerHtml += '<p style="color: var(--text-secondary); font-size: 0.8rem; margin-bottom: 0.75rem;">Browse derived addresses on mempool.space. Click any address to view it on-chain.</p>';
            explorerHtml += '<div class="address-explorer-controls">';
            explorerHtml += `<button class="explorer-nav-btn" id="explorer-prev" onclick="navigateExplorer(-10)">← Prev 10</button>`;
            explorerHtml += `<span class="explorer-range" id="explorer-range"></span>`;
            explorerHtml += `<button class="explorer-nav-btn" id="explorer-next" onclick="navigateExplorer(10)">Next 10 →</button>`;
            explorerHtml += '</div>';
            explorerHtml += '<div id="address-explorer-list" class="address-explorer-list"></div>';

            explorerCard.innerHTML = explorerHtml;
            pathResultsEl.appendChild(explorerCard);

            // Store the descriptor for the explorer to use
            window._explorerDescriptor = descriptor;
            window._explorerNetwork = network;
            window._explorerStart = Math.max(0, currentIndex - 5);

            // Render the initial batch
            renderExplorerAddresses(window._explorerStart);
        }
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

/**
 * Get the mempool.space URL for an address, respecting the selected network.
 * Returns null for regtest (not available on mempool.space).
 */
function getMempoolAddressUrl(address, network) {
    if (!address) return null;
    switch (network) {
        case 'bitcoin':
            return `https://mempool.space/address/${address}`;
        case 'testnet':
            return `https://mempool.space/testnet/address/${address}`;
        case 'signet':
            return `https://mempool.space/signet/address/${address}`;
        case 'regtest':
            return null; // regtest is not on mempool.space
        default:
            return `https://mempool.space/address/${address}`;
    }
}

/**
 * Render a batch of derived addresses in the Address Explorer.
 * Derives addresses at indices [startIndex .. startIndex+9] using the WASM analyzer.
 */
function renderExplorerAddresses(startIndex) {
    const listEl = document.getElementById('address-explorer-list');
    const rangeEl = document.getElementById('explorer-range');
    const prevBtn = document.getElementById('explorer-prev');
    if (!listEl) return;

    const descriptor = window._explorerDescriptor;
    const network = window._explorerNetwork;
    const count = 10;
    const endIndex = startIndex + count - 1;

    rangeEl.textContent = `Indices ${startIndex} – ${endIndex}`;
    prevBtn.disabled = startIndex === 0;

    let html = '<table class="explorer-table">';
    html += '<thead><tr><th>Index</th><th>Address</th><th>mempool.space</th></tr></thead>';
    html += '<tbody>';

    for (let i = startIndex; i <= endIndex; i++) {
        try {
            const resultJson = analyze_descriptor(descriptor, i, network);
            const result = JSON.parse(resultJson);

            // Get the first path's address (receive path)
            let address = null;
            if (result.paths && result.paths.length > 0) {
                address = result.paths[0].analysis.address;
            }

            if (address) {
                const mempoolUrl = getMempoolAddressUrl(address, network);
                const currentIdx = parseInt(document.getElementById('index').value) || 0;
                const isCurrentIndex = i === currentIdx;
                const rowClass = isCurrentIndex ? 'explorer-row-current' : '';
                html += `<tr class="${rowClass}">
                    <td>${i}</td>
                    <td class="explorer-address">${escapeHtml(address)}</td>
                    <td>${mempoolUrl ? `<a href="${mempoolUrl}" target="_blank" rel="noopener noreferrer" class="mempool-link">🔍 View</a>` : '—'}</td>
                </tr>`;
            } else {
                html += `<tr><td>${i}</td><td style="color: var(--text-muted);">Could not derive</td><td>—</td></tr>`;
            }
        } catch (e) {
            html += `<tr><td>${i}</td><td style="color: var(--accent-red);">Error</td><td>—</td></tr>`;
        }
    }

    html += '</tbody></table>';
    listEl.innerHTML = html;

    window._explorerStart = startIndex;
}

/**
 * Navigate the Address Explorer forward or backward.
 */
function navigateExplorer(delta) {
    const newStart = Math.max(0, window._explorerStart + delta);
    renderExplorerAddresses(newStart);
}

// Make explorer functions available globally
window.navigateExplorer = navigateExplorer;

// Allow Ctrl+Enter to analyze
document.getElementById('descriptor').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
        analyzeDescriptor();
    }
});
