// Settings Page Logic
document.addEventListener('DOMContentLoaded', () => {
    const configInput = document.getElementById('config-name');
    const loadBtn = document.getElementById('load-btn');
    const configDisplay = document.getElementById('config-display');
    const configContent = document.getElementById('config-content');
    const errorMessage = document.getElementById('error-message');
    
    // Load config when button is clicked
    loadBtn.addEventListener('click', loadConfig);
    
    // Load config when Enter is pressed
    configInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            loadConfig();
        }
    });
    
    async function loadConfig() {
        const configName = configInput.value.trim();
        
        if (!configName) {
            showError('Please enter a config preset name');
            return;
        }
        
        try {
            const response = await fetch(`/settings/load?config=${encodeURIComponent(configName)}`);
            
            if (!response.ok) {
                const errorText = await response.text();
                showError(errorText || `Failed to load config: ${response.status}`);
                return;
            }
            
            const config = await response.json();
            displayConfig(config);
            hideError();
            
        } catch (error) {
            showError(`Error loading config: ${error.message}`);
        }
    }
    
    function displayConfig(config) {
        configContent.innerHTML = '';
        
        // Display each config property
        for (const [key, value] of Object.entries(config)) {
            const item = document.createElement('div');
            item.className = 'config-item';
            
            const keyEl = document.createElement('span');
            keyEl.className = 'config-key';
            keyEl.textContent = formatKey(key);
            
            const valueEl = document.createElement('span');
            valueEl.className = 'config-value';
            valueEl.textContent = formatValue(value);
            
            item.appendChild(keyEl);
            item.appendChild(valueEl);
            configContent.appendChild(item);
        }
        
        configDisplay.classList.remove('hidden');
    }
    
    function formatKey(key) {
        // Convert camelCase to Title Case with spaces
        return key
            .replace(/([A-Z])/g, ' $1')
            .replace(/^./, str => str.toUpperCase())
            .trim() + ':';
    }
    
    function formatValue(value) {
        if (typeof value === 'boolean') {
            return value ? '✓ Yes' : '✗ No';
        }
        return String(value);
    }
    
    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.classList.remove('hidden');
        configDisplay.classList.add('hidden');
    }
    
    function hideError() {
        errorMessage.classList.add('hidden');
    }
});
