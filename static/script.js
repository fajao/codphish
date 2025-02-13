const form = document.getElementById('url-form');
const urlInput = document.getElementById('url-input');
const resultDiv = document.getElementById('result');
const checksList = document.getElementById('checks-list');

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = sanitizeInput(urlInput.value);

    if (!isValidUrl(url)) {
        resultDiv.textContent = 'Please enter a valid URL.';
        return;
    }

    try {
        const loadingDiv = document.getElementById('loading');
        resultDiv.innerHTML = '';
        loadingDiv.style.display = 'block';

        const response = await fetch('/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url }),
        });

        if (!response.ok) {
            throw new Error('Network response was not ok');
        }

        const data = await response.json();
        loadingDiv.style.display = 'none';
        resultDiv.innerHTML = `<div class="${data.prediction.toLowerCase()}">Result: The URL is ${data.prediction}</div>`;

        // Refresh the recent checks after a new prediction
        fetchRecentChecks();
    } catch (error) {
        console.error('Error:', error);
        resultDiv.textContent = 'An error occurred while checking the URL.';
    }
});

async function fetchRecentChecks() {
    try {
        const response = await fetch('/last_checks');
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }

        const checks = await response.json();
        checksList.innerHTML = ''; // Clear existing checks

        checks.forEach(check => {
            const checkItem = document.createElement('div');
            checkItem.className = 'check-item';
            checkItem.innerHTML = DOMPurify.sanitize(`
                <div class="check-url">${check.url}</div>
                <div class="check-result ${check.prediction.toLowerCase()}">${check.prediction}</div>
                <div class="check-date">${new Date(check.timestamp).toLocaleString()}</div>
            `);
            checksList.appendChild(checkItem);
        });
    } catch (error) {
        console.error('Error fetching recent checks:', error);
        checksList.innerHTML = '<p>Failed to load recent checks.</p>';
    }
}

function sanitizeInput(input) {
    // Basic sanitization: remove any HTML tags and trim whitespace
    return DOMPurify.sanitize(input.trim());
}

function isValidUrl(string) {
    try {
        new URL(string);
        return true;
    } catch (_) {
        return false;
    }
}

// Fetch recent checks when the page loads
fetchRecentChecks();

function adjustLayout() {
    const isMobile = window.innerWidth <= 768;
    const checkItems = document.querySelectorAll('.check-item');
    
    checkItems.forEach(item => {
        const url = item.querySelector('.check-url');
        const result = item.querySelector('.check-result');
        const date = item.querySelector('.check-date');
        
        if (isMobile) {
            url.textContent = url.textContent.slice(0, 30) + '...';
            result.textContent = result.textContent.replace('Result: ', '');
            date.textContent = new Date(date.textContent).toLocaleDateString();
        }
    });
}

// Call this function when the page loads and when the window is resized
window.addEventListener('load', adjustLayout);
window.addEventListener('resize', adjustLayout);