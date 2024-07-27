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
        resultDiv.textContent = `Result: ${data.prediction}`;
        resultDiv.className = data.prediction;

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
            checkItem.className = `check-item ${check.prediction}`;
            checkItem.innerHTML = DOMPurify.sanitize(`
                <p><strong>URL:</strong> ${check.url}</p>
                <p><strong>Status:</strong> ${check.prediction}</p>
                <p><strong>Date:</strong> ${new Date(check.timestamp).toLocaleString()}</p>
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