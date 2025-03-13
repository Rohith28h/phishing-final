
// Add any client-side functionality here
document.addEventListener('DOMContentLoaded', function() {
    // Form validation
    const urlForm = document.querySelector('form');
    if (urlForm) {
        urlForm.addEventListener('submit', function(e) {
            const urlInput = document.querySelector('#url');
            if (urlInput && !urlInput.value.trim()) {
                e.preventDefault();
                alert('Please enter a URL');
            }
        });
    }
});
