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
    
    // Button effects
    const buttons = document.querySelectorAll('.btn');
    buttons.forEach(button => {
        button.addEventListener('mouseenter', function() {
            this.classList.add('shadow-sm');
        });
        
        button.addEventListener('mouseleave', function() {
            this.classList.remove('shadow-sm');
        });
    });
    
    // Feature table highlighting
    const featureRows = document.querySelectorAll('table tbody tr');
    featureRows.forEach(row => {
        const valueCell = row.querySelector('td:nth-child(2)');
        if (valueCell) {
            const value = valueCell.textContent.trim();
            if (value === '1' || value === '1.0') {
                row.classList.add('table-success');
            } else if (value === '-1' || value === '-1.0') {
                row.classList.add('table-danger');
            }
        }
    });
});
