/**
 * Phishing Detection App - Main JavaScript
 * ========================================
 * 
 * This file contains all client-side functionality for the phishing detection web application.
 * It includes:
 * - Form validation and submission handling
 * - UI interaction enhancements
 * - Feature analysis table highlighting
 * - Event listeners for dynamic elements
 */
document.addEventListener('DOMContentLoaded', function() {
    /**
     * URL Form Validation
     * ------------------
     * Prevents form submission if URL field is empty
     * and shows an alert to the user
     */
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
    
    /**
     * Button Interaction Effects
     * -------------------------
     * Adds visual feedback when hovering over buttons
     * by toggling shadow classes
     */
    const buttons = document.querySelectorAll('.btn');
    buttons.forEach(button => {
        button.addEventListener('mouseenter', function() {
            this.classList.add('shadow-sm');
        });
        
        button.addEventListener('mouseleave', function() {
            this.classList.remove('shadow-sm');
        });
    });
    
    /**
     * Feature Analysis Table Highlighting
     * ----------------------------------
     * Colors table rows based on feature values:
     * - 1/1.0 (positive indicators) = green
     * - -1/-1.0 (negative indicators) = red
     */
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
