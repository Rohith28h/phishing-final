/**
 * Phishing Detection System - Main JavaScript File
 * Handles performance optimizations and UI enhancements
 */

document.addEventListener('DOMContentLoaded', function() {
    // Optimize page load performance
    addPreconnect('https://cdn.jsdelivr.net');
    addPreconnect('https://cdn.replit.com');
    
    // Enhance UI with animations
    fadeInElements('.fade-in');
    
    // Add loading spinners to forms
    setupFormSubmitSpinners();
    
    // Prefetch pages user is likely to visit next
    setupPrefetching();
    
    // Optimize tables if they exist
    optimizeTables();
});

/**
 * Adds preconnect hint for resource domains
 */
function addPreconnect(url) {
    if (!url) return;
    
    const link = document.createElement('link');
    link.rel = 'preconnect';
    link.href = url;
    document.head.appendChild(link);
}

/**
 * Fades in elements with a specified selector for a smoother UI
 */
function fadeInElements(selector) {
    const elements = document.querySelectorAll(selector);
    elements.forEach(element => {
        let opacity = 0;
        element.style.opacity = '0';
        element.style.display = 'block';
        
        const fade = setInterval(() => {
            if (opacity >= 1) {
                clearInterval(fade);
            }
            element.style.opacity = opacity.toString();
            opacity += 0.1;
        }, 30);
    });
}

/**
 * Adds loading spinners to forms when submitting
 */
function setupFormSubmitSpinners() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn) {
            const originalText = submitBtn.innerHTML;
            
            form.addEventListener('submit', function() {
                if (form.checkValidity()) {
                    // Disable form to prevent multiple submissions
                    const inputs = form.querySelectorAll('input, button, select, textarea');
                    inputs.forEach(input => input.setAttribute('disabled', 'disabled'));
                    
                    // Add spinner to button
                    submitBtn.innerHTML = `
                        <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
                        Processing...
                    `;
                }
            });
        }
    });
}

/**
 * Prefetches pages that user might navigate to next
 */
function setupPrefetching() {
    // Prefetch check URL page for logged in users
    if (document.querySelector('.nav-link[href*="logout"]')) {
        setTimeout(() => {
            prefetchPage('/check_url');
        }, 2000);
    } else {
        // For users not logged in, prefetch login and register pages
        setTimeout(() => {
            prefetchPage('/login');
            prefetchPage('/register');
        }, 2000);
    }
}

/**
 * Prefetches a given page URL
 */
function prefetchPage(url) {
    if (!url) return;
    
    const link = document.createElement('link');
    link.rel = 'prefetch';
    link.href = url;
    document.head.appendChild(link);
}

/**
 * Optimizes tables with striping and responsive behavior
 */
function optimizeTables() {
    const tables = document.querySelectorAll('table');
    if (tables.length === 0) return;
    
    tables.forEach((table, index) => {
        // Add bootstrap classes if not already present
        if (!table.classList.contains('table')) {
            table.classList.add('table', 'table-striped', 'table-hover', 'table-responsive');
        }
        
        // Add ID if none exists
        if (!table.id) {
            table.id = `data-table-${index}`;
        }
        
        // Add responsive wrapper if needed
        if (!table.parentNode.classList.contains('table-responsive')) {
            const wrapper = document.createElement('div');
            wrapper.classList.add('table-responsive');
            table.parentNode.insertBefore(wrapper, table);
            wrapper.appendChild(table);
        }
    });
}