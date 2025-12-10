// Main JavaScript for Blood Bank Management System

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Auto-hide alerts after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert');
        alerts.forEach(function(alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);

    // Form validation
    const forms = document.querySelectorAll('.needs-validation');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });

    // Blood availability chart
    if (document.getElementById('bloodAvailabilityChart')) {
        loadBloodAvailabilityChart();
    }

    // Real-time notifications
    if (document.getElementById('notifications')) {
        loadNotifications();
        setInterval(loadNotifications, 30000); // Refresh every 30 seconds
    }

    // Search functionality
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            const tableRows = document.querySelectorAll('tbody tr');
            
            tableRows.forEach(function(row) {
                const text = row.textContent.toLowerCase();
                if (text.includes(searchTerm)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    }

    // Appointment date validation
    const appointmentDateInput = document.getElementById('appointment_date');
    if (appointmentDateInput) {
        const today = new Date();
        const tomorrow = new Date(today);
        tomorrow.setDate(tomorrow.getDate() + 1);
        
        appointmentDateInput.min = tomorrow.toISOString().slice(0, 16);
        
        // Set max date to 3 months from now
        const maxDate = new Date(today);
        maxDate.setMonth(maxDate.getMonth() + 3);
        appointmentDateInput.max = maxDate.toISOString().slice(0, 16);
    }

    // Blood group compatibility check
    const bloodGroupSelect = document.getElementById('blood_group');
    const compatibleGroups = document.getElementById('compatibleGroups');
    
    if (bloodGroupSelect && compatibleGroups) {
        bloodGroupSelect.addEventListener('change', function() {
            const selectedGroup = this.value;
            const compatibility = getBloodGroupCompatibility(selectedGroup);
            compatibleGroups.innerHTML = compatibility.map(group => 
                `<span class="badge bg-info me-1">${group}</span>`
            ).join('');
        });
    }

    // Emergency contact functionality
    const emergencyBtn = document.getElementById('emergencyBtn');
    if (emergencyBtn) {
        emergencyBtn.addEventListener('click', function() {
            if (confirm('Are you sure you want to make an emergency blood request? This will be prioritized immediately.')) {
                // Add emergency class to form
                const form = document.querySelector('form');
                if (form) {
                    form.classList.add('emergency-request');
                    const urgencySelect = document.getElementById('urgency_level');
                    if (urgencySelect) {
                        urgencySelect.value = 'emergency';
                        urgencySelect.disabled = true;
                    }
                }
            }
        });
    }
});

// Load blood availability chart
function loadBloodAvailabilityChart() {
    fetch('/api/blood-availability')
        .then(response => response.json())
        .then(data => {
            const ctx = document.getElementById('bloodAvailabilityChart').getContext('2d');
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: Object.keys(data),
                    datasets: [{
                        label: 'Available Units',
                        data: Object.values(data),
                        backgroundColor: [
                            '#e74c3c', '#c0392b', '#3498db', '#2980b9',
                            '#9b59b6', '#8e44ad', '#f39c12', '#e67e22'
                        ],
                        borderColor: [
                            '#c0392b', '#a93226', '#2980b9', '#1f618d',
                            '#8e44ad', '#7d3c98', '#d68910', '#ca6f1e'
                        ],
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Blood Availability by Group'
                        },
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                stepSize: 1
                            }
                        }
                    }
                }
            });
        })
        .catch(error => console.error('Error loading blood availability:', error));
}

// Load notifications
function loadNotifications() {
    // This would typically fetch from an API endpoint
    // For now, we'll simulate with local data
    const notifications = [
        {
            id: 1,
            title: 'New Blood Request',
            message: 'Emergency request for O+ blood group',
            type: 'warning',
            time: '2 minutes ago'
        },
        {
            id: 2,
            title: 'Appointment Reminder',
            message: 'Your donation appointment is tomorrow at 10:00 AM',
            type: 'info',
            time: '1 hour ago'
        }
    ];

    const container = document.getElementById('notifications');
    if (container) {
        container.innerHTML = notifications.map(notification => `
            <div class="notification-item ${notification.type === 'warning' ? 'unread' : ''}">
                <div class="d-flex justify-content-between align-items-start">
                    <div>
                        <h6 class="mb-1">${notification.title}</h6>
                        <p class="mb-1">${notification.message}</p>
                        <small class="text-muted">${notification.time}</small>
                    </div>
                    <button class="btn btn-sm btn-outline-secondary" onclick="markAsRead(${notification.id})">
                        <i class="fas fa-check"></i>
                    </button>
                </div>
            </div>
        `).join('');
    }
}

// Mark notification as read
function markAsRead(notificationId) {
    // This would typically make an API call
    console.log('Marking notification as read:', notificationId);
    // Remove the unread class
    const notification = document.querySelector(`[onclick="markAsRead(${notificationId})"]`).closest('.notification-item');
    notification.classList.remove('unread');
}

// Get blood group compatibility
function getBloodGroupCompatibility(bloodGroup) {
    const compatibility = {
        'A+': ['A+', 'A-', 'O+', 'O-'],
        'A-': ['A-', 'O-'],
        'B+': ['B+', 'B-', 'O+', 'O-'],
        'B-': ['B-', 'O-'],
        'AB+': ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-'],
        'AB-': ['A-', 'B-', 'AB-', 'O-'],
        'O+': ['O+', 'O-'],
        'O-': ['O-']
    };
    return compatibility[bloodGroup] || [];
}

// Format date for display
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Show loading spinner
function showLoading(element) {
    const spinner = document.createElement('div');
    spinner.className = 'spinner-border spinner-border-sm me-2';
    spinner.setAttribute('role', 'status');
    element.prepend(spinner);
    element.disabled = true;
}

// Hide loading spinner
function hideLoading(element) {
    const spinner = element.querySelector('.spinner-border');
    if (spinner) {
        spinner.remove();
    }
    element.disabled = false;
}

// Show success message
function showSuccess(message) {
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-success alert-dismissible fade show';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    const container = document.querySelector('.container-fluid');
    container.insertBefore(alertDiv, container.firstChild);
    
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

// Show error message
function showError(message) {
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-danger alert-dismissible fade show';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    const container = document.querySelector('.container-fluid');
    container.insertBefore(alertDiv, container.firstChild);
    
    setTimeout(() => {
        alertDiv.remove();
    }, 5000);
}

// Validate phone number
function validatePhoneNumber(phone) {
    const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
    return phoneRegex.test(phone);
}

// Validate email
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Check donor eligibility
function checkEligibility() {
    const age = parseInt(document.getElementById('age').value);
    const weight = parseFloat(document.getElementById('weight').value);
    const lastDonation = document.getElementById('last_donation').value;
    
    let eligibility = {
        eligible: true,
        reasons: []
    };
    
    if (age < 18 || age > 65) {
        eligibility.eligible = false;
        eligibility.reasons.push('Age must be between 18 and 65 years');
    }
    
    if (weight < 50) {
        eligibility.eligible = false;
        eligibility.reasons.push('Weight must be at least 50 kg');
    }
    
    if (lastDonation) {
        const lastDonationDate = new Date(lastDonation);
        const today = new Date();
        const daysSinceLastDonation = Math.floor((today - lastDonationDate) / (1000 * 60 * 60 * 24));
        
        if (daysSinceLastDonation < 56) {
            eligibility.eligible = false;
            eligibility.reasons.push('Must wait at least 56 days between donations');
        }
    }
    
    return eligibility;
}

// Update eligibility status
function updateEligibilityStatus() {
    const eligibility = checkEligibility();
    const statusDiv = document.getElementById('eligibilityStatus');
    
    if (statusDiv) {
        if (eligibility.eligible) {
            statusDiv.innerHTML = '<div class="alert alert-success"><i class="fas fa-check-circle me-2"></i>You are eligible to donate blood!</div>';
        } else {
            statusDiv.innerHTML = `<div class="alert alert-warning"><i class="fas fa-exclamation-triangle me-2"></i>Not eligible: ${eligibility.reasons.join(', ')}</div>`;
        }
    }
}
