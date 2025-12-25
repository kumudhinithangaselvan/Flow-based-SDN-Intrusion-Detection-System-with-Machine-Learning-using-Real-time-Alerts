// Custom JavaScript for the SDN Intrusion Detection System

// Document ready function
 $(document).ready(function() {
    // Initialize tooltips
    $('[data-toggle="tooltip"]').tooltip();
    
    // Initialize popovers
    $('[data-toggle="popover"]').popover();
    
    // Auto-hide alerts after 5 seconds
    setTimeout(function() {
        $(".alert").alert('close');
    }, 5000);
});

// Function to format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Function to validate file upload
function validateFileUpload(fileInput) {
    const fileSize = fileInput.files[0].size;
    const fileType = fileInput.files[0].type;
    const validTypes = ['text/csv', 'application/vnd.ms-excel'];
    
    if (!validTypes.includes(fileType)) {
        alert('Please upload a CSV file.');
        return false;
    }
    
    if (fileSize > 5 * 1024 * 1024) { // 5MB limit
        alert('File size must be less than 5MB.');
        return false;
    }
    
    return true;
}

// Function to show loading spinner
function showLoadingSpinner() {
    const spinner = `
        <div class="d-flex justify-content-center">
            <div class="spinner-border text-primary" role="status">
                <span class="sr-only">Loading...</span>
            </div>
        </div>
    `;
    return spinner;
}

// Function to update progress bar
function updateProgressBar(progressBar, percent) {
    progressBar.style.width = percent + '%';
    progressBar.setAttribute('aria-valuenow', percent);
}

// Function to format date
function formatDate(date) {
    const options = { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
    return new Date(date).toLocaleDateString(undefined, options);
}