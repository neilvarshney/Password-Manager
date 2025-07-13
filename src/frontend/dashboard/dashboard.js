document.addEventListener('DOMContentLoaded', () => {
    // Check if user is authenticated
    const token = localStorage.getItem('jwt_token');
    const username = localStorage.getItem('username');
    
    if (!token || !username) {
        // Not authenticated, redirect to login
        window.location.href = '../auth/login.html';
        return;
    }
    
    // Display username if you have a place to show it
    const usernameElement = document.getElementById('username');
    if (usernameElement) {
        usernameElement.textContent = username;
    }
    
    // Add logout functionality
    const logoutButton = document.getElementById('logoutButton');
    if (logoutButton) {
        logoutButton.addEventListener('click', () => {
            // Clear authentication data
            localStorage.removeItem('jwt_token');
            localStorage.removeItem('username');
            
            // Redirect to login page
            window.location.href = '../auth/login.html';
        });
    }
    
    // Add logout functionality to back button as well
    const backButton = document.querySelector('.back_button a');
    if (backButton) {
        backButton.addEventListener('click', (event) => {
            // Clear authentication data when going back
            localStorage.removeItem('jwt_token');
            localStorage.removeItem('username');
        });
    }
}); 