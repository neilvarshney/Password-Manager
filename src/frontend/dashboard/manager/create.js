document.addEventListener('DOMContentLoaded', () => {
    const websiteField = document.getElementById('websiteInput');
    const passwordField = document.getElementById('passwordInput');
    const createPasswordForm = document.getElementById('createPasswordForm');
    const backendResponse = document.getElementById('backendResponse');

    const backendUrl = 'http://127.0.0.1:5000/passwords';

    createPasswordForm.addEventListener('submit', async (event) => {

        event.preventDefault();
        const inputWebsite = websiteField.value;
        const inputPassword = passwordField.value;

        if (inputWebsite.trim() === '' || inputPassword.trim() === '') 
        {
            backendResponse.textContent = 'Please enter all information.';
            backendResponse.classList.add("error_message");
            backendResponse.classList.remove("success_message");
            return;
        }

        // Prompt user for their login password for key derivation
        const userPassword = prompt('Please enter your login password:');
        if (!userPassword) {
            backendResponse.textContent = 'Login password is required for encryption.';
            backendResponse.classList.add("error_message");
            backendResponse.classList.remove("success_message");
            return;
        }

        backendResponse.textContent = 'Saving password...';
        backendResponse.classList.remove("error_message");
        backendResponse.classList.remove("success_message");

        // Get JWT token from localStorage
        const token = localStorage.getItem('jwt_token');
        if (!token) {
            backendResponse.textContent = 'Not authenticated. Please login again.';
            backendResponse.classList.add("error_message");
            backendResponse.classList.remove("success_message");
            return;
        }

        try {
            const response = await fetch(backendUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ 
                    website: inputWebsite, 
                    password: inputPassword,
                    user_password: userPassword
                }),
            });

            if (!response.ok) 
            {
                const errorData = await response.json();
                console.error(`Create password error! status: ${response.status}, message: ${errorData.text}`);
                backendResponse.textContent = `Error: ${errorData.text}`;
                backendResponse.classList.add("error_message");
                backendResponse.classList.remove("success_message");
            }

            else if (response.ok) {
                const data = await response.json();
                if (data.status === "success") {
                    backendResponse.classList.add("success_message");
                    backendResponse.classList.remove("error_message");
                    backendResponse.textContent = data.text;
                    
                    // Clear the form
                    websiteField.value = '';
                    passwordField.value = '';
                }
            }


        } catch (error) {
            console.error('Fetch error:', error);
            backendResponse.textContent = `Error: ${error.message}`;
            backendResponse.classList.add("error_message");
            backendResponse.classList.remove("success_message");
        }
    });
});