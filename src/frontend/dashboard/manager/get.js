document.addEventListener('DOMContentLoaded', () => {
    const websiteField = document.getElementById('websiteInput');
    const getPasswordForm = document.getElementById('getPasswordForm');
    const backendResponse = document.getElementById('backendResponse');

    const backendUrlBase = 'http://127.0.0.1:5000/passwords/get';

    getPasswordForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const inputWebsite = websiteField.value;

        if (inputWebsite.trim() === '') {
            backendResponse.textContent = 'Please enter website.';
            backendResponse.classList.add("error_message");
            backendResponse.classList.remove("success_message");
            return;
        }

        // Prompt user for their login password for key derivation
        const userPassword = prompt('Please enter your login password:');
        if (!userPassword) {
            backendResponse.textContent = 'Login password is required for decryption.';
            backendResponse.classList.add("error_message");
            backendResponse.classList.remove("success_message");
            return;
        }

        backendResponse.textContent = 'Finding website...';
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
            const response = await fetch(backendUrlBase, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    site: inputWebsite,
                    user_password: userPassword
                })
            });

            if (!response.ok) 
            {
                const errorData = await response.json();
                console.error(`Get password error! status: ${response.status}, message: ${errorData.text}`);
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