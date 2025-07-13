document.addEventListener('DOMContentLoaded', () => {
    const usernameField = document.getElementById('usernameInput');
    const passwordField = document.getElementById('passwordInput');
    const loginForm = document.getElementById('loginForm');
    const backendResponse = document.getElementById('backendResponse');

    const backendUrl = 'http://127.0.0.1:5000/sessions';

    loginForm.addEventListener('submit', async (event) => {

        event.preventDefault();
        const inputUsername = usernameField.value;
        const inputPassword = passwordField.value;

        if (inputUsername.trim() === '' || inputPassword.trim() === '') 
        {
            backendResponse.textContent = 'Please enter login information.';
            backendResponse.classList.add("error_message");
            backendResponse.classList.remove("success_message");
            return;
        }

        backendResponse.textContent = 'Logging in...';
        backendResponse.classList.remove("error_message");
        backendResponse.classList.remove("success_message");

        try {
            const response = await fetch(backendUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username: inputUsername, password: inputPassword }),
            });

            if (!response.ok) 
            {
                const errorData = await response.json();
                console.error(`Login error! status: ${response.status}, message: ${errorData.text}`);
                backendResponse.textContent = `Error: ${errorData.text}`;
                backendResponse.classList.add("error_message");
                backendResponse.classList.remove("success_message");
            }

            else if (response.ok) {
                const data = await response.json();
                
                if (data.status === "success") {
                    // Store the JWT token
                    localStorage.setItem('jwt_token', data.token);
                    localStorage.setItem('username', inputUsername);
                    
                    backendResponse.classList.add("success_message");
                    backendResponse.classList.remove("error_message");
                    backendResponse.textContent = data.text;
                    
                    // Redirect to dashboard
                    window.location.href = '../dashboard/dashboard.html';
                } else {
                    backendResponse.classList.add("error_message");
                    backendResponse.classList.remove("success_message");
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