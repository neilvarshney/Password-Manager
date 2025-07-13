document.addEventListener('DOMContentLoaded', () => {
    const usernameField = document.getElementById('usernameInput');
    const passwordField = document.getElementById('passwordInput');
    const createAccountForm = document.getElementById('createAccountForm');
    const backendResponse = document.getElementById('backendResponse');

    const backendUrl = 'http://127.0.0.1:5000/accounts';

    createAccountForm.addEventListener('submit', async (event) => {

        event.preventDefault();
        const inputUsername = usernameField.value;
        const inputPassword = passwordField.value;

        if (inputUsername.trim() === '' || inputPassword.trim() === '') 
        {
            backendResponse.textContent = 'Please enter account information.';
            return;
        }

        backendResponse.textContent = 'Creating account...';

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

                backendResponse.classList.add("error_message")
                backendResponse.classList.remove("success_message")
                console.error(`Create account error! status: ${response.status}, message: ${errorData.text}`);
                backendResponse.textContent = `Error: ${errorData.text}`;
            }

            else if (response.ok) {
                const data = await response.json();
                if (data.status === "success") {
                    backendResponse.classList.add("success_message")
                    backendResponse.classList.remove("error_message")
                    backendResponse.textContent = data.text
                    window.location.href = '../index.html';
                }
            }


        } catch (error) {
            console.error('Fetch error:', error);
            backendResponse.textContent = `Error: ${error.message}`;
        }
    });
});