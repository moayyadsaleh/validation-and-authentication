document.addEventListener('DOMContentLoaded', function() {
    const registrationForm = document.querySelector('form[action="/register"][method="POST"]');
    const errorMessages = document.querySelector('#errorMessages');
  
    if (!registrationForm) {
      console.error('Registration form element not found.');
      return;
    }
  
    registrationForm.addEventListener('submit', function(event) {
      event.preventDefault();
  
      const usernameInput = registrationForm.querySelector('[name="username"]');
      const passwordInput = registrationForm.querySelector('[name="password"]');
      
      const errors = [];
  
      // Client-side validation for username
      if (usernameInput.value.trim().length < 4) {
        errors.push('Username must be at least 4 characters long.');
      }
  
      // Client-side validation for password length, special characters, and mixed case
      const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
      if (!passwordPattern.test(passwordInput.value)) {
        errors.push('Password must be at least 8 characters and include lowercase, uppercase, digits, and special characters.');
      }
  
      const specialCharPattern = /[!@#$%^&*()_+[\]{};:'"|<,.>?]/;
      if (!specialCharPattern.test(passwordInput.value)) {
        errors.push('Password must include at least one special character.');
      }
  
      const uppercasePattern = /[A-Z]/;
      const lowercasePattern = /[a-z]/;
      if (!uppercasePattern.test(passwordInput.value) || !lowercasePattern.test(passwordInput.value)) {
        errors.push('Password must include both uppercase and lowercase letters.');
      }
  
      if (errors.length > 0) {
        errorMessages.style.display = 'block';
        errorMessages.innerHTML = errors.map(error => `<p>${error}</p>`).join('');
        return;
      }
  
      // If validation passes, submit the form
      registrationForm.submit();
    });
  });
  