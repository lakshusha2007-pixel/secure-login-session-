/**
 * ============================================================================
 *  assets/js/main.js — Vanilla JavaScript (no libraries)
 * ============================================================================
 *  Responsibilities:
 *      1. Password show/hide toggle.
 *      2. Client-side input validation for login & registration forms.
 *      3. Prevent double-submission of forms.
 *      4. Auto-dismiss flash alerts.
 * ============================================================================
 */
(function () {
    'use strict';

    /* --------------------------------------------------------------------
     * 1) Password show/hide toggle
     * -------------------------------------------------------------------- */
    document.querySelectorAll('.toggle-password').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var input = document.getElementById(btn.getAttribute('data-target'));
            if (!input) return;

            var isHidden = input.type === 'password';
            input.type = isHidden ? 'text' : 'password';
            btn.textContent = isHidden ? '\u{1F441}' : '\u{1F441}\uFE0E';
        });
    });

    /* --------------------------------------------------------------------
     * 2) Login form client-side validation (Name or Email + Password)
     * -------------------------------------------------------------------- */
    var loginForm = document.getElementById('login-form');

    if (loginForm) {
        loginForm.addEventListener('submit', function (e) {
            var identity = document.getElementById('identity');
            var password = document.getElementById('password');
            var valid    = true;

            [identity, password].forEach(function (field) {
                if (field) field.classList.remove('is-invalid');
            });

            if (identity && !identity.value.trim()) {
                identity.classList.add('is-invalid');
                valid = false;
            }

            if (password && !password.value) {
                password.classList.add('is-invalid');
                valid = false;
            }

            if (!valid) {
                e.preventDefault();
                return;
            }

            var submitBtn = loginForm.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Signing in\u2026';
            }
        });
    }

    /* --------------------------------------------------------------------
     * 3) Registration form client-side validation
     * -------------------------------------------------------------------- */
    var registerForm = document.getElementById('register-form');

    if (registerForm) {
        registerForm.addEventListener('submit', function (e) {
            var fullname        = document.getElementById('fullname');
            var emailPrefix     = document.getElementById('email_prefix');
            var phoneNum        = document.getElementById('phone_num');
            var password        = document.getElementById('password');
            var confirmPassword = document.getElementById('confirm_password');
            var valid           = true;

            [fullname, emailPrefix, phoneNum, password, confirmPassword].forEach(function (field) {
                if (field) field.classList.remove('is-invalid');
            });

            if (fullname) {
                var nameVal = fullname.value.trim();
                if (nameVal.length < 12 || nameVal.length > 15) {
                    fullname.classList.add('is-invalid');
                    valid = false;
                }
            }

            if (emailPrefix && !emailPrefix.value.trim()) {
                emailPrefix.classList.add('is-invalid');
                valid = false;
            }

            if (phoneNum && !/^[0-9]{10}$/.test(phoneNum.value.trim())) {
                phoneNum.classList.add('is-invalid');
                valid = false;
            }

            if (password && password.value.length < 8) {
                password.classList.add('is-invalid');
                valid = false;
            }

            if (confirmPassword && password && confirmPassword.value !== password.value) {
                confirmPassword.classList.add('is-invalid');
                valid = false;
            }

            if (!valid) {
                e.preventDefault();
                return;
            }

            var submitBtn = registerForm.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Creating Account\u2026';
            }
        });
    }

    /* --------------------------------------------------------------------
     * 4) Logout confirmation
     * -------------------------------------------------------------------- */
    var logoutForm = document.getElementById('logout-form');
    if (logoutForm) {
        logoutForm.addEventListener('submit', function (e) {
            if (!window.confirm('Are you sure you want to log out?')) {
                e.preventDefault();
            }
        });
    }

    /* --------------------------------------------------------------------
     * 5) Auto-dismiss alert messages after 6 seconds
     * -------------------------------------------------------------------- */
    document.querySelectorAll('.alert').forEach(function (alert) {
        setTimeout(function () {
            alert.style.transition = 'opacity 0.5s ease';
            alert.style.opacity = '0';
            setTimeout(function () {
                if (alert.parentNode) {
                    alert.parentNode.removeChild(alert);
                }
            }, 500);
        }, 6000);
    });
})();
