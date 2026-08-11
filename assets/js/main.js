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
     * 1) Password show/hide toggle & Realtime error clearing
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

    // Clear red error border immediately when user types or focuses on an input
    document.querySelectorAll('.form-control').forEach(function (input) {
        ['input', 'focus', 'keydown'].forEach(function (evt) {
            input.addEventListener(evt, function () {
                this.classList.remove('is-invalid');
            });
        });
    });

    /* --------------------------------------------------------------------
     * 2) Login form submit handling
     * -------------------------------------------------------------------- */
    var loginForm = document.getElementById('login-form');

    if (loginForm) {
        loginForm.addEventListener('submit', function () {
            var submitBtn = loginForm.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Signing in\u2026';
            }
        });
    }

    /* --------------------------------------------------------------------
     * 3) Registration form submit handling
     * -------------------------------------------------------------------- */
    var registerForm = document.getElementById('register-form');

    if (registerForm) {
        registerForm.addEventListener('submit', function () {
            var submitBtn = registerForm.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Creating Account\u2026';
            }
        });
    }

    /* --------------------------------------------------------------------
     * 3b) Profile form submit handling
     * -------------------------------------------------------------------- */
    var profileForm = document.getElementById('profile-form');
    if (profileForm) {
        profileForm.addEventListener('submit', function () {
            var submitBtn = profileForm.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
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
