/**
 * ============================================================================
 *  assets/js/main.js — Senior Human UI/UX Interaction Module
 * ============================================================================
 *  Features:
 *      1. Password visibility toggle & realtime input error clearing.
 *      2. Accessible form submission loading feedback.
 *      3. Smooth alert dismissals.
 * ============================================================================
 */
(function () {
    'use strict';

    /* --------------------------------------------------------------------
     * 1) Button Click Reflection & Password Toggle
     * -------------------------------------------------------------------- */
    document.addEventListener('click', function (e) {
        var btn = e.target.closest('.btn');
        if (!btn) return;

        btn.classList.remove('btn-clicked');
        void btn.offsetWidth; // Trigger reflow for animation restart
        btn.classList.add('btn-clicked');
        setTimeout(function () {
            btn.classList.remove('btn-clicked');
        }, 450);
    });

    var svgEyeShow = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>';
    var svgEyeHide = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>';

    document.querySelectorAll('.toggle-password').forEach(function (btn) {
        btn.innerHTML = svgEyeShow;
        btn.addEventListener('click', function () {
            var input = document.getElementById(btn.getAttribute('data-target'));
            if (!input) return;

            var isHidden = input.type === 'password';
            input.type = isHidden ? 'text' : 'password';
            btn.innerHTML = isHidden ? svgEyeHide : svgEyeShow;
            btn.setAttribute('aria-label', isHidden ? 'Hide password' : 'Show password');
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
                submitBtn.textContent = 'Signing in…';
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
                submitBtn.textContent = 'Creating Account…';
            }
        });
    }

    /* --------------------------------------------------------------------
     * 4) Profile form submit handling
     * -------------------------------------------------------------------- */
    var profileForm = document.getElementById('profile-form');
    if (profileForm) {
        profileForm.addEventListener('submit', function () {
            var submitBtn = profileForm.querySelector('button[type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.textContent = 'Saving Changes…';
            }
        });
    }

    /* --------------------------------------------------------------------
     * 5) Auto-dismiss alert messages after 6 seconds
     * -------------------------------------------------------------------- */
    document.querySelectorAll('.alert').forEach(function (alert) {
        setTimeout(function () {
            alert.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-6px)';
            setTimeout(function () {
                if (alert.parentNode) {
                    alert.parentNode.removeChild(alert);
                }
            }, 400);
        }, 6000);
    });

    /* --------------------------------------------------------------------
     * 6) Dynamic Forgot Password link updater
     * -------------------------------------------------------------------- */
    var identityInput = document.getElementById('identity');
    var forgotLink = document.getElementById('forgot-link');
    if (identityInput && forgotLink) {
        function updateForgotLink() {
            var val = identityInput.value.trim();
            if (val !== '') {
                if (val.indexOf('@') === -1) {
                    val += '@gmail.com';
                }
                forgotLink.href = 'forgot_password.php?login_email=' + encodeURIComponent(val);
            } else {
                forgotLink.href = 'forgot_password.php';
            }
        }
        identityInput.addEventListener('input', updateForgotLink);
        updateForgotLink();
    }

    /* --------------------------------------------------------------------
     * 7) 60-Second OTP Countdown Timer Handler
     * -------------------------------------------------------------------- */
    var timerEl = document.getElementById('otp-timer');
    var countEl = document.getElementById('otp-count');
    if (timerEl && countEl) {
        var rawRemaining = timerEl.getAttribute('data-remaining');
        var remaining = rawRemaining !== null ? parseInt(rawRemaining, 10) : 60;
        if (isNaN(remaining)) remaining = 0;
        countEl.textContent = Math.max(0, remaining);

        if (remaining <= 0) {
            timerEl.textContent = 'Your OTP code has expired. Please request a new code.';
        } else {
            var tick = setInterval(function () {
                remaining = Math.max(0, remaining - 1);
                countEl.textContent = remaining;
                if (remaining <= 0) {
                    clearInterval(tick);
                    timerEl.textContent = 'Your OTP code has expired. Please request a new code.';
                }
            }, 1000);
        }
    }

    /* --------------------------------------------------------------------
     * 8) 60-Second OTP Resend Cooldown Handler
     * -------------------------------------------------------------------- */
    var resendBtn = document.getElementById('resend-btn');
    var resendText = document.getElementById('resend-text');
    if (resendBtn && resendText) {
        var rawCooldown = resendBtn.getAttribute('data-cooldown');
        var cooldownSec = rawCooldown !== null ? parseInt(rawCooldown, 10) : 0;
        if (isNaN(cooldownSec)) cooldownSec = 0;

        function updateCooldown() {
            if (cooldownSec > 0) {
                resendBtn.disabled = true;
                resendText.textContent = 'Resend OTP in ' + cooldownSec + 's';
                cooldownSec--;
                setTimeout(updateCooldown, 1000);
            } else {
                resendBtn.disabled = false;
                resendText.textContent = 'Resend OTP Code';
            }
        }
        updateCooldown();
    }
})();

