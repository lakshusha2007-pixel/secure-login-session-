<?php
/**
 * ============================================================================
 *  includes/footer.php — SHARED FOOTER + JAVASCRIPT
 * ============================================================================
 *
 *  Include this file at the very bottom of every full page to close the HTML
 *  and load our single vanilla-JS file.
 * ============================================================================
 */
?>
</main>

<footer class="site-footer">
    <div class="container">
        <p>&copy; <?php echo date('Y'); ?> SecureAuth &mdash; Secure Login &amp; Session Management Demo.</p>
        <p class="footnote">Protected with prepared statements, password_hash(), HttpOnly + Secure + SameSite cookies.</p>
    </div>
</footer>

<!-- Our own vanilla-JS file (no libraries). -->
<script src="assets/js/main.js"></script>
</body>
</html>
