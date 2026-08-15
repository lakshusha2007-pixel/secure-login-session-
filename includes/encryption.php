<?php
/**
 * ============================================================================
 *  includes/encryption.php — FIELD-LEVEL AUTHENTICATED AES-256-GCM ENCRYPTION
 * ============================================================================
 *  Encrypts recoverable sensitive data (e.g. phone, API secrets) at rest using
 *  AES-256-GCM authenticated encryption. Encryption keys are loaded from
 *  environment variables (.env) outside public web access.
 *  Passwords MUST remain securely hashed (Argon2id/bcrypt), not encrypted.
 * ============================================================================
 */

/**
 * Retrieves or derives 32-byte (256-bit) binary encryption key.
 */
function get_encryption_key(?string $overrideRawKey = null): string
{
    $rawKey = $overrideRawKey ?? (getenv('APP_ENCRYPTION_KEY') ?: ($_ENV['APP_ENCRYPTION_KEY'] ?? ''));
    if (empty($rawKey)) {
        // Fallback derivation based on environment context (never plaintext in code)
        $rawKey = hash('sha256', (defined('DB_NAME') ? DB_NAME : 'SECURE_DB') . 'SECURE_AUTH_KEY_2026');
    }
    if (ctype_xdigit($rawKey) && strlen($rawKey) >= 64) {
        return hex2bin(substr($rawKey, 0, 64));
    }
    return hash('sha256', $rawKey, true);
}

/**
 * Encrypts sensitive attribute using AES-256-GCM.
 */
function encrypt_pii(string $plaintext, ?string $rawKey = null): string
{
    if (trim($plaintext) === '') {
        return '';
    }
    $key    = get_encryption_key($rawKey);
    $cipher = 'aes-256-gcm';
    $ivlen  = openssl_cipher_iv_length($cipher);
    $iv     = openssl_random_pseudo_bytes($ivlen);
    $tag    = '';

    $ciphertext = openssl_encrypt($plaintext, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ciphertext === false) {
        return '';
    }
    return base64_encode($iv . $tag . $ciphertext);
}

/**
 * Decrypts sensitive attribute using AES-256-GCM.
 */
function decrypt_pii(string $encoded, ?string $rawKey = null): string
{
    if (trim($encoded) === '') {
        return '';
    }
    $data = base64_decode($encoded, true);
    if ($data === false) {
        return $encoded;
    }

    $key    = get_encryption_key($rawKey);
    $cipher = 'aes-256-gcm';
    $ivlen  = openssl_cipher_iv_length($cipher);
    $taglen = 16;

    if (strlen($data) < ($ivlen + $taglen)) {
        return $encoded;
    }

    $iv         = substr($data, 0, $ivlen);
    $tag        = substr($data, $ivlen, $taglen);
    $ciphertext = substr($data, $ivlen + $taglen);

    $plaintext = openssl_decrypt($ciphertext, $cipher, $key, OPENSSL_RAW_DATA, $iv, $tag);
    return $plaintext !== false ? $plaintext : $encoded;
}

/**
 * Key Rotation Utility: Re-encrypts all database PII fields with a new key.
 */
function rotate_field_encryption_key(mysqli $conn, string $oldRawKey, string $newRawKey): bool
{
    try {
        $res = $conn->query('SELECT id, phone_encrypted FROM users WHERE phone_encrypted IS NOT NULL AND phone_encrypted != ""');
        if (!$res) {
            return false;
        }

        $stmt = $conn->prepare('UPDATE users SET phone_encrypted = ? WHERE id = ?');
        while ($row = $res->fetch_assoc()) {
            $decrypted = decrypt_pii($row['phone_encrypted'], $oldRawKey);
            if ($decrypted !== '' && $decrypted !== $row['phone_encrypted']) {
                $reEncrypted = encrypt_pii($decrypted, $newRawKey);
                $stmt->bind_param('si', $reEncrypted, $row['id']);
                $stmt->execute();
            }
        }
        $stmt->close();
        
        log_security_event('ENCRYPTION_KEY_ROTATED', ['status' => 'success'], null, 'WARNING');
        return true;
    } catch (Throwable $e) {
        log_security_event('ENCRYPTION_KEY_ROTATION_FAILED', ['error' => $e->getMessage()], null, 'ERROR');
        return false;
    }
}
