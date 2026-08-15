<?php
/**
 * ============================================================================
 *  includes/totp.php — PURE PHP TOTP (RFC 6238) AUTHENTICATOR MODULE
 * ============================================================================
 *  Provides standard Time-based One-Time Password (TOTP) functionality
 *  compatible with Google Authenticator, Authy, Microsoft Authenticator, etc.
 * ============================================================================
 */

class TOTP
{
    private static string $base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Generates a 16-character Base32 random secret.
     */
    public static function generateSecret(int $length = 16): string
    {
        $secret = '';
        $bytes = random_bytes($length);
        for ($i = 0; $i < $length; $i++) {
            $secret .= self::$base32Chars[ord($bytes[$i]) % 32];
        }
        return $secret;
    }

    /**
     * Calculates the current 6-digit TOTP code for a given secret.
     */
    public static function getCode(string $secret, ?int $timeSlice = null): string
    {
        if ($timeSlice === null) {
            $timeSlice = (int)floor(time() / 30);
        }

        $secretKey = self::base32Decode($secret);
        // Pack timeSlice as 64-bit big-endian binary string
        $timePacked = pack('N*', 0) . pack('N*', $timeSlice);
        $hash = hash_hmac('sha1', $timePacked, $secretKey, true);
        $offset = ord(substr($hash, -1)) & 0x0F;

        $part = substr($hash, $offset, 4);
        $value = unpack('N', $part)[1] & 0x7FFFFFFF;

        $modulo = 10 ** 6;
        return str_pad((string)($value % $modulo), 6, '0', STR_PAD_LEFT);
    }

    /**
     * Verifies a 6-digit TOTP code against a secret within a clock skew window.
     */
    public static function verifyCode(string $secret, string $code, int $discrepancy = 1): bool
    {
        $code = trim($code);
        if (strlen($code) !== 6 || !ctype_digit($code)) {
            return false;
        }

        $currentTimeSlice = (int)floor(time() / 30);
        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $calculatedCode = self::getCode($secret, $currentTimeSlice + $i);
            if (hash_equals($calculatedCode, $code)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Builds standard otpauth:// URI for authenticator apps.
     */
    public static function getOtpAuthUrl(string $label, string $issuer, string $secret): string
    {
        return 'otpauth://totp/' . rawurlencode($issuer) . ':' . rawurlencode($label) .
               '?secret=' . rawurlencode($secret) . '&issuer=' . rawurlencode($issuer) . '&algorithm=SHA1&digits=6&period=30';
    }

    /**
     * Generates 8 single-use 10-character recovery codes.
     */
    public static function generateRecoveryCodes(int $count = 8): array
    {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $code = strtoupper(bin2hex(random_bytes(5)));
            $codes[] = substr($code, 0, 5) . '-' . substr($code, 5, 5);
        }
        return $codes;
    }

    /**
     * Decodes Base32 string to raw binary string.
     */
    private static function base32Decode(string $base32): string
    {
        $base32 = strtoupper($base32);
        $base32 = preg_replace('/[^A-Z2-7]/', '', $base32);
        $buffer = 0;
        $bitsLeft = 0;
        $output = '';

        for ($i = 0; $i < strlen($base32); $i++) {
            $val = strpos(self::$base32Chars, $base32[$i]);
            if ($val === false) continue;

            $buffer = ($buffer << 5) | $val;
            $bitsLeft += 5;

            if ($bitsLeft >= 8) {
                $bitsLeft -= 8;
                $output .= chr(($buffer >> $bitsLeft) & 0xFF);
            }
        }
        return $output;
    }
}
