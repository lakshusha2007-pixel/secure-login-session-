<?php
/**
 * ============================================================================
 *  config/mail.php — GMAIL SMTP DISPATCH & EMAIL HELPER
 * ============================================================================
 *  Sends HTML emails using Gmail SMTP (STARTTLS / App Password) or PHP mail().
 *  Supports environment variables: MAIL_HOST, MAIL_PORT, MAIL_USERNAME, etc.
 * ============================================================================
 */

require_once __DIR__ . '/env.php';

if (!defined('MAIL_HOST'))       define('MAIL_HOST',       getenv('MAIL_HOST')       ?: 'smtp.gmail.com');
if (!defined('MAIL_PORT'))       define('MAIL_PORT',       (int)(getenv('MAIL_PORT') ?: 587));
if (!defined('MAIL_USERNAME'))   define('MAIL_USERNAME',   getenv('MAIL_USERNAME')   ?: '');
if (!defined('MAIL_PASSWORD'))   define('MAIL_PASSWORD',   getenv('MAIL_PASSWORD')   ?: '');
if (!defined('MAIL_FROM_EMAIL')) define('MAIL_FROM_EMAIL', getenv('MAIL_FROM_EMAIL') ?: 'no-reply@secureauth.local');
if (!defined('MAIL_FROM_NAME'))  define('MAIL_FROM_NAME',  getenv('MAIL_FROM_NAME')  ?: 'SecureAuth System');

/**
 * Dispatches an HTML email via Gmail SMTP socket or native PHP mail()
 */
function send_app_mail(string $toEmail, string $toName, string $subject, string $bodyHtml): bool
{
    $timestamp = date('Y-m-d H:i:s');
    
    // Log email dispatch event to logs/mail_outbox.log (without logging OTPs/passwords)
    $logDir = __DIR__ . '/../logs';
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0777, true);
    }
    $logFile = $logDir . '/mail_outbox.log';
    $logEntry = "[$timestamp] MAIL DISPATCH -> To: $toName <$toEmail> | Subject: $subject | Status: SENT\n";
    @file_put_contents($logFile, $logEntry, FILE_APPEND);

    // If Gmail SMTP credentials are configured, send via SMTP Socket
    if (MAIL_USERNAME !== '' && MAIL_PASSWORD !== '') {
        return send_smtp_socket(MAIL_HOST, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD, MAIL_FROM_EMAIL, MAIL_FROM_NAME, $toEmail, $toName, $subject, $bodyHtml);
    }

    // Fallback to native PHP mail()
    $headers  = "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
    $headers .= "From: " . MAIL_FROM_NAME . " <" . MAIL_FROM_EMAIL . ">\r\n";
    $headers .= "Reply-To: " . MAIL_FROM_EMAIL . "\r\n";

    return @mail($toEmail, $subject, $bodyHtml, $headers);
}

/**
 * Native Socket-based SMTP Client supporting TLS / Gmail App Passwords
 */
function send_smtp_socket(string $host, int $port, string $user, string $pass, string $fromEmail, string $fromName, string $toEmail, string $toName, string $subject, string $bodyHtml): bool
{
    $timeout = 15;
    $socket  = @fsockopen($host, $port, $errno, $errstr, $timeout);

    if (!$socket) {
        error_log("SMTP Connection Error: $errstr ($errno)");
        return false;
    }

    $read = function() use ($socket) {
        $response = '';
        while ($line = @fgets($socket, 512)) {
            $response .= $line;
            if (substr($line, 3, 1) === ' ') break;
        }
        return $response;
    };

    $send = function(string $cmd) use ($socket) {
        @fputs($socket, $cmd . "\r\n");
    };

    $read(); // Read initial server welcome string

    $send("EHLO " . gethostname());
    $read();

    if ($port === 587) {
        $send("STARTTLS");
        $tlsRes = $read();
        if (str_starts_with($tlsRes, '220')) {
            @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
            $send("EHLO " . gethostname());
            $read();
        }
    }

    $send("AUTH LOGIN");
    $read();
    $send(base64_encode($user));
    $read();
    $send(base64_encode($pass));
    $authRes = $read();

    if (!str_starts_with($authRes, '235')) {
        error_log("SMTP Auth Failed: " . trim($authRes));
        @fclose($socket);
        return false;
    }

    $send("MAIL FROM: <$fromEmail>");
    $read();
    $send("RCPT TO: <$toEmail>");
    $read();
    $send("DATA");
    $read();

    $headers  = "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
    $headers .= "From: $fromName <$fromEmail>\r\n";
    $headers .= "To: $toName <$toEmail>\r\n";
    $headers .= "Subject: $subject\r\n\r\n";

    $send($headers . $bodyHtml . "\r\n.");
    $read();

    $send("QUIT");
    @fclose($socket);

    return true;
}
