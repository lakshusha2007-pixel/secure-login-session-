<?php
/**
 * ============================================================================
 *  includes/validation.php — API INPUT SCHEMA & DATA TYPE VALIDATION
 * ============================================================================
 *  Validates incoming JSON payloads and POST arrays against schema rules,
 *  rejecting malformed or unexpected data before database or business logic execution.
 * ============================================================================
 */

/**
 * Validates input data against schema rules.
 *
 * Example Schema Rule Array:
 * [
 *     'fullname' => ['required', 'string', 'min_len:3', 'max_len:50'],
 *     'email'    => ['required', 'email'],
 *     'role'     => ['string', 'in:user,admin,super_admin']
 * ]
 */
function validate_input_schema(array $input, array $schema): array
{
    $errors = [];

    foreach ($schema as $field => $rules) {
        $value = $input[$field] ?? null;

        foreach ($rules as $rule) {
            if ($rule === 'required') {
                if ($value === null || (is_string($value) && trim($value) === '') || (is_array($value) && empty($value))) {
                    $errors[$field][] = "The field '{$field}' is required.";
                    break;
                }
            }

            // Skip further checks if optional field is empty/null
            if ($value === null || $value === '') {
                continue;
            }

            if ($rule === 'string') {
                if (!is_string($value)) {
                    $errors[$field][] = "The field '{$field}' must be a string.";
                }
            } elseif ($rule === 'int' || $rule === 'integer') {
                if (!filter_var($value, FILTER_VALIDATE_INT) && !is_int($value)) {
                    $errors[$field][] = "The field '{$field}' must be an integer.";
                }
            } elseif ($rule === 'numeric') {
                if (!is_numeric($value)) {
                    $errors[$field][] = "The field '{$field}' must be numeric.";
                }
            } elseif ($rule === 'array') {
                if (!is_array($value)) {
                    $errors[$field][] = "The field '{$field}' must be an array.";
                }
            } elseif ($rule === 'email') {
                if (!filter_var($value, FILTER_VALIDATE_EMAIL)) {
                    $errors[$field][] = "The field '{$field}' must be a valid email address.";
                }
            } elseif (str_starts_with($rule, 'min_len:')) {
                $min = (int)explode(':', $rule)[1];
                if (is_string($value) && mb_strlen($value, 'UTF-8') < $min) {
                    $errors[$field][] = "The field '{$field}' must be at least {$min} characters long.";
                }
            } elseif (str_starts_with($rule, 'max_len:')) {
                $max = (int)explode(':', $rule)[1];
                if (is_string($value) && mb_strlen($value, 'UTF-8') > $max) {
                    $errors[$field][] = "The field '{$field}' must not exceed {$max} characters.";
                }
            } elseif (str_starts_with($rule, 'min:')) {
                $min = (float)explode(':', $rule)[1];
                if (is_numeric($value) && (float)$value < $min) {
                    $errors[$field][] = "The field '{$field}' must be at least {$min}.";
                }
            } elseif (str_starts_with($rule, 'max:')) {
                $max = (float)explode(':', $rule)[1];
                if (is_numeric($value) && (float)$value > $max) {
                    $errors[$field][] = "The field '{$field}' must not exceed {$max}.";
                }
            } elseif (str_starts_with($rule, 'in:')) {
                $allowed = explode(',', explode(':', $rule)[1]);
                if (!in_array((string)$value, $allowed, true)) {
                    $errors[$field][] = "The field '{$field}' must be one of: " . implode(', ', $allowed) . ".";
                }
            }
        }
    }

    return [
        'valid'  => empty($errors),
        'errors' => $errors
    ];
}

/**
 * Returns formatted HTTP 400 validation error JSON response and exits.
 */
function send_validation_error(array $errors): void
{
    http_response_code(400);
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode([
        'error'   => 'Validation failed. Invalid input schema provided.',
        'details' => $errors
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

/**
 * Detects common SQL injection attack patterns in user inputs.
 */
function detect_sqli_pattern(string $input): bool
{
    if (empty($input)) {
        return false;
    }

    $patterns = [
        '/\b(union(\s+all)?\s+select)\b/i',
        '/\b(select\s+.+\s+from)\b/i',
        '/\b(insert\s+into.+values)\b/i',
        '/\b(update\s+.+\s+set)\b/i',
        '/\b(delete\s+from)\b/i',
        '/\b(drop\s+(table|database|view|trigger))\b/i',
        '/\b(alter\s+table)\b/i',
        '/\b(truncate\s+table)\b/i',
        '/\b(benchmark|sleep)\s*\(/i',
        '/(\'|\")\s*(or|and)\s*(\'|\")?\s*\d+\s*=\s*(\'|\")?\d+/i',
        '/(\'|\")\s*(or|and)\s*(\'|\")?[a-z0-9_]*(\'|\")?\s*=\s*(\'|\")?[a-z0-9_]*/i',
        '/(\'|\")\s*(or|and)\s*(\'|\")\s*=\s*(\'|\")/i',
        '/\badmin(\'|\")\s*(--|#)/i',
        '/(--|#)\s*$/m',
        '/\/\*.*?\*\//s',
        '/;\s*(select|insert|update|delete|drop)/i'
    ];

    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $input)) {
            return true;
        }
    }
    return false;
}
