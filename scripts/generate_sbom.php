<?php
/**
 * ============================================================================
 *  scripts/generate_sbom.php — SOFTWARE BILL OF MATERIALS (SBOM) GENERATOR
 * ============================================================================
 *  Generates an SPDX/CycloneDX compatible JSON Software Bill of Materials (sbom.json)
 *  auditing PHP runtime extensions, vendor packages, and security dependencies.
 * ============================================================================
 */

echo "=======================================================\n";
echo " GENERATING SOFTWARE BILL OF MATERIALS (SBOM)\n";
echo "=======================================================\n";

$projectRoot = dirname(__DIR__);
$sbomPath = $projectRoot . '/sbom.json';

$components = [
    [
        'type' => 'platform',
        'name' => 'PHP',
        'version' => PHP_VERSION,
        'licenses' => ['PHP-3.01'],
        'description' => 'PHP Core Runtime Environment'
    ]
];

// Scan active PHP extensions
$loadedExts = get_loaded_extensions();
foreach (['mysqli', 'openssl', 'json', 'mbstring', 'curl', 'sodium'] as $ext) {
    if (in_array($ext, $loadedExts, true)) {
        $components[] = [
            'type' => 'extension',
            'name' => "ext-{$ext}",
            'version' => phpversion($ext) ?: PHP_VERSION,
            'status' => 'active'
        ];
    }
}

// Parse composer.json / composer.lock if present
if (file_exists($projectRoot . '/composer.lock')) {
    $lockData = json_decode(file_get_contents($projectRoot . '/composer.lock'), true);
    if (isset($lockData['packages'])) {
        foreach ($lockData['packages'] as $pkg) {
            $components[] = [
                'type' => 'library',
                'name' => $pkg['name'],
                'version' => $pkg['version'],
                'license' => $pkg['license'] ?? ['UNKNOWN'],
                'source' => $pkg['source']['url'] ?? ''
            ];
        }
    }
}

$sbom = [
    'bomFormat' => 'CycloneDX',
    'specVersion' => '1.4',
    'serialNumber' => 'urn:uuid:' . sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    ),
    'metadata' => [
        'timestamp' => date('c'),
        'tools' => [
            ['name' => 'SecureAuth SBOM Generator', 'version' => '2.0.0']
        ],
        'component' => [
            'name' => 'SecureAuth Login & Session Management Module',
            'version' => '2.0.0',
            'type' => 'application'
        ]
    ],
    'components' => $components
];

file_put_contents($sbomPath, json_encode($sbom, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

echo "✅ [SUCCESS] SBOM generated successfully: sbom.json (" . count($components) . " components audited)\n";
