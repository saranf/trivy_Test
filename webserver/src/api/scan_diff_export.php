<?php
/**
 * Scan Diff Export — CSOP Lab
 *
 * Exports a scan-to-scan diff as either a MORI import envelope (JSON,
 * schema: mori.trivy.findings.v1) or an evidence CSV.
 *
 * This is step 1 of MORI integration (download the artifact). Step 2 sends it
 * to server_mock; step 3 posts to MORI. See docs/MORI_INTEGRATION.md.
 *
 *   GET api/scan_diff_export.php?old=<id>&new=<id>&format=json|csv
 */
require_once __DIR__ . '/../db_functions.php';

$conn = getDbConnection();
$old = (int)($_GET['old'] ?? 0);
$new = (int)($_GET['new'] ?? 0);
$format = strtolower($_GET['format'] ?? 'json');
$dest = strtolower($_GET['dest'] ?? 'download');

if (!$conn || !$old || !$new) {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'need valid old and new scan ids']);
    exit;
}

$stamp = date('Ymd_His');

// dest=mori → push the diff-aware envelope to MORI POST /ingest/evidence
if ($dest === 'mori') {
    header('Content-Type: application/json');
    $envelope = buildMoriEvidenceEnvelope($conn, $old, $new);
    $resp = moriApiPost('/ingest/evidence', $envelope);
    $status = $resp['_status'] ?? 0;
    if ($status >= 200 && $status < 300) {
        echo json_encode(['success' => true, 'status' => $status,
                          'sent' => count($envelope['findings']), 'mori' => $resp]);
    } else {
        echo json_encode(['success' => false, 'status' => $status,
                          'error' => $resp['_error'] ?? 'MORI push failed', 'mori' => $resp]);
    }
    exit;
}

if ($format === 'csv') {
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="scan_diff_' . $stamp . '.csv"');
    echo buildScanDiffCsv($conn, $old, $new);
} else {
    $envelope = buildMoriEvidenceEnvelope($conn, $old, $new);
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Disposition: attachment; filename="mori_trivy_findings_' . $stamp . '.json"');
    echo json_encode($envelope, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}
