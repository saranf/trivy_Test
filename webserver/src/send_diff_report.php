<?php
/**
 * 지능형 Diff 기반 리포팅 시스템
 * - 이전 스캔 vs 현재 스캔 비교
 * - New/Fixed/Persistent 분류
 * - 요약 제목 자동 생성
 */

// API 호출인지 확인
$isApiCall = $_SERVER['REQUEST_METHOD'] === 'POST' || isset($_GET['action']);

if ($isApiCall) {
    error_reporting(0);
    ini_set('display_errors', 0);
    header('Content-Type: application/json');

    session_start();
    require_once 'db_functions.php';

    // 로그인 확인
    if (!isset($_SESSION['user'])) {
        echo json_encode(['success' => false, 'message' => '로그인이 필요합니다.']);
        exit;
    }

    // Operator 이상 권한
    $userRole = $_SESSION['user']['role'] ?? '';
    $levels = ['viewer' => 1, 'operator' => 2, 'admin' => 3];
    if (($levels[$userRole] ?? 0) < 2) {
        echo json_encode(['success' => false, 'message' => 'Operator 이상 권한이 필요합니다.']);
        exit;
    }
} else {
    require_once 'auth.php';
    $user = requireRole('operator');
}

require_once 'db_functions.php';

// 메일 설정
$mailConfig = [
    'from' => getenv('FROM_EMAIL') ?: 'trivy-scanner@' . gethostname(),
    'fromName' => getenv('FROM_NAME') ?: 'Trivy Scanner'
];

/**
 * Diff 리포트 생성 및 발송
 * @param int $scanId 현재 스캔 ID
 * @param string $toEmail 수신자 이메일
 * @return array 결과
 */
function sendDiffReport($scanId, $toEmail, $mailConfig) {
    $conn = getDbConnection();
    if (!$conn) {
        return ['success' => false, 'message' => 'DB 연결 실패'];
    }
    initDatabase($conn);
    
    // 현재 스캔 정보 조회
    $stmt = $conn->prepare("SELECT * FROM scan_history WHERE id = ?");
    $stmt->bind_param("i", $scanId);
    $stmt->execute();
    $currentScan = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    
    if (!$currentScan) {
        return ['success' => false, 'message' => '스캔 데이터를 찾을 수 없습니다.'];
    }
    
    $imageName = $currentScan['image_name'];
    $currentVulns = getScanVulnerabilities($conn, $scanId);

    // 예외 처리된 취약점 목록 조회
    $activeExceptions = getActiveExceptions($conn);
    $exceptedVulns = [];
    foreach ($activeExceptions as $ex) {
        $exceptedVulns[$ex['vulnerability_id']] = $ex;
    }

    // 예외 처리 적용 (필터링)
    $filteredVulns = [];
    $exceptedList = [];  // 예외 처리된 항목 별도 저장
    foreach ($currentVulns as $v) {
        if (isset($exceptedVulns[$v['vulnerability']])) {
            $v['excepted'] = true;
            $v['exception_reason'] = $exceptedVulns[$v['vulnerability']]['reason'];
            $v['exception_expires'] = $exceptedVulns[$v['vulnerability']]['expires_at'];
            $exceptedList[] = $v;
        } else {
            $v['excepted'] = false;
            $filteredVulns[] = $v;
        }
    }

    // 이전 스캔 조회 (같은 이미지의 직전 스캔)
    $stmt = $conn->prepare("SELECT id FROM scan_history WHERE image_name = ? AND id < ? ORDER BY id DESC LIMIT 1");
    $stmt->bind_param("si", $imageName, $scanId);
    $stmt->execute();
    $prevResult = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    $diff = [
        'new' => [],
        'fixed' => [],
        'persistent' => [],
        'excepted' => $exceptedList,  // 예외 처리된 항목
        'has_previous' => false
    ];

    if ($prevResult) {
        $diff['has_previous'] = true;
        $prevVulns = getScanVulnerabilities($conn, $prevResult['id']);

        // 이전 취약점 맵 생성 (예외 제외)
        $prevMap = [];
        foreach ($prevVulns as $v) {
            if (!isset($exceptedVulns[$v['vulnerability']])) {
                $prevMap[$v['vulnerability']] = $v;
            }
        }

        // 현재 취약점 맵 생성 (예외 제외)
        $currMap = [];
        foreach ($filteredVulns as $v) {
            $currMap[$v['vulnerability']] = $v;
        }

        // New: 현재에만 있는 것 (예외 제외)
        foreach ($filteredVulns as $v) {
            if (!isset($prevMap[$v['vulnerability']])) {
                $diff['new'][] = $v;
            } else {
                $diff['persistent'][] = $v;
            }
        }

        // Fixed: 이전에만 있는 것
        foreach ($prevVulns as $v) {
            if (!isset($currMap[$v['vulnerability']]) && !isset($exceptedVulns[$v['vulnerability']])) {
                $diff['fixed'][] = $v;
            }
        }
    } else {
        // 첫 스캔인 경우 모두 new로 처리 (예외 제외)
        $diff['new'] = $filteredVulns;
    }
    
    // 심각도별 신규 취약점 카운트
    $newCounts = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
    foreach ($diff['new'] as $v) {
        if (isset($newCounts[$v['severity']])) {
            $newCounts[$v['severity']]++;
        }
    }
    
    // 제목 생성
    $subject = generateDiffSubject($diff, $newCounts, $imageName);
    
    // HTML 생성
    $html = generateDiffHtml($currentScan, $diff, $newCounts);
    
    // CSV 생성
    $csv = generateDiffCsv($currentScan, $diff);
    
    // 이메일 발송
    include_once 'send_email.php';
    return sendEmailLocal($toEmail, $subject, $html, $csv, $mailConfig);
}

/**
 * Diff 기반 제목 생성
 */
function generateDiffSubject($diff, $newCounts, $imageName) {
    $newTotal = count($diff['new']);
    $fixedTotal = count($diff['fixed']);

    $parts = [];

    if ($newTotal > 0) {
        $criticalNote = $newCounts['CRITICAL'] > 0 ? " (Critical {$newCounts['CRITICAL']}건)" : "";
        $parts[] = "신규 {$newTotal}건{$criticalNote}";
    }

    if ($fixedTotal > 0) {
        $parts[] = "조치 {$fixedTotal}건";
    }

    if (empty($parts)) {
        return "[보안알림] {$imageName} - 변동 없음";
    }

    $shortImage = basename(explode(':', $imageName)[0]);
    return "[보안알림] {$shortImage} - " . implode(' / ', $parts);
}

/**
 * Diff HTML 생성
 */
function generateDiffHtml($scan, $diff, $newCounts) {
    $html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .summary-box { display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }
        .summary-card { padding: 20px; border-radius: 8px; text-align: center; min-width: 120px; }
        .card-new { background: #fff3cd; border: 2px solid #ffc107; }
        .card-fixed { background: #d4edda; border: 2px solid #28a745; }
        .card-persistent { background: #e2e3e5; border: 2px solid #6c757d; }
        .card-number { font-size: 36px; font-weight: bold; }
        .card-label { font-size: 14px; color: #666; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 10px; text-align: left; border: 1px solid #ddd; font-size: 13px; }
        th { background: #f8f9fa; }
        .critical { background: #dc3545; color: white; padding: 3px 8px; border-radius: 4px; }
        .high { background: #fd7e14; color: white; padding: 3px 8px; border-radius: 4px; }
        .medium { background: #ffc107; color: #333; padding: 3px 8px; border-radius: 4px; }
        .low { background: #28a745; color: white; padding: 3px 8px; border-radius: 4px; }
        .section-new { border-left: 4px solid #ffc107; padding-left: 15px; }
        .section-fixed { border-left: 4px solid #28a745; padding-left: 15px; }
        .section-persistent { border-left: 4px solid #6c757d; padding-left: 15px; }
        .tag-new { background: #ffc107; color: #333; padding: 2px 6px; border-radius: 3px; font-size: 11px; }
        .tag-fixed { background: #28a745; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px; }
        .no-data { color: #666; font-style: italic; }
    </style></head><body><div class="container">';

    $html .= '<h1>🔒 Trivy 보안 스캔 리포트</h1>';
    $html .= '<p><strong>이미지:</strong> ' . htmlspecialchars($scan['image_name']) . '</p>';
    $html .= '<p><strong>스캔일시:</strong> ' . $scan['scan_date'] . '</p>';

    // 요약 카드
    $exceptedCount = count($diff['excepted'] ?? []);
    $html .= '<div class="summary-box">';
    $html .= '<div class="summary-card card-new"><div class="card-number">' . count($diff['new']) . '</div><div class="card-label">🆕 신규 취약점</div></div>';
    $html .= '<div class="summary-card card-fixed"><div class="card-number">' . count($diff['fixed']) . '</div><div class="card-label">✅ 조치 완료</div></div>';
    $html .= '<div class="summary-card card-persistent"><div class="card-number">' . count($diff['persistent']) . '</div><div class="card-label">⏳ 미조치</div></div>';
    if ($exceptedCount > 0) {
        $html .= '<div class="summary-card" style="background:#e3f2fd;border:2px solid #1976d2;"><div class="card-number">' . $exceptedCount . '</div><div class="card-label">🛡️ 예외 처리</div></div>';
    }
    $html .= '</div>';

    // 신규 취약점 (가장 중요)
    $html .= '<div class="section-new"><h2>🆕 신규 취약점 (' . count($diff['new']) . '건)</h2>';
    if (!empty($diff['new'])) {
        $html .= renderVulnTable($diff['new']);
    } else {
        $html .= '<p class="no-data">신규 취약점이 없습니다.</p>';
    }
    $html .= '</div>';

    // 조치 완료
    $html .= '<div class="section-fixed"><h2>✅ 조치 완료 (' . count($diff['fixed']) . '건)</h2>';
    if (!empty($diff['fixed'])) {
        $html .= renderVulnTable($diff['fixed']);
    } else {
        $html .= '<p class="no-data">조치 완료된 취약점이 없습니다.</p>';
    }
    $html .= '</div>';

    // 미조치 (persistent)
    if (!empty($diff['persistent'])) {
        $html .= '<div class="section-persistent"><h2>⏳ 미조치 (' . count($diff['persistent']) . '건)</h2>';
        $html .= renderVulnTable($diff['persistent']);
        $html .= '</div>';
    }

    // 예외 처리된 항목
    if (!empty($diff['excepted'])) {
        $html .= '<div style="border-left:4px solid #1976d2;padding-left:15px;"><h2>🛡️ 예외 처리됨 (' . $exceptedCount . '건)</h2>';
        $html .= '<p style="color:#666;font-size:13px;">아래 취약점은 예외 처리되어 집계에서 제외되었습니다.</p>';
        $html .= renderExceptedTable($diff['excepted']);
        $html .= '</div>';
    }

    $html .= '<hr><p style="color:#666;font-size:12px;">이 메일은 Trivy Security Scanner에서 자동 발송되었습니다.</p>';
    $html .= '</div></body></html>';

    return $html;
}

function renderVulnTable($vulns) {
    $html = '<table><thead><tr><th>Library</th><th>CVE</th><th>심각도</th><th>설치버전</th><th>패치버전</th></tr></thead><tbody>';
    foreach ($vulns as $v) {
        $sevClass = strtolower($v['severity']);
        $html .= '<tr>';
        $html .= '<td>' . htmlspecialchars($v['library']) . '</td>';
        $html .= '<td>' . htmlspecialchars($v['vulnerability']) . '</td>';
        $html .= '<td><span class="' . $sevClass . '">' . $v['severity'] . '</span></td>';
        $html .= '<td>' . htmlspecialchars($v['installed_version']) . '</td>';
        $html .= '<td>' . htmlspecialchars($v['fixed_version'] ?: '-') . '</td>';
        $html .= '</tr>';
    }
    $html .= '</tbody></table>';
    return $html;
}

function renderExceptedTable($vulns) {
    $html = '<table><thead><tr><th>Library</th><th>CVE</th><th>심각도</th><th>예외 사유</th><th>만료일</th></tr></thead><tbody>';
    foreach ($vulns as $v) {
        $sevClass = strtolower($v['severity']);
        $expiresDate = isset($v['exception_expires']) ? date('Y-m-d', strtotime($v['exception_expires'])) : '-';
        $html .= '<tr style="background:#f0f7ff;">';
        $html .= '<td>' . htmlspecialchars($v['library']) . '</td>';
        $html .= '<td>' . htmlspecialchars($v['vulnerability']) . '</td>';
        $html .= '<td><span class="' . $sevClass . '">' . $v['severity'] . '</span></td>';
        $html .= '<td>' . htmlspecialchars($v['exception_reason'] ?? '-') . '</td>';
        $html .= '<td>' . $expiresDate . '</td>';
        $html .= '</tr>';
    }
    $html .= '</tbody></table>';
    return $html;
}

/**
 * Diff CSV 생성
 */
function generateDiffCsv($scan, $diff) {
    $lines = [];
    $lines[] = "Status,Image,Library,Vulnerability,Severity,Installed Version,Fixed Version,Exception Reason,Exception Expires";

    $imageName = $scan['image_name'];

    foreach ($diff['new'] as $v) {
        $lines[] = sprintf('"NEW","%s","%s","%s","%s","%s","%s","",""',
            str_replace('"', '""', $imageName),
            str_replace('"', '""', $v['library']),
            str_replace('"', '""', $v['vulnerability']),
            $v['severity'],
            str_replace('"', '""', $v['installed_version']),
            str_replace('"', '""', $v['fixed_version'] ?: '')
        );
    }

    foreach ($diff['fixed'] as $v) {
        $lines[] = sprintf('"FIXED","%s","%s","%s","%s","%s","%s","",""',
            str_replace('"', '""', $imageName),
            str_replace('"', '""', $v['library']),
            str_replace('"', '""', $v['vulnerability']),
            $v['severity'],
            str_replace('"', '""', $v['installed_version']),
            str_replace('"', '""', $v['fixed_version'] ?: '')
        );
    }

    foreach ($diff['persistent'] as $v) {
        $lines[] = sprintf('"PERSISTENT","%s","%s","%s","%s","%s","%s","",""',
            str_replace('"', '""', $imageName),
            str_replace('"', '""', $v['library']),
            str_replace('"', '""', $v['vulnerability']),
            $v['severity'],
            str_replace('"', '""', $v['installed_version']),
            str_replace('"', '""', $v['fixed_version'] ?: '')
        );
    }

    // 예외 처리된 항목
    foreach ($diff['excepted'] ?? [] as $v) {
        $expiresDate = isset($v['exception_expires']) ? date('Y-m-d', strtotime($v['exception_expires'])) : '';
        $lines[] = sprintf('"EXCEPTED","%s","%s","%s","%s","%s","%s","%s","%s"',
            str_replace('"', '""', $imageName),
            str_replace('"', '""', $v['library']),
            str_replace('"', '""', $v['vulnerability']),
            $v['severity'],
            str_replace('"', '""', $v['installed_version']),
            str_replace('"', '""', $v['fixed_version'] ?: ''),
            str_replace('"', '""', $v['exception_reason'] ?? ''),
            $expiresDate
        );
    }

    return implode("\n", $lines);
}

// Preview API (화면에 Diff 결과 표시)
if (isset($_GET['action']) && $_GET['action'] === 'preview') {
    $scanId = (int)($_GET['scan_id'] ?? 0);

    if ($scanId <= 0) {
        echo json_encode(['success' => false, 'message' => 'scan_id가 필요합니다.']);
        exit;
    }

    $conn = getDbConnection();
    if (!$conn) {
        echo json_encode(['success' => false, 'message' => 'DB 연결 실패']);
        exit;
    }
    initDatabase($conn);

    // 현재 스캔 정보
    $stmt = $conn->prepare("SELECT * FROM scan_history WHERE id = ?");
    $stmt->bind_param("i", $scanId);
    $stmt->execute();
    $currentScan = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    if (!$currentScan) {
        echo json_encode(['success' => false, 'message' => '스캔을 찾을 수 없습니다.']);
        exit;
    }

    // 이전 스캔 찾기
    $stmt = $conn->prepare("SELECT * FROM scan_history WHERE image_name = ? AND id < ? ORDER BY id DESC LIMIT 1");
    $stmt->bind_param("si", $currentScan['image_name'], $scanId);
    $stmt->execute();
    $prevScan = $stmt->get_result()->fetch_assoc();
    $stmt->close();

    // 현재 취약점
    $currentVulns = getScanVulnerabilities($conn, $scanId);
    $prevVulns = $prevScan ? getScanVulnerabilities($conn, $prevScan['id']) : [];

    // 예외 처리 정보
    $activeExceptions = getActiveExceptions($conn);
    $exceptedMap = [];
    foreach ($activeExceptions as $ex) {
        $exceptedMap[$ex['vulnerability_id']] = $ex;
    }

    // Diff 계산
    $currentKeys = [];
    $prevKeys = [];

    foreach ($currentVulns as $v) {
        $key = $v['vulnerability'] . '|' . $v['library'];
        $currentKeys[$key] = $v;
    }
    foreach ($prevVulns as $v) {
        $key = $v['vulnerability'] . '|' . $v['library'];
        $prevKeys[$key] = $v;
    }

    $diff = ['new' => [], 'fixed' => [], 'persistent' => [], 'excepted' => []];

    // New & Persistent
    foreach ($currentKeys as $key => $v) {
        // 예외 처리 확인
        if (isset($exceptedMap[$v['vulnerability']])) {
            $v['excepted'] = true;
            $v['exception_reason'] = $exceptedMap[$v['vulnerability']]['reason'];
            $v['exception_expires'] = $exceptedMap[$v['vulnerability']]['expires_at'];
            $diff['excepted'][] = $v;
        } elseif (!isset($prevKeys[$key])) {
            $diff['new'][] = $v;
        } else {
            $diff['persistent'][] = $v;
        }
    }

    // Fixed
    foreach ($prevKeys as $key => $v) {
        if (!isset($currentKeys[$key])) {
            $diff['fixed'][] = $v;
        }
    }

    $summary = [
        'new' => count($diff['new']),
        'fixed' => count($diff['fixed']),
        'persistent' => count($diff['persistent']),
        'excepted' => count($diff['excepted']),
        'total' => count($currentVulns)
    ];

    echo json_encode([
        'success' => true,
        'scan' => $currentScan,
        'prev_scan' => $prevScan,
        'diff' => $diff,
        'summary' => $summary
    ]);
    exit;
}

// Send API (이메일 발송)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    $scanId = (int)($data['scan_id'] ?? 0);
    $toEmail = $data['email'] ?? '';

    if ($scanId <= 0 || empty($toEmail)) {
        echo json_encode(['success' => false, 'message' => 'scan_id와 email이 필요합니다.']);
        exit;
    }

    if (!filter_var($toEmail, FILTER_VALIDATE_EMAIL)) {
        echo json_encode(['success' => false, 'message' => '유효하지 않은 이메일 주소입니다.']);
        exit;
    }

    $result = sendDiffReport($scanId, $toEmail, $mailConfig);

    // 감사 로그
    $conn = getDbConnection();
    if ($conn) {
        logAudit($conn, $_SESSION['user']['id'] ?? null, $_SESSION['user']['username'] ?? 'unknown',
                 'SEND_DIFF_REPORT', 'scan', $scanId, "to: {$toEmail}");
    }

    echo json_encode($result);
    exit;
}

// UI 페이지
$conn = getDbConnection();
if ($conn) {
    initDatabase($conn);
}
$scans = $conn ? getScanHistory($conn, '', '') : [];
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Diff 리포트</title>
    <style>
        <?= getAuthStyles() ?>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .card { background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: 600; color: #333; }
        select, input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
        .btn { padding: 12px 25px; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; margin-right: 10px; }
        .btn-preview { background: #17a2b8; }
        .btn-preview:hover { background: #138496; }
        .btn-send { background: #f5576c; }
        .btn-send:hover { background: #e4455b; }
        .btn:disabled { background: #ccc; }
        .result { margin-top: 20px; padding: 15px; border-radius: 4px; }
        .result.success { background: #d4edda; color: #155724; }
        .result.error { background: #f8d7da; color: #721c24; }
        .info-box { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .info-box h2 { margin-top: 0; }
        .summary-cards { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 20px; }
        .summary-card { padding: 15px; border-radius: 8px; text-align: center; color: white; }
        .summary-card h3 { margin: 0 0 5px 0; font-size: 28px; }
        .summary-card p { margin: 0; font-size: 12px; }
        .card-new { background: #dc3545; }
        .card-fixed { background: #28a745; }
        .card-persistent { background: #6c757d; }
        .card-excepted { background: #1976d2; }
        .card-total { background: #343a40; }
        .diff-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .diff-table th, .diff-table td { padding: 10px; border: 1px solid #ddd; text-align: left; font-size: 13px; }
        .diff-table th { background: #f8f9fa; font-weight: 600; }
        .status-new { background: #f8d7da; }
        .status-fixed { background: #d4edda; }
        .status-persistent { background: #fff3cd; }
        .status-excepted { background: #cce5ff; }
        .badge { padding: 3px 8px; border-radius: 12px; font-size: 11px; color: white; }
        .badge.critical { background: #dc3545; }
        .badge.high { background: #fd7e14; }
        .badge.medium { background: #ffc107; color: #333; }
        .badge.low { background: #28a745; }
        .exception-badge { background: #1976d2; color: white; padding: 2px 6px; border-radius: 10px; font-size: 10px; margin-left: 5px; }
        #diffResult { display: none; }
        .btn-group { display: flex; gap: 10px; align-items: center; }
    </style>
</head>
<body>
    <?= getNavMenu() ?>
    <div class="container">
        <div class="info-box">
            <h2>📊 Diff 기반 지능형 리포트</h2>
            <p>이전 스캔 대비 취약점 변화를 분석하여 New/Fixed/Persistent/Excepted로 분류합니다.</p>
        </div>

        <div class="card">
            <h2>1️⃣ 스캔 선택 및 분석</h2>
            <div class="form-group">
                <label for="scanId">분석할 스캔 선택</label>
                <select id="scanId" required>
                    <option value="">-- 스캔 기록 선택 --</option>
                    <?php foreach ($scans as $s): ?>
                    <option value="<?= $s['id'] ?>">[<?= $s['id'] ?>] <?= htmlspecialchars($s['image_name']) ?> (<?= $s['scan_date'] ?>) - <?= $s['total_vulns'] ?>건</option>
                    <?php endforeach; ?>
                </select>
            </div>
            <button class="btn btn-preview" id="previewBtn" onclick="previewDiff()">🔍 Diff 미리보기</button>
        </div>

        <div id="diffResult">
            <div class="summary-cards" id="summaryCards"></div>

            <div class="card">
                <h2>📋 Diff 상세 결과</h2>
                <div id="diffTables"></div>
            </div>

            <div class="card">
                <h2>2️⃣ 이메일 발송 (선택)</h2>
                <div class="form-group">
                    <label for="email">수신 이메일</label>
                    <input type="email" id="email" placeholder="report@example.com">
                </div>
                <div class="btn-group">
                    <button class="btn btn-send" id="sendBtn" onclick="sendReport()">📨 이메일 발송</button>
                    <span id="sendStatus"></span>
                </div>
            </div>
        </div>
    </div>

    <script>
    let currentDiffData = null;

    async function previewDiff() {
        const scanId = document.getElementById('scanId').value;
        if (!scanId) { alert('스캔을 선택하세요.'); return; }

        const btn = document.getElementById('previewBtn');
        btn.disabled = true;
        btn.textContent = '분석 중...';

        try {
            const resp = await fetch('send_diff_report.php?action=preview&scan_id=' + scanId);
            const data = await resp.json();

            if (data.success) {
                currentDiffData = data;
                renderDiffResult(data);
                document.getElementById('diffResult').style.display = 'block';
            } else {
                alert('오류: ' + data.message);
            }
        } catch (err) {
            alert('오류: ' + err.message);
        }

        btn.disabled = false;
        btn.textContent = '🔍 Diff 미리보기';
    }

    function renderDiffResult(data) {
        const diff = data.diff;
        const summary = data.summary;

        // Summary Cards
        document.getElementById('summaryCards').innerHTML = `
            <div class="summary-card card-new"><h3>${summary.new}</h3><p>🆕 신규</p></div>
            <div class="summary-card card-fixed"><h3>${summary.fixed}</h3><p>✅ 조치 완료</p></div>
            <div class="summary-card card-persistent"><h3>${summary.persistent}</h3><p>⚠️ 잔존</p></div>
            <div class="summary-card card-excepted"><h3>${summary.excepted || 0}</h3><p>🛡️ 예외 처리</p></div>
            <div class="summary-card card-total"><h3>${summary.total}</h3><p>📊 전체</p></div>
        `;

        // Tables
        let html = '';

        if (diff.new && diff.new.length > 0) {
            html += renderTable('🆕 신규 취약점 (NEW)', diff.new, 'status-new');
        }
        if (diff.fixed && diff.fixed.length > 0) {
            html += renderTable('✅ 조치 완료 (FIXED)', diff.fixed, 'status-fixed');
        }
        if (diff.excepted && diff.excepted.length > 0) {
            html += renderTable('🛡️ 예외 처리 (EXCEPTED)', diff.excepted, 'status-excepted', true);
        }
        if (diff.persistent && diff.persistent.length > 0) {
            html += renderTable('⚠️ 잔존 취약점 (PERSISTENT)', diff.persistent, 'status-persistent');
        }

        if (!html) {
            html = '<p style="text-align:center;color:#666;">이전 스캔이 없거나 변동 사항이 없습니다.</p>';
        }

        document.getElementById('diffTables').innerHTML = html;
    }

    function renderTable(title, items, rowClass, showException = false) {
        let html = `<h3>${title} (${items.length}건)</h3>`;
        html += `<table class="diff-table"><thead><tr>
            <th>Library</th><th>Vulnerability</th><th>Severity</th>
            <th>Installed</th><th>Fixed</th>${showException ? '<th>예외 사유</th><th>만료일</th>' : ''}</tr></thead><tbody>`;

        items.forEach(v => {
            const sevClass = (v.severity || '').toLowerCase();
            html += `<tr class="${rowClass}">
                <td>${v.library || ''}</td>
                <td>${v.vulnerability || ''}${v.excepted ? '<span class="exception-badge">🛡️예외</span>' : ''}</td>
                <td><span class="badge ${sevClass}">${v.severity || ''}</span></td>
                <td>${v.installed_version || ''}</td>
                <td>${v.fixed_version || '-'}</td>`;
            if (showException) {
                html += `<td>${v.exception_reason || ''}</td><td>${v.exception_expires ? v.exception_expires.split(' ')[0] : ''}</td>`;
            }
            html += '</tr>';
        });

        html += '</tbody></table>';
        return html;
    }

    async function sendReport() {
        const scanId = document.getElementById('scanId').value;
        const email = document.getElementById('email').value;

        if (!email) { alert('이메일을 입력하세요.'); return; }
        if (!scanId) { alert('스캔을 먼저 선택하세요.'); return; }

        const btn = document.getElementById('sendBtn');
        const status = document.getElementById('sendStatus');
        btn.disabled = true;
        btn.textContent = '발송 중...';

        try {
            const resp = await fetch('send_diff_report.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scan_id: scanId, email: email })
            });
            const data = await resp.json();

            if (data.success) {
                status.innerHTML = '<span style="color:green;">✅ ' + data.message + '</span>';
            } else {
                status.innerHTML = '<span style="color:red;">❌ ' + data.message + '</span>';
            }
        } catch (err) {
            status.innerHTML = '<span style="color:red;">❌ 오류: ' + err.message + '</span>';
        }

        btn.disabled = false;
        btn.textContent = '📨 이메일 발송';
    }
    </script>
</body>
</html>
