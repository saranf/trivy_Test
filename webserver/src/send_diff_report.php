<?php
/**
 * 지능형 Diff 기반 리포팅 시스템
 * - 이전 스캔 vs 현재 스캔 비교
 * - New/Fixed/Persistent 분류
 * - 요약 제목 자동 생성
 */

error_reporting(0);
ini_set('display_errors', 0);
header('Content-Type: application/json');

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
    $html .= '<div class="summary-box">';
    $html .= '<div class="summary-card card-new"><div class="card-number">' . count($diff['new']) . '</div><div class="card-label">🆕 신규 취약점</div></div>';
    $html .= '<div class="summary-card card-fixed"><div class="card-number">' . count($diff['fixed']) . '</div><div class="card-label">✅ 조치 완료</div></div>';
    $html .= '<div class="summary-card card-persistent"><div class="card-number">' . count($diff['persistent']) . '</div><div class="card-label">⏳ 미조치</div></div>';
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

/**
 * Diff CSV 생성
 */
function generateDiffCsv($scan, $diff) {
    $lines = [];
    $lines[] = "Status,Image,Library,Vulnerability,Severity,Installed Version,Fixed Version";

    $imageName = $scan['image_name'];

    foreach ($diff['new'] as $v) {
        $lines[] = sprintf('"NEW","%s","%s","%s","%s","%s","%s"',
            str_replace('"', '""', $imageName),
            str_replace('"', '""', $v['library']),
            str_replace('"', '""', $v['vulnerability']),
            $v['severity'],
            str_replace('"', '""', $v['installed_version']),
            str_replace('"', '""', $v['fixed_version'] ?: '')
        );
    }

    foreach ($diff['fixed'] as $v) {
        $lines[] = sprintf('"FIXED","%s","%s","%s","%s","%s","%s"',
            str_replace('"', '""', $imageName),
            str_replace('"', '""', $v['library']),
            str_replace('"', '""', $v['vulnerability']),
            $v['severity'],
            str_replace('"', '""', $v['installed_version']),
            str_replace('"', '""', $v['fixed_version'] ?: '')
        );
    }

    foreach ($diff['persistent'] as $v) {
        $lines[] = sprintf('"PERSISTENT","%s","%s","%s","%s","%s","%s"',
            str_replace('"', '""', $imageName),
            str_replace('"', '""', $v['library']),
            str_replace('"', '""', $v['vulnerability']),
            $v['severity'],
            str_replace('"', '""', $v['installed_version']),
            str_replace('"', '""', $v['fixed_version'] ?: '')
        );
    }

    return implode("\n", $lines);
}

// API 엔드포인트
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
    echo json_encode($result);
    exit;
}

echo json_encode([
    'status' => 'ok',
    'usage' => 'POST with {scan_id, email}'
]);

