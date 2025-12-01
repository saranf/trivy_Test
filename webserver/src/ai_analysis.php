<?php
/**
 * 🤖 AI 취약점 분석 API
 * - Gemini API를 사용하여 CVE 조치 방법 추천
 */

require_once 'db_functions.php';
require_once 'auth.php';
require_once 'gemini_api.php';

header('Content-Type: application/json; charset=utf-8');

$action = $_GET['action'] ?? '';

// 컨테이너 전체 분석
if ($action === 'analyze_container') {
    $scanId = intval($_GET['scan_id'] ?? 0);
    
    if ($scanId <= 0) {
        echo json_encode(['success' => false, 'error' => '스캔 ID가 필요합니다.']);
        exit;
    }
    
    $conn = getDbConnection();
    if (!$conn) {
        echo json_encode(['success' => false, 'error' => 'DB 연결 실패']);
        exit;
    }
    
    initDatabase($conn);
    
    // 다시 분석 요청인지 확인
    $forceRefresh = isset($_GET['refresh']) && $_GET['refresh'] === '1';

    // 이미 분석된 결과가 있는지 확인 (refresh가 아닌 경우만)
    if (!$forceRefresh) {
        $existing = getContainerAiRecommendation($conn, $scanId);
        if ($existing) {
            echo json_encode([
                'success' => true,
                'recommendation' => $existing,
                'cached' => true
            ]);
            $conn->close();
            exit;
        }
    } else {
        // 기존 추천 삭제
        $stmt = $conn->prepare("DELETE FROM ai_recommendations WHERE scan_id = ? AND recommendation_type = 'container'");
        $stmt->bind_param("i", $scanId);
        $stmt->execute();
        $stmt->close();
    }
    
    // 스캔 정보 조회
    $stmt = $conn->prepare("SELECT * FROM scan_history WHERE id = ?");
    $stmt->bind_param("i", $scanId);
    $stmt->execute();
    $scan = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    
    if (!$scan) {
        echo json_encode(['success' => false, 'error' => '스캔을 찾을 수 없습니다.']);
        $conn->close();
        exit;
    }
    
    // 취약점 조회
    $vulns = getScanVulnerabilities($conn, $scanId);
    
    if (empty($vulns)) {
        echo json_encode([
            'success' => true,
            'recommendation' => '✅ 이 컨테이너에서 취약점이 발견되지 않았습니다. 현재 보안 상태가 양호합니다.',
            'cached' => false
        ]);
        $conn->close();
        exit;
    }
    
    // Gemini API 호출
    $result = getAiRecommendationForContainer(
        $scan['image_name'],
        $vulns,
        $scan['critical_count'],
        $scan['high_count']
    );
    
    if ($result['success']) {
        // DB에 저장
        saveAiRecommendation($conn, $scanId, 'container', $result['response']);
        
        echo json_encode([
            'success' => true,
            'recommendation' => $result['response'],
            'cached' => false
        ]);
    } else {
        echo json_encode([
            'success' => false,
            'error' => $result['error']
        ]);
    }
    
    $conn->close();
    exit;
}

// 개별 CVE 분석
if ($action === 'analyze_cve') {
    $scanId = intval($_GET['scan_id'] ?? 0);
    $cveId = $_GET['cve_id'] ?? '';
    
    if ($scanId <= 0 || empty($cveId)) {
        echo json_encode(['success' => false, 'error' => '스캔 ID와 CVE ID가 필요합니다.']);
        exit;
    }
    
    $conn = getDbConnection();
    if (!$conn) {
        echo json_encode(['success' => false, 'error' => 'DB 연결 실패']);
        exit;
    }
    
    initDatabase($conn);
    
    // 이미 분석된 결과가 있는지 확인
    $existing = getCveAiRecommendation($conn, $scanId, $cveId);
    if ($existing) {
        echo json_encode([
            'success' => true,
            'recommendation' => $existing,
            'cached' => true
        ]);
        $conn->close();
        exit;
    }
    
    // CVE 정보 조회
    $stmt = $conn->prepare("SELECT * FROM scan_vulnerabilities WHERE scan_id = ? AND vulnerability = ?");
    $stmt->bind_param("is", $scanId, $cveId);
    $stmt->execute();
    $vuln = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    
    if (!$vuln) {
        echo json_encode(['success' => false, 'error' => 'CVE를 찾을 수 없습니다.']);
        $conn->close();
        exit;
    }
    
    // Gemini API 호출
    $result = getAiRecommendationForCve(
        $vuln['vulnerability'],
        $vuln['library'],
        $vuln['severity'],
        $vuln['title'],
        $vuln['installed_version'],
        $vuln['fixed_version']
    );
    
    if ($result['success']) {
        saveAiRecommendation($conn, $scanId, 'cve', $result['response'], $cveId);
        echo json_encode(['success' => true, 'recommendation' => $result['response'], 'cached' => false]);
    } else {
        echo json_encode(['success' => false, 'error' => $result['error']]);
    }
    
    $conn->close();
    exit;
}

// API 정보
echo json_encode([
    'status' => 'ok',
    'endpoints' => [
        'analyze_container' => '?action=analyze_container&scan_id=ID',
        'analyze_cve' => '?action=analyze_cve&scan_id=ID&cve_id=CVE-XXXX-XXXX'
    ],
    'gemini_configured' => !empty(GEMINI_API_KEY)
]);

