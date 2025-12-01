<?php
/**
 * 취약점 예외 처리 API
 * Risk Acceptance Lifecycle 관리
 */

error_reporting(0);
ini_set('display_errors', 0);

session_start();
require_once 'db_functions.php';

// 로그인 확인 (API이므로 JSON으로 에러 반환)
if (!isset($_SESSION['user'])) {
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'message' => '로그인이 필요합니다.']);
    exit;
}

// Operator 이상 권한 확인
$userRole = $_SESSION['user']['role'] ?? '';
$levels = ['viewer' => 1, 'operator' => 2, 'admin' => 3];
if (($levels[$userRole] ?? 0) < 2) {
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'message' => 'Operator 이상 권한이 필요합니다.']);
    exit;
}

header('Content-Type: application/json');

$conn = getDbConnection();
if (!$conn) {
    echo json_encode(['success' => false, 'message' => 'DB 연결 실패']);
    exit;
}
initDatabase($conn);

$action = $_GET['action'] ?? $_POST['action'] ?? '';

// 예외 추가
if ($action === 'add') {
    $input = json_decode(file_get_contents('php://input'), true);

    $vulnId = $input['vulnerability_id'] ?? '';
    $imagePattern = $input['image_pattern'] ?? '*';
    $reason = $input['reason'] ?? '';
    $expiresAt = $input['expires_at'] ?? '';
    $createdBy = $_SESSION['user']['username'] ?? 'admin';
    
    if (empty($vulnId) || empty($reason) || empty($expiresAt)) {
        echo json_encode(['success' => false, 'message' => '필수 항목을 입력하세요. (vulnerability_id, reason, expires_at)']);
        exit;
    }
    
    // 만료일 검증
    $expireDate = strtotime($expiresAt);
    if ($expireDate === false || $expireDate <= time()) {
        echo json_encode(['success' => false, 'message' => '만료일은 미래 날짜여야 합니다.']);
        exit;
    }
    
    $id = addException($conn, $vulnId, $imagePattern, $reason, $expiresAt, $createdBy);

    // 감사 로그
    logAudit($conn, $_SESSION['user']['id'] ?? null, $_SESSION['user']['username'] ?? 'unknown',
             'ADD_EXCEPTION', 'exception', $id, "vuln: {$vulnId}, expires: {$expiresAt}");

    echo json_encode([
        'success' => true,
        'message' => '예외 처리가 등록되었습니다.',
        'exception_id' => $id
    ]);
    exit;
}

// 예외 목록 조회
if ($action === 'list') {
    $includeAll = isset($_GET['all']) && $_GET['all'] === '1';
    
    if ($includeAll) {
        $exceptions = getAllExceptions($conn);
    } else {
        $exceptions = getActiveExceptions($conn);
    }
    
    echo json_encode(['success' => true, 'exceptions' => $exceptions]);
    exit;
}

// 예외 삭제
if ($action === 'delete') {
    $id = (int)($_GET['id'] ?? $_POST['id'] ?? 0);
    
    if ($id <= 0) {
        echo json_encode(['success' => false, 'message' => '유효하지 않은 ID입니다.']);
        exit;
    }
    
    deleteException($conn, $id);
    echo json_encode(['success' => true, 'message' => '예외 처리가 삭제되었습니다.']);
    exit;
}

// 만료된 예외 처리 (크론잡 등에서 호출)
if ($action === 'process_expired') {
    $expired = processExpiredExceptions($conn);
    echo json_encode([
        'success' => true, 
        'message' => count($expired) . '개의 만료된 예외가 처리되었습니다.',
        'expired' => $expired
    ]);
    exit;
}

// 특정 취약점 예외 여부 확인
if ($action === 'check') {
    $vulnId = $_GET['vulnerability_id'] ?? '';
    $imageName = $_GET['image_name'] ?? null;
    
    if (empty($vulnId)) {
        echo json_encode(['success' => false, 'message' => 'vulnerability_id가 필요합니다.']);
        exit;
    }
    
    $excepted = isExcepted($conn, $vulnId, $imageName);
    echo json_encode(['success' => true, 'is_excepted' => $excepted]);
    exit;
}

// 기본 응답
echo json_encode([
    'status' => 'ok',
    'endpoints' => [
        'add' => 'POST ?action=add (body: vulnerability_id, image_pattern, reason, expires_at)',
        'list' => 'GET ?action=list&all=0|1',
        'delete' => 'GET/POST ?action=delete&id=ID',
        'check' => 'GET ?action=check&vulnerability_id=CVE-XXX&image_name=IMAGE',
        'process_expired' => 'GET ?action=process_expired'
    ]
]);

