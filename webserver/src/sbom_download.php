<?php
/**
 * SBOM (Software Bill of Materials) 다운로드 API
 * - CycloneDX 또는 SPDX 포맷 지원
 * - 실시간 Trivy 스캔으로 SBOM 생성
 */

require_once 'db_functions.php';
require_once 'auth.php';

// 로그인 확인
if (!isLoggedIn()) {
    http_response_code(401);
    die('Unauthorized');
}

$conn = getDbConnection();

// 파라미터 받기
$imageName = $_GET['image'] ?? '';
$format = $_GET['format'] ?? 'cyclonedx';  // cyclonedx, spdx-json
$scanId = $_GET['scan_id'] ?? '';

// scan_id가 있으면 DB에서 이미지명 조회
if ($scanId && !$imageName) {
    $stmt = $conn->prepare("SELECT image_name FROM scan_history WHERE id = ?");
    $stmt->bind_param("i", $scanId);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc()) {
        $imageName = $row['image_name'];
    }
    $stmt->close();
}

if (empty($imageName)) {
    http_response_code(400);
    die('이미지명이 필요합니다.');
}

// 데모 모드: 샘플 SBOM 반환
if (isDemoMode()) {
    $sampleSbom = [
        'bomFormat' => 'CycloneDX',
        'specVersion' => '1.4',
        'version' => 1,
        'metadata' => [
            'timestamp' => date('c'),
            'tools' => [['vendor' => 'aquasecurity', 'name' => 'trivy', 'version' => '0.45.0']],
            'component' => ['type' => 'container', 'name' => 'demo-image', 'version' => 'latest']
        ],
        'components' => [
            ['type' => 'library', 'name' => 'demo-package-1', 'version' => '1.0.0', 'purl' => 'pkg:npm/demo-package-1@1.0.0'],
            ['type' => 'library', 'name' => 'demo-package-2', 'version' => '2.3.1', 'purl' => 'pkg:npm/demo-package-2@2.3.1'],
            ['type' => 'library', 'name' => 'demo-package-3', 'version' => '0.9.5', 'purl' => 'pkg:pypi/demo-package-3@0.9.5']
        ],
        '_demo_notice' => '🎓 데모 모드: 실제 SBOM이 아닌 샘플 데이터입니다.'
    ];
    
    header('Content-Type: application/json');
    header('Content-Disposition: attachment; filename="demo-sbom-' . date('Ymd-His') . '.json"');
    echo json_encode($sampleSbom, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

// Trivy SBOM 포맷 매핑
$trivyFormat = match($format) {
    'spdx-json' => 'spdx-json',
    'spdx' => 'spdx-json',
    default => 'cyclonedx'
};

// 파일 확장자
$extension = ($format === 'spdx-json' || $format === 'spdx') ? 'spdx.json' : 'cdx.json';

// 에이전트 API 호출로 SBOM 생성
$result = generateSbomViaAgent($imageName, $trivyFormat);

if (!$result['success']) {
    http_response_code(500);
    echo "SBOM 생성 실패\n";
    echo "이미지: " . htmlspecialchars($imageName) . "\n";
    echo "오류: " . ($result['error'] ?? 'Unknown error') . "\n\n";
    echo "\n가능한 원인:\n";
    echo "- 이미지가 로컬에 없음 (docker pull 필요)\n";
    echo "- 이미지명이 잘못됨\n";
    echo "- 에이전트 연결 오류\n";
    exit;
}

$output = $result['sbom'] ?? '';

if (empty($output)) {
    http_response_code(500);
    echo "SBOM 생성 실패: 빈 결과\n";
    echo "이미지: " . htmlspecialchars($imageName) . "\n";
    exit;
}

// JSON 유효성 검사
$json = json_decode($output);
if (json_last_error() !== JSON_ERROR_NONE) {
    error_log("SBOM JSON parse error for $imageName: " . json_last_error_msg());
    http_response_code(500);
    echo "SBOM 생성 중 오류가 발생했습니다.\n";
    echo "이미지: " . htmlspecialchars($imageName) . "\n";
    echo "오류: " . json_last_error_msg() . "\n";
    echo "\n가능한 원인:\n";
    echo "- 이미지가 로컬에 없어서 pull이 필요\n";
    echo "- 이미지 이름이 잘못됨\n";
    echo "- 에이전트 오류\n";
    exit;
}

// 파일명 생성 (이미지명에서 특수문자 제거)
$safeFileName = preg_replace('/[^a-zA-Z0-9\-_]/', '_', $imageName);
$fileName = "sbom-{$safeFileName}-" . date('Ymd-His') . ".{$extension}";

// 감사 로그
if (isset($_SESSION['user'])) {
    logAudit($conn, $_SESSION['user']['id'], $_SESSION['user']['username'], 'DOWNLOAD_SBOM', 'image', $imageName, "Format: $format");
}

// 다운로드 헤더
header('Content-Type: application/json');
header('Content-Disposition: attachment; filename="' . $fileName . '"');
header('Content-Length: ' . strlen($output));

echo $output;

