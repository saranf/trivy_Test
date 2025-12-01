<?php
/**
 * 👮 컴플라이언스 스캔 (Compliance & Misconfig Scanner)
 * - 설정 오류(Misconfig) 스캔: Dockerfile, K8s, Terraform 등
 * - 컴플라이언스 표준 체크: Docker CIS, K8s CIS, PCI-DSS 등
 */
require_once 'auth.php';
$user = requireRole('operator');

require_once 'db_functions.php';

header('Content-Type: text/html; charset=utf-8');

// 지원하는 컴플라이언스 표준
$complianceStandards = [
    'docker-cis-1.6' => ['name' => 'Docker CIS Benchmark 1.6', 'icon' => '🐳', 'type' => 'image'],
    'docker-cis' => ['name' => 'Docker CIS Benchmark (Latest)', 'icon' => '🐳', 'type' => 'image'],
];

// 지원하는 샘플 Dockerfile/Config 목록 (컨테이너 내부 경로)
$sampleConfigs = [
    '/var/www/html' => '📁 웹 애플리케이션 루트',
    '/etc/nginx' => '🌐 Nginx 설정',
    '/etc/php' => '🐘 PHP 설정',
];

// Trivy Config 스캔 실행 (설정 오류)
function scanConfig($path, $severity = 'HIGH,CRITICAL') {
    $safePath = escapeshellarg($path);
    $safeSeverity = escapeshellarg($severity);

    // Trivy config 스캔 (misconfig만)
    $command = "trivy config --no-progress --severity $safeSeverity --format json $safePath 2>&1";
    exec($command, $output, $resultCode);

    $jsonOutput = implode("\n", $output);
    $data = json_decode($jsonOutput, true);

    return [
        'success' => $data !== null && isset($data['Results']),
        'data' => $data,
        'raw' => $jsonOutput,
        'path' => $path
    ];
}

// Trivy 컴플라이언스 표준 체크 (Docker CIS 등)
function scanCompliance($target, $standard = 'docker-cis-1.6') {
    $safeTarget = escapeshellarg($target);
    $safeStandard = escapeshellarg($standard);

    // Trivy compliance 스캔
    $command = "trivy image --compliance $safeStandard --format json $safeTarget 2>&1";
    exec($command, $output, $resultCode);

    $jsonOutput = implode("\n", $output);
    $data = json_decode($jsonOutput, true);

    return [
        'success' => $data !== null,
        'data' => $data,
        'raw' => $jsonOutput,
        'target' => $target,
        'standard' => $standard
    ];
}

// 컴플라이언스 결과를 Markdown으로 변환
function convertComplianceToMarkdown($data, $target, $standard) {
    $md = "# 📋 컴플라이언스 체크 결과\n\n";
    $md .= "**대상 이미지**: `$target`\n\n";
    $md .= "**컴플라이언스 표준**: `$standard`\n\n";
    $md .= "**스캔 시간**: " . date('Y-m-d H:i:s') . "\n\n";
    $md .= "---\n\n";

    if (!$data || !isset($data['Results'])) {
        // 대체 형식 체크
        if (isset($data['Metadata'])) {
            $md .= "## ✅ 컴플라이언스 요약\n\n";
            if (isset($data['Metadata']['ReportTitle'])) {
                $md .= "**리포트**: " . $data['Metadata']['ReportTitle'] . "\n\n";
            }
        }

        if (isset($data['Results']) && is_array($data['Results'])) {
            foreach ($data['Results'] as $result) {
                $md .= processComplianceResult($result);
            }
        } else {
            $md .= "⚠️ 컴플라이언스 데이터를 파싱할 수 없습니다.\n\n";
            $md .= "```\n" . substr(json_encode($data, JSON_PRETTY_PRINT), 0, 2000) . "\n```\n";
        }
        return $md;
    }

    $passCount = 0;
    $failCount = 0;
    $details = "";

    foreach ($data['Results'] as $result) {
        $class = $result['Class'] ?? 'unknown';
        $type = $result['Type'] ?? 'unknown';

        if (isset($result['Misconfigurations'])) {
            foreach ($result['Misconfigurations'] as $m) {
                $status = $m['Status'] ?? 'FAIL';
                $severity = $m['Severity'] ?? 'UNKNOWN';
                $id = $m['ID'] ?? $m['AVDID'] ?? 'N/A';
                $title = $m['Title'] ?? 'No Title';
                $desc = $m['Description'] ?? '';
                $resolution = $m['Resolution'] ?? '';

                if ($status === 'PASS') {
                    $passCount++;
                } else {
                    $failCount++;
                    $icon = getSeverityIcon($severity);
                    $details .= "| $icon $severity | `$id` | $title |\n";
                }
            }
        }
    }

    $total = $passCount + $failCount;
    $passRate = $total > 0 ? round(($passCount / $total) * 100, 1) : 0;

    $md .= "## 📊 컴플라이언스 현황\n\n";
    $md .= "| 항목 | 수치 |\n|------|------|\n";
    $md .= "| ✅ 준수 (PASS) | $passCount |\n";
    $md .= "| ❌ 미준수 (FAIL) | $failCount |\n";
    $md .= "| 📈 준수율 | **{$passRate}%** |\n\n";

    if ($failCount > 0) {
        $md .= "## ❌ 미준수 항목\n\n";
        $md .= "| 심각도 | ID | 설명 |\n|--------|-----|------|\n";
        $md .= $details;
    } else {
        $md .= "## ✅ 모든 항목 준수!\n\n";
    }

    return $md;
}

function getSeverityIcon($severity) {
    switch ($severity) {
        case 'CRITICAL': return '🔴';
        case 'HIGH': return '🟠';
        case 'MEDIUM': return '🟡';
        case 'LOW': return '🟢';
        default: return '⚪';
    }
}

// 결과를 Markdown으로 변환
function convertConfigToMarkdown($data, $path) {
    $md = "# 👮 컴플라이언스 스캔 결과\n\n";
    $md .= "**스캔 경로**: `$path`\n\n";
    $md .= "**스캔 시간**: " . date('Y-m-d H:i:s') . "\n\n";
    $md .= "---\n\n";
    
    $totalMisconfigs = 0;
    $counts = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
    $details = "";
    
    if (!isset($data['Results']) || empty($data['Results'])) {
        $md .= "## ✅ 설정 오류가 발견되지 않았습니다!\n\n";
        $md .= "이 경로의 설정 파일들은 보안 모범 사례를 준수하고 있습니다.\n";
        return $md;
    }
    
    foreach ($data['Results'] as $result) {
        $target = $result['Target'] ?? 'Unknown';
        $configType = $result['Type'] ?? 'Unknown';
        
        if (isset($result['Misconfigurations']) && !empty($result['Misconfigurations'])) {
            $details .= "### 📋 $target\n";
            $details .= "**유형**: $configType\n\n";
            $details .= "| 심각도 | ID | 제목 | 설명 | 해결 방법 |\n";
            $details .= "|:------:|-----|------|------|----------|\n";
            
            foreach ($result['Misconfigurations'] as $m) {
                $sev = $m['Severity'] ?? 'UNKNOWN';
                $icon = getSeverityIcon($sev);
                $id = $m['ID'] ?? $m['AVDID'] ?? 'N/A';
                $title = substr($m['Title'] ?? 'N/A', 0, 40);
                $desc = substr($m['Description'] ?? '-', 0, 50);
                $resolution = substr($m['Resolution'] ?? '-', 0, 40);
                
                $details .= "| $icon $sev | $id | $title | $desc | $resolution |\n";
                $totalMisconfigs++;
                if (isset($counts[$sev])) $counts[$sev]++;
            }
            $details .= "\n";
        }
    }
    
    // 요약
    $md .= "## 📊 요약\n\n";
    $md .= "- **총 설정 오류**: $totalMisconfigs 개\n";
    $md .= "- 🔴 CRITICAL: {$counts['CRITICAL']} 개\n";
    $md .= "- 🟠 HIGH: {$counts['HIGH']} 개\n";
    $md .= "- 🟡 MEDIUM: {$counts['MEDIUM']} 개\n";
    $md .= "- 🟢 LOW: {$counts['LOW']} 개\n\n";
    
    if ($totalMisconfigs > 0) {
        $md .= "---\n\n## 👮 상세 결과\n\n" . $details;
    }
    
    return $md;
}

// API 요청 처리
$action = $_GET['action'] ?? '';

// 설정 오류 스캔 API
if ($action === 'scan') {
    header('Content-Type: application/json');
    $path = $_GET['path'] ?? '';
    $severity = $_GET['severity'] ?? 'HIGH,CRITICAL';

    if (empty($path)) {
        echo json_encode(['success' => false, 'markdown' => "# ❌ 오류\n\n스캔 경로를 지정해주세요."]);
        exit;
    }

    // 보안: 경로 검증 (상위 디렉토리 이동 차단)
    if (strpos($path, '..') !== false) {
        echo json_encode(['success' => false, 'markdown' => "# ❌ 오류\n\n잘못된 경로입니다."]);
        exit;
    }

    $result = scanConfig($path, $severity);

    if ($result['success']) {
        $markdown = convertConfigToMarkdown($result['data'], $path);
    } else {
        $markdown = "## ❌ 스캔 실패\n\n```\n{$result['raw']}\n```\n\n";
        $markdown .= "**가능한 원인**:\n";
        $markdown .= "- 경로가 존재하지 않음\n";
        $markdown .= "- 스캔 가능한 설정 파일이 없음 (Dockerfile, *.yaml, *.tf 등)\n";
    }

    echo json_encode([
        'success' => $result['success'],
        'markdown' => $markdown,
        'data' => $result['data'],
        'path' => $path
    ]);
    exit;
}

// 컴플라이언스 표준 체크 API
if ($action === 'compliance') {
    header('Content-Type: application/json');
    $target = $_GET['target'] ?? '';
    $standard = $_GET['standard'] ?? 'docker-cis-1.6';

    if (empty($target)) {
        echo json_encode(['success' => false, 'markdown' => "# ❌ 오류\n\n대상 이미지를 지정해주세요."]);
        exit;
    }

    $result = scanCompliance($target, $standard);

    if ($result['success']) {
        $markdown = convertComplianceToMarkdown($result['data'], $target, $standard);
    } else {
        $markdown = "## ❌ 컴플라이언스 체크 실패\n\n```\n{$result['raw']}\n```\n\n";
        $markdown .= "**가능한 원인**:\n";
        $markdown .= "- 이미지를 찾을 수 없음\n";
        $markdown .= "- 해당 컴플라이언스 표준이 지원되지 않음\n";
    }

    echo json_encode([
        'success' => $result['success'],
        'markdown' => $markdown,
        'data' => $result['data'],
        'target' => $target,
        'standard' => $standard
    ]);
    exit;
}

// 저장 API
if ($action === 'save') {
    header('Content-Type: application/json');

    // 데모 모드: 저장 시뮬레이션
    if (isDemoMode()) {
        echo json_encode([
            'success' => true,
            'scanId' => 'DEMO-' . rand(1000, 9999),
            'message' => '✅ [데모] 스캔 결과가 저장되었습니다. (실제로는 저장되지 않음)'
        ]);
        exit;
    }

    $input = json_decode(file_get_contents('php://input'), true);

    if (!$input || !isset($input['path']) || !isset($input['data'])) {
        echo json_encode(['success' => false, 'message' => '잘못된 요청입니다.']);
        exit;
    }

    $conn = getDbConnection();
    if ($conn) {
        initDatabase($conn);
        $scanId = saveConfigScanResult($conn, $input['path'], $input['data']);
        auditLog($conn, 'CONFIG_SCAN', 'config_scan', $scanId, "path: {$input['path']}");
        $conn->close();
        echo json_encode(['success' => true, 'scanId' => $scanId, 'message' => "스캔 결과가 저장되었습니다. (ID: $scanId)"]);
    } else {
        echo json_encode(['success' => false, 'message' => 'DB 연결에 실패했습니다.']);
    }
    exit;
}

// 컨테이너 내 디렉토리 목록 가져오기
function getDirectoryList($basePath = '/') {
    $dirs = [];
    if (is_dir($basePath)) {
        $items = @scandir($basePath);
        if ($items) {
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') continue;
                $fullPath = rtrim($basePath, '/') . '/' . $item;
                if (is_dir($fullPath)) {
                    $dirs[] = $fullPath;
                }
            }
        }
    }
    return array_slice($dirs, 0, 20); // 최대 20개
}

// Config 스캔 결과 저장
function saveConfigScanResult($conn, $path, $data) {
    $totalMisconfigs = 0;
    $counts = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
    $misconfigs = [];

    if (isset($data['Results'])) {
        foreach ($data['Results'] as $result) {
            if (isset($result['Misconfigurations'])) {
                foreach ($result['Misconfigurations'] as $m) {
                    $sev = $m['Severity'] ?? 'UNKNOWN';
                    if (isset($counts[$sev])) $counts[$sev]++;
                    $totalMisconfigs++;
                    $misconfigs[] = array_merge($m, ['Target' => $result['Target'] ?? '', 'Type' => $result['Type'] ?? '']);
                }
            }
        }
    }

    // scan_history에 저장 (image_name에 경로 저장, scan_source를 'config'로)
    $stmt = $conn->prepare("INSERT INTO scan_history (image_name, total_vulns, critical_count, high_count, medium_count, low_count, scan_source, misconfig_count, misconfig_critical, misconfig_high) VALUES (?, 0, 0, 0, 0, 0, 'config', ?, ?, ?)");
    $stmt->bind_param("siii", $path, $totalMisconfigs, $counts['CRITICAL'], $counts['HIGH']);
    $stmt->execute();
    $scanId = $conn->insert_id;
    $stmt->close();

    // 설정 오류 상세 저장
    if (!empty($misconfigs)) {
        $stmt = $conn->prepare("INSERT INTO scan_misconfigs (scan_id, config_type, config_id, title, description, severity, resolution) VALUES (?, ?, ?, ?, ?, ?, ?)");
        foreach ($misconfigs as $m) {
            $configType = $m['Type'] ?? '';
            $configId = $m['ID'] ?? $m['AVDID'] ?? '';
            $title = $m['Title'] ?? '';
            $desc = $m['Description'] ?? '';
            $sev = $m['Severity'] ?? '';
            $resolution = $m['Resolution'] ?? '';
            $stmt->bind_param("issssss", $scanId, $configType, $configId, $title, $desc, $sev, $resolution);
            $stmt->execute();
        }
        $stmt->close();
    }

    return $scanId;
}
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>👮 컴플라이언스 스캔</title>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        <?= getAuthStyles() ?>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #333; }
        .info-box { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .info-box h2 { margin-top: 0; }
        .info-box ul { margin: 10px 0; padding-left: 20px; }
        .controls { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .form-row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 15px; }
        select, input[type="text"], button { padding: 10px 15px; font-size: 14px; border-radius: 4px; }
        select, input[type="text"] { border: 1px solid #ddd; min-width: 300px; }
        input[type="text"] { flex: 1; }
        button { background: #764ba2; color: white; border: none; cursor: pointer; }
        button:hover { background: #5a3a7e; }
        button:disabled { background: #ccc; cursor: not-allowed; }
        .result { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .result table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        .result th, .result td { border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 13px; }
        .result th { background: #f8f9fa; }
        .loading { text-align: center; padding: 40px; color: #666; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab { padding: 10px 20px; background: #e9ecef; border-radius: 4px; text-decoration: none; color: #333; }
        .tab.active { background: #764ba2; color: white; }
        .sample-list { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 10px; }
        .sample-btn { padding: 8px 15px; background: #e9ecef; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; }
        .sample-btn:hover { background: #dee2e6; }
        .scan-tabs { display: flex; gap: 0; margin-bottom: 20px; }
        .scan-tab { padding: 15px 25px; background: #e9ecef; border: none; cursor: pointer; font-size: 14px; font-weight: 600; }
        .scan-tab:first-child { border-radius: 8px 0 0 8px; }
        .scan-tab:last-child { border-radius: 0 8px 8px 0; }
        .scan-tab.active { background: #764ba2; color: white; }
        .scan-tab:hover:not(.active) { background: #dee2e6; }
        .scan-panel { display: none; }
        .scan-panel.active { display: block; }
        .compliance-cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .compliance-card { background: white; border: 2px solid #e9ecef; border-radius: 8px; padding: 20px; cursor: pointer; transition: all 0.2s; }
        .compliance-card:hover { border-color: #764ba2; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        .compliance-card.selected { border-color: #764ba2; background: #f3e5f5; }
        .compliance-card h3 { margin: 0 0 8px; font-size: 16px; }
        .compliance-card p { margin: 0; color: #666; font-size: 13px; }
        .compliance-card .icon { font-size: 24px; margin-bottom: 10px; }
    </style>
</head>
<body>
    <?= getNavMenu() ?>
    <?= getDemoBanner() ?>
    <div class="container">
        <div class="tabs">
            <a href="container_scan.php" class="tab">🐳 이미지 스캔</a>
            <a href="config_scan.php" class="tab active">👮 컴플라이언스 스캔</a>
        </div>

        <h1>👮 컴플라이언스 & 설정 오류 스캔</h1>

        <!-- 스캔 타입 선택 탭 -->
        <div class="scan-tabs">
            <button class="scan-tab active" onclick="switchTab('compliance')">📋 컴플라이언스 표준</button>
            <button class="scan-tab" onclick="switchTab('misconfig')">⚙️ 설정 오류 스캔</button>
        </div>

        <!-- 컴플라이언스 표준 체크 패널 -->
        <div id="compliancePanel" class="scan-panel active">
            <div class="info-box" style="background: linear-gradient(135deg, #2196f3 0%, #1976d2 100%);">
                <h2>📋 컴플라이언스 표준 체크</h2>
                <p>Docker 이미지가 보안 표준(CIS Benchmark, PCI-DSS 등)을 준수하는지 검사합니다.</p>
                <ul>
                    <li>🐳 <strong>Docker CIS</strong>: Docker 컨테이너 보안 벤치마크</li>
                    <li>🔒 <strong>보안 모범사례</strong>: 권한, 네트워크, 파일시스템 설정 검증</li>
                </ul>
            </div>

            <div class="controls">
                <h3 style="margin-top:0;">1️⃣ 컴플라이언스 표준 선택</h3>
                <div class="compliance-cards">
                    <div class="compliance-card selected" onclick="selectStandard(this, 'docker-cis-1.6')">
                        <div class="icon">🐳</div>
                        <h3>Docker CIS Benchmark 1.6</h3>
                        <p>CIS Docker Benchmark v1.6.0 기반 컨테이너 보안 검사</p>
                    </div>
                    <div class="compliance-card" onclick="selectStandard(this, 'docker-cis')">
                        <div class="icon">🐳</div>
                        <h3>Docker CIS (Latest)</h3>
                        <p>최신 Docker CIS Benchmark 적용</p>
                    </div>
                </div>

                <h3>2️⃣ 대상 이미지 선택</h3>
                <div class="form-row">
                    <select id="complianceTarget" style="flex:1;">
                        <option value="">-- 이미지 선택 --</option>
                        <?php
                        exec('docker images --format "{{.Repository}}:{{.Tag}}"', $images);
                        foreach ($images as $img) {
                            if ($img !== '<none>:<none>') {
                                echo "<option value=\"" . htmlspecialchars($img) . "\">" . htmlspecialchars($img) . "</option>";
                            }
                        }
                        ?>
                    </select>
                    <button onclick="runComplianceCheck()" id="complianceBtn">📋 컴플라이언스 체크</button>
                </div>
            </div>
        </div>

        <!-- 설정 오류 스캔 패널 -->
        <div id="misconfigPanel" class="scan-panel">
            <div class="info-box">
                <h2>⚙️ 설정 오류 스캔 (Misconfig)</h2>
                <p>Dockerfile, Kubernetes 매니페스트, Terraform 등 IaC 파일의 보안 설정 오류를 탐지합니다.</p>
                <ul>
                    <li>📋 <strong>Dockerfile</strong>: USER 미지정, 불필요한 권한</li>
                    <li>☸️ <strong>Kubernetes</strong>: privileged 모드, securityContext</li>
                    <li>🏗️ <strong>Terraform</strong>: 퍼블릭 버킷, 암호화 미설정</li>
                </ul>
            </div>

            <div class="controls">
                <div class="form-row">
                    <label><strong>스캔 경로:</strong></label>
                    <input type="text" id="scanPath" placeholder="스캔할 경로 입력" value="/var/www/html">
                    <select id="severitySelect">
                        <option value="CRITICAL">CRITICAL만</option>
                        <option value="HIGH,CRITICAL" selected>HIGH 이상</option>
                        <option value="MEDIUM,HIGH,CRITICAL">MEDIUM 이상</option>
                        <option value="LOW,MEDIUM,HIGH,CRITICAL">전체</option>
                    </select>
                    <button onclick="scanConfig()" id="scanBtn">🔍 스캔 시작</button>
                </div>
                <div>
                    <strong>빠른 선택:</strong>
                    <div class="sample-list">
                        <button class="sample-btn" onclick="setPath('/var/www/html')">📁 웹 루트</button>
                        <button class="sample-btn" onclick="setPath('/etc/nginx')">🌐 Nginx</button>
                        <button class="sample-btn" onclick="setPath('/etc')">⚙️ /etc</button>
                        <button class="sample-btn" onclick="setPath('/app')">📦 /app</button>
                    </div>
                </div>
            </div>
        </div>

        <div class="result" id="result">
            <p>📋 컴플라이언스 표준을 선택하고 이미지를 선택한 후 체크를 시작하세요.</p>
            <p style="color:#666;font-size:13px;">💡 또는 "설정 오류 스캔" 탭에서 IaC 파일을 직접 스캔할 수 있습니다.</p>
        </div>

        <div id="saveArea" style="display:none; margin-top:20px; padding:15px; background:#e8f4f8; border-radius:8px; text-align:center;">
            <p style="margin:0 0 10px 0;">📥 이 스캔 결과를 저장하시겠습니까?</p>
            <button onclick="saveResult()" id="saveBtn" style="background:#28a745;">💾 저장하기</button>
            <button onclick="hideSaveArea()" style="background:#6c757d;margin-left:10px;">취소</button>
        </div>
        <div id="saveMessage" style="display:none; margin-top:10px; padding:10px; border-radius:4px; text-align:center;"></div>
    </div>

    <script>
        let lastScanData = null;
        let lastScanPath = null;
        let selectedStandard = 'docker-cis-1.6';

        // 탭 전환
        function switchTab(tab) {
            document.querySelectorAll('.scan-tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.scan-panel').forEach(p => p.classList.remove('active'));

            if (tab === 'compliance') {
                document.querySelector('.scan-tab:first-child').classList.add('active');
                document.getElementById('compliancePanel').classList.add('active');
            } else {
                document.querySelector('.scan-tab:last-child').classList.add('active');
                document.getElementById('misconfigPanel').classList.add('active');
            }
        }

        // 컴플라이언스 표준 선택
        function selectStandard(el, standard) {
            document.querySelectorAll('.compliance-card').forEach(c => c.classList.remove('selected'));
            el.classList.add('selected');
            selectedStandard = standard;
        }

        // 컴플라이언스 체크 실행
        async function runComplianceCheck() {
            const target = document.getElementById('complianceTarget').value;
            const resultDiv = document.getElementById('result');
            const btn = document.getElementById('complianceBtn');

            if (!target) { alert('대상 이미지를 선택하세요.'); return; }

            lastScanData = null;
            lastScanPath = null;
            document.getElementById('saveArea').style.display = 'none';
            document.getElementById('saveMessage').style.display = 'none';

            btn.disabled = true;
            btn.textContent = '⏳ 체크 중...';
            resultDiv.innerHTML = '<div class="loading">📋 컴플라이언스 표준 검사 중...<br><small>(' + selectedStandard + ')</small></div>';

            try {
                const response = await fetch(`config_scan.php?action=compliance&target=${encodeURIComponent(target)}&standard=${encodeURIComponent(selectedStandard)}`);
                const result = await response.json();
                resultDiv.innerHTML = marked.parse(result.markdown);
            } catch (e) {
                resultDiv.innerHTML = '<p style="color:red;">오류가 발생했습니다: ' + e.message + '</p>';
            }

            btn.disabled = false;
            btn.textContent = '📋 컴플라이언스 체크';
        }

        function setPath(path) {
            document.getElementById('scanPath').value = path;
        }

        async function scanConfig() {
            const path = document.getElementById('scanPath').value.trim();
            const severity = document.getElementById('severitySelect').value;
            const resultDiv = document.getElementById('result');
            const scanBtn = document.getElementById('scanBtn');

            if (!path) { alert('스캔 경로를 입력하세요.'); return; }

            lastScanData = null;
            lastScanPath = null;
            document.getElementById('saveArea').style.display = 'none';
            document.getElementById('saveMessage').style.display = 'none';

            scanBtn.disabled = true;
            scanBtn.textContent = '⏳ 스캔 중...';
            resultDiv.innerHTML = '<div class="loading">🔄 설정 파일을 분석 중입니다...</div>';

            try {
                const response = await fetch(`config_scan.php?action=scan&path=${encodeURIComponent(path)}&severity=${encodeURIComponent(severity)}`);
                const result = await response.json();
                resultDiv.innerHTML = marked.parse(result.markdown);

                if (result.success && result.data) {
                    lastScanData = result.data;
                    lastScanPath = result.path;
                    document.getElementById('saveArea').style.display = 'block';
                }
            } catch (e) {
                resultDiv.innerHTML = '<p style="color:red;">오류가 발생했습니다: ' + e.message + '</p>';
            }

            scanBtn.disabled = false;
            scanBtn.textContent = '🔍 스캔 시작';
        }

        async function saveResult() {
            if (!lastScanData || !lastScanPath) {
                alert('저장할 스캔 결과가 없습니다.');
                return;
            }

            const saveBtn = document.getElementById('saveBtn');
            const saveMessage = document.getElementById('saveMessage');
            saveBtn.disabled = true;
            saveBtn.textContent = '저장 중...';

            try {
                const response = await fetch('config_scan.php?action=save', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: lastScanPath, data: lastScanData })
                });
                const result = await response.json();

                if (result.success) {
                    saveMessage.style.display = 'block';
                    saveMessage.style.background = '#d4edda';
                    saveMessage.style.color = '#155724';
                    saveMessage.innerHTML = '✅ ' + result.message + ' <a href="scan_history.php">스캔 기록 보기 →</a>';
                    document.getElementById('saveArea').style.display = 'none';
                } else {
                    saveMessage.style.display = 'block';
                    saveMessage.style.background = '#f8d7da';
                    saveMessage.style.color = '#721c24';
                    saveMessage.textContent = '❌ ' + result.message;
                }
            } catch (e) {
                saveMessage.style.display = 'block';
                saveMessage.style.background = '#f8d7da';
                saveMessage.style.color = '#721c24';
                saveMessage.textContent = '❌ 저장 중 오류: ' + e.message;
            }

            saveBtn.disabled = false;
            saveBtn.textContent = '💾 저장하기';
        }

        function hideSaveArea() {
            document.getElementById('saveArea').style.display = 'none';
        }
    </script>
</body>
</html>

