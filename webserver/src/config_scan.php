<?php
/**
 * 👮 컴플라이언스 스캔 (Misconfig Scanner)
 * Dockerfile, Kubernetes 매니페스트, Terraform 등 IaC 파일 스캔
 */
require_once 'auth.php';
$user = requireRole('operator');

require_once 'db_functions.php';

header('Content-Type: text/html; charset=utf-8');

// 지원하는 샘플 Dockerfile/Config 목록 (컨테이너 내부 경로)
$sampleConfigs = [
    '/var/www/html' => '📁 웹 애플리케이션 루트',
    '/etc/nginx' => '🌐 Nginx 설정',
    '/etc/php' => '🐘 PHP 설정',
];

// Trivy Config 스캔 실행
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

function getSeverityIcon($severity) {
    switch ($severity) {
        case 'CRITICAL': return '🔴';
        case 'HIGH': return '🟠';
        case 'MEDIUM': return '🟡';
        case 'LOW': return '🟢';
        default: return '⚪';
    }
}

// API 요청 처리
$action = $_GET['action'] ?? '';

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

        <h1>👮 컴플라이언스 스캔 (Misconfig Scanner)</h1>

        <div class="info-box">
            <h2>🔍 설정 오류 스캔이란?</h2>
            <p>Dockerfile, Kubernetes 매니페스트, Terraform 등 IaC(Infrastructure as Code) 파일의 <strong>보안 설정 오류</strong>를 탐지합니다.</p>
            <ul>
                <li>📋 <strong>Dockerfile</strong>: USER 미지정, 불필요한 권한, 보안 모범 사례 위반</li>
                <li>☸️ <strong>Kubernetes</strong>: privileged 모드, hostPath 마운트, securityContext 설정</li>
                <li>🏗️ <strong>Terraform/CloudFormation</strong>: 퍼블릭 버킷, 암호화 미설정, 보안 그룹 규칙</li>
            </ul>
        </div>

        <div class="controls">
            <div class="form-row">
                <label><strong>스캔 경로:</strong></label>
                <input type="text" id="scanPath" placeholder="스캔할 경로 입력 (예: /var/www/html, /app)" value="/var/www/html">
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
                    <button class="sample-btn" onclick="setPath('/etc')">⚙️ /etc 전체</button>
                    <button class="sample-btn" onclick="setPath('/app')">📦 /app</button>
                    <button class="sample-btn" onclick="setPath('/home')">🏠 /home</button>
                </div>
            </div>
        </div>

        <div class="result" id="result">
            <p>스캔할 경로를 입력하고 스캔을 시작하세요.</p>
            <p style="color:#666;font-size:13px;">💡 Dockerfile, *.yaml, *.yml, *.tf, *.json 등의 설정 파일이 있는 디렉토리를 스캔합니다.</p>
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

