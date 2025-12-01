<?php
require_once 'auth.php';
$user = requireRole('operator');  // Operator 이상만 접근 가능

header('Content-Type: text/html; charset=utf-8');

// 실행 중인 컨테이너 목록 가져오기
function getRunningContainers() {
    exec('docker ps --format "{{.ID}}|{{.Image}}|{{.Names}}"', $output, $result_code);
    $containers = [];
    if ($result_code === 0) {
        foreach ($output as $line) {
            $parts = explode('|', $line);
            if (count($parts) === 3) {
                $containers[] = [
                    'id' => $parts[0],
                    'image' => $parts[1],
                    'name' => $parts[2]
                ];
            }
        }
    }
    return $containers;
}

// Trivy 스캔 실행 및 Markdown 변환 (v0.29.2 호환)
function scanContainer($imageOrId, $severity = 'HIGH,CRITICAL', $scanSecrets = true) {
    $safeTarget = escapeshellarg($imageOrId);
    $safeSeverity = escapeshellarg($severity);

    // Trivy v0.29.2: --security-checks 사용 (신버전의 --scanners 대신)
    $securityChecks = $scanSecrets ? 'vuln,config,secret' : 'vuln,config';
    $command = "trivy image --security-checks $securityChecks --severity $safeSeverity --format json $safeTarget 2>/dev/null";
    exec($command, $output, $result_code);

    $jsonOutput = implode("\n", $output);

    // JSON 시작 위치 찾기 (INFO 로그가 섞여있을 경우 대비)
    $jsonStart = strpos($jsonOutput, '{');
    if ($jsonStart !== false && $jsonStart > 0) {
        $jsonOutput = substr($jsonOutput, $jsonStart);
    }

    $data = json_decode($jsonOutput, true);

    if ($data === null) {
        return "## ❌ 스캔 오류\n\n```\n" . $jsonOutput . "\n```";
    }

    return convertToMarkdown($data, $imageOrId);
}

// JSON 결과를 Markdown으로 변환 (예외 처리 정보 포함 + 컴플라이언스)
function convertToMarkdown($data, $target) {
    // 예외 처리 정보 가져오기
    $exceptedMap = [];
    $conn = getDbConnection();
    if ($conn) {
        initDatabase($conn);
        $activeExceptions = getActiveExceptions($conn);
        foreach ($activeExceptions as $ex) {
            $exceptedMap[$ex['vulnerability_id']] = $ex;
        }
    }

    $md = "# 🔍 Trivy 보안 스캔 결과\n\n";
    $md .= "**스캔 대상**: `$target`\n\n";
    $md .= "**스캔 시간**: " . date('Y-m-d H:i:s') . "\n\n";
    $md .= "---\n\n";

    $totalVulns = 0;
    $totalMisconfigs = 0;
    $totalSecrets = 0;
    $exceptedCount = 0;
    $severityCounts = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
    $misconfigCounts = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];

    $vulnMd = "";
    $misconfigMd = "";
    $secretMd = "";

    if (!isset($data['Results']) || empty($data['Results'])) {
        $md .= "## ✅ 보안 이슈가 발견되지 않았습니다!\n";
        return $md;
    }

    // 취약점 처리
    foreach ($data['Results'] as $result) {
        if (isset($result['Vulnerabilities']) && !empty($result['Vulnerabilities'])) {
            $vulnMd .= "### 📦 " . ($result['Target'] ?? 'Unknown') . "\n\n";
            $vulnMd .= "| 심각도 | CVE ID | 패키지 | 설치 버전 | 수정 버전 | 상태 | 설명 |\n";
            $vulnMd .= "|:------:|--------|--------|-----------|-----------|------|------|\n";

            foreach ($result['Vulnerabilities'] as $vuln) {
                $severity = $vuln['Severity'] ?? 'UNKNOWN';
                $severityIcon = getSeverityIcon($severity);
                $vulnId = $vuln['VulnerabilityID'] ?? 'N/A';
                $pkgName = $vuln['PkgName'] ?? 'N/A';
                $installed = $vuln['InstalledVersion'] ?? 'N/A';
                $fixed = $vuln['FixedVersion'] ?? '-';
                $title = substr($vuln['Title'] ?? $vuln['Description'] ?? 'N/A', 0, 40);

                $status = '';
                if (isset($exceptedMap[$vulnId])) {
                    $status = '🛡️예외';
                    $exceptedCount++;
                }

                $vulnMd .= "| $severityIcon $severity | $vulnId | $pkgName | $installed | $fixed | $status | $title |\n";
                $totalVulns++;
                if (isset($severityCounts[$severity])) {
                    $severityCounts[$severity]++;
                }
            }
            $vulnMd .= "\n";
        }

        // 설정 오류 (Misconfigurations) 처리
        if (isset($result['Misconfigurations']) && !empty($result['Misconfigurations'])) {
            $misconfigMd .= "### 📋 " . ($result['Target'] ?? 'Unknown') . "\n\n";
            $misconfigMd .= "| 심각도 | ID | 유형 | 제목 | 해결 방법 |\n";
            $misconfigMd .= "|:------:|-----|------|------|----------|\n";

            foreach ($result['Misconfigurations'] as $misconfig) {
                $severity = $misconfig['Severity'] ?? 'UNKNOWN';
                $severityIcon = getSeverityIcon($severity);
                $configId = $misconfig['ID'] ?? $misconfig['AVDID'] ?? 'N/A';
                $configType = $misconfig['Type'] ?? 'N/A';
                $title = substr($misconfig['Title'] ?? 'N/A', 0, 50);
                $resolution = substr($misconfig['Resolution'] ?? '-', 0, 40);

                $misconfigMd .= "| $severityIcon $severity | $configId | $configType | $title | $resolution |\n";
                $totalMisconfigs++;
                if (isset($misconfigCounts[$severity])) {
                    $misconfigCounts[$severity]++;
                }
            }
            $misconfigMd .= "\n";
        }

        // 시크릿 (하드코딩된 비밀번호, API 키 등) 처리
        if (isset($result['Secrets']) && !empty($result['Secrets'])) {
            $secretMd .= "### 🔐 " . ($result['Target'] ?? 'Unknown') . "\n\n";
            $secretMd .= "| 심각도 | 유형 | 파일 경로 | 매칭 |\n";
            $secretMd .= "|:------:|------|----------|------|\n";

            foreach ($result['Secrets'] as $secret) {
                $severity = $secret['Severity'] ?? 'HIGH';
                $severityIcon = getSeverityIcon($severity);
                $ruleId = $secret['RuleID'] ?? $secret['Category'] ?? 'Secret';
                $title = $secret['Title'] ?? $ruleId;
                $match = substr($secret['Match'] ?? '***', 0, 30) . '...';

                $secretMd .= "| $severityIcon $severity | $title | " . ($result['Target'] ?? '') . " | `$match` |\n";
                $totalSecrets++;
            }
            $secretMd .= "\n";
        }
    }

    // 요약
    $summary = "## 📊 요약\n\n";
    $summary .= "### 🔒 소프트웨어 취약점 (CVE)\n";
    $summary .= "- **총 취약점**: $totalVulns 개\n";
    $summary .= "- 🔴 CRITICAL: {$severityCounts['CRITICAL']} 개\n";
    $summary .= "- 🟠 HIGH: {$severityCounts['HIGH']} 개\n";
    $summary .= "- 🟡 MEDIUM: {$severityCounts['MEDIUM']} 개\n";
    $summary .= "- 🟢 LOW: {$severityCounts['LOW']} 개\n";
    if ($exceptedCount > 0) {
        $summary .= "- 🛡️ **예외 처리**: {$exceptedCount} 개\n";
    }
    $summary .= "\n";

    if ($totalMisconfigs > 0) {
        $summary .= "### 👮 컴플라이언스 (설정 오류)\n";
        $summary .= "- **총 설정 오류**: $totalMisconfigs 개\n";
        $summary .= "- 🔴 CRITICAL: {$misconfigCounts['CRITICAL']} 개\n";
        $summary .= "- 🟠 HIGH: {$misconfigCounts['HIGH']} 개\n";
        $summary .= "- 🟡 MEDIUM: {$misconfigCounts['MEDIUM']} 개\n";
        $summary .= "- 🟢 LOW: {$misconfigCounts['LOW']} 개\n";
        $summary .= "\n";
    }

    if ($totalSecrets > 0) {
        $summary .= "### 🔐 시크릿 (하드코딩된 비밀정보)\n";
        $summary .= "- **총 시크릿**: $totalSecrets 개\n";
        $summary .= "- ⚠️ API 키, 비밀번호, 토큰 등이 코드에 하드코딩됨\n";
        $summary .= "\n";
    }

    // 탭 구분으로 출력
    $output = $summary;
    if ($totalVulns > 0) {
        $output .= "---\n\n## 🔒 소프트웨어 취약점\n\n" . $vulnMd;
    }
    if ($totalMisconfigs > 0) {
        $output .= "---\n\n## 👮 컴플라이언스 (설정/보안위규)\n\n" . $misconfigMd;
    }
    if ($totalSecrets > 0) {
        $output .= "---\n\n## 🔐 시크릿 탐지 (Secret Detection)\n\n" . $secretMd;
    }
    if ($totalVulns == 0 && $totalMisconfigs == 0 && $totalSecrets == 0) {
        $output .= "## ✅ 보안 이슈가 발견되지 않았습니다!\n";
    }

    return $output;
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

// MySQL 연결 (스캔 결과 저장용)
require_once 'db_functions.php';

// API 요청 처리
$action = $_GET['action'] ?? '';

// 스캔 API
if ($action === 'scan') {
    header('Content-Type: application/json');
    $target = $_GET['target'] ?? '';
    $severity = $_GET['severity'] ?? 'HIGH,CRITICAL';

    if (empty($target)) {
        echo json_encode(['success' => false, 'markdown' => "# ❌ 오류\n\n스캔 대상을 지정해주세요."]);
        exit;
    }

    $result = scanContainerWithData($target, $severity);
    echo json_encode([
        'success' => $result['data'] !== null,
        'markdown' => $result['markdown'],
        'data' => $result['data'],
        'target' => $target
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

    if (!$input || !isset($input['target']) || !isset($input['data'])) {
        echo json_encode(['success' => false, 'message' => '잘못된 요청입니다.']);
        exit;
    }

    $conn = getDbConnection();
    if ($conn) {
        initDatabase($conn);
        $scanId = saveScanResult($conn, $input['target'], $input['data']);

        // 감사 로그
        auditLog($conn, 'MANUAL_SCAN', 'scan', $scanId, "image: {$input['target']}");

        $conn->close();
        echo json_encode(['success' => true, 'scanId' => $scanId, 'message' => "스캔 결과가 저장되었습니다. (ID: $scanId)"]);
    } else {
        echo json_encode(['success' => false, 'message' => 'DB 연결에 실패했습니다.']);
    }
    exit;
}

// 스캔 + 데이터 반환 함수 (v0.29.2 호환)
function scanContainerWithData($imageOrId, $severity = 'HIGH,CRITICAL') {
    $safeTarget = escapeshellarg($imageOrId);
    $safeSeverity = escapeshellarg($severity);

    // Trivy v0.29.2 호환
    $command = "trivy image --severity $safeSeverity --format json $safeTarget 2>/dev/null";
    exec($command, $output, $result_code);

    $jsonOutput = implode("\n", $output);

    // JSON 시작 위치 찾기 (INFO 로그가 섞여있을 경우 대비)
    $jsonStart = strpos($jsonOutput, '{');
    if ($jsonStart !== false && $jsonStart > 0) {
        $jsonOutput = substr($jsonOutput, $jsonStart);
    }

    $data = json_decode($jsonOutput, true);

    if ($data === null) {
        return ['markdown' => "## ❌ 스캔 오류\n\n```\n" . $jsonOutput . "\n```", 'data' => null];
    }

    return ['markdown' => convertToMarkdown($data, $imageOrId), 'data' => $data];
}

// 실행 중인 컨테이너 목록
$containers = getRunningContainers();
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Docker Container Trivy Scanner</title>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #333; }
        .controls { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        select, button { padding: 10px 15px; font-size: 14px; border-radius: 4px; margin-right: 10px; }
        select { border: 1px solid #ddd; min-width: 300px; }
        button { background: #007bff; color: white; border: none; cursor: pointer; }
        button:hover { background: #0056b3; }
        button:disabled { background: #ccc; cursor: not-allowed; }
        .result { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .result table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        .result th, .result td { border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 13px; }
        .result th { background: #f8f9fa; }
        .loading { text-align: center; padding: 40px; color: #666; }
        .refresh-btn { background: #28a745; }
        .refresh-btn:hover { background: #1e7e34; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab { padding: 10px 20px; background: #e9ecef; border-radius: 4px; text-decoration: none; color: #333; }
        .tab.active { background: #007bff; color: white; }
        .tab:hover { opacity: 0.9; }
        <?= getAuthStyles() ?>
    </style>
</head>
<body>
    <?= getNavMenu() ?>
    <?= getDemoBanner() ?>
    <div class="container">
        <div class="tabs">
            <a href="container_scan.php" class="tab active">🐳 이미지 스캔</a>
            <a href="config_scan.php" class="tab">👮 컴플라이언스 스캔</a>
        </div>
        <h1>🐳 Docker Container Trivy Scanner</h1>
        <div class="controls">
            <label><strong>실행 중인 컨테이너:</strong></label><br><br>
            <?php if (empty($containers)): ?>
                <p style="color:#e74c3c;">⚠️ 실행 중인 컨테이너가 없거나 Docker에 접근할 수 없습니다.</p>
                <input type="text" id="containerSelect" placeholder="이미지명 직접 입력 (예: nginx:latest)" style="padding:10px;width:350px;border:1px solid #ddd;border-radius:4px;">
            <?php else: ?>
                <select id="containerSelect">
                    <option value="">-- 컨테이너 선택 --</option>
                    <?php foreach ($containers as $c): ?>
                    <option value="<?= htmlspecialchars($c['image']) ?>">[<?= htmlspecialchars($c['name']) ?>] <?= htmlspecialchars($c['image']) ?></option>
                    <?php endforeach; ?>
                </select>
            <?php endif; ?>
            <select id="severitySelect">
                <option value="CRITICAL">CRITICAL만</option>
                <option value="HIGH,CRITICAL" selected>HIGH 이상</option>
                <option value="MEDIUM,HIGH,CRITICAL">MEDIUM 이상</option>
                <option value="LOW,MEDIUM,HIGH,CRITICAL">전체</option>
            </select>
            <button onclick="scanContainer()" id="scanBtn">🔍 스캔 시작</button>
            <button onclick="location.reload()" class="refresh-btn">🔄 새로고침</button>
            <a href="scan_history.php" class="btn" style="background:#6c757d;color:white;padding:10px 15px;text-decoration:none;border-radius:4px;margin-left:10px;">📋 스캔 기록</a>
        </div>
        <div class="result" id="result">
            <p>컨테이너를 선택하고 스캔을 시작하세요.</p>
        </div>
        <div id="saveArea" style="display:none; margin-top:20px; padding:15px; background:#e8f5e9; border-radius:8px; text-align:center;">
            <p style="margin:0 0 10px 0;">📥 이 스캔 결과를 저장하시겠습니까?</p>
            <button onclick="saveResult()" id="saveBtn" style="background:#28a745;color:white;padding:10px 20px;border:none;border-radius:4px;cursor:pointer;font-size:14px;">💾 저장하기</button>
            <button onclick="hideSaveArea()" style="background:#6c757d;color:white;padding:10px 20px;border:none;border-radius:4px;cursor:pointer;font-size:14px;margin-left:10px;">취소</button>
        </div>

        <!-- SBOM 다운로드 영역 -->
        <div id="sbomArea" style="display:none; margin-top:20px; padding:15px; background:linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border-radius:8px; text-align:center;">
            <p style="margin:0 0 10px 0; color:#4ade80;">📦 SBOM (Software Bill of Materials) 다운로드</p>
            <button onclick="downloadSbom('cyclonedx')" style="background:#4ade80;color:#1a1a2e;padding:10px 20px;border:none;border-radius:4px;cursor:pointer;font-size:14px;font-weight:bold;">📄 CycloneDX</button>
            <button onclick="downloadSbom('spdx-json')" style="background:#60a5fa;color:white;padding:10px 20px;border:none;border-radius:4px;cursor:pointer;font-size:14px;margin-left:10px;">📄 SPDX</button>
        </div>
        <div id="saveMessage" style="display:none; margin-top:10px; padding:10px; border-radius:4px; text-align:center;"></div>

        <!-- Grafana 링크 영역 -->
        <div id="grafanaArea" style="display:none; margin-top:20px; padding:20px; background:linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius:8px;">
            <h3 style="color:white; margin:0 0 10px 0;">📊 Grafana 모니터링</h3>
            <p style="color:rgba(255,255,255,0.9); margin:0 0 15px 0;">스캔한 컨테이너의 상세 메트릭과 로그를 확인하세요</p>
            <div style="display:flex; flex-wrap:wrap; gap:10px;">
                <a id="grafanaContainerLink" href="#" target="_blank" style="display:inline-block; background:white; color:#667eea; padding:10px 20px; border-radius:4px; text-decoration:none; font-weight:bold;">🐳 이 컨테이너 메트릭</a>
                <a id="lokiContainerLink" href="#" target="_blank" style="display:inline-block; background:#4ade80; color:#1a1a2e; padding:10px 20px; border-radius:4px; text-decoration:none; font-weight:bold;">📋 이 컨테이너 로그</a>
            </div>
        </div>
    </div>
    <script>
        let lastScanData = null;
        let lastScanTarget = null;

        async function scanContainer() {
            const target = document.getElementById('containerSelect').value.trim();
            const severity = document.getElementById('severitySelect').value;
            const resultDiv = document.getElementById('result');
            const scanBtn = document.getElementById('scanBtn');
            const saveArea = document.getElementById('saveArea');
            const saveMessage = document.getElementById('saveMessage');

            if (!target) { alert('컨테이너를 선택하세요.'); return; }

            // 초기화
            lastScanData = null;
            lastScanTarget = null;
            saveArea.style.display = 'none';
            saveMessage.style.display = 'none';

            scanBtn.disabled = true;
            scanBtn.textContent = '⏳ 스캔 중...';
            resultDiv.innerHTML = '<div class="loading">🔄 스캔 중입니다. 잠시만 기다려주세요...</div>';

            try {
                const response = await fetch(`container_scan.php?action=scan&target=${encodeURIComponent(target)}&severity=${encodeURIComponent(severity)}`);
                const result = await response.json();
                resultDiv.innerHTML = marked.parse(result.markdown);

                // 스캔 성공 시 저장 버튼, SBOM, Grafana 링크 표시
                if (result.success && result.data) {
                    lastScanData = result.data;
                    lastScanTarget = result.target;
                    saveArea.style.display = 'block';

                    // SBOM 다운로드 영역 표시
                    document.getElementById('sbomArea').style.display = 'block';

                    // Grafana 메트릭 + Loki 로그 링크 표시
                    const grafanaArea = document.getElementById('grafanaArea');
                    const grafanaLink = document.getElementById('grafanaContainerLink');
                    const lokiContainerLink = document.getElementById('lokiContainerLink');
                    const containerName = getContainerName(target);

                    // 메트릭 대시보드 링크 (해당 컨테이너 필터)
                    grafanaLink.href = `http://monitor.rmstudio.co.kr:3000/d/trivy-security/trivy-security-scanner?orgId=1&var-container=${encodeURIComponent(containerName)}&var-image=${encodeURIComponent(target)}`;

                    // Loki 로그 대시보드 링크 (해당 컨테이너 필터)
                    lokiContainerLink.href = `http://monitor.rmstudio.co.kr:3000/d/loki-logs/container-logs-loki?orgId=1&var-container=${encodeURIComponent(containerName)}`;

                    grafanaArea.style.display = 'block';
                }
            } catch (e) {
                resultDiv.innerHTML = '<p style="color:red;">오류가 발생했습니다: ' + e.message + '</p>';
            }

            scanBtn.disabled = false;
            scanBtn.textContent = '🔍 스캔 시작';
        }

        async function saveResult() {
            if (!lastScanData || !lastScanTarget) {
                alert('저장할 스캔 결과가 없습니다.');
                return;
            }

            const saveBtn = document.getElementById('saveBtn');
            const saveMessage = document.getElementById('saveMessage');
            saveBtn.disabled = true;
            saveBtn.textContent = '저장 중...';

            try {
                const response = await fetch('container_scan.php?action=save', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: lastScanTarget, data: lastScanData })
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

        function getContainerName(imageOrName) {
            // 컨테이너 목록에서 이름 추출
            const select = document.getElementById('containerSelect');
            if (select.tagName === 'SELECT') {
                const selectedOption = select.options[select.selectedIndex];
                if (selectedOption && selectedOption.text) {
                    const match = selectedOption.text.match(/\[([^\]]+)\]/);
                    if (match) return match[1];
                }
            }
            // 이미지 이름에서 컨테이너 이름 추정
            return imageOrName.replace(/[/:]/g, '_');
        }

        // SBOM 다운로드
        function downloadSbom(format) {
            if (!lastScanTarget) {
                alert('먼저 스캔을 수행해주세요.');
                return;
            }
            const url = `sbom_download.php?image=${encodeURIComponent(lastScanTarget)}&format=${format}`;
            window.location.href = url;
        }
    </script>
</body>
</html>

