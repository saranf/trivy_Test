<?php
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

// Trivy 스캔 실행 및 Markdown 변환
function scanContainer($imageOrId, $severity = 'HIGH,CRITICAL') {
    $safeTarget = escapeshellarg($imageOrId);
    $safeSeverity = escapeshellarg($severity);

    // Trivy 스캔 실행 (JSON 형식)
    $command = "trivy image --no-progress --severity $safeSeverity --format json $safeTarget 2>/dev/null";
    exec($command, $output, $result_code);

    $jsonOutput = implode("\n", $output);
    $data = json_decode($jsonOutput, true);

    if ($data === null) {
        return "## ❌ 스캔 오류\n\n```\n" . $jsonOutput . "\n```";
    }

    return convertToMarkdown($data, $imageOrId);
}

// JSON 결과를 Markdown으로 변환
function convertToMarkdown($data, $target) {
    $md = "# 🔍 Trivy 취약점 스캔 결과\n\n";
    $md .= "**스캔 대상**: `$target`\n\n";
    $md .= "**스캔 시간**: " . date('Y-m-d H:i:s') . "\n\n";
    $md .= "---\n\n";
    
    $totalVulns = 0;
    $severityCounts = ['CRITICAL' => 0, 'HIGH' => 0, 'MEDIUM' => 0, 'LOW' => 0];
    
    if (!isset($data['Results']) || empty($data['Results'])) {
        $md .= "## ✅ 취약점이 발견되지 않았습니다!\n";
        return $md;
    }
    
    foreach ($data['Results'] as $result) {
        if (!isset($result['Vulnerabilities']) || empty($result['Vulnerabilities'])) {
            continue;
        }
        
        $md .= "## 📦 " . ($result['Target'] ?? 'Unknown') . "\n\n";
        $md .= "| 심각도 | CVE ID | 패키지 | 설치 버전 | 수정 버전 | 설명 |\n";
        $md .= "|:------:|--------|--------|-----------|-----------|------|\n";
        
        foreach ($result['Vulnerabilities'] as $vuln) {
            $severity = $vuln['Severity'] ?? 'UNKNOWN';
            $severityIcon = getSeverityIcon($severity);
            $vulnId = $vuln['VulnerabilityID'] ?? 'N/A';
            $pkgName = $vuln['PkgName'] ?? 'N/A';
            $installed = $vuln['InstalledVersion'] ?? 'N/A';
            $fixed = $vuln['FixedVersion'] ?? '-';
            $title = substr($vuln['Title'] ?? $vuln['Description'] ?? 'N/A', 0, 50);
            
            $md .= "| $severityIcon $severity | $vulnId | $pkgName | $installed | $fixed | $title |\n";
            
            $totalVulns++;
            if (isset($severityCounts[$severity])) {
                $severityCounts[$severity]++;
            }
        }
        $md .= "\n";
    }
    
    // 요약 추가
    $summary = "## 📊 요약\n\n";
    $summary .= "- **총 취약점**: $totalVulns 개\n";
    $summary .= "- 🔴 CRITICAL: {$severityCounts['CRITICAL']} 개\n";
    $summary .= "- 🟠 HIGH: {$severityCounts['HIGH']} 개\n";
    $summary .= "- 🟡 MEDIUM: {$severityCounts['MEDIUM']} 개\n";
    $summary .= "- 🟢 LOW: {$severityCounts['LOW']} 개\n\n";
    
    return $summary . $md;
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
    $target = $_GET['target'] ?? '';
    $severity = $_GET['severity'] ?? 'HIGH,CRITICAL';

    if (empty($target)) {
        echo "# ❌ 오류\n\n스캔 대상을 지정해주세요.";
        exit;
    }

    echo scanContainer($target, $severity);
    exit;
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
    </style>
</head>
<body>
    <div class="container">
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
        </div>
        <div class="result" id="result">
            <p>컨테이너를 선택하고 스캔을 시작하세요.</p>
        </div>
    </div>
    <script>
        async function scanContainer() {
            const target = document.getElementById('containerSelect').value.trim();
            const severity = document.getElementById('severitySelect').value;
            const resultDiv = document.getElementById('result');
            const scanBtn = document.getElementById('scanBtn');

            if (!target) { alert('컨테이너를 선택하세요.'); return; }

            scanBtn.disabled = true;
            scanBtn.textContent = '⏳ 스캔 중...';
            resultDiv.innerHTML = '<div class="loading">🔄 스캔 중입니다. 잠시만 기다려주세요...</div>';

            try {
                const response = await fetch(`container_scan.php?action=scan&target=${encodeURIComponent(target)}&severity=${encodeURIComponent(severity)}`);
                const markdown = await response.text();
                resultDiv.innerHTML = marked.parse(markdown);
            } catch (e) {
                resultDiv.innerHTML = '<p style="color:red;">오류가 발생했습니다: ' + e.message + '</p>';
            }

            scanBtn.disabled = false;
            scanBtn.textContent = '🔍 스캔 시작';
        }
    </script>
</body>
</html>

