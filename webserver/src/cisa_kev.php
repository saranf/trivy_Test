<?php
/**
 * 🚨 CISA KEV (Known Exploited Vulnerabilities) 연동
 * - 미국 CISA에서 제공하는 실제 악용 중인 취약점 목록
 * - CVE와 매칭하여 우선순위 결정에 활용
 * 
 * 데이터 소스: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
 */

require_once 'db_functions.php';

define('CISA_KEV_URL', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
define('KEV_CACHE_FILE', '/tmp/cisa_kev_cache.json');
define('KEV_CACHE_TTL', 86400); // 24시간

/**
 * CISA KEV 데이터 가져오기 (캐시 사용)
 */
function getKevData($forceRefresh = false) {
    // 캐시 확인
    if (!$forceRefresh && file_exists(KEV_CACHE_FILE)) {
        $cacheTime = filemtime(KEV_CACHE_FILE);
        if (time() - $cacheTime < KEV_CACHE_TTL) {
            $cached = json_decode(file_get_contents(KEV_CACHE_FILE), true);
            if ($cached) return $cached;
        }
    }
    
    // CISA에서 데이터 다운로드
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => CISA_KEV_URL,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_SSL_VERIFYPEER => true
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    // curl_close는 PHP 8.0+에서 자동 처리되므로 제거

    if ($httpCode !== 200 || !$response) {
        // 실패시 캐시된 데이터 반환 (있으면)
        if (file_exists(KEV_CACHE_FILE)) {
            return json_decode(file_get_contents(KEV_CACHE_FILE), true);
        }
        return null;
    }
    
    $data = json_decode($response, true);
    if (!$data || !isset($data['vulnerabilities'])) {
        return null;
    }
    
    // CVE ID를 키로 하는 맵 생성
    $kevMap = [];
    foreach ($data['vulnerabilities'] as $vuln) {
        $cveId = $vuln['cveID'] ?? '';
        if ($cveId) {
            $kevMap[$cveId] = [
                'vendorProject' => $vuln['vendorProject'] ?? '',
                'product' => $vuln['product'] ?? '',
                'vulnerabilityName' => $vuln['vulnerabilityName'] ?? '',
                'dateAdded' => $vuln['dateAdded'] ?? '',
                'shortDescription' => $vuln['shortDescription'] ?? '',
                'requiredAction' => $vuln['requiredAction'] ?? '',
                'dueDate' => $vuln['dueDate'] ?? '',
                'knownRansomwareCampaignUse' => $vuln['knownRansomwareCampaignUse'] ?? 'Unknown'
            ];
        }
    }
    
    $result = [
        'catalogVersion' => $data['catalogVersion'] ?? '',
        'dateReleased' => $data['dateReleased'] ?? '',
        'count' => count($kevMap),
        'vulnerabilities' => $kevMap
    ];
    
    // 캐시 저장
    file_put_contents(KEV_CACHE_FILE, json_encode($result));
    
    return $result;
}

/**
 * CVE가 KEV 목록에 있는지 확인
 */
function isKnownExploited($cveId) {
    $kevData = getKevData();
    if (!$kevData) return false;
    return isset($kevData['vulnerabilities'][$cveId]);
}

/**
 * CVE의 KEV 상세 정보 가져오기
 */
function getKevDetails($cveId) {
    $kevData = getKevData();
    if (!$kevData || !isset($kevData['vulnerabilities'][$cveId])) {
        return null;
    }
    return $kevData['vulnerabilities'][$cveId];
}

/**
 * 스캔 결과에서 KEV 취약점 추출
 */
function findKevVulnerabilities($scanData) {
    $kevData = getKevData();
    if (!$kevData) return [];
    
    $kevVulns = [];
    $results = $scanData['Results'] ?? [];
    
    foreach ($results as $result) {
        $vulns = $result['Vulnerabilities'] ?? [];
        foreach ($vulns as $v) {
            $cveId = $v['VulnerabilityID'] ?? '';
            if (isset($kevData['vulnerabilities'][$cveId])) {
                $kevVulns[] = [
                    'cveId' => $cveId,
                    'library' => $v['PkgName'] ?? '',
                    'severity' => $v['Severity'] ?? '',
                    'installedVersion' => $v['InstalledVersion'] ?? '',
                    'fixedVersion' => $v['FixedVersion'] ?? '',
                    'kev' => $kevData['vulnerabilities'][$cveId]
                ];
            }
        }
    }
    
    return $kevVulns;
}

/**
 * DB 스캔 결과에서 KEV 매칭
 */
function matchKevFromDb($conn, $scanId) {
    $kevData = getKevData();
    if (!$kevData) return ['success' => false, 'error' => 'KEV 데이터 로드 실패'];
    
    $stmt = $conn->prepare("SELECT vulnerabilities FROM scan_history WHERE id = ?");
    $stmt->bind_param("i", $scanId);
    $stmt->execute();
    $row = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    
    if (!$row) return ['success' => false, 'error' => '스캔 결과 없음'];
    
    $vulns = json_decode($row['vulnerabilities'], true) ?? [];
    $kevMatches = [];
    
    foreach ($vulns as $v) {
        $cveId = $v['vulnerability'] ?? $v['VulnerabilityID'] ?? '';
        if (isset($kevData['vulnerabilities'][$cveId])) {
            $kevMatches[] = array_merge($v, [
                'kev' => $kevData['vulnerabilities'][$cveId],
                'isKev' => true
            ]);
        }
    }
    
    return [
        'success' => true,
        'kevCount' => count($kevMatches),
        'totalVulns' => count($vulns),
        'kevVulnerabilities' => $kevMatches,
        'catalogVersion' => $kevData['catalogVersion'],
        'catalogDate' => $kevData['dateReleased']
    ];
}

/**
 * KEV 통계 가져오기
 */
function getKevStats() {
    $kevData = getKevData();
    if (!$kevData) return null;

    $ransomwareCount = 0;
    foreach ($kevData['vulnerabilities'] as $v) {
        if (($v['knownRansomwareCampaignUse'] ?? '') === 'Known') {
            $ransomwareCount++;
        }
    }

    return [
        'totalKev' => $kevData['count'],
        'ransomwareRelated' => $ransomwareCount,
        'catalogVersion' => $kevData['catalogVersion'],
        'lastUpdated' => $kevData['dateReleased']
    ];
}

// API 엔드포인트 처리 (직접 호출시에만 - require_once로 포함될 때는 실행 안함)
if (basename($_SERVER['SCRIPT_FILENAME']) === 'cisa_kev.php' && isset($_GET['action'])) {
    header('Content-Type: application/json');

    $action = $_GET['action'];

    // refresh: KEV 데이터 새로고침
    if ($action === 'refresh') {
        $data = getKevData(true);
        echo json_encode([
            'success' => $data !== null,
            'count' => $data['count'] ?? 0,
            'version' => $data['catalogVersion'] ?? '',
            'date' => $data['dateReleased'] ?? ''
        ]);
        exit;
    }

    // stats: KEV 통계
    if ($action === 'stats') {
        echo json_encode(getKevStats());
        exit;
    }

    // check: 특정 CVE가 KEV인지 확인
    if ($action === 'check') {
        $cveId = $_GET['cve'] ?? '';
        if (empty($cveId)) {
            echo json_encode(['error' => 'CVE ID 필요']);
            exit;
        }

        $details = getKevDetails($cveId);
        echo json_encode([
            'cveId' => $cveId,
            'isKev' => $details !== null,
            'details' => $details
        ]);
        exit;
    }

    // match: 스캔 결과에서 KEV 매칭
    if ($action === 'match') {
        $scanId = (int)($_GET['scan_id'] ?? 0);
        if ($scanId <= 0) {
            echo json_encode(['error' => 'scan_id 필요']);
            exit;
        }

        $conn = getDbConnection();
        $result = matchKevFromDb($conn, $scanId);
        $conn->close();

        echo json_encode($result);
        exit;
    }

    // list: 전체 KEV 목록 (페이징)
    if ($action === 'list') {
        $page = max(1, (int)($_GET['page'] ?? 1));
        $limit = min(100, max(10, (int)($_GET['limit'] ?? 50)));

        $kevData = getKevData();
        if (!$kevData) {
            echo json_encode(['error' => 'KEV 데이터 로드 실패']);
            exit;
        }

        $all = array_values($kevData['vulnerabilities']);
        $total = count($all);
        $offset = ($page - 1) * $limit;

        echo json_encode([
            'total' => $total,
            'page' => $page,
            'limit' => $limit,
            'totalPages' => ceil($total / $limit),
            'vulnerabilities' => array_slice($all, $offset, $limit)
        ]);
        exit;
    }

    echo json_encode(['error' => '알 수 없는 액션']);
    exit;
}

