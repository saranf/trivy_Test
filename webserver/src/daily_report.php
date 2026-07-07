<?php
/**
 * 📊 일일 보안 보고서 시스템
 * - 1일 1회 전체 컨테이너 스캔
 * - Before/After 비교
 * - Google Spreadsheet 자동 저장
 */

require_once 'db_functions.php';
require_once 'webhook.php';

// Google Spreadsheet 설정
define('GOOGLE_SHEET_ID', getenv('GOOGLE_SHEET_ID') ?: '');
define('GOOGLE_SERVICE_ACCOUNT_KEY', getenv('GOOGLE_SERVICE_ACCOUNT_KEY') ?: '/var/www/html/google-credentials.json');

/**
 * 일일 보고서 생성
 */
function generateDailyReport($conn) {
    $today = date('Y-m-d');
    $yesterday = date('Y-m-d', strtotime('-1 day'));
    
    // 오늘의 스캔 결과 조회
    $todayScans = getDailyScanSummary($conn, $today);
    $yesterdayScans = getDailyScanSummary($conn, $yesterday);
    
    // Before/After 비교
    $comparison = compareDailyScans($yesterdayScans, $todayScans);
    
    return [
        'date' => $today,
        'generated_at' => date('Y-m-d H:i:s'),
        'summary' => [
            'total_images' => count($todayScans),
            'total_critical' => array_sum(array_column($todayScans, 'critical')),
            'total_high' => array_sum(array_column($todayScans, 'high')),
            'total_medium' => array_sum(array_column($todayScans, 'medium')),
            'total_low' => array_sum(array_column($todayScans, 'low'))
        ],
        'comparison' => $comparison,
        'images' => $todayScans
    ];
}

/**
 * 일일 스캔 요약 조회
 */
function getDailyScanSummary($conn, $date) {
    $sql = "SELECT 
                image_name,
                MAX(id) as latest_scan_id,
                MAX(critical_count) as critical,
                MAX(high_count) as high,
                MAX(medium_count) as medium,
                MAX(low_count) as low,
                MAX(total_vulns) as total
            FROM scan_history 
            WHERE DATE(scan_date) = ?
            GROUP BY image_name";
    
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $date);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $scans = [];
    while ($row = $result->fetch_assoc()) {
        $scans[$row['image_name']] = $row;
    }
    $stmt->close();
    
    return $scans;
}

/**
 * 전일 대비 비교
 */
function compareDailyScans($yesterday, $today) {
    $comparison = [
        'new_vulnerabilities' => [],      // 신규 취약점
        'fixed_vulnerabilities' => [],    // 조치된 취약점  
        'persistent_vulnerabilities' => [], // 기존 취약점
        'new_images' => [],               // 신규 스캔 이미지
        'removed_images' => [],           // 제거된 이미지
        'stats' => [
            'critical_change' => 0,
            'high_change' => 0,
            'total_change' => 0
        ]
    ];
    
    $yesterdayTotal = ['critical' => 0, 'high' => 0, 'total' => 0];
    $todayTotal = ['critical' => 0, 'high' => 0, 'total' => 0];
    
    // 전일 합계
    foreach ($yesterday as $img => $data) {
        $yesterdayTotal['critical'] += (int)$data['critical'];
        $yesterdayTotal['high'] += (int)$data['high'];
        $yesterdayTotal['total'] += (int)$data['total'];
        
        if (!isset($today[$img])) {
            $comparison['removed_images'][] = $img;
        }
    }
    
    // 금일 합계 및 비교
    foreach ($today as $img => $data) {
        $todayTotal['critical'] += (int)$data['critical'];
        $todayTotal['high'] += (int)$data['high'];
        $todayTotal['total'] += (int)$data['total'];
        
        if (!isset($yesterday[$img])) {
            $comparison['new_images'][] = $img;
        } else {
            // 변화량 계산
            $prevData = $yesterday[$img];
            $critDiff = (int)$data['critical'] - (int)$prevData['critical'];
            $highDiff = (int)$data['high'] - (int)$prevData['high'];
            
            if ($critDiff > 0 || $highDiff > 0) {
                $comparison['new_vulnerabilities'][] = [
                    'image' => $img,
                    'critical_new' => max(0, $critDiff),
                    'high_new' => max(0, $highDiff)
                ];
            }
            if ($critDiff < 0 || $highDiff < 0) {
                $comparison['fixed_vulnerabilities'][] = [
                    'image' => $img,
                    'critical_fixed' => abs(min(0, $critDiff)),
                    'high_fixed' => abs(min(0, $highDiff))
                ];
            }
        }
    }
    
    $comparison['stats'] = [
        'critical_change' => $todayTotal['critical'] - $yesterdayTotal['critical'],
        'high_change' => $todayTotal['high'] - $yesterdayTotal['high'],
        'total_change' => $todayTotal['total'] - $yesterdayTotal['total']
    ];

    return $comparison;
}

/**
 * Google Spreadsheet에 보고서 저장
 */
function saveToGoogleSheet($report) {
    if (empty(GOOGLE_SHEET_ID)) {
        return ['success' => false, 'error' => 'GOOGLE_SHEET_ID가 설정되지 않았습니다.'];
    }

    if (!file_exists(GOOGLE_SERVICE_ACCOUNT_KEY)) {
        return ['success' => false, 'error' => 'Google 서비스 계정 키 파일이 없습니다.'];
    }

    try {
        $accessToken = getGoogleAccessToken();
        if (!$accessToken) {
            return ['success' => false, 'error' => 'Google 인증 실패'];
        }

        // 시트 데이터 준비
        $rows = prepareSheetData($report);

        // Sheets API 호출
        $result = appendToSheet($accessToken, GOOGLE_SHEET_ID, $rows);

        return $result;
    } catch (Exception $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

/**
 * Google OAuth2 액세스 토큰 획득
 */
function getGoogleAccessToken() {
    $keyFile = GOOGLE_SERVICE_ACCOUNT_KEY;
    if (!file_exists($keyFile)) return null;

    $key = json_decode(file_get_contents($keyFile), true);
    if (!$key) return null;

    $now = time();
    $header = base64_encode(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
    $claim = base64_encode(json_encode([
        'iss' => $key['client_email'],
        'scope' => 'https://www.googleapis.com/auth/spreadsheets',
        'aud' => 'https://oauth2.googleapis.com/token',
        'exp' => $now + 3600,
        'iat' => $now
    ]));

    $signature = '';
    openssl_sign("$header.$claim", $signature, $key['private_key'], 'SHA256');
    $jwt = "$header.$claim." . base64_encode($signature);

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => 'https://oauth2.googleapis.com/token',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion' => $jwt
        ])
    ]);

    $response = json_decode(curl_exec($ch), true);
    unset($ch);

    return $response['access_token'] ?? null;
}

/**
 * 시트 데이터 준비
 */
function prepareSheetData($report) {
    $date = $report['date'];
    $summary = $report['summary'];
    $stats = $report['comparison']['stats'];

    $rows = [];

    // 헤더 행 (첫 실행시)
    // $rows[] = ['날짜', '이미지', 'Critical', 'High', 'Medium', 'Low', '총계', 'Critical변화', 'High변화', '상태'];

    // 요약 행
    $status = '';
    if ($stats['critical_change'] > 0) $status = '🚨 Critical 증가';
    elseif ($stats['high_change'] > 0) $status = '⚠️ High 증가';
    elseif ($stats['critical_change'] < 0 || $stats['high_change'] < 0) $status = '✅ 개선';
    else $status = '➖ 변동없음';

    $rows[] = [
        $date,
        '[전체요약]',
        $summary['total_critical'],
        $summary['total_high'],
        $summary['total_medium'],
        $summary['total_low'],
        $summary['total_critical'] + $summary['total_high'] + $summary['total_medium'] + $summary['total_low'],
        ($stats['critical_change'] >= 0 ? '+' : '') . $stats['critical_change'],
        ($stats['high_change'] >= 0 ? '+' : '') . $stats['high_change'],
        $status
    ];

    // 이미지별 행
    foreach ($report['images'] as $img => $data) {
        $rows[] = [
            $date,
            $img,
            (int)$data['critical'],
            (int)$data['high'],
            (int)$data['medium'],
            (int)$data['low'],
            (int)$data['total'],
            '',
            '',
            ''
        ];
    }

    return $rows;
}

/**
 * Google Sheets에 데이터 추가
 */
function appendToSheet($accessToken, $sheetId, $rows) {
    $range = 'Daily Report!A:J';
    $url = "https://sheets.googleapis.com/v4/spreadsheets/{$sheetId}/values/{$range}:append";
    $url .= "?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS";

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode(['values' => $rows]),
        CURLOPT_HTTPHEADER => [
            'Authorization: Bearer ' . $accessToken,
            'Content-Type: application/json'
        ]
    ]);

    $response = json_decode(curl_exec($ch), true);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    unset($ch);

    if ($httpCode === 200) {
        return ['success' => true, 'updates' => $response['updates'] ?? null];
    }

    return ['success' => false, 'error' => $response['error']['message'] ?? 'API 오류'];
}

/**
 * 일일 보고서 실행 및 Slack 알림
 */
function runDailyReportJob() {
    $conn = getDbConnection();
    if (!$conn) {
        return ['success' => false, 'error' => 'DB 연결 실패'];
    }

    initDatabase($conn);

    // 보고서 생성
    $report = generateDailyReport($conn);

    // DB에 저장
    saveDailyReportToDb($conn, $report);

    // Google Spreadsheet에 저장
    $sheetResult = saveToGoogleSheet($report);

    // Slack 알림
    $slackResult = sendDailyReportSlack($report);

    $conn->close();

    return [
        'success' => true,
        'report' => $report,
        'sheet_saved' => $sheetResult['success'] ?? false,
        'slack_sent' => $slackResult['success'] ?? false
    ];
}

/**
 * 일일 보고서 DB 저장
 */
function saveDailyReportToDb($conn, $report) {
    // daily_reports 테이블 생성 (없으면)
    $conn->query("CREATE TABLE IF NOT EXISTS daily_reports (
        id INT AUTO_INCREMENT PRIMARY KEY,
        report_date DATE NOT NULL UNIQUE,
        total_images INT DEFAULT 0,
        total_critical INT DEFAULT 0,
        total_high INT DEFAULT 0,
        total_medium INT DEFAULT 0,
        total_low INT DEFAULT 0,
        critical_change INT DEFAULT 0,
        high_change INT DEFAULT 0,
        report_json LONGTEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )");

    $stmt = $conn->prepare("INSERT INTO daily_reports
        (report_date, total_images, total_critical, total_high, total_medium, total_low,
         critical_change, high_change, report_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
        total_images = VALUES(total_images),
        total_critical = VALUES(total_critical),
        total_high = VALUES(total_high),
        total_medium = VALUES(total_medium),
        total_low = VALUES(total_low),
        critical_change = VALUES(critical_change),
        high_change = VALUES(high_change),
        report_json = VALUES(report_json)");

    $json = json_encode($report);
    $stmt->bind_param("siiiiiiis",
        $report['date'],
        $report['summary']['total_images'],
        $report['summary']['total_critical'],
        $report['summary']['total_high'],
        $report['summary']['total_medium'],
        $report['summary']['total_low'],
        $report['comparison']['stats']['critical_change'],
        $report['comparison']['stats']['high_change'],
        $json
    );

    $stmt->execute();
    $stmt->close();
}

/**
 * 일일 보고서 Slack 발송
 */
function sendDailyReportSlack($report) {
    if (!isWebhookConfigured()) {
        return ['success' => false, 'error' => 'Webhook not configured'];
    }

    $summary = $report['summary'];
    $stats = $report['comparison']['stats'];

    $statusEmoji = '➖';
    $color = 'good';
    if ($stats['critical_change'] > 0) {
        $statusEmoji = '🚨';
        $color = 'danger';
    } elseif ($stats['high_change'] > 0) {
        $statusEmoji = '⚠️';
        $color = 'warning';
    } elseif ($stats['critical_change'] < 0 || $stats['high_change'] < 0) {
        $statusEmoji = '✅';
    }

    $changeText = [];
    if ($stats['critical_change'] != 0) {
        $sign = $stats['critical_change'] > 0 ? '+' : '';
        $changeText[] = "Critical: {$sign}{$stats['critical_change']}";
    }
    if ($stats['high_change'] != 0) {
        $sign = $stats['high_change'] > 0 ? '+' : '';
        $changeText[] = "High: {$sign}{$stats['high_change']}";
    }

    $message = "{$statusEmoji} *일일 보안 보고서* - {$report['date']}";

    $attachments = [[
        'color' => $color,
        'fields' => [
            ['title' => '📦 스캔 이미지', 'value' => (string)$summary['total_images'], 'short' => true],
            ['title' => '🔴 Critical', 'value' => (string)$summary['total_critical'], 'short' => true],
            ['title' => '🟠 High', 'value' => (string)$summary['total_high'], 'short' => true],
            ['title' => '🟡 Medium', 'value' => (string)$summary['total_medium'], 'short' => true],
            ['title' => '📊 전일 대비', 'value' => empty($changeText) ? '변동 없음' : implode(' / ', $changeText), 'short' => false]
        ],
        'footer' => 'Trivy Daily Report',
        'ts' => time()
    ]];

    // 신규 취약점 이미지 목록
    if (!empty($report['comparison']['new_vulnerabilities'])) {
        $newList = array_slice($report['comparison']['new_vulnerabilities'], 0, 5);
        $newText = implode("\n", array_map(fn($v) =>
            "• {$v['image']}: +{$v['critical_new']} Critical, +{$v['high_new']} High",
            $newList
        ));
        if (count($report['comparison']['new_vulnerabilities']) > 5) {
            $newText .= "\n... 외 " . (count($report['comparison']['new_vulnerabilities']) - 5) . "개";
        }
        $attachments[] = [
            'color' => 'danger',
            'title' => '🆕 신규 취약점 발견',
            'text' => $newText
        ];
    }

    return sendSlackNotification($message, $attachments);
}

// API 엔드포인트 처리
if (isset($_GET['action']) || php_sapi_name() === 'cli') {
    $action = $_GET['action'] ?? ($argv[1] ?? 'generate');

    if ($action === 'generate' || $action === 'run') {
        header('Content-Type: application/json');

        // CLI 또는 Admin만 실행 가능
        if (php_sapi_name() !== 'cli') {
            session_start();
            if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'admin') {
                echo json_encode(['success' => false, 'error' => 'Admin 권한 필요']);
                exit;
            }
        }

        $result = runDailyReportJob();
        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        exit;
    }

    if ($action === 'view') {
        // 최근 보고서 조회
        header('Content-Type: application/json');
        $conn = getDbConnection();
        $result = $conn->query("SELECT * FROM daily_reports ORDER BY report_date DESC LIMIT 30");
        $reports = [];
        while ($row = $result->fetch_assoc()) {
            $reports[] = $row;
        }
        $conn->close();
        echo json_encode($reports, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        exit;
    }
}

