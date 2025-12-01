<?php
/**
 * 스캔 결과 이메일 발송 API (네이버 SMTP + CSV 첨부)
 */

error_reporting(0);
ini_set('display_errors', 0);

header('Content-Type: application/json');

require_once 'db_functions.php';

// SMTP 설정 (네이버)
$smtpConfig = [
    'host' => getenv('SMTP_HOST') ?: 'smtp.naver.com',
    'port' => (int)(getenv('SMTP_PORT') ?: 465),
    'user' => getenv('SMTP_USER') ?: '',
    'pass' => getenv('SMTP_PASS') ?: '',
    'from' => getenv('FROM_EMAIL') ?: '',
    'fromName' => getenv('FROM_NAME') ?: 'Trivy Scanner'
];

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'POST method required']);
    exit;
}

$data = json_decode(file_get_contents('php://input'), true);
$scanIds = $data['scan_ids'] ?? [];
$toEmail = $data['email'] ?? '';
$subject = $data['subject'] ?? 'Trivy 스캔 결과 리포트';

if (empty($scanIds) || empty($toEmail)) {
    echo json_encode(['success' => false, 'message' => '스캔 ID와 이메일 주소가 필요합니다.']);
    exit;
}

if (!filter_var($toEmail, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['success' => false, 'message' => '유효하지 않은 이메일 주소입니다.']);
    exit;
}

$conn = getDbConnection();
if (!$conn) {
    echo json_encode(['success' => false, 'message' => 'DB 연결 실패']);
    exit;
}

// 스캔 데이터 조회
$placeholders = implode(',', array_fill(0, count($scanIds), '?'));
$types = str_repeat('i', count($scanIds));

$stmt = $conn->prepare("SELECT * FROM scan_history WHERE id IN ($placeholders) ORDER BY scan_date DESC");
$stmt->bind_param($types, ...$scanIds);
$stmt->execute();
$result = $stmt->get_result();

$scans = [];
while ($row = $result->fetch_assoc()) {
    $row['vulnerabilities'] = getScanVulnerabilities($conn, $row['id']);
    $scans[] = $row;
}
$stmt->close();

if (empty($scans)) {
    echo json_encode(['success' => false, 'message' => '스캔 데이터를 찾을 수 없습니다.']);
    exit;
}

// CSV 생성
$csv = generateCsv($scans);

// HTML 이메일 본문 생성
$html = generateEmailHtml($scans);

// 이메일 발송 (CSV 첨부)
$result = sendEmailSmtp($toEmail, $subject, $html, $csv, $smtpConfig);

echo json_encode($result);

// CSV 생성 함수
function generateCsv($scans) {
    $lines = [];
    $lines[] = "Image,Scan Date,Library,Vulnerability,Severity,Installed Version,Fixed Version";

    foreach ($scans as $scan) {
        $imageName = $scan['image_name'];
        $scanDate = $scan['scan_date'];

        if (!empty($scan['vulnerabilities'])) {
            foreach ($scan['vulnerabilities'] as $v) {
                $lines[] = sprintf('"%s","%s","%s","%s","%s","%s","%s"',
                    str_replace('"', '""', $imageName),
                    $scanDate,
                    str_replace('"', '""', $v['library']),
                    str_replace('"', '""', $v['vulnerability']),
                    $v['severity'],
                    str_replace('"', '""', $v['installed_version']),
                    str_replace('"', '""', $v['fixed_version'] ?: '')
                );
            }
        } else {
            $lines[] = sprintf('"%s","%s","No vulnerabilities found","","","",""', $imageName, $scanDate);
        }
    }

    return implode("\n", $lines);
}

function generateEmailHtml($scans) {
    $html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        h2 { color: #007bff; border-bottom: 2px solid #007bff; padding-bottom: 5px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
        th, td { padding: 10px; text-align: left; border: 1px solid #ddd; }
        th { background: #f8f9fa; }
        .summary { background: #f5f5f5; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .critical { background: #dc3545; color: white; padding: 3px 8px; border-radius: 4px; }
        .high { background: #fd7e14; color: white; padding: 3px 8px; border-radius: 4px; }
        .medium { background: #ffc107; color: #333; padding: 3px 8px; border-radius: 4px; }
        .low { background: #28a745; color: white; padding: 3px 8px; border-radius: 4px; }
    </style></head><body>';
    
    $html .= '<h1>🔒 Trivy 스캔 결과 리포트</h1>';
    $html .= '<p>생성일시: ' . date('Y-m-d H:i:s') . '</p>';
    
    foreach ($scans as $scan) {
        $html .= '<h2>' . htmlspecialchars($scan['image_name']) . '</h2>';
        $html .= '<div class="summary">';
        $html .= '<strong>스캔일시:</strong> ' . $scan['scan_date'] . '<br>';
        $html .= '<strong>총 취약점:</strong> ' . $scan['total_vulns'] . ' | ';
        $html .= '<span class="critical">C: ' . $scan['critical_count'] . '</span> ';
        $html .= '<span class="high">H: ' . $scan['high_count'] . '</span> ';
        $html .= '<span class="medium">M: ' . $scan['medium_count'] . '</span> ';
        $html .= '<span class="low">L: ' . $scan['low_count'] . '</span>';
        $html .= '</div>';
        
        if (!empty($scan['vulnerabilities'])) {
            $html .= '<table><thead><tr><th>Library</th><th>Vulnerability</th><th>Severity</th><th>Installed</th><th>Fixed</th></tr></thead><tbody>';
            foreach ($scan['vulnerabilities'] as $v) {
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
        }
    }
    
    $html .= '<hr><p style="color:#666;font-size:12px;">이 메일은 Trivy Security Scanner에서 자동 발송되었습니다.</p>';
    $html .= '</body></html>';
    
    return $html;
}

function sendEmailSmtp($to, $subject, $html, $csv, $config) {
    $host = $config['host'];
    $port = $config['port'];
    $user = $config['user'];
    $pass = $config['pass'];
    $from = $config['from'] ?: $user;
    $fromName = $config['fromName'];

    if (empty($user) || empty($pass)) {
        return ['success' => false, 'message' => 'SMTP 설정이 필요합니다. docker-compose.yml에서 SMTP_USER, SMTP_PASS를 설정하세요.'];
    }

    try {
        // SSL 연결 (포트 465)
        $context = stream_context_create([
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true
            ]
        ]);

        $socket = @stream_socket_client("ssl://$host:$port", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $context);

        if (!$socket) {
            return ['success' => false, 'message' => "SMTP 연결 실패: $errstr ($errno)"];
        }

        stream_set_timeout($socket, 30);

        // 서버 응답 읽기
        $response = fgets($socket, 515);
        if (substr($response, 0, 3) != '220') {
            fclose($socket);
            return ['success' => false, 'message' => "SMTP 서버 응답 오류: $response"];
        }

        // EHLO
        fputs($socket, "EHLO localhost\r\n");
        while ($line = fgets($socket, 515)) {
            if (substr($line, 3, 1) == ' ') break;
        }

        // AUTH LOGIN
        fputs($socket, "AUTH LOGIN\r\n");
        $authResponse = fgets($socket, 515);
        if (substr($authResponse, 0, 3) != '334') {
            fclose($socket);
            return ['success' => false, 'message' => "AUTH 시작 실패: $authResponse"];
        }

        fputs($socket, base64_encode($user) . "\r\n");
        $userResponse = fgets($socket, 515);
        if (substr($userResponse, 0, 3) != '334') {
            fclose($socket);
            return ['success' => false, 'message' => "사용자명 인증 실패"];
        }

        fputs($socket, base64_encode($pass) . "\r\n");
        $passResponse = fgets($socket, 515);
        if (substr($passResponse, 0, 3) != '235') {
            fclose($socket);
            return ['success' => false, 'message' => 'SMTP 인증 실패. 아이디/비밀번호를 확인하세요.'];
        }

        // MAIL FROM
        fputs($socket, "MAIL FROM:<$from>\r\n");
        $mailFromResponse = fgets($socket, 515);
        if (substr($mailFromResponse, 0, 3) != '250') {
            fclose($socket);
            return ['success' => false, 'message' => "MAIL FROM 실패"];
        }

        // RCPT TO
        fputs($socket, "RCPT TO:<$to>\r\n");
        $rcptResponse = fgets($socket, 515);
        if (substr($rcptResponse, 0, 3) != '250') {
            fclose($socket);
            return ['success' => false, 'message' => "RCPT TO 실패"];
        }

        // DATA
        fputs($socket, "DATA\r\n");
        $dataStartResponse = fgets($socket, 515);
        if (substr($dataStartResponse, 0, 3) != '354') {
            fclose($socket);
            return ['success' => false, 'message' => "DATA 시작 실패"];
        }

        // Multipart 이메일 (HTML + CSV 첨부)
        $boundary = md5(time());

        $message = "From: =?UTF-8?B?" . base64_encode($fromName) . "?= <$from>\r\n";
        $message .= "To: $to\r\n";
        $message .= "Subject: =?UTF-8?B?" . base64_encode($subject) . "?=\r\n";
        $message .= "MIME-Version: 1.0\r\n";
        $message .= "Content-Type: multipart/mixed; boundary=\"$boundary\"\r\n";
        $message .= "Date: " . date('r') . "\r\n";
        $message .= "\r\n";

        // HTML 본문
        $message .= "--$boundary\r\n";
        $message .= "Content-Type: text/html; charset=UTF-8\r\n";
        $message .= "Content-Transfer-Encoding: base64\r\n";
        $message .= "\r\n";
        $message .= chunk_split(base64_encode($html));
        $message .= "\r\n";

        // CSV 첨부파일
        $message .= "--$boundary\r\n";
        $message .= "Content-Type: text/csv; charset=UTF-8; name=\"trivy_scan_result.csv\"\r\n";
        $message .= "Content-Disposition: attachment; filename=\"trivy_scan_result.csv\"\r\n";
        $message .= "Content-Transfer-Encoding: base64\r\n";
        $message .= "\r\n";
        $message .= chunk_split(base64_encode("\xEF\xBB\xBF" . $csv)); // BOM for Excel
        $message .= "\r\n";

        $message .= "--$boundary--\r\n";
        $message .= ".\r\n";

        fputs($socket, $message);
        $dataResponse = fgets($socket, 515);

        fputs($socket, "QUIT\r\n");
        fclose($socket);

        if (substr($dataResponse, 0, 3) == '250') {
            return ['success' => true, 'message' => "이메일이 $to 로 발송되었습니다."];
        } else {
            return ['success' => false, 'message' => "이메일 발송 실패: $dataResponse"];
        }
    } catch (Exception $e) {
        return ['success' => false, 'message' => '이메일 발송 중 오류: ' . $e->getMessage()];
    }
}

