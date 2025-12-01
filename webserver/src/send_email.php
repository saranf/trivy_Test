<?php
/**
 * 스캔 결과 이메일 발송 API
 */

error_reporting(0);
ini_set('display_errors', 0);

header('Content-Type: application/json');

require_once 'db_functions.php';

// SMTP 설정 (환경변수 또는 기본값) - MailHog 사용
$smtpConfig = [
    'host' => getenv('SMTP_HOST') ?: 'mailhog',
    'port' => (int)(getenv('SMTP_PORT') ?: 1025),
    'from' => getenv('FROM_EMAIL') ?: 'scanner@trivy.local',
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

// HTML 이메일 본문 생성
$html = generateEmailHtml($scans);

// 이메일 발송
$result = sendEmailSmtp($toEmail, $subject, $html, $smtpConfig);

echo json_encode($result);

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

function sendEmailSmtp($to, $subject, $html, $config) {
    $host = $config['host'];
    $port = $config['port'];
    $user = $config['user'];
    $pass = $config['pass'];
    $from = $config['from'] ?: $user;
    $fromName = $config['fromName'];

    // SMTP 설정 확인
    if (empty($user) || empty($pass)) {
        return ['success' => false, 'message' => 'SMTP 설정이 필요합니다. docker-compose.yml에서 SMTP_USER, SMTP_PASS를 설정하세요.'];
    }

    try {
        // SSL/TLS 직접 연결 (포트 465) 또는 STARTTLS (포트 587)
        if ($port == 465) {
            $socket = @fsockopen("ssl://$host", $port, $errno, $errstr, 30);
        } else {
            $socket = @fsockopen($host, $port, $errno, $errstr, 30);
        }

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
        $ehloResponse = '';
        while ($line = fgets($socket, 515)) {
            $ehloResponse .= $line;
            if (substr($line, 3, 1) == ' ') break;
        }

        // STARTTLS (포트 587인 경우)
        if ($port == 587) {
            fputs($socket, "STARTTLS\r\n");
            $starttlsResponse = fgets($socket, 515);
            if (substr($starttlsResponse, 0, 3) != '220') {
                fclose($socket);
                return ['success' => false, 'message' => "STARTTLS 실패: $starttlsResponse"];
            }

            // TLS 활성화
            $crypto = stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT);
            if (!$crypto) {
                fclose($socket);
                return ['success' => false, 'message' => 'TLS 암호화 활성화 실패'];
            }

            // TLS 후 다시 EHLO
            fputs($socket, "EHLO localhost\r\n");
            while ($line = fgets($socket, 515)) {
                if (substr($line, 3, 1) == ' ') break;
            }
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
            return ['success' => false, 'message' => "사용자명 인증 실패: $userResponse"];
        }

        fputs($socket, base64_encode($pass) . "\r\n");
        $passResponse = fgets($socket, 515);
        if (substr($passResponse, 0, 3) != '235') {
            fclose($socket);
            return ['success' => false, 'message' => 'SMTP 인증 실패. 앱 비밀번호를 확인하세요.'];
        }

        // MAIL FROM
        fputs($socket, "MAIL FROM:<$from>\r\n");
        $mailFromResponse = fgets($socket, 515);
        if (substr($mailFromResponse, 0, 3) != '250') {
            fclose($socket);
            return ['success' => false, 'message' => "MAIL FROM 실패: $mailFromResponse"];
        }

        // RCPT TO
        fputs($socket, "RCPT TO:<$to>\r\n");
        $rcptResponse = fgets($socket, 515);
        if (substr($rcptResponse, 0, 3) != '250') {
            fclose($socket);
            return ['success' => false, 'message' => "RCPT TO 실패: $rcptResponse"];
        }

        // DATA
        fputs($socket, "DATA\r\n");
        $dataStartResponse = fgets($socket, 515);
        if (substr($dataStartResponse, 0, 3) != '354') {
            fclose($socket);
            return ['success' => false, 'message' => "DATA 시작 실패: $dataStartResponse"];
        }

        // 이메일 헤더 및 본문
        $message = "From: $fromName <$from>\r\n";
        $message .= "To: $to\r\n";
        $message .= "Subject: =?UTF-8?B?" . base64_encode($subject) . "?=\r\n";
        $message .= "MIME-Version: 1.0\r\n";
        $message .= "Content-Type: text/html; charset=UTF-8\r\n";
        $message .= "Date: " . date('r') . "\r\n";
        $message .= "\r\n";
        $message .= $html;
        $message .= "\r\n.\r\n";

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

