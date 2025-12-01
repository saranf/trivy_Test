<?php
/**
 * 스캔 결과 이메일 발송 API
 */

error_reporting(0);
ini_set('display_errors', 0);

header('Content-Type: application/json');

require_once 'db_functions.php';

// SMTP 설정 (환경변수 또는 기본값)
$smtpHost = getenv('SMTP_HOST') ?: 'smtp.gmail.com';
$smtpPort = getenv('SMTP_PORT') ?: 587;
$smtpUser = getenv('SMTP_USER') ?: '';
$smtpPass = getenv('SMTP_PASS') ?: '';
$fromEmail = getenv('FROM_EMAIL') ?: $smtpUser;
$fromName = getenv('FROM_NAME') ?: 'Trivy Scanner';

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
$result = sendEmail($toEmail, $subject, $html, $smtpHost, $smtpPort, $smtpUser, $smtpPass, $fromEmail, $fromName);

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

function sendEmail($to, $subject, $html, $host, $port, $user, $pass, $from, $fromName) {
    // PHPMailer 없이 기본 mail() 사용 또는 socket으로 SMTP
    if (empty($user) || empty($pass)) {
        // 기본 mail() 함수 사용
        $headers = "MIME-Version: 1.0\r\n";
        $headers .= "Content-type: text/html; charset=UTF-8\r\n";
        $headers .= "From: $fromName <$from>\r\n";
        
        if (mail($to, $subject, $html, $headers)) {
            return ['success' => true, 'message' => '이메일이 발송되었습니다.'];
        } else {
            return ['success' => false, 'message' => '이메일 발송 실패. SMTP 설정을 확인하세요.'];
        }
    }
    
    // SMTP 발송 (간단한 구현)
    return sendSmtpEmail($to, $subject, $html, $host, $port, $user, $pass, $from, $fromName);
}

function sendSmtpEmail($to, $subject, $body, $host, $port, $user, $pass, $from, $fromName) {
    $socket = @fsockopen($host, $port, $errno, $errstr, 30);
    if (!$socket) {
        return ['success' => false, 'message' => "SMTP 연결 실패: $errstr"];
    }

    stream_set_timeout($socket, 30);

    $response = fgets($socket, 515);

    // EHLO
    fputs($socket, "EHLO localhost\r\n");
    while ($line = fgets($socket, 515)) {
        if (substr($line, 3, 1) == ' ') break;
    }

    // STARTTLS
    fputs($socket, "STARTTLS\r\n");
    fgets($socket, 515);

    stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);

    fputs($socket, "EHLO localhost\r\n");
    while ($line = fgets($socket, 515)) {
        if (substr($line, 3, 1) == ' ') break;
    }

    // AUTH LOGIN
    fputs($socket, "AUTH LOGIN\r\n");
    fgets($socket, 515);

    fputs($socket, base64_encode($user) . "\r\n");
    fgets($socket, 515);

    fputs($socket, base64_encode($pass) . "\r\n");
    $authResponse = fgets($socket, 515);

    if (substr($authResponse, 0, 3) != '235') {
        fclose($socket);
        return ['success' => false, 'message' => 'SMTP 인증 실패'];
    }

    // MAIL FROM
    fputs($socket, "MAIL FROM:<$from>\r\n");
    fgets($socket, 515);

    // RCPT TO
    fputs($socket, "RCPT TO:<$to>\r\n");
    fgets($socket, 515);

    // DATA
    fputs($socket, "DATA\r\n");
    fgets($socket, 515);

    $headers = "From: $fromName <$from>\r\n";
    $headers .= "To: $to\r\n";
    $headers .= "Subject: =?UTF-8?B?" . base64_encode($subject) . "?=\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
    $headers .= "\r\n";

    fputs($socket, $headers . $body . "\r\n.\r\n");
    $dataResponse = fgets($socket, 515);

    fputs($socket, "QUIT\r\n");
    fclose($socket);

    if (substr($dataResponse, 0, 3) == '250') {
        return ['success' => true, 'message' => '이메일이 발송되었습니다.'];
    } else {
        return ['success' => false, 'message' => '이메일 발송 실패'];
    }
}

