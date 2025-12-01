<?php
/**
 * 스캔 결과 이메일 발송 API (서버 로컬 발송 + CSV 첨부)
 */

error_reporting(0);
ini_set('display_errors', 0);

header('Content-Type: application/json');

require_once 'auth.php';
require_once 'db_functions.php';

// 메일 설정
$mailConfig = [
    'from' => getenv('FROM_EMAIL') ?: 'trivy-scanner@' . gethostname(),
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

// 데모 모드: 메일 발송 시뮬레이션
if (isDemoMode()) {
    echo json_encode([
        'success' => true,
        'message' => '✅ [데모] 이메일이 발송되었습니다. (실제로는 발송되지 않음)',
        'demo' => true,
        'to' => $toEmail,
        'scanCount' => count($scanIds)
    ]);
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

// 예외 처리 정보 가져오기
$activeExceptions = getActiveExceptions($conn);
$exceptedMap = [];
foreach ($activeExceptions as $ex) {
    $exceptedMap[$ex['vulnerability_id']] = $ex;
}

$scans = [];
while ($row = $result->fetch_assoc()) {
    $vulns = getScanVulnerabilities($conn, $row['id']);
    // 예외 처리 정보 추가
    foreach ($vulns as &$v) {
        if (isset($exceptedMap[$v['vulnerability']])) {
            $v['is_excepted'] = true;
            $v['exception_reason'] = $exceptedMap[$v['vulnerability']]['reason'];
            $v['exception_expires'] = $exceptedMap[$v['vulnerability']]['expires_at'];
        } else {
            $v['is_excepted'] = false;
        }
    }
    $row['vulnerabilities'] = $vulns;
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

// 이메일 발송 (CSV 첨부) - 로컬 sendmail 사용
$result = sendEmailLocal($toEmail, $subject, $html, $csv, $mailConfig);

echo json_encode($result);

// CSV 생성 함수 (예외 처리 정보 포함)
function generateCsv($scans) {
    $lines = [];
    $lines[] = "Image,Scan Date,Library,Vulnerability,Severity,Installed Version,Fixed Version,Exception Status,Exception Reason,Exception Expires";

    foreach ($scans as $scan) {
        $imageName = $scan['image_name'];
        $scanDate = $scan['scan_date'];

        if (!empty($scan['vulnerabilities'])) {
            foreach ($scan['vulnerabilities'] as $v) {
                $exStatus = !empty($v['is_excepted']) ? 'EXCEPTED' : '';
                $exReason = $v['exception_reason'] ?? '';
                $exExpires = isset($v['exception_expires']) ? date('Y-m-d', strtotime($v['exception_expires'])) : '';

                $lines[] = sprintf('"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s"',
                    str_replace('"', '""', $imageName),
                    $scanDate,
                    str_replace('"', '""', $v['library']),
                    str_replace('"', '""', $v['vulnerability']),
                    $v['severity'],
                    str_replace('"', '""', $v['installed_version']),
                    str_replace('"', '""', $v['fixed_version'] ?: ''),
                    $exStatus,
                    str_replace('"', '""', $exReason),
                    $exExpires
                );
            }
        } else {
            $lines[] = sprintf('"%s","%s","No vulnerabilities found","","","","","","",""', $imageName, $scanDate);
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
        .excepted-row { background: #e3f2fd; }
        .exception-badge { background: #1976d2; color: white; padding: 2px 6px; border-radius: 10px; font-size: 11px; margin-left: 5px; }
    </style></head><body>';

    $html .= '<h1>🔒 Trivy 스캔 결과 리포트</h1>';
    $html .= '<p>생성일시: ' . date('Y-m-d H:i:s') . '</p>';

    foreach ($scans as $scan) {
        // 예외 처리된 취약점 수 계산
        $exceptedCount = 0;
        foreach ($scan['vulnerabilities'] as $v) {
            if (!empty($v['is_excepted'])) $exceptedCount++;
        }

        $html .= '<h2>' . htmlspecialchars($scan['image_name']) . '</h2>';
        $html .= '<div class="summary">';
        $html .= '<strong>스캔일시:</strong> ' . $scan['scan_date'] . '<br>';
        $html .= '<strong>총 취약점:</strong> ' . $scan['total_vulns'] . ' | ';
        $html .= '<span class="critical">C: ' . $scan['critical_count'] . '</span> ';
        $html .= '<span class="high">H: ' . $scan['high_count'] . '</span> ';
        $html .= '<span class="medium">M: ' . $scan['medium_count'] . '</span> ';
        $html .= '<span class="low">L: ' . $scan['low_count'] . '</span>';
        if ($exceptedCount > 0) {
            $html .= ' <span style="background:#1976d2;color:white;padding:3px 8px;border-radius:4px;">🛡️ 예외: ' . $exceptedCount . '</span>';
        }
        $html .= '</div>';

        if (!empty($scan['vulnerabilities'])) {
            $html .= '<table><thead><tr><th>Library</th><th>Vulnerability</th><th>Severity</th><th>Installed</th><th>Fixed</th><th>Status</th></tr></thead><tbody>';
            foreach ($scan['vulnerabilities'] as $v) {
                $sevClass = strtolower($v['severity']);
                $rowClass = !empty($v['is_excepted']) ? 'excepted-row' : '';
                $html .= '<tr class="' . $rowClass . '">';
                $html .= '<td>' . htmlspecialchars($v['library']) . '</td>';
                $html .= '<td>' . htmlspecialchars($v['vulnerability']);
                if (!empty($v['is_excepted'])) {
                    $html .= '<span class="exception-badge">🛡️예외</span>';
                }
                $html .= '</td>';
                $html .= '<td><span class="' . $sevClass . '">' . $v['severity'] . '</span></td>';
                $html .= '<td>' . htmlspecialchars($v['installed_version']) . '</td>';
                $html .= '<td>' . htmlspecialchars($v['fixed_version'] ?: '-') . '</td>';
                $html .= '<td>';
                if (!empty($v['is_excepted'])) {
                    $html .= htmlspecialchars($v['exception_reason'] ?? '');
                    if (!empty($v['exception_expires'])) {
                        $html .= '<br><small>만료: ' . date('Y-m-d', strtotime($v['exception_expires'])) . '</small>';
                    }
                } else {
                    $html .= '-';
                }
                $html .= '</td>';
                $html .= '</tr>';
            }
            $html .= '</tbody></table>';
        }
    }

    $html .= '<hr><p style="color:#666;font-size:12px;">이 메일은 Trivy Security Scanner에서 자동 발송되었습니다.</p>';
    $html .= '</body></html>';

    return $html;
}

function sendEmailLocal($to, $subject, $html, $csv, $config) {
    $from = $config['from'];
    $fromName = $config['fromName'];

    try {
        // Multipart 이메일 (HTML + CSV 첨부)
        $boundary = md5(uniqid(time()));

        // 헤더 설정
        $headers = [];
        $headers[] = "From: =?UTF-8?B?" . base64_encode($fromName) . "?= <$from>";
        $headers[] = "Reply-To: $from";
        $headers[] = "MIME-Version: 1.0";
        $headers[] = "Content-Type: multipart/mixed; boundary=\"$boundary\"";
        $headers[] = "X-Mailer: Trivy-Scanner";

        // 메시지 본문
        $body = "";

        // HTML 본문
        $body .= "--$boundary\r\n";
        $body .= "Content-Type: text/html; charset=UTF-8\r\n";
        $body .= "Content-Transfer-Encoding: base64\r\n";
        $body .= "\r\n";
        $body .= chunk_split(base64_encode($html));
        $body .= "\r\n";

        // CSV 첨부파일
        $body .= "--$boundary\r\n";
        $body .= "Content-Type: text/csv; charset=UTF-8; name=\"trivy_scan_result.csv\"\r\n";
        $body .= "Content-Disposition: attachment; filename=\"trivy_scan_result.csv\"\r\n";
        $body .= "Content-Transfer-Encoding: base64\r\n";
        $body .= "\r\n";
        $body .= chunk_split(base64_encode("\xEF\xBB\xBF" . $csv)); // BOM for Excel
        $body .= "\r\n";

        $body .= "--$boundary--\r\n";

        // 제목 인코딩
        $encodedSubject = "=?UTF-8?B?" . base64_encode($subject) . "?=";

        // SMTP (mailserver 컨테이너)로 먼저 시도
        $smtpResult = sendViaSmtp($to, $encodedSubject, $body, $headers, $from);
        if ($smtpResult['success']) {
            return $smtpResult;
        }

        // SMTP 실패 시 PHP mail() 시도
        $result = mail($to, $encodedSubject, $body, implode("\r\n", $headers), "-f$from");
        if ($result) {
            return ['success' => true, 'message' => "이메일이 $to 로 발송되었습니다."];
        }

        // mail() 실패 시 sendmail 시도
        return sendViaSendmail($to, $encodedSubject, $body, $headers, $from);

    } catch (Exception $e) {
        return ['success' => false, 'message' => '이메일 발송 중 오류: ' . $e->getMessage()];
    }
}

/**
 * SMTP를 통해 메일 발송 (mailserver 컨테이너 사용)
 */
function sendViaSmtp($to, $subject, $body, $headers, $from) {
    $smtpHost = getenv('SMTP_HOST') ?: 'mailserver';  // Docker 컨테이너 이름
    $smtpPort = getenv('SMTP_PORT') ?: 25;

    try {
        $socket = @fsockopen($smtpHost, $smtpPort, $errno, $errstr, 10);
        if (!$socket) {
            return ['success' => false, 'message' => "SMTP 연결 실패: $errstr ($errno)"];
        }

        // SMTP 응답 읽기
        $response = fgets($socket, 512);
        if (substr($response, 0, 3) != '220') {
            fclose($socket);
            return ['success' => false, 'message' => "SMTP 서버 응답 오류: $response"];
        }

        // HELO
        fputs($socket, "HELO localhost\r\n");
        $response = fgets($socket, 512);

        // MAIL FROM
        fputs($socket, "MAIL FROM:<$from>\r\n");
        $response = fgets($socket, 512);
        if (substr($response, 0, 3) != '250') {
            fclose($socket);
            return ['success' => false, 'message' => "MAIL FROM 실패: $response"];
        }

        // RCPT TO
        fputs($socket, "RCPT TO:<$to>\r\n");
        $response = fgets($socket, 512);
        if (substr($response, 0, 3) != '250') {
            fclose($socket);
            return ['success' => false, 'message' => "RCPT TO 실패: $response"];
        }

        // DATA
        fputs($socket, "DATA\r\n");
        $response = fgets($socket, 512);
        if (substr($response, 0, 3) != '354') {
            fclose($socket);
            return ['success' => false, 'message' => "DATA 실패: $response"];
        }

        // 메일 내용 전송
        $fullMessage = implode("\r\n", $headers) . "\r\n";
        $fullMessage .= "To: $to\r\n";
        $fullMessage .= "Subject: $subject\r\n";
        $fullMessage .= "\r\n";
        $fullMessage .= $body;
        $fullMessage .= "\r\n.\r\n";  // 메일 종료

        fputs($socket, $fullMessage);
        $response = fgets($socket, 512);
        if (substr($response, 0, 3) != '250') {
            fclose($socket);
            return ['success' => false, 'message' => "메일 전송 실패: $response"];
        }

        // QUIT
        fputs($socket, "QUIT\r\n");
        fclose($socket);

        return ['success' => true, 'message' => "이메일이 $to 로 발송되었습니다."];

    } catch (Exception $e) {
        if (isset($socket) && $socket) fclose($socket);
        return ['success' => false, 'message' => 'SMTP 오류: ' . $e->getMessage()];
    }
}

function sendViaSendmail($to, $subject, $body, $headers, $from) {
    $sendmail = '/usr/sbin/sendmail';

    if (!file_exists($sendmail)) {
        return ['success' => false, 'message' => 'sendmail이 설치되지 않았습니다. SMTP 서버도 연결할 수 없습니다.'];
    }

    $fullMessage = implode("\r\n", $headers) . "\r\n";
    $fullMessage .= "To: $to\r\n";
    $fullMessage .= "Subject: $subject\r\n";
    $fullMessage .= "\r\n";
    $fullMessage .= $body;

    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w']
    ];

    $process = proc_open("$sendmail -t -f $from", $descriptors, $pipes);

    if (is_resource($process)) {
        fwrite($pipes[0], $fullMessage);
        fclose($pipes[0]);

        $output = stream_get_contents($pipes[1]);
        $error = stream_get_contents($pipes[2]);

        fclose($pipes[1]);
        fclose($pipes[2]);

        $returnCode = proc_close($process);

        if ($returnCode === 0) {
            return ['success' => true, 'message' => "이메일이 $to 로 발송되었습니다."];
        } else {
            return ['success' => false, 'message' => "sendmail 발송 실패: $error"];
        }
    }

    return ['success' => false, 'message' => 'sendmail 프로세스 시작 실패'];
}

