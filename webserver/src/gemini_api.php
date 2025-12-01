<?php
/**
 * 🤖 Google Gemini API 연동
 * - CVE 취약점 조치 방법 추천
 * - 컨테이너 전체 보안 분석
 */

// Gemini API 설정
define('GEMINI_API_KEY', getenv('GEMINI_API_KEY') ?: '');
define('GEMINI_MODEL', 'gemini-1.5-flash');
define('GEMINI_API_URL', 'https://generativelanguage.googleapis.com/v1beta/models/' . GEMINI_MODEL . ':generateContent');

/**
 * Gemini API 호출
 */
function callGeminiApi($prompt, $maxTokens = 2048) {
    if (empty(GEMINI_API_KEY)) {
        return ['success' => false, 'error' => 'GEMINI_API_KEY가 설정되지 않았습니다.'];
    }

    $url = GEMINI_API_URL . '?key=' . GEMINI_API_KEY;
    
    $data = [
        'contents' => [
            [
                'parts' => [
                    ['text' => $prompt]
                ]
            ]
        ],
        'generationConfig' => [
            'temperature' => 0.7,
            'maxOutputTokens' => $maxTokens,
            'topP' => 0.8,
            'topK' => 40
        ]
    ];

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($data),
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json'
        ],
        CURLOPT_TIMEOUT => 60
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($error) {
        return ['success' => false, 'error' => "cURL 오류: $error"];
    }

    if ($httpCode !== 200) {
        $errorData = json_decode($response, true);
        $errorMsg = $errorData['error']['message'] ?? "HTTP $httpCode";
        return ['success' => false, 'error' => "API 오류: $errorMsg"];
    }

    $result = json_decode($response, true);
    
    if (isset($result['candidates'][0]['content']['parts'][0]['text'])) {
        return [
            'success' => true,
            'response' => $result['candidates'][0]['content']['parts'][0]['text']
        ];
    }

    return ['success' => false, 'error' => 'API 응답 파싱 실패'];
}

/**
 * 개별 CVE 조치 방법 추천
 */
function getAiRecommendationForCve($cve, $library, $severity, $title, $installedVersion, $fixedVersion) {
    $prompt = <<<PROMPT
당신은 컨테이너 보안 전문가입니다. 다음 취약점에 대한 조치 방법을 한국어로 간결하게 설명해주세요.

**취약점 정보:**
- CVE ID: {$cve}
- 라이브러리: {$library}
- 심각도: {$severity}
- 제목: {$title}
- 설치 버전: {$installedVersion}
- 수정 버전: {$fixedVersion}

다음 형식으로 답변해주세요:
1. **조치 방법** (2-3줄)
2. **임시 완화 방법** (수정 버전으로 업그레이드할 수 없는 경우, 1-2줄)
3. **위험도 설명** (1줄)

답변은 200자 이내로 간결하게 작성하세요.
PROMPT;

    return callGeminiApi($prompt, 512);
}

/**
 * 컨테이너 전체 취약점 분석 및 조치 우선순위 추천
 */
function getAiRecommendationForContainer($imageName, $vulnerabilities, $criticalCount, $highCount) {
    // 취약점 요약 생성
    $vulnSummary = [];
    $count = 0;
    foreach ($vulnerabilities as $v) {
        if ($count >= 10) break; // 최대 10개만 포함
        $vulnSummary[] = "- [{$v['severity']}] {$v['vulnerability']}: {$v['library']} ({$v['installed_version']} → {$v['fixed_version']})";
        $count++;
    }
    $vulnList = implode("\n", $vulnSummary);
    $totalVulns = count($vulnerabilities);

    $prompt = <<<PROMPT
당신은 컨테이너 보안 전문가입니다. 다음 컨테이너의 취약점을 분석하고 조치 우선순위와 방법을 한국어로 설명해주세요.

**컨테이너 정보:**
- 이미지: {$imageName}
- 총 취약점: {$totalVulns}개 (CRITICAL: {$criticalCount}, HIGH: {$highCount})

**주요 취약점 목록:**
{$vulnList}

다음 형식으로 분석해주세요:

## 🔴 즉시 조치 필요
(CRITICAL 취약점 조치 방법, 2-3개)

## 🟠 우선 조치 권장
(HIGH 취약점 조치 방법, 2-3개)

## 📋 종합 권장사항
(전체적인 보안 개선 방향, 3-4줄)

## ⚡ 빠른 조치 명령어
(Docker/패키지 업데이트 명령어 예시)

답변은 800자 이내로 작성하세요.
PROMPT;

    return callGeminiApi($prompt, 1024);
}

