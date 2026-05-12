package com.smartsec.smartsec_api.service;

import com.smartsec.smartsec_api.model.Vulnerability;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class ScannerEngine {

    @Value("${ai.api.key}")
    private String apiKey;

    @Value("${ai.api.url}")
    private String apiUrl;

    private final ObjectMapper objectMapper = new ObjectMapper();

    // ─────────────────────────────────────────────────────────────────────
    //  PUBLIC API
    // ─────────────────────────────────────────────────────────────────────

    public record ScanResult(List<Vulnerability> vulnerabilities, List<JsonNode> rawNodes) {}

    public ScanResult scanCodeFull(String input) {
        try {
            String prompt = buildScanPrompt(input);
            String aiResponse = callGeminiApi(prompt);
            return parseResponse(aiResponse);
        } catch (Exception e) {
            throw new RuntimeException("AI scan failed: " + e.getMessage(), e);
        }
    }

    private String buildScanPrompt(String input) {
        return """
                You are an expert cybersecurity analyst specialising in web application security.
                
                            Analyse the following code or input thoroughly for ALL security vulnerabilities.
                            Check for but do not limit yourself to:
                            - XSS (CWE-79)
                            - SQL Injection (CWE-89)
                            - Command Injection (CWE-78)
                            - Path Traversal (CWE-22)
                            - Insecure Deserialization (CWE-502)
                            - SSRF (CWE-918)
                            - LDAP Injection (CWE-90)
                            - Open Redirect (CWE-601)
                            - Sensitive Data Exposure (CWE-200)
                            - Weak Cryptography (CWE-327)
                            - Missing Security Headers (CWE-693)
                            - Hardcoded Secrets (CWE-798)
                            - Any other vulnerability you detect
                
                            Input to analyse:
                            ---
                            %s
                            ---
                
                            Respond ONLY with a valid JSON array. No explanation outside the JSON.
                            If no vulnerabilities found, return empty array: []
                
                            Each item must follow this exact structure:
                            [
                              {
                                "cwe_code": "CWE-79",
                                "vuln_type": "XSS",
                                "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
                                "description": "Short description of what was detected",
                                "affected_input": "The exact snippet or field that is vulnerable",
                                "line_number": 12,
                                "explanation": "Plain English explanation of why this is dangerous (2-3 sentences)",
                                "fix_recommendation": "Specific actionable steps to fix this (3-5 sentences)",
                                "fixed_code_snippet": "Corrected version of the vulnerable code, or null"
                              }
                            ]
                """.formatted(input);
    }

    private String callGeminiApi(String prompt) throws Exception {
        //Gemini request body format
        Map<String, Object> requestBody = Map.of(
                "contents", List.of(
                        Map.of(
                                "parts", List.of(
                                        Map.of("text", prompt)
                                )
                        )
                ),
                "generationConfig", Map.of(
                        "temperature", 0.1,
                        "maxOutputTokens", 4000
                )
        );
        String bodyJson = objectMapper.writeValueAsString(requestBody);
        String urlWithKey = apiUrl + "?key=" + apiKey;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(urlWithKey))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(bodyJson))
                .build();

        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("Gemini API call failed: "
                    + response.statusCode() +" " + response.body());
        }
        // Gemini response structure:
        // { "candidates": [ { "content": { "parts": [ { "text": "..." } ] } } ] }
        JsonNode root = objectMapper.readTree(response.body());
        return root
                .path("candidates").get(0)
                .path("content")
                .path("parts").get(0)
                .path("teaxt")
                .asText();
    }
    private ScanResult parseResponse(String aiResponse) {
        try {
            String clean = aiResponse
                    .replaceAll("(?s)'''json\\s*", "")
                    .replaceAll("(?s)''''", "")
                    .trim();

            JsonNode array = objectMapper.readTree(clean);
            List<Vulnerability> vulns = new ArrayList<>();
            List<JsonNode> nodes = new ArrayList<>();

            for (JsonNode node : array) {
                Vulnerability vuln = Vulnerability.builder()
                        .cweCode(node.path("cwe_code").asText("UNKNOWN"))
                        .vulnType(node.path("vuln_type").asText("UNKNOWN"))
                        .severity(parseSeverity(node.path("severity").asText("MEDIUM")))
                        .description(node.path("description").asText())
                        .affectedInput(node.path("affected_input").asText())
                        .lineNumber(node.path("line_number").asInt(-1))
                        .build();

                vulns.add(vuln);
                nodes.add(node);
            }
            return new ScanResult(vulns, nodes);
        } catch (Exception e) {
            throw new RuntimeException("AI scan failed: " + e.getMessage(), e);
        }
    }

    private Vulnerability.Severity parseSeverity(String value) {
        try {
            return Vulnerability.Severity.valueOf(value.toUpperCase());
        } catch (Exception e) {
            return Vulnerability.Severity.MEDIUM;
        }
    }

}
