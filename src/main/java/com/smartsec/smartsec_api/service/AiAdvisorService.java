package com.smartsec.smartsec_api.service;

import com.smartsec.smartsec_api.model.AiSuggestion;
import com.smartsec.smartsec_api.model.Vulnerability;
import com.smartsec.smartsec_api.repository.AiSuggestionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.*;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AiAdvisorService {

    @Value("${ai.api.key}")
    private String apiKey;

    @Value("${ai.api.url}")
    private String apiUrl;

    private final AiSuggestionRepository aiSuggestionRepository;
    private final ObjectMapper objectMapper;


    /*
     * Save AI suggestions that came from the scanner response directly.
     * No extra API call needed — data already in rawNodes.
     */

    public void saveAiSuggestion(List<Vulnerability> vulnerabilities, List<JsonNode> rawNodes) {
        for (int i = 0; i < vulnerabilities.size(); i++) {
            Vulnerability vuln = vulnerabilities.get(i);
            JsonNode node = rawNodes.get(i);

            AiSuggestion suggestion =  AiSuggestion.builder()
                    .vulnerability(vuln)
                    .severityClassification(vuln.getSeverity())
                    .explanation(node.path("explanation").asText())
                    .fixRecommendation(node.path("fix_recommendation").asText())
                    .fixedCodeSnippet(node.path("fixed_code_snippet").asText(null))
                    .build();

            aiSuggestionRepository.save(suggestion);
        }
    }

    /**
     * Re-analyse a single vulnerability on demand.
     */
    public AiSuggestion reanalyse(Vulnerability vuln) throws Exception {
        String prompt = """
            You are a cybersecurity expert. Give a detailed fix for this vulnerability.

            Type: %s
            CWE: %s
            Affected code: %s

            Respond ONLY with JSON, no extra text:
            {
              "explanation": "...",
              "fix_recommendation": "...",
              "fixed_code_snippet": "..."
            }
            """.formatted(vuln.getVulnType(), vuln.getCweCode(), vuln.getAffectedInput());

        Map<String, Object> requestBody = Map.of(
                "contents", List.of(
                        Map.of("parts", List.of(Map.of("text", prompt)))
                ),
                "generationConfig", Map.of("temperature", 0.1, "maxOutputTokens", 1000)
        );

        String urlWithKey = apiUrl + "?key=" + apiKey;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(urlWithKey))
                .header("Content-Type", "applcation/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        objectMapper.writeValueAsString(requestBody)))
                .build();


        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofString());

        JsonNode root = objectMapper.readTree(response.body());
        String text = root.path("candidates").get(0)
                .path("content").path("parts").get(0)
                .path("text").asText();

        String clean = text
                .replaceAll("(?s)```json\\s*", "")
                .replaceAll("(?s)```\\s*", "")
                .trim();

        JsonNode json = objectMapper.readTree(clean);

        AiSuggestion suggestion = AiSuggestion.builder()
                .vulnerability(vuln)
                .severityClassification(vuln.getSeverity())
                .explanation(json.path("explanation").asText())
                .fixRecommendation(json.path("fix_recommendation").asText())
                .fixedCodeSnippet(json.path("fixed_code_snippet").asText(null))
                .build();

        return aiSuggestionRepository.save(suggestion);
    }

}
