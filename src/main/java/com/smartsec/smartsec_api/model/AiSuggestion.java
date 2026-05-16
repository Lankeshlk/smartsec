package com.smartsec.smartsec_api.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "ai_suggestions")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AiSuggestion {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "vulnerability_id", nullable = false)
    private Vulnerability vulnerability;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity_classification")
    private Vulnerability.Severity severityClassification;

    @Column(columnDefinition = "TEXT")
    private String explanation;

    @Column(name = "fix_recommendation", columnDefinition = "TEXT")
    private String fixRecommendation;

    @Column(name = "fixed_code_snippet", columnDefinition = "TEXT")
    private String fixedCodeSnippet;

    @Builder.Default
    @Column(name = "generated_at", updatable = false)
    private LocalDateTime generatedAt = LocalDateTime.now();
}
