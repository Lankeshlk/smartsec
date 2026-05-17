package com.smartsec.smartsec_api.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "scans")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Scan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ToString.Exclude
    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "target_url", length = 500)
    private String targetUrl;

    @Column(name = "code_snippet", columnDefinition = "TEXT")
    private String codeSnippet;

    @Builder.Default
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ScanStatus status = ScanStatus.PENDING;

    @Enumerated(EnumType.STRING)
    @Column(name = "scan_type", nullable = false)
    private ScanType scanType;

    @Builder.Default
    @Column(name = "scanned_at", updatable = false)
    private LocalDateTime scannedAt = LocalDateTime.now();

    @ToString.Exclude
    @JsonIgnoreProperties
    @OneToMany(mappedBy = "scan", cascade = CascadeType.ALL, fetch = FetchType.EAGER )
    private List<Vulnerability> vulnerabilities;

    public enum ScanStatus {
    PENDING, IN_PROGRESS, COMPLETED, FAILED
    }

    public enum ScanType {
        URL, CODE_SNIPPET
    }
}
