package com.smartsec.smartsec_api.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

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

    @OneToMany(mappedBy = "scan", cascade = CascadeType.ALL, fetch = FetchType.LAZY )
    private List<Vulnerability> vulnerabilities;

    public enum ScanStatus {
    PENDING, IN_PROGRESS, COMPLETED, FAILED
    }

    public enum ScanType {
        URL, CODE_SNIPPET
    }
}
