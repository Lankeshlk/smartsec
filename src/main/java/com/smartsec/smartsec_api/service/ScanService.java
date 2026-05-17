package com.smartsec.smartsec_api.service;

import com.smartsec.smartsec_api.dto.ScanRequestDto;
import com.smartsec.smartsec_api.model.Scan;
import com.smartsec.smartsec_api.model.User;
import com.smartsec.smartsec_api.model.Vulnerability;
import com.smartsec.smartsec_api.repository.ScanRepository;
import com.smartsec.smartsec_api.repository.VulnerabilityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ScanService {

    private final ScannerEngine scannerEngine;
    private final ScanRepository scanRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final AiAdvisorService aiAdvisorService;

    public Scan performScan(User user, String input, Scan.ScanType scanType) {

        Scan scan = Scan.builder()
                .user(user)
                .scanType(scanType)
                .status(Scan.ScanStatus.IN_PROGRESS)
                .build();

        if (scanType == Scan.ScanType.URL) {
            scan.setTargetUrl(input);
        } else {
            scan.setCodeSnippet(input);
        }

        scan  = scanRepository.save(scan);

        try {
            ScannerEngine.ScanResult result = scannerEngine.scanCodeFull(input);

            for (Vulnerability vuln : result.vulnerabilities()){
                vuln.setScan(scan);
            }
            vulnerabilityRepository.saveAll(result.vulnerabilities());

            if (!result.vulnerabilities().isEmpty()){
                aiAdvisorService.saveAiSuggestions(
                        result.vulnerabilities(),
                        result.rawNodes());
            }
            scan.setStatus(Scan.ScanStatus.COMPLETED);
            scan.setVulnerabilities(result.vulnerabilities());
        } catch (Exception e) {
            System.out.println("Scan failed with error: " + e.getMessage());
            e.printStackTrace();
            scan.setStatus(Scan.ScanStatus.FAILED);
        }
        return scanRepository.save(scan);
    }

    public List<Scan> getScansByUser(Long userId) {
        return scanRepository.findByUserIdOrderByScannedAtDesc(userId);
    }

    public Scan getScanById(Long scanId) {
        return scanRepository.findById(scanId).orElseThrow(() -> new RuntimeException("Scan not found" + scanId));
    }

}
