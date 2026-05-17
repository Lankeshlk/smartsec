package com.smartsec.smartsec_api.controller;

import com.smartsec.smartsec_api.dto.ScanRequestDto;
import com.smartsec.smartsec_api.model.Scan;
import com.smartsec.smartsec_api.model.User;
import com.smartsec.smartsec_api.repository.UserRepository;
import com.smartsec.smartsec_api.service.ScanService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/scan")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:5173")
public class ScanController {

    private final ScanService scanService;
    private final UserRepository userRepository;

    @PostMapping
    public ResponseEntity<?> submitScan(@RequestBody ScanRequestDto request) {

        // Get email from security context
        String email = SecurityContextHolder.getContext()
                .getAuthentication()
                .getName();

        System.out.println("Authenticated user email: " + email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found: " + email));

        Scan.ScanType scanType = request.getTargetUrl() != null
                ? Scan.ScanType.URL
                : Scan.ScanType.CODE_SNIPPET;

        String input = scanType == Scan.ScanType.URL
                ? request.getTargetUrl()
                : request.getCodeSnippet();

        Scan result = scanService.performScan(user, input, scanType);

        return ResponseEntity.ok(result);
    }

    @GetMapping("/history")
    public ResponseEntity<List<Scan>> getScanHistory() {
        String email = SecurityContextHolder.getContext()
                .getAuthentication()
                .getName();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return ResponseEntity.ok(scanService.getScansByUser(user.getId()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<Scan> getScanById(@PathVariable Long id) {
        return ResponseEntity.ok(scanService.getScanById(id));
    }


}