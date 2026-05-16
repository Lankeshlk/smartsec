package com.smartsec.smartsec_api.controller;

import com.smartsec.smartsec_api.dto.ScanRequestDto;
import com.smartsec.smartsec_api.model.Scan;
import com.smartsec.smartsec_api.model.User;
import com.smartsec.smartsec_api.service.ScanService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/scan")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:3000")
public class ScanController {

    private final ScanService scanService;

    public ResponseEntity<Scan> submitScan(
            @RequestBody ScanRequestDto request,
            @AuthenticationPrincipal User user) {

        Scan.ScanType scanType = request.getTargetUrl() != null
                ? Scan.ScanType.URL
                : Scan.ScanType.CODE_SNIPPET;

        String input = scanType == Scan.ScanType.URL
                ? request.getTargetUrl()
                : request.getCodeSnippet();

        return ResponseEntity.ok(scanService.performScan(user, input, scanType));
    }

    @GetMapping("/history")
    public ResponseEntity<List<Scan>> getScanHistory(
            @AuthenticationPrincipal User user) {
        return  ResponseEntity.ok(scanService.getScansByUser(user.getId()));
    }

    public ResponseEntity<Scan> getScanById(@PathVariable Long id) {
        return ResponseEntity.ok(scanService.getScanById(id));
    }
}
