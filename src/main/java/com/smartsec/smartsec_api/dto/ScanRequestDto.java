package com.smartsec.smartsec_api.dto;

import lombok.Data;

@Data
public class ScanRequestDto {
    private String targetUrl;
    private String codeSnippet;
}
