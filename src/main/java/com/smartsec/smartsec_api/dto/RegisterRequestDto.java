package com.smartsec.smartsec_api.dto;

import lombok.Data;

@Data
public class RegisterRequestDto {
    private String email;
    private String password;
    private String username;
}
