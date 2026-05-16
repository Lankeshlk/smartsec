package com.smartsec.smartsec_api.service;

import com.smartsec.smartsec_api.dto.AuthResponseDto;
import com.smartsec.smartsec_api.dto.LoginRequestDto;
import com.smartsec.smartsec_api.dto.RegisterRequestDto;
import com.smartsec.smartsec_api.model.User;
import com.smartsec.smartsec_api.repository.UserRepository;
import com.smartsec.smartsec_api.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthResponseDto register(RegisterRequestDto request) {

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already in use");
        }
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .role(User.Role.USER)
                .build();

        userRepository.save(user);

        String token = jwtUtil.generateToken(user.getEmail());
        return new AuthResponseDto(token, user.getUsername(),
        user.getEmail(), user.getRole().name());
    }

    public AuthResponseDto login(LoginRequestDto request) {

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Invalid email"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new RuntimeException("Invalid password");
        }

        String token = jwtUtil.generateToken(user.getEmail());
        return new AuthResponseDto(token, user.getUsername(),
                user.getEmail(), user.getRole().name());
    }
}
