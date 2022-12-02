package com.jwt.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtResponse {
    private String accessToken;
    private String type="Bearer";
    private String refreshToken;
    private String username;
    private List<String> roles;
    // AccessToken + RefreshToken �߱� [ ���� �߱� �� ]
    public JwtResponse(String accessToken, String refreshToken, String username, List<String> roles) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.username = username;
        this.roles = roles;
    }

    // AccessToken ��߱� ��
    public JwtResponse(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
}
