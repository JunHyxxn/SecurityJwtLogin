package com.jwt.model.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Token {
    // DB에 저장된 토큰 정보 VO
    private String username;
    private String accessToken;
    private String refreshToken;
}
