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
    // DB�� ����� ��ū ���� VO
    private String username;
    private String accessToken;
    private String refreshToken;
}
