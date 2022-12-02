package com.jwt.model.vo;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
    // 아이디
    private String username;
    // 패스워드
    private String password;
    // 유효한 유저
    private boolean activated;
    // 권한 리스트
    private List<Authority> roles;
}
