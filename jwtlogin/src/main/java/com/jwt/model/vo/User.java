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
    // ���̵�
    private String username;
    // �н�����
    private String password;
    // ��ȿ�� ����
    private boolean activated;
    // ���� ����Ʈ
    private List<Authority> roles;
}
