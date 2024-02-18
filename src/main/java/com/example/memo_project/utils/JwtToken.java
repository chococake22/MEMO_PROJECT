package com.example.memo_project.utils;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class JwtToken {

    private String grantType;
    private String accessToken;
    private String refreshToken;
}
