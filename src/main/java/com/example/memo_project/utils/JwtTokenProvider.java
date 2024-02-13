package com.example.memo_project.utils;

import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;

@Slf4j
@Component
public class JwtTokenProvider {

    private final Key key;

    // key값 저장
    public JwtTokenProvider(@Value("${jwt.security}") String secretKey) {
        byte[] keyBytes= Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }
}
