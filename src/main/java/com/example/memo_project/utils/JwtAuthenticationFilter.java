package com.example.memo_project.utils;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

// 클라이언트 요청 시 JWT 인증을 하기 위해 설치하는 커스텀 필터
// UsernamePasswordAuthenticationFilter 이전에 실행됨
// => 이 말은 JwtAuthenticationFilter를 통과하면 UsernamePasswordAuthenticationFilter 이후의 필터는 통과한 것으로 본다는 뜻입니다.
// = username+password를 통한 인증을 JWT를 통해 수행한다는 것!

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends GenericFilterBean {
    private final JwtTokenProvider jwtTokenProvider;
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        // 1. Header에서 JWT 토큰 추출
        String token = resolveToken((HttpServletRequest) request);

        // 2. 토큰 추출 후 유효성 검사
        if (token != null && jwtTokenProvider.validateToken(token)) {

            // 토큰이 유효할 경우 토큰으로부터 authentication 객체 추출 후에 security에 저장.
            Authentication authentication = jwtTokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        chain.doFilter(request, response);

    }

    // Request 객체의 header에서 토큰 정보를 얻는다.
    private String resolveToken(HttpServletRequest request) {

        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
            // 7번째부터 가져오기("Bearer "는 제외)
            return bearerToken.substring(7);
        }

        return null;

    }
}
