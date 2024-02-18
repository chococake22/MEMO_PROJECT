package com.example.memo_project.controller;

import com.example.memo_project.domain.UserVo;
import com.example.memo_project.service.UserService;
import com.example.memo_project.utils.JwtToken;
import com.example.memo_project.utils.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    private final JwtTokenProvider jwtTokenProvider;

    // 로그인 정보 가져오기
    @GetMapping("/login")
    public JwtToken login(@AuthenticationPrincipal UserVo userVo) {

        // userId로 토큰 만들기
        // 근데 여기서 말고 filter에서 해야하나?
        // JsonUsernamePasswordAuthenticationFilter에서 가능한지 확인 필요.
        Authentication principal = SecurityContextHolder.getContext().getAuthentication();

        JwtToken jwtToken = jwtTokenProvider.createToken(principal);

        return jwtToken;
    }

    // 사용자 생성
    @PostMapping("/user")
    public ResponseEntity<UserVo> createUser(@RequestBody UserVo userVo) {
        return userService.insertUser(userVo);
    }
}
