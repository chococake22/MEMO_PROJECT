package com.example.memo_project.controller;

import com.example.memo_project.domain.UserVo;
import com.example.memo_project.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {

    private final UserService userService;

    // 로그인 정보 가져오기
    @GetMapping("/login")
    public String login() {
        return "로그인 성공";
    }

    @PostMapping("/user")
    public Map<String, Object> createUser(@RequestBody UserVo userVo) {
        return userService.insertUser(userVo);
    }
}
