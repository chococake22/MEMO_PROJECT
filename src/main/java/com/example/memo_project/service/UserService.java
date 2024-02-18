package com.example.memo_project.service;


import com.example.memo_project.domain.UserVo;
import com.example.memo_project.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserMapper userMapper;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Transactional
    public ResponseEntity<UserVo> insertUser(UserVo userVo) {

        HttpHeaders header = new HttpHeaders();
        header.setContentType(new MediaType("application", "json", Charset.forName("UTF-8")));

        // 아이디 중복 확인
        UserVo userVoChk = userMapper.findUserByUserId(userVo.userId);

        UserVo newUser;

        // 사용중인 계정이 아닌 경우
        if (userVoChk == null) {
            // 비밀번호 체크 확인

            if (!userVo.getPassword().equals(userVo.getPasswordChk())) {
                throw new RuntimeException("두 비밀번호가 다릅니다.");
            } else {
                // 비밀번호 암호화
                // DB에 저장할때 암호화된 상태로 저장되어야 함

                newUser = UserVo
                        .builder()
                        .userId(userVo.userId)
                        .password(bCryptPasswordEncoder.encode(userVo.password))
                        .name(userVo.name)
                        .phone(userVo.phone)
                        .role("USER_ADMIN")
                        .build();


//                userVo.encPwd(bCryptPasswordEncoder);
                userMapper.insertUser(newUser);
            }
        } else {
            throw new RuntimeException("이미 사용중인 아이디입니다.");
        }

        System.out.println(newUser);
        System.out.println(header);

        return new ResponseEntity<>(newUser, header, HttpStatus.OK);
    }
}
