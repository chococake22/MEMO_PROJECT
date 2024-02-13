package com.example.memo_project.service;


import com.example.memo_project.domain.UserVo;
import com.example.memo_project.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserMapper userMapper;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Transactional
    public Map<String, Object> insertUser(UserVo userVo) {

        Map<String, Object> resultMap = new HashMap<>();

        // 아이디 중복 확인
        UserVo userVoChk = userMapper.findUserByUserId(userVo.userId);

        if (userVoChk == null) {

            // 비밀번호 체크 확인
            // DB에 저장할때 암호화된 상태로 저장되어야 함
            if (!userVo.getPassword().equals(userVo.getPasswordChk())) {
                resultMap.put("result", false);
                resultMap.put("message", "두 비밀번호가 다릅니다.");
                resultMap.put("data", null);
            } else {
                // 비밀번호 암호화
                userVo.encPwd(bCryptPasswordEncoder);
                userMapper.insertUser(userVo);
                resultMap.put("result", true);
                resultMap.put("message", "계정이 생성되었습니다.");
                resultMap.put("data", userVo);
            }

        } else {
            resultMap.put("result", false);
            resultMap.put("message", "이미 사용중인 아이디입니다.");
            resultMap.put("data", null);
        }

        return resultMap;
    }

}
