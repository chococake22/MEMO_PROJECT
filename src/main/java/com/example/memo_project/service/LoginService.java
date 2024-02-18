package com.example.memo_project.service;


import com.example.memo_project.domain.UserVo;
import com.example.memo_project.mapper.UserMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LoginService implements UserDetailsService {

    private final UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {

        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        UserVo userVo = userMapper.findUserByUserId(userId);

        if (userVo.getUserId().equals("") || userVo.getUserId() == null) {
            throw new RuntimeException("존재하지 않는 아이디입니다.");
        }

        return UserVo.builder()
                .userId("apple12")
                .password(passwordEncoder.encode("1234"))
                .role("USER_ADMIN")
                .phone("01012341234")
                .build();
    }
}
