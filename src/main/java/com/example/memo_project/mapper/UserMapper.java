package com.example.memo_project.mapper;

import com.example.memo_project.domain.UserVo;
import org.apache.ibatis.annotations.Mapper;


@Mapper
public interface UserMapper {

    public UserVo findUser(String userId);

    public UserVo findUserByUserId(String userId);

    public int insertUser(UserVo userVo);

}
