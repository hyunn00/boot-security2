package kroryi.spring.service;

import kroryi.spring.dto.LoginRequestDto;

public interface AuthService {
    String login(LoginRequestDto dto);
}
