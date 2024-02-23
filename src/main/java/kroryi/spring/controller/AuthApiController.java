package kroryi.spring.controller;

import kroryi.spring.dto.LoginRequestDto;
import kroryi.spring.service.AuthService;
import kroryi.spring.service.AuthServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthApiController {
    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<String> getMemberProfile (
            @RequestBody LoginRequestDto request
    ) {
        String token = this.authService.login(request);
        return ResponseEntity.status(HttpStatus.OK).body(token);
    }
}
