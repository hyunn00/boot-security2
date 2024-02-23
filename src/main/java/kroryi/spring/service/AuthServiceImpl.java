package kroryi.spring.service;

import kroryi.spring.dto.LoginRequestDto;
import kroryi.spring.dto.MemberDto;
import kroryi.spring.entity.Member;
import kroryi.spring.jwt.JwtUtil;
import kroryi.spring.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthServiceImpl implements AuthService{
    private final JwtUtil jwtUtil;
    private final MemberRepository memberRepository;
    private final PasswordEncoder encoder;
    private final ModelMapper modelMapper;

    @Override
    @Transactional
    public String login(LoginRequestDto dto) {
        String email = dto.getEmail();
        String password = dto.getPassword();
        Optional<Member> member = memberRepository.findMemberByEmail(email);

        if(member.isEmpty()) {
            throw new UsernameNotFoundException("이메일이 존재하지 않습니다.");
        }

        if(!encoder.matches(password, member.get().getPassword())) {
            throw new BadCredentialsException("비밀번호가 일치하지 않습니다.");
        }

        MemberDto info = modelMapper.map(member, MemberDto.class);
        String accessToken = jwtUtil.createAccessToken(info);
        return accessToken;
    }
}
