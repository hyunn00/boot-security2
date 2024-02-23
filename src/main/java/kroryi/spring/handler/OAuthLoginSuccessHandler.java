package kroryi.spring.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import kroryi.spring.dto.MemberDto;
import kroryi.spring.entity.Member;
import kroryi.spring.jwt.CookieUtil;
import kroryi.spring.jwt.JwtUtil;
import kroryi.spring.oauth2.CustomOAuth2User;
import kroryi.spring.oauth2.OAuth2AuthorizationRequestBasedOnCookieRepository;
import kroryi.spring.repository.MemberRepository;
import kroryi.spring.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuthLoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final MemberService memberService;
    private final MemberRepository memberRepository;
    private final JwtUtil jwtUtil;
    private final ModelMapper modelMapper;
    private final OAuth2AuthorizationRequestBasedOnCookieRepository authorizationRequestRepository;

    public static final String REFRESH_TOKEN_COOKIE_NAME = "refresh_token";
    public static final Duration REFRESH_TOKEN_DURATION = Duration.ofDays(14);
    public static final Duration ACCESS_TOKEN_DURATION = Duration.ofDays(1);
    public static final String REDIRECT_PATH = "/";


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        log.info("OAuth2AuthenticationToken -> {}", token);
        log.info("OAuth2User -> {}", authentication.getPrincipal());
        OAuth2User user = (OAuth2User) authentication.getPrincipal();
        log.info("OAuth2User.email -> {}", ((Map<String, Object>)user.getAttribute("kakao_account")).get("email").toString());



        String email = null;
        String oauthType = token.getAuthorizedClientRegistrationId();
        log.info("oauthType -> {}", oauthType);


        email = switch (oauthType.toLowerCase()) {
            case "kakao" -> ((Map<String, Object>)token.getPrincipal().getAttribute("kakao_account")).get("email").toString();
            case "naver" -> ((Map<String, Object>)token.getPrincipal().getAttribute("response")).get("email").toString();
            case "google" -> token.getPrincipal().getAttribute("email").toString();
            default -> email;
        };

        Member member = memberRepository.findMemberByEmail(email).orElseThrow(() -> new UsernameNotFoundException("존재하지 않는 email 입니다. 다시 확인 부탁합니다."));
        String accessToken = jwtUtil.createAccessToken(modelMapper.map(member, MemberDto.class));
        log.info("accessToken -> {}", accessToken);

        Cookie cookie = new Cookie("jwt-cookie", accessToken);
        cookie.setMaxAge(7*24*60*60);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);

//        log.info("LOGIN SUCCESS : {} FROM {}", email, oauthType);
//        Member member = memberService.getUserByEmailAndOAuthType(email, oauthType);
//
//        log.info("USER SAVED IN SESSION");
//        HttpSession session = request.getSession();
//        session.setAttribute("member", member);

        super.onAuthenticationSuccess(request, response, authentication);
    }

    private void addRefreshTokenToCookie(HttpServletRequest request, HttpServletResponse response, String refreshToken) {
        int cookieMaxAge = (int) REFRESH_TOKEN_DURATION.toSeconds();

        CookieUtil.deleteCookie(request, response, REFRESH_TOKEN_COOKIE_NAME);
        CookieUtil.addCookie(response, REFRESH_TOKEN_COOKIE_NAME, refreshToken, cookieMaxAge);
    }

    // 인증 관련 설정값, 쿠키 제거
    private void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }
    private String getTargetUrl(String token) {
        return UriComponentsBuilder.fromUriString(REDIRECT_PATH)
                .queryParam("token", token)
                .build()
                .toUriString();
    }
}
