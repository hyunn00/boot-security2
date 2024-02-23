package kroryi.spring.config;

import kroryi.spring.component.CustomAccessDenieHandler;
import kroryi.spring.component.CustomAuthenticationEntryPoint;
import kroryi.spring.handler.OAuthLoginFailureHandler;
import kroryi.spring.handler.OAuthLoginSuccessHandler;
import kroryi.spring.jwt.JwtAuthFilter;
import kroryi.spring.jwt.JwtUtil;
import kroryi.spring.oauth2.OAuth2AuthorizationRequestBasedOnCookieRepository;
import kroryi.spring.service.CustomUserDetailsService;
import kroryi.spring.service.MemberService;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig {
    private final OAuthLoginSuccessHandler oAuthLoginSuccessHandler;
    private final OAuthLoginFailureHandler oAuthLoginFailureHandler;
    private final MemberService memberService;
    private final CustomUserDetailsService customUserDetailsService;
    private final JwtUtil jwtUtil;
    private final CustomAccessDenieHandler accessDenieHandler;
    private final CustomAuthenticationEntryPoint authenticationEntryPoint;
    private final OAuth2AuthorizationRequestBasedOnCookieRepository authorizationRequestRepository;
    private static final String[] AUTH_WHITELIST = {
            "/", "/api/v1/member/**", "/api/v1/auth/**"
    };

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http.csrf(configurer -> configurer.disable())
        http.csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                .authorizeHttpRequests(registry ->
                        registry.requestMatchers(AUTH_WHITELIST).permitAll()
                                .requestMatchers("/user/**").authenticated()
                                .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN")
                                .requestMatchers("/admin/**").hasRole("ADMIN")
                                .anyRequest().permitAll()
                )
//                .formLogin(configurer ->
//                        configurer.loginPage("/login")
//                                .loginProcessingUrl("/loginProc")
//                                .defaultSuccessUrl("/")
//                )
                .formLogin(AbstractHttpConfigurer::disable)
                .oauth2Login(configurer -> configurer
                        .loginPage("/login") // google login page와 로그인 페이지를 맵핑 시켜줍니다.
                        .userInfoEndpoint(config -> config.userService(memberService))
                        .redirectionEndpoint(Customizer.withDefaults())
                        .authorizationEndpoint(author -> author.authorizationRequestRepository(authorizationRequestRepository))
                        .successHandler(oAuthLoginSuccessHandler)
                        .failureHandler(oAuthLoginFailureHandler)
                );

        http.exceptionHandling((exceptionHandling) -> exceptionHandling
                .authenticationEntryPoint(authenticationEntryPoint)
                .accessDeniedHandler(accessDenieHandler)
        );

        http.addFilterBefore(new JwtAuthFilter(customUserDetailsService, jwtUtil), UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }

}
