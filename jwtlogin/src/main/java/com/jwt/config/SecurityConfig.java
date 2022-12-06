package com.jwt.config;

import com.jwt.filter.JwtFilter;
import com.jwt.security.jwt.JwtAccessDeniedHandler;
import com.jwt.security.jwt.JwtAuthenticationEntryPoint;
import com.jwt.security.jwt.TokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity // @Configuration + �߰� ��� ����
@EnableGlobalMethodSecurity(prePostEnabled = true) // Method ������ @PreAuthorize, @PostAuthorize ��� �����ϵ��� ����
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final TokenProvider tokenProvider;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    public SecurityConfig(TokenProvider tokenProvider,
                          JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
                          JwtAccessDeniedHandler jwtAccessDeniedHandler) {
        this.tokenProvider = tokenProvider;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
    }

    // PasswordEncoder ���
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    // web ����
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers(HttpMethod.OPTIONS, "/**")
                .antMatchers("/favicon.ico");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // CORS, CSRF ����
                .cors()
                .and()
                .csrf().disable()

                // ExceptionHandler ���
                .exceptionHandling()
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)

                // Session ���� -> JWT ��� �α��� ���� -> StateLess
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                // request�� resource ���� ���� ����
                .and()
                .authorizeHttpRequests()
                .antMatchers("/**").permitAll()

                // JwtFilter ��� - tokenProvider �����ؼ� ����Ѵ�.
                // �� ���ʹ� ���� ������ UsernamePasswordAuthenticationFilter ���� ������ݴϴ�.
                .and()
                .addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class);
    }
}
