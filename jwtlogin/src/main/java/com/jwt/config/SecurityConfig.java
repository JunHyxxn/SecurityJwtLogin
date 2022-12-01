package com.jwt.config;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@EnableWebSecurity // @Configuration + �߰� ��� ����
@EnableGlobalMethodSecurity(prePostEnabled = true) // Method ������ @PreAuthorize, @PostAuthorize ��� �����ϵ��� ����
public class SecurityConfig extends WebSecurityConfigurerAdapter {

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

                // Session ���� -> JWT ��� �α��� ���� -> StateLess
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                // request�� resource ���� ���� ����
                .and()
                .authorizeHttpRequests()
                .antMatchers("/**").permitAll();
    }
}
