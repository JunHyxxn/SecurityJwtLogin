package com.jwt.filter;

import com.jwt.security.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter{
    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);

    public static final String AUTHORIZATION_HEADER = "Authorization";
    private final TokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwt = resolveToken(request);
        String requestURI = request.getRequestURI();

        // jwt 존재하고 && 유효하다면
        if(jwt != null && tokenProvider.validateToken(jwt)) {
            logger.info("JwtFilter with token : ", jwt);

            // Authentication 가져오기
            Authentication authentication = tokenProvider.getAuthentication(jwt);
            // Context에 Authentication 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
            logger.debug("SecurityContext에 '{}' 인증 정보를 저장했습니다, uri : {}", authentication, requestURI);
        }
        // Do Next Filter
        filterChain.doFilter(request, response);
    }

    // Header 에서 토큰 꺼내기
    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }
}
