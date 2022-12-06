package com.jwt.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider implements InitializingBean {
    private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

    private static final String AUTHORITIES_KEY = "auth";

    private final String secret;
    private final long accesstokenValidityInMilliSeconds;
    private final long refreshtokenValidityInMilliSeconds;

    private Key key;

    public TokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.accesstoken-validity-in-seconds}") long accesstokenValidityInMilliSeconds,
            @Value("${jwt.refreshtoken-validity-in-seconds}") long refreshtokenValidityInMilliSeconds
    ) {
        this.secret = secret;
        this.accesstokenValidityInMilliSeconds = accesstokenValidityInMilliSeconds * 1000;
        this.refreshtokenValidityInMilliSeconds = refreshtokenValidityInMilliSeconds * 1000;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        byte[] ketBytes = Decoders.BASE64.decode(secret);
        // Creates a new SecretKey instance for use with HMAC-SHA algorithms based on the specified key byte array.
        this.key = Keys.hmacShaKeyFor(ketBytes);
    }

    // Access Token Generator
    public String createAccessToken(Authentication authentication) {
        // Authority
        String authorities = authentication.getAuthorities().stream()
                // 현재 authentication이 가진 권한
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        logger.info("[Create Access token] authorities : ", authorities);

        // Set Expiration Time
        long now = (new Date()).getTime();
        Date validity = new Date(now + this.accesstokenValidityInMilliSeconds);

        return Jwts.builder()
                .setSubject(authentication.getName()) // username
                // Claim 에 Key="auth", data= username 을 넣기도 한다.
                .claim(AUTHORITIES_KEY, authorities) // auth: roles
                .signWith(key, SignatureAlgorithm.HS512) // secretKey, algorithms
                .setExpiration(validity)
                .compact();
    }
    // Refresh Token Generator
    public String createRefreshToken(Authentication authentication) {
        // Authority
        String authorities = authentication.getAuthorities().stream()
                // 현재 authentication이 가진 권한
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        logger.info("[Create Refresh token] authorities : ", authorities);

        // Set Expiration Time
        long now = (new Date()).getTime();
        Date validity = new Date(now + this.refreshtokenValidityInMilliSeconds);

        return Jwts.builder()
                .setSubject(authentication.getName()) // username
                // Claim 에 Key="auth", data= username 을 넣기도 한다.
                .claim(AUTHORITIES_KEY, authorities) // auth: roles
                .signWith(key, SignatureAlgorithm.HS512) // secretKey, algorithms
                .setExpiration(validity)
                .compact();
    }

    // token으로부터 Authentication 객체 리턴
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key) // secretKey  설정
                .build()
                .parseClaimsJws(token)
                .getBody();

        // claims에 auth: roles로 담아둔 정보를 가져온다.
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // UserDetails 의 구현체인 User
        // 기본적으로 Principal, Credential, authorities 필요하다.
        // token의 subject에 username을 담아뒀다.
        User principal = new User(claims.getSubject(), "", authorities);
        // Authentication 리턴
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    // 토큰 유효성 검사
    public boolean validateToken(String token) {
        try {
            // 성공적으로 만들어진다면 유효한 토큰이다.
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch(SecurityException | MalformedJwtException e) {
            logger.info("잘못된 JWT 서명입니다.");
        } catch (ExpiredJwtException e) {
            logger.info("만료된 토큰입니다.");
        } catch (UnsupportedJwtException e) {
            logger.info("지원되지 않는 JWT 토큰입니다.");
        } catch (IllegalArgumentException e) {
            logger.info("잘못된 JWT 토큰입니다.");
        }
        return false;
    }
}
