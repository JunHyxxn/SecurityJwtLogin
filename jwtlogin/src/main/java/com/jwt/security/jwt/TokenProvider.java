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
                // ���� authentication�� ���� ����
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        logger.info("[Create Access token] authorities : ", authorities);

        // Set Expiration Time
        long now = (new Date()).getTime();
        Date validity = new Date(now + this.accesstokenValidityInMilliSeconds);

        return Jwts.builder()
                .setSubject(authentication.getName()) // username
                // Claim �� Key="auth", data= username �� �ֱ⵵ �Ѵ�.
                .claim(AUTHORITIES_KEY, authorities) // auth: roles
                .signWith(key, SignatureAlgorithm.HS512) // secretKey, algorithms
                .setExpiration(validity)
                .compact();
    }
    // Refresh Token Generator
    public String createRefreshToken(Authentication authentication) {
        // Authority
        String authorities = authentication.getAuthorities().stream()
                // ���� authentication�� ���� ����
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        logger.info("[Create Refresh token] authorities : ", authorities);

        // Set Expiration Time
        long now = (new Date()).getTime();
        Date validity = new Date(now + this.refreshtokenValidityInMilliSeconds);

        return Jwts.builder()
                .setSubject(authentication.getName()) // username
                // Claim �� Key="auth", data= username �� �ֱ⵵ �Ѵ�.
                .claim(AUTHORITIES_KEY, authorities) // auth: roles
                .signWith(key, SignatureAlgorithm.HS512) // secretKey, algorithms
                .setExpiration(validity)
                .compact();
    }

    // token���κ��� Authentication ��ü ����
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(key) // secretKey  ����
                .build()
                .parseClaimsJws(token)
                .getBody();

        // claims�� auth: roles�� ��Ƶ� ������ �����´�.
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        // UserDetails �� ����ü�� User
        // �⺻������ Principal, Credential, authorities �ʿ��ϴ�.
        // token�� subject�� username�� ��Ƶ״�.
        User principal = new User(claims.getSubject(), "", authorities);
        // Authentication ����
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    // ��ū ��ȿ�� �˻�
    public boolean validateToken(String token) {
        try {
            // ���������� ��������ٸ� ��ȿ�� ��ū�̴�.
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch(SecurityException | MalformedJwtException e) {
            logger.info("�߸��� JWT �����Դϴ�.");
        } catch (ExpiredJwtException e) {
            logger.info("����� ��ū�Դϴ�.");
        } catch (UnsupportedJwtException e) {
            logger.info("�������� �ʴ� JWT ��ū�Դϴ�.");
        } catch (IllegalArgumentException e) {
            logger.info("�߸��� JWT ��ū�Դϴ�.");
        }
        return false;
    }
}
