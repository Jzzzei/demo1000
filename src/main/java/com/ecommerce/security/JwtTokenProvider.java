package com.ecommerce.security;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private int jwtExpirationInMs;



    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 86400000)) // 24 hours
                .signWith(SignatureAlgorithm.HS256, jwtSecret.getBytes()) // 改用 HS256 而不是 HS512
                .compact();
    }

    public String getUsernameFromJWT(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException ex) {
            // 无效的JWT签名
            return false;
        } catch (MalformedJwtException ex) {
            // 无效的JWT令牌
            return false;
        } catch (ExpiredJwtException ex) {
            // 过期的JWT令牌
            return false;
        } catch (UnsupportedJwtException ex) {
            // 不支持的JWT令牌
            return false;
        } catch (IllegalArgumentException ex) {
            // JWT声明字符串为空
            return false;
        }
    }
} 