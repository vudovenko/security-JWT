package com.alibou.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Сервис для работы с JWT-токенами.
 */
@Service
public class JwtService {

    @Value("${auth.secret}")
    private String SECRET_KEY;

    /**
     * Генерирует токен для пользователя на основе информации о пользователе.
     * @param userDetails информация о пользователе
     * @return сгенерированный токен
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Генерирует токен для пользователя с дополнительными данными.
     *
     * @param extraClaims дополнительные данные для токена
     * @param userDetails информация о пользователе
     * @return сгенерированный токен
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Проверяет, действителен ли токен для указанного пользователя.
     *
     * @param token токен для проверки
     * @param userDetails сведения о пользователе
     * @return true, если токен действителен для указанного пользователя, в противном случае - false
     */
    public Boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    /**
     * Проверяет, истек ли срок действия токена.
     *
     * @param token Токен для проверки
     * @return Истина, если токен истек, ложь в противном случае
     */
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Извлекает дату истечения срока действия из токена.
     *
     * @param token токен, из которого нужно извлечь дату истечения
     * @return дата истечения из токена
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Извлекает утверждение из токена с помощью заданного распаковщика утверждений.
     *
     * @param token          токен, из которого нужно извлечь утверждение
     * @param claimsResolver распаковщик утверждений, используемый для извлечения утверждения из токена
     * @return извлеченное утверждение
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Метод извлекает все Claims из токена
     *
     * @param token токен
     * @return Claims из токена
     */
    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
    }
}
