package com.alibou.security.auth;

import com.alibou.security.config.JwtService;
import com.alibou.security.user.Role;
import com.alibou.security.user.SecurityUser;
import com.alibou.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    /**
     * Регистрирует нового пользователя на основе данных из запроса.
     * Создает нового пользователя, сохраняет его в репозитории и генерирует JWT токен.
     *
     * @param request объект запроса с данными нового пользователя
     * @return объект ответа со сгенерированным JWT токеном
     */
    public AuthenticationResponse register(RegisterRequest request) {
        // Создание нового пользователя на основе данных из запроса
        SecurityUser securityUser = SecurityUser.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole() == null ? Role.USER : request.getRole())
                .build();

        // Сохранение нового пользователя в репозитории
        SecurityUser savedSecurityUser = repository.save(securityUser);

        // Генерация JWT токена для пользователя
        String jwtToken = jwtService.generateToken(securityUser);

        // Возвращение объекта ответа со сгенерированным JWT токеном
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    /**
     * Аутентификация пользователя на основе переданного запроса.
     * При успешной аутентификации генерируется JWT токен и возвращается объект ответа с токенами доступа и обновления.
     *
     * @param request объект запроса с данными для аутентификации
     * @return объект ответа со сгенерированными JWT токенами доступа и обновления
     */
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        /*Аутентификация пользователя на основе email и пароля из запроса.
         * authenticationManager выполняет всю работу для аутентификации пользователя.
         * В случае, если имя пользователя или пароль неверны, будет выброшено исключение.*/
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // Поиск пользователя по email в репозитории
        SecurityUser securityUser = repository.findByEmail(request.getEmail())
                .orElseThrow();

        // Генерация JWT токена для пользователя
        String jwtToken = jwtService.generateToken(securityUser);

        // Возвращение объекта ответа со сгенерированным JWT токеном
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
