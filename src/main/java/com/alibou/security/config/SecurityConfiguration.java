package com.alibou.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

/**
 * Класс конфигурации для настроек безопасности.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    /**
     * Определяет цепочку фильтров безопасности.
     *
     * @param http объект HttpSecurity
     * @return объект SecurityFilterChain
     * @throws Exception если произошла ошибка
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeRequests()
                .requestMatchers("/api/v1/auth/**", "/api/v1/auth2/**", "/api/v1/greeting-controller/**")
                .permitAll()
                .requestMatchers("/api/v1/demo-controller/with-auth", "/api/v1/index-controller/**")
                .hasAnyAuthority("USER")
                .requestMatchers("/api/v1/demo-controller/**")
                .permitAll()
                .and().formLogin(form -> form
                        .loginPage("/api/v1/auth2/login-page")
                        .failureUrl("/api/v1/auth2/login-page"))
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/api/v1/auth2/login-page")
                        .deleteCookies("token"))
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
