package com.example.oauth_server.oauth_server.oauth;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.example.oauth_server.oauth_server.repository.ApiRegisteredClientRepository;
import com.example.oauth_server.oauth_server.utils.JwtUtil;
import com.example.services.ApiUserDetailsService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer
                = OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer)
                        -> authorizationServer
                        .oidc(Customizer.withDefaults()) // Enable OpenID Connect 1.0
                )
                .authorizeHttpRequests((authorize)
                        -> authorize
                        .anyRequest().authenticated()
                )
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
                );

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
                )
                .formLogin(form -> form
                .successHandler((HttpServletRequest request, HttpServletResponse response, Authentication authentication) -> {
                    RestTemplate restTemplate = restTemplate();
                    String email = authentication.getName();
                    String apiUrl = "http://localhost:1313/api/clients/email/" + email;
                    try {
                        Object userResponse = restTemplate.getForObject(apiUrl, Object.class);
                        if (userResponse == null) {
                            System.err.println("User not found for email: " + email);
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User not found");
                            return;
                        }
                        String jwt = JwtUtil.generateToken(
                                userResponse.toString()
                        );

                        // // Logging (optional)
                        // System.out.println("Generated JWT: " + jwt);
                        // // Send JWT to Angular via:
                        // // Option A: URL Fragment (for redirect)
                        // response.sendRedirect("http://localhost:4200/login-success#token=" + jwt);
                        Cookie cookie = new Cookie("the-armory-jwt", jwt);
                        cookie.setHttpOnly(true);
                        cookie.setSecure(true); // Enable in production
                        cookie.setPath("/");
                        response.addCookie(cookie);
                        response.sendRedirect("http://localhost:4200");

                    } catch (RestClientException e) {
                        System.err.println("Failed to fetch user from API: " + e.getMessage());
                    }

                })
                )
                .csrf(csrf -> csrf.disable());

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new ApiUserDetailsService(restTemplate());
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(ApiRegisteredClientRepository apiRegisteredClientRepository) {
        return apiRegisteredClientRepository;
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }
}
