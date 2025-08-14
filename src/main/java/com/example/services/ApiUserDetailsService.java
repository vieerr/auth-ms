package com.example.services;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.example.oauth_server.oauth_server.dto.Client;

@Service
public class ApiUserDetailsService implements UserDetailsService {

    private final RestTemplate restTemplate;
    private final String clientsApiUrl = "http://localhost:1313/api/clients";

    public ApiUserDetailsService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // Call your clients API to get user details by email
        Client client = restTemplate.getForObject(clientsApiUrl + "/email/" + email, Client.class);

        if (client == null) {
            throw new UsernameNotFoundException("User not found");
        }

        System.out.println("Client found: " + client.toString());

        String password = "{noop}" + client.getPassword();
        return User.builder()
                .username(client.getEmail())
                .password(password) // Make sure passwords are properly encoded
                .roles(client.getRole())
                .build();
    }
}
