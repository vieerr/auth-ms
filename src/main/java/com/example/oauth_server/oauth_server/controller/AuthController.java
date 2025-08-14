package com.example.oauth_server.oauth_server.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.example.oauth_server.oauth_server.dto.Client;

// Import RegistrationRequest if it exists elsewhere
// import com.example.oauth_server.oauth_server.dto.RegistrationRequest;
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final RestTemplate restTemplate;

    private final String clientsApiUrl = "http://localhost:1313/api/clients";

// Add RegistrationRequest class if it does not exist elsewhere
    class RegistrationRequest {

        private String firstName;
        private String lastName;
        private String email;
        private String password;

        public String getFirstName() {
            return firstName;
        }

        public void setFirstName(String firstName) {
            this.firstName = firstName;
        }

        public String getLastName() {
            return lastName;
        }

        public void setLastName(String lastName) {
            this.lastName = lastName;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }

    public AuthController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegistrationRequest request) {
        // Call your clients API to create the user
        Client newClient = new Client();
        newClient.setFirstName(request.getFirstName());
        newClient.setLastName(request.getLastName());
        newClient.setEmail(request.getEmail());
        newClient.setPassword(request.getPassword());

        // newClient.setPassword(passwordEncoder.encode(request.getPassword()));
        Client createdClient = restTemplate.postForObject(clientsApiUrl, newClient, Client.class);

        return ResponseEntity.ok(createdClient);
    }
}
