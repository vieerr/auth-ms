package com.example.oauth_server.oauth_server.repository;

import java.util.UUID;

import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Repository;
import org.springframework.web.client.RestTemplate;

import com.example.oauth_server.oauth_server.dto.OAuthClient;

@Repository("apiRegisteredClientRepository")
@Primary
public class ApiRegisteredClientRepository implements RegisteredClientRepository {

    private final RestTemplate restTemplate;
    private final String clientsApiUrl = "http://localhost:1313/api/oauth-clients"; // Your OAuth clients API endpoint

    public ApiRegisteredClientRepository(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        // Implement if you need to dynamically register clients
        throw new UnsupportedOperationException();
    }

    @Override
    public RegisteredClient findById(String id) {
        OAuthClient client = restTemplate.getForObject(clientsApiUrl + "/" + id, OAuthClient.class);
        return convertToRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        if ("your-client-id".equals(clientId)) {
            return RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("your-client-id")
                    .clientSecret("{noop}your-client-secret")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://localhost:4200/login/oauth2/code/your-client-id") // Key change here
                    .postLogoutRedirectUri("http://localhost:4200")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope("read")
                    .scope("write")
                    .build();
        }
        return null;
    }
    // @Override
    // public RegisteredClient findByClientId(String clientId) {
    //     OAuthClient client = restTemplate.getForObject(clientsApiUrl + "/client-id/" + clientId, OAuthClient.class);
    //     return convertToRegisteredClient(client);
    // }

    private RegisteredClient convertToRegisteredClient(OAuthClient client) {
        if (client == null) {
            return null;
        }

        return RegisteredClient.withId(client.getId())
                .clientId(client.getClientId())
                .clientSecret(client.getClientSecret())
                .clientAuthenticationMethod(new ClientAuthenticationMethod(client.getClientAuthenticationMethod()))
                .authorizationGrantType(new AuthorizationGrantType(client.getAuthorizationGrantType()))
                .redirectUri(client.getRedirectUri())
                .scope(client.getScope())
                .build();
    }
}
