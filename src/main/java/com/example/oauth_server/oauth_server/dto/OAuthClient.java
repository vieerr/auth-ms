package com.example.oauth_server.oauth_server.dto;
public class OAuthClient {
    private String id;
    private String clientId;
    private String clientSecret;
    private String clientAuthenticationMethod;
    private String authorizationGrantType;
    private String redirectUri;
    private String scope;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getClientAuthenticationMethod() {
        return clientAuthenticationMethod;
    }

    public void setClientAuthenticationMethod(String clientAuthenticationMethod) {
        this.clientAuthenticationMethod = clientAuthenticationMethod;
    }

    public String getAuthorizationGrantType() {
        return authorizationGrantType;
    }

    public void setAuthorizationGrantType(String authorizationGrantType) {
        this.authorizationGrantType = authorizationGrantType;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    @Override
    public String toString() {
        return "OAuthClient{" +
                "id='" + id + '\'' +
                ", clientId='" + clientId + '\'' +
                ", clientSecret='" + clientSecret + '\'' +
                ", clientAuthenticationMethod='" + clientAuthenticationMethod + '\'' +
                ", authorizationGrantType='" + authorizationGrantType + '\'' +
                ", redirectUri='" + redirectUri + '\'' +
                ", scope='" + scope + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OAuthClient that = (OAuthClient) o;
        return java.util.Objects.equals(id, that.id) &&
                java.util.Objects.equals(clientId, that.clientId) &&
                java.util.Objects.equals(clientSecret, that.clientSecret) &&
                java.util.Objects.equals(clientAuthenticationMethod, that.clientAuthenticationMethod) &&
                java.util.Objects.equals(authorizationGrantType, that.authorizationGrantType) &&
                java.util.Objects.equals(redirectUri, that.redirectUri) &&
                java.util.Objects.equals(scope, that.scope);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(id, clientId, clientSecret, clientAuthenticationMethod, authorizationGrantType, redirectUri, scope);
    }
}