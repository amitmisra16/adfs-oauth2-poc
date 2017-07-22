package com.example.demo;

import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.FixedAuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.FixedPrincipalExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;


public class AdfsUserInfoTokenServices implements ResourceServerTokenServices {

protected final Logger logger = LoggerFactory.getLogger(getClass());

private final String userInfoEndpointUrl;

private final String clientId;

private String tokenType = DefaultOAuth2AccessToken.BEARER_TYPE;

private AuthoritiesExtractor authoritiesExtractor = new FixedAuthoritiesExtractor();

private PrincipalExtractor principalExtractor = new FixedPrincipalExtractor();

public AdfsUserInfoTokenServices(String userInfoEndpointUrl, String clientId) {
    this.userInfoEndpointUrl = userInfoEndpointUrl;
    this.clientId = clientId;
}

public void setTokenType(String tokenType) {
    this.tokenType = tokenType;
}

public void setRestTemplate(OAuth2RestOperations restTemplate) {
    // not used
}

public void setAuthoritiesExtractor(AuthoritiesExtractor authoritiesExtractor) {
    Assert.notNull(authoritiesExtractor, "AuthoritiesExtractor must not be null");
    this.authoritiesExtractor = authoritiesExtractor;
}

public void setPrincipalExtractor(PrincipalExtractor principalExtractor) {
    Assert.notNull(principalExtractor, "PrincipalExtractor must not be null");
    this.principalExtractor = principalExtractor;
}

@Override
public OAuth2Authentication loadAuthentication(String accessToken)
        throws AuthenticationException, InvalidTokenException {
          logger.info("loadAuthentication called");
    Map<String, Object> map = getMap(this.userInfoEndpointUrl, accessToken);
    if (map.containsKey("error")) {
        if (this.logger.isInfoEnabled()) {
            this.logger.info("userinfo returned error: " + map.get("error"));
        }
        throw new InvalidTokenException(accessToken);
    }
    return extractAuthentication(map);
}

private OAuth2Authentication extractAuthentication(Map<String, Object> map) {
    logger.info("extractAuthentication called");
    Object principal = getPrincipal(map);
    List<GrantedAuthority> authorities = this.authoritiesExtractor
            .extractAuthorities(map);
    OAuth2Request request = new OAuth2Request(null, this.clientId, null, true, null,
            null, null, null, null);
    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
            principal, "N/A", authorities);
    token.setDetails(map);
    return new OAuth2Authentication(request, token);
}

/**
 * Return the principal that should be used for the token. The default implementation
 * delegates to the {@link PrincipalExtractor}.
 * @param map the source map
 * @return the principal or {@literal "unknown"}
 */
protected Object getPrincipal(Map<String, Object> map) {
    Object principal = this.principalExtractor.extractPrincipal(map);
    return (principal == null ? "unknown" : principal);
}

@Override
public OAuth2AccessToken readAccessToken(String accessToken) {
    throw new UnsupportedOperationException("Not supported: read access token");
}

private Map<String, Object> getMap(String path, String accessToken) {
    if (this.logger.isInfoEnabled()) {
        this.logger.info("Getting user info from: " + path);
    }
    try {
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(
                accessToken);
        token.setTokenType(this.tokenType);

        logger.info("Token value: " + token.getValue());

        String jwtBase64 = token.getValue().split("\\.")[1];

        logger.info("Token: Encoded JWT: " + jwtBase64);

        String jwtJson = new String(Base64.getDecoder().decode(jwtBase64.getBytes()));
        logger.info("Decoded JWT: {}", jwtJson);

        ObjectMapper mapper = new ObjectMapper();

        return mapper.readValue(jwtJson, new TypeReference<Map<String, Object>>(){});
    }
    catch (Exception ex) {
        this.logger.warn("Could not fetch user details: " + ex.getClass() + ", "
                + ex.getMessage());
        return Collections.<String, Object>singletonMap("error",
                "Could not fetch user details");
    }
}
}
