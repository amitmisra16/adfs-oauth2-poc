package com.example.demo;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Arrays;
import java.util.Map;

import javax.servlet.Filter;

import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.PrincipalExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.OAuth2AccessTokenSupport;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.View;
import org.springframework.web.servlet.view.RedirectView;

@SpringBootApplication
@EnableOAuth2Sso
@RestController
//@EnableResourceServer
public class SimpleApplication extends WebSecurityConfigurerAdapter {

    private static Logger LOGGER = LoggerFactory.getLogger(SimpleApplication.class);

    @Autowired
  private ResourceServerProperties sso;

//    @Primary
//	@Bean("userInfoTokenServices")
//	public ResourceServerTokenServices userInfoTokenServices() {
//	    return new AdfsUserInfoTokenServices(sso.getUserInfoUri(), sso.getClientId());
//	}

@Override
  protected void configure(HttpSecurity http) throws Exception {
    http
      .antMatcher("/**")
      .authorizeRequests()
        .antMatchers("/", "/login**", "/webjars/**")
        .permitAll()
      .anyRequest()
        .authenticated()
            .and().addFilterBefore(oauthFilter(), BasicAuthenticationFilter.class);
  }

    @Autowired
    OAuth2ClientContext oauth2ClientContext;

    @Autowired
    OAuth2ProtectedResourceDetails resource;

    @Autowired
    ResourceServerProperties resourceServer;

    @Autowired
    RequestHelper requestHelper;
// https://stackoverflow.com/questions/37854133/how-to-set-proxy-on-spring-oauth2-oauth2accesstoken-request-or-how-to-override-o

    private Filter oauthFilter() throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {
        OAuth2ClientAuthenticationProcessingFilter oauthFilter = new OAuth2ClientAuthenticationProcessingFilter("/login");
        // Set request factory for '/userinfo'
        LOGGER.info("token info uri {}, clientId {}", sso.getTokenInfoUri(), sso.getClientId());
        ResourceServerTokenServices userInfoTokenServices = new AdfsUserInfoTokenServices(sso.getTokenInfoUri(), sso.getClientId());
        oauthFilter.setTokenServices(userInfoTokenServices);

        OAuth2RestTemplate oauthTemplate = new OAuth2RestTemplate(resource, oauth2ClientContext);
        OAuth2AccessTokenSupport authAccessProvider = new AuthorizationCodeAccessTokenProvider();
        // Set request factory for '/oauth/token'
        authAccessProvider.setRequestFactory(requestHelper.getRequestFactory());
        AccessTokenProvider accessTokenProvider = new AccessTokenProviderChain(Arrays.<AccessTokenProvider> asList(
                (AuthorizationCodeAccessTokenProvider)authAccessProvider));
        oauthTemplate.setAccessTokenProvider(accessTokenProvider);
        oauthTemplate.setRequestFactory(requestHelper.getRequestFactory());
        oauthFilter.setRestTemplate(oauthTemplate);
        // UserInfoTokenServices userInfoTokenService = new UserInfoTokenServices(resourceServer.getUserInfoUri(), resource.getClientId());
        // userInfoTokenService.setRestTemplate(oauthTemplate);
        // oauthFilter.setTokenServices(userInfoTokenService);
        return oauthFilter;
    }

	@RequestMapping("/user")
  public Principal user(Principal principal) {

    return principal;
  }

  @RequestMapping("/getAToken")
  public View getAToken(Model model) {
        return new RedirectView("index.html");
  }

	public static void main(String[] args) {
		SpringApplication.run(SimpleApplication.class, args);
	}


	private static class AdfsPrincipalExtractor implements PrincipalExtractor {

        @Override
        public Object extractPrincipal(Map<String, Object> map) {
           String[] principalKeys = {"upn"};

           return map.keySet().stream().filter(key -> ArrayUtils.contains(principalKeys, key)).map(key -> map.get(key)).findAny().get();
        }
    }
}
