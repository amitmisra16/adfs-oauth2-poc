package com.example.demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SimpleApplication extends GlobalMethodSecurityConfiguration {

    private static Logger LOGGER = LoggerFactory.getLogger(SimpleApplication.class);

    @Autowired
  private ResourceServerProperties sso;

    @Primary
	@Bean("userInfoTokenServices")
	public ResourceServerTokenServices userInfoTokenServices() {
	    return new AdfsUserInfoTokenServices("https://adfs1.crosisdev.com/adfs/oauth2/token", "914bf0c5-cdd0-4b70-b188-f3682fec920f");
	}

    /*@Primary
    @Bean
    public RemoteTokenServices tokenServices() {
        RemoteTokenServices tokenService = new RemoteTokenServices();
        tokenService.setCheckTokenEndpointUrl("https://adfs1.crosisdev.com/adfs/oauth2/token");
        tokenService.setClientId("914bf0c5-cdd0-4b70-b188-f3682fec920f");
        tokenService.setClientSecret("F4aZJptMfIaYXlFgcNr-J6rnCMbiPhxn9BuJ6nqV");
        return tokenService;
    }*/

    @Override
    protected MethodSecurityExpressionHandler createExpressionHandler() {
        return new OAuth2MethodSecurityExpressionHandler();
    }

    @PreAuthorize("#oauth2.hasScope('read')")
  @RequestMapping("/hello")
  public String sayHello(String userName) {

        return "{\"message\": \"Hello World\"}";
  }

	public static void main(String[] args) {
		SpringApplication.run(SimpleApplication.class, args);
	}

}
