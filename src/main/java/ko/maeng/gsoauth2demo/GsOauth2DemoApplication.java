package ko.maeng.gsoauth2demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.Filter;
import java.security.Principal;

@SpringBootApplication
@EnableOAuth2Client
@RestController
public class GsOauth2DemoApplication extends WebSecurityConfigurerAdapter {

	//@EnableOAuth2Sso(OAuth2를 Enable하는데, Sso(Single Sign On)로 한다.
	//Single Sign On이란? : 하나의 아이디 및 패스워드를 통해 여러 시스템에 접근할 수 있는 통합 로그인(인증) 솔루션

	//@EnableOAuth2Client : @EnableOAuth2Sso보다 낮은 레벨의 어노테이션이다.
	//더 낮은 레벨의 어노테이션으로 변경하는 이유는 커스터마이징과 수동설정때문.

	@Autowired
	OAuth2ClientContext oAuth2ClientContext;

	@RequestMapping("/user")
	public Principal user(Principal principal){
		return principal;
	}

	public static void main(String[] args) {
		SpringApplication.run(GsOauth2DemoApplication.class, args);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/webjars/**", "/error**").permitAll().anyRequest()
						.authenticated().and().exceptionHandling()
						.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/")).and().logout()
						.logoutSuccessUrl("/").permitAll().and().csrf()
						.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
						.addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
		// @formatter:on
	}

	//oauth2ClientFilterRegistration() 메서드를 빈으로 등록함으로써 앱에서 페이스북 리다이렉트를 명시적으로 지원하게 만들어줌.
	//이는 서블릿 Filter를 가진 Spring OAuth2에서 처리되어진다. 이 필터는 @EnableOAuth2Client 선언으로 Application Context에서 이미 사용이 가능하다.
	//다만, 이 필터를 엮어서 사용하려면 스프링부트 애플리케이션의 올바른 순서 안에서 호출해 주기만 하면 된다.
	//이것을 위해서 FilterRegistrationBean이 필요한 것이다.

	//이미 사용가능한 필터를 Autowired해두었고, 이 필터를 메인 스프링 시큐리티 필터가 불러지기 전에 호출되도록
	//충분히 낮은 순서로 등록을 해두었다. 이 방법으로 우리는 인증요청의 exception을 통해 리다이렉트를 처리할 수 있다.
	//이 단계까지의 수정을 통해 logout예제와 동일하게 동작하며, 다만 설정을 단계별로 쪼개서 스프링 부트가 해주는
	//마법과 같은 자동화는 더 이상 없다. (이는 단지 설정의 뼈대일 뿐이다.) 그리고 이것은 바로 사용가능하게 자동으로 제공되었던
	//기능을 확장하기 위한, 우리 자신의 생각과 비즈니스 요구사항을 추가하여 커스터마이징하기 위한 준비가 되는 것이다.

	@Bean
	public FilterRegistrationBean oauth2ClientFilterRegistration(
			OAuth2ClientContextFilter filter){
		FilterRegistrationBean registrationBean = new FilterRegistrationBean();
		registrationBean.setFilter(filter);
		registrationBean.setOrder(-100);
		return registrationBean;
	}

	private Filter ssoFilter(){
		OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter(
				"/login/facebook");
		OAuth2RestTemplate facebookTemplate = new OAuth2RestTemplate(facebook(), oAuth2ClientContext);
		facebookFilter.setRestTemplate(facebookTemplate);
		UserInfoTokenServices tokenServices = new UserInfoTokenServices(facebookResource().getUserInfoUri(),
				facebook().getClientId());
		tokenServices.setRestTemplate(facebookTemplate);
		facebookFilter.setTokenServices(tokenServices);
		return facebookFilter;
	}

	//facebook()과 facebookResource()라는 "정적인" 데이터 객체에 @ConfigurationProperties로 설정된 @Bean을 등록했다.
	//이것은 application.yml 설정의 접두어인 security.oauth2 대신 facebook으로 사용하는 약간의 새로운 포맷팅을 의미한다.

	@Bean
	@ConfigurationProperties("facebook.client")
	public AuthorizationCodeResourceDetails facebook(){
		return new AuthorizationCodeResourceDetails();
	}

	@Bean
	@ConfigurationProperties("facebook.resource")
	public ResourceServerProperties facebookResource(){
		return new ResourceServerProperties();
	}

}
