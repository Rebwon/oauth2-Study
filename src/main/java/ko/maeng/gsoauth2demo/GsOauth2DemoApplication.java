package ko.maeng.gsoauth2demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@SpringBootApplication
@EnableOAuth2Sso
@RestController
public class GsOauth2DemoApplication extends WebSecurityConfigurerAdapter {

	//@EnableOAuth2Sso(OAuth2를 Enable하는데, Sso(Single Sign On)로 한다.
	//Single Sign On이란? : 하나의 아이디 및 패스워드를 통해 여러 시스템에 접근할 수 있는 통합 로그인(인증) 솔루션

	@RequestMapping("/user")
	public Principal user(Principal principal){
		return principal;
	}

	public static void main(String[] args) {
		SpringApplication.run(GsOauth2DemoApplication.class, args);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.antMatcher("/**")
			.authorizeRequests()
				.antMatchers("/", "/login**", "/webjars/**", "/error**")
				.permitAll()
			.anyRequest()
				.authenticated();
	}
}
