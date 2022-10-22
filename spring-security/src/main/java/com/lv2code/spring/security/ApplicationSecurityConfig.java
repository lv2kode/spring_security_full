package com.lv2code.spring.security;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.lv2code.spring.security.service.ApplicationUserService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final PasswordEncoder passwordEncoder;
	
	private final ApplicationUserService applicationUserService;
	
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
		this.passwordEncoder = passwordEncoder;
		this.applicationUserService = applicationUserService;
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		// when to use csrf protection?
		// our recommendation is to use csrf protection for any request that could be processed
		// by a browser by normal users. If you are only creating a service that is used by non-browser clients,
		// you will likely want to disable CSRF protection.
//		.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//		.and()
		.csrf().disable()
		.authorizeRequests()
		.antMatchers("/", "index", "/css/*", "/js/*").permitAll()
		.antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
		//Instead of these 4 below code snippet we can use directly method level security
		//.antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
		//.antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
		//.antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
		//.antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())
		.anyRequest()
		.authenticated()
		.and()
		// this is basic auth code
		// .httpBasic();
		
		// this is form based auth code
		.formLogin()
			.loginPage("/login")
			.permitAll()
			.defaultSuccessUrl("/courses", true)
			// customer username and password form input tags names
			.passwordParameter("password")
			.usernameParameter("username")
		
		// Remember Me 
		.and()
		.rememberMe() // defaults to 2 weeks
			.tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
			.key("somethingverysecured")
			// Remember me customer form input tag name
			.rememberMeParameter("remember-me")
			
		// Custom logout configuration
		.and()
		.logout()
			.logoutUrl("/logout")
			// CSRF is disabled because of that we should use the below line of code and it will be any http method
			// if in case csrf is enabled then we should use post method only
			.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
			.clearAuthentication(true)
			.invalidateHttpSession(true)
			.deleteCookies("JSESSIONID", "remember-me")
			.logoutSuccessUrl("/login")
		;		
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
	}
	
	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		
		return provider;
	}
	
//	@Override
//	@Bean
//	protected UserDetailsService userDetailsService() {
//		UserDetails annaSmithUser = User.builder()
//				.username("annasmith")
//				.password(passwordEncoder.encode("password"))
////				.roles(ApplicationUserRole.STUDENT.name()) // ROLE_STUDENT
//				.authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
//				.build();
//		
//		UserDetails lindaUser = User.builder()
//				.username("linda")
//				.password(passwordEncoder.encode("password123"))
////				.roles(ApplicationUserRole.ADMIN.name()) // ROLE_ADMIN
//				.authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
//				.build();
//		
//		UserDetails tomUser = User.builder()
//				.username("tom")
//				.password(passwordEncoder.encode("password123"))
////				.roles(ApplicationUserRole.ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
//				.authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
//				.build();
//		
//		return new InMemoryUserDetailsManager(annaSmithUser, lindaUser, tomUser);
//	}
}
