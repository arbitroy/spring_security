package com.company.spring_security.security;

import com.company.spring_security.auth.ApplicationUserService;
import com.company.spring_security.jwt.JwtUsernameAndPasswordAuthentificationFilter;
import com.company.spring_security.jwt.TokenVerifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;


import static com.company.spring_security.security.ApplicationUserRole.*;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
    public class ApplicationSecurityConfig implements ApplicationSecurityConfiguration {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    private final AuthenticationConfiguration configuration;
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService, AuthenticationConfiguration configuration) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.configuration = configuration;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthentificationFilter(authenticationManager(configuration)))
                .addFilterAfter(new TokenVerifier(), JwtUsernameAndPasswordAuthentificationFilter.class)
                .authorizeHttpRequests((authz) -> authz

                        .antMatchers("/", "index", "/css/*", "/js/*")
                        .permitAll()
                        .antMatchers("/api/**").hasRole(STUDENT.name())
                        .anyRequest()
                        .authenticated()
                );

        return http.build();
    }
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth.authenticationProvider(daoAuthenticationProvider());
    }
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

}
