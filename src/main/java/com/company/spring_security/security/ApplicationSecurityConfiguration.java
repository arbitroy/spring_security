package com.company.spring_security.security;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;

public interface ApplicationSecurityConfiguration {
    void configure(AuthenticationManagerBuilder auth) throws Exception;
}
