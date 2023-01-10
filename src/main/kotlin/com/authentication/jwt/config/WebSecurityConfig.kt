package com.authentication.jwt.config

import com.authentication.jwt.service.CustomUserDetailsService
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
class WebSecurityConfig(
    val customUserDetailsService: CustomUserDetailsService,
    val jwtAuthenticationFilter: JwtAuthenticationFilter,
    val jwtAuthenticationEntryPoint: JwtAuthenticationEntryPoint
) : WebSecurityConfigurerAdapter() {
    //control what will be the authentication mode and how it works
    override fun configure(auth: AuthenticationManagerBuilder) {
        auth.userDetailsService(customUserDetailsService)
    }

    //control which endpoints are permitted
    override fun configure(http: HttpSecurity) {
        http.csrf().disable().cors().disable()
            .authorizeRequests()
            .antMatchers("/api/v1/login").permitAll()
            .antMatchers("/api/v1/register").permitAll()
            .antMatchers("/api/v1/remove/user").access("hasRole('ROLE_ADMIN')")
            .antMatchers("/api/v1/remove/role").access("hasRole('ROLE_ADMIN')")
            .antMatchers("/api/v1/user/role").access("hasRole('ROLE_ADMIN')")
            .anyRequest().authenticated()
            .and()
            .exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint)
            .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //server does not
        //have to manage the session

        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter::class.java)
    }

    @Bean
    fun passEncoder(): PasswordEncoder {
        return BCryptPasswordEncoder()
    }

    @Bean
    override fun authenticationManagerBean(): AuthenticationManager {
        return super.authenticationManagerBean()
    }

}