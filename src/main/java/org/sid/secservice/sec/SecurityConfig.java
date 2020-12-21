package org.sid.secservice.sec;

import org.sid.secservice.sec.filters.JwtAuthenticationFilter;
import org.sid.secservice.sec.filters.JwtAutorizationFilter;
import org.sid.secservice.sec.service.AccountService;
import org.sid.secservice.sec.service.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private UserDetailsServiceImpl userDetailsService;
    private AccountService accountService;

    public SecurityConfig(UserDetailsServiceImpl userDetailsService, AccountService accountService) {
        this.userDetailsService = userDetailsService;
        this.accountService = accountService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //FRF
        http.csrf().disable();
        //sans utilisation des sessions cote serveur
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        //desactiver la protection contre les frames
        http.headers().frameOptions().disable();
        //demande authentification sauf h2
        http.authorizeRequests().antMatchers("/h2-console/**","/refreshToken/**").permitAll();
        //http.formLogin();
        http.authorizeRequests().anyRequest().authenticated();
        http.addFilter(new JwtAuthenticationFilter(authenticationManagerBean()));
        //
        http.addFilterBefore(new JwtAutorizationFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
