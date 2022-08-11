package br.com.alura.forum.config

import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.config.http.UserDetailsServiceFactoryBean
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder

@Configuration
@EnableWebSecurity
class SecurityConfiguration(
    private val userDetailsService: UserDetailsService
)
    : WebSecurityConfigurerAdapter() {
    // Autorizar qualquer requisição sem guardar estado da configuracao o form login desabilitado e o usuario passar pelo postman ou
    // outro meio
    override fun configure(http: HttpSecurity?){
        http?.authorizeRequests()?.
        anyRequest()?.
        authenticated()?.
        and()?.
        sessionManagement()?.sessionCreationPolicy(SessionCreationPolicy.STATELESS)?.
        and()?.
        httpBasic()?.
        disable()?.
        httpBasic()
    }

    fun bCryptPasswordEncoder(): BCryptPasswordEncoder {
        return BCryptPasswordEncoder()
    }
    override fun configure(auth: AuthenticationManagerBuilder?) {
        auth?.userDetailsService(userDetailsService)?.passwordEncoder(bCryptPasswordEncoder())
    }

}