package com.authentication.jwt.service

import com.authentication.jwt.model.AuthUserRepo
import java.util.stream.Collector
import java.util.stream.Collectors
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class CustomUserDetailsService(val authUserRepo: AuthUserRepo) : UserDetailsService {
    override fun loadUserByUsername(email: String): UserDetails {
        val user = authUserRepo.findByEmail(email)
        if (user !== null) {
            val authorities = ArrayList<SimpleGrantedAuthority>()
            user.roles.forEach { role -> authorities.add(SimpleGrantedAuthority(role.name.roleName)) }
            return User(user.email, user.password, authorities)
        } else {
            throw UsernameNotFoundException("User with email:$email does not exist!")
        }
    }
}