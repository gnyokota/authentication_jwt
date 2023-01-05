package com.authentication.jwt.config

import com.authentication.jwt.service.CustomUserDetailsService
import com.authentication.jwt.utils.JwtUtil
import javax.servlet.FilterChain
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

@Component
class JwtAuthenticationFilter(
    val customUserDetailsService: CustomUserDetailsService,
    val jwtUtil: JwtUtil
) : OncePerRequestFilter() {

    val loggerFactory: Logger = LoggerFactory.getLogger(JwtAuthenticationFilter::class.java)

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val bearerToken = request.getHeader("Authorization")
            if (bearerToken != null && bearerToken.startsWith("Bearer ")
            ) {
                val token = bearerToken.substring(7)
                val email = jwtUtil.extractUsername(token)
                val userDetails = customUserDetailsService.loadUserByUsername(email)

                if (SecurityContextHolder.getContext().authentication == null) {

                    val usernamePasswordAuthenticationToken = UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.authorities
                    )
                    usernamePasswordAuthenticationToken
                        .details = WebAuthenticationDetailsSource().buildDetails(request)
                    SecurityContextHolder.getContext().authentication = usernamePasswordAuthenticationToken

                } else {
                    loggerFactory.error("The token is invalid!")
                    throw Exception("The has token invalid format!")
                }

                try {
                } catch (exc: Exception) {
                    throw Exception(exc.message)
                }
            } else {
                loggerFactory.error("The token is invalid!")
            }

            filterChain.doFilter(request, response)
        }
}