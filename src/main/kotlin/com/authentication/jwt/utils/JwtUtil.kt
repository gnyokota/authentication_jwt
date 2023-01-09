package com.authentication.jwt.utils

import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import java.util.Date
import org.springframework.beans.factory.annotation.Value
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.stereotype.Component


// Method to generate jwt token
// Method to validate jwt token
// Method to check expiration date from jwt token
@Component
class JwtUtil {

    @Value("\${jwt.secret}")
    private lateinit var secret: String

    @Value("\${jwt.expiration.ms}")
    private lateinit var expiration: String

    fun extractUsername(token: String): String {
        return extractClaim(token, Claims::getSubject)
    }

    fun extractExpiration(token: String): Date {
        return extractClaim(token, Claims::getExpiration)
    }

    fun <T> extractClaim(token: String, claimsResolver: (Claims) -> T): T {
        val claims = extractAllClaims(token)
        return claimsResolver(claims)
    }

    fun extractAllClaims(token: String): Claims {
        return Jwts.parserBuilder().setSigningKey(secret).build().parseClaimsJws(token).body
    }

    fun isTokenExpired(token: String): Boolean {
        return extractExpiration(token).before(Date())
    }

    fun generateToken(userDetails: UserDetails): String {
        val claims = HashMap<String, Any>()
        return createToken(claims, userDetails.username)
    }

    fun createToken(claims: Map<String, Any>, subject: String): String {
        return Jwts.builder().setClaims(claims)
            .setSubject(subject).setIssuedAt(Date(System.currentTimeMillis()))
            .setExpiration(Date(System.currentTimeMillis() + expiration.toLong()))
            .signWith(SignatureAlgorithm.HS512, secret).compact()
    }

}