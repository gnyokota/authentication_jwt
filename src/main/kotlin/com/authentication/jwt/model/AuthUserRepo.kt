package com.authentication.jwt.model

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface AuthUserRepo : JpaRepository<AuthUser, Long> {
    fun findByUsername(username: String): AuthUser?
    fun findByEmail(email: String): AuthUser?
}