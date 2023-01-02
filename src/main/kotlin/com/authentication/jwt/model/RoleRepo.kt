package com.authentication.jwt.model

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository

@Repository
interface RoleRepo: JpaRepository<Role,Long> {
    fun findByName(name:ERole): Role?
}