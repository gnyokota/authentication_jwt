package com.authentication.jwt.model

import javax.persistence.Entity
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id

@Entity
data class Role(
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    var id: Long?,
    val name: ERole,
    val description: String
)