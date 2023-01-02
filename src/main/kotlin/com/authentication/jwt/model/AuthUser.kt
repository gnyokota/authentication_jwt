package com.authentication.jwt.model

import javax.persistence.Entity
import javax.persistence.FetchType
import javax.persistence.GeneratedValue
import javax.persistence.GenerationType
import javax.persistence.Id
import javax.persistence.JoinColumn
import javax.persistence.JoinTable
import javax.persistence.ManyToMany
import javax.validation.constraints.Email
import javax.validation.constraints.Size

@Entity
data class AuthUser(
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    var id:Long?,
    @field:Size(min=6)
    val username:String,
    @field:Email
    val email:String,
    @field:Size(min=6)
    val password:String,
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "user_to_role",
        joinColumns = [JoinColumn(name = "user_id")],
        inverseJoinColumns = [JoinColumn(name = "role_id")])
    val roles: MutableList<Role>
)
