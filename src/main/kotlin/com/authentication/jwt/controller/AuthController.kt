package com.authentication.jwt.controller

import com.authentication.jwt.model.AuthUser
import com.authentication.jwt.model.AuthUserRepo
import com.authentication.jwt.model.ERole
import com.authentication.jwt.model.Role
import com.authentication.jwt.model.RoleRepo
import com.authentication.jwt.model.RoleRequest
import com.authentication.jwt.model.UserRequest
import org.springframework.http.ResponseEntity
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("api/v1")
class AuthController(val roleRepo: RoleRepo, val authUserRepo: AuthUserRepo, val passwordEncoder: PasswordEncoder) {

    @GetMapping("/user")
    fun getUsers(): ResponseEntity<List<AuthUser>> {
        return ResponseEntity.ok(authUserRepo.findAll())
    }

    @PostMapping("/user")
    fun registerUser(@RequestBody userReq: UserRequest): ResponseEntity<*> {
        val foundUser = authUserRepo.findByEmail(userReq.email)
        if (foundUser != null) {
            return ResponseEntity.badRequest().body("Email ${userReq.email} is already taken")
        }
        val roleList = mutableListOf(roleRepo.findByName(ERole.USER) as Role)
        val newUser = AuthUser(
            null, userReq.username,
            userReq.email,
            passwordEncoder.encode(userReq.password),
            roleList
        )
        return ResponseEntity.ok(authUserRepo.save(newUser))
    }

    @GetMapping("/role")
    fun getRoles(): ResponseEntity<List<Role>> {
        return ResponseEntity.ok(roleRepo.findAll())
    }

    @PostMapping("/role")
    fun saveRole(@RequestBody roleReq: RoleRequest): ResponseEntity<*> {
        val foundRole = roleRepo.findByName(ERole.valueOf(roleReq.name))
        if (foundRole != null) {
            return ResponseEntity.badRequest().body("Role already exists")
        }
        val newRole = Role(null, ERole.valueOf(roleReq.name), roleReq.description)
        return ResponseEntity.ok(roleRepo.save(newRole))
    }
}