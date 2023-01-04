package com.authentication.jwt.controller

import com.authentication.jwt.model.AuthUser
import com.authentication.jwt.model.AuthUserRepo
import com.authentication.jwt.model.ERole
import com.authentication.jwt.model.JwtResponse
import com.authentication.jwt.model.Role
import com.authentication.jwt.model.RoleRepo
import com.authentication.jwt.model.RoleRequest
import com.authentication.jwt.model.UserRequest
import com.authentication.jwt.service.CustomUserDetailsService
import com.authentication.jwt.utils.JwtUtil
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("api/v1")
class AuthController(
    val roleRepo: RoleRepo,
    val authUserRepo: AuthUserRepo,
    val passwordEncoder: PasswordEncoder,
    val jwtUtil: JwtUtil,
    val customUserDetailsService: CustomUserDetailsService,
    val authenticationManager: AuthenticationManager
) {

    @GetMapping("/user")
    fun getUsers(): ResponseEntity<List<AuthUser>> {
        return ResponseEntity.ok(authUserRepo.findAll())
    }

    @PostMapping("/register")
    fun registerUser(@RequestBody userReq: UserRequest): ResponseEntity<*> {
        val foundUser = authUserRepo.findByEmail(userReq.email)
        if (foundUser != null) {
            return ResponseEntity.badRequest().body("Email ${userReq.email} is already taken")
        }
        val roleList = mutableListOf(roleRepo.findByName(ERole.USER) as Role)
        val newUser = AuthUser(
            null,
            userReq.email,
            passwordEncoder.encode(userReq.password),
            roleList
        )
        return ResponseEntity.ok(authUserRepo.save(newUser))
    }

    @PostMapping("/login")
    fun loginUser(@RequestBody userReq: UserRequest): ResponseEntity<*> {
        val foundUser = authUserRepo.findByEmail(userReq.email)
        if (foundUser != null) {
            if (matchPassword(userReq.password, foundUser.password)) {
                val token = UsernamePasswordAuthenticationToken(userReq.email, userReq.password)
                authenticationManager.authenticate(token)
                val userDetails = customUserDetailsService.loadUserByUsername(userReq.email)
                val generatedToken = jwtUtil.generateToken(userDetails)
                return ResponseEntity.ok(JwtResponse(generatedToken))
            }
        }
        return ResponseEntity.badRequest().body("Password/Email is incorrect")
    }

    @DeleteMapping("/user")
    fun deleteUser(@RequestBody email: String): ResponseEntity<*> {
        val foundUser = authUserRepo.findByEmail(email)
            ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User with email:$email not found")

        foundUser.id?.let { authUserRepo.deleteById(it) }
        return ResponseEntity.ok("User successfully deleted!")
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

    @DeleteMapping("/role")
    fun deleteRole(@RequestBody roleName: String): ResponseEntity<*> {
        val roleUser = roleRepo.findByName(ERole.valueOf(roleName))
            ?: return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Role with name:$roleName not found")

        roleUser.id?.let { authUserRepo.deleteById(it) }
        return ResponseEntity.ok("Role successfully deleted!")
    }

    private fun matchPassword( loginPass: String, storedPass: String): Boolean {
        return passwordEncoder.matches(loginPass, storedPass)
    }
}