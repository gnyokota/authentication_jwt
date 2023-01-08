package com.authentication.jwt.model

import javax.validation.constraints.NotNull
import javax.validation.constraints.Size

class UserRequest(
    @field:NotNull
    val email: String,
    @field:Size(min=6)
    val password: String
)