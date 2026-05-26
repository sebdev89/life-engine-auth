package com.devito.lifeengine.auth.api;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Request body for non-production self-registration only. */
public record LocalDevRegisterRequest(
        @NotBlank @Email @Size(max = 320) String email, @NotBlank @Size(min = 12, max = 128) String password) {}
