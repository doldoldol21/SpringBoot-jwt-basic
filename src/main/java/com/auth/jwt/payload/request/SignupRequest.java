package com.auth.jwt.payload.request;

import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.hibernate.validator.constraints.Length;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class SignupRequest {

    @NonNull
    @Length(min = 3, max = 20)
    private String username;

    @NonNull
    @Length(min = 6, max = 40)
    private String password;

    private Set<String> role;
}
