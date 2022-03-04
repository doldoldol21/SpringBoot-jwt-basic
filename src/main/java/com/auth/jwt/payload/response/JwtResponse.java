package com.auth.jwt.payload.response;

import java.util.List;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class JwtResponse {

    private String accessToken;

    @Builder.Default
    private String type = "Bearer";

    private String refreshToken;
    private Long id;
    private String username;
    private List<String> roles;
}
