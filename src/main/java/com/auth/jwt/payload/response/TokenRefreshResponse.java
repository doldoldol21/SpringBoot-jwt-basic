package com.auth.jwt.payload.response;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class TokenRefreshResponse {

    private String accessToken;
    private String refreshToken;

    @Builder.Default
    private String tokenType = "Bearer";
}
