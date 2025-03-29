package org.example.Gateway.Gateway.filters;

import org.example.Gateway.Gateway.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private RouteValidator validator;

    @Autowired
    private JwtUtil jwtUtil;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();

            ServerHttpRequest modifiedRequest = request.mutate()
                    .headers(headers -> {
                        if (request.getCookies().containsKey("jwtAuth")) {
                            String token = request.getCookies().getFirst("jwtAuth").getValue();
                            headers.add("Authorization", "Bearer " + token);
                        }
                    })
                    .build();
            ServerWebExchange modifiedExchange = exchange.mutate()
                    .request(modifiedRequest)
                    .build();

            if (!validator.isSecured.test(request)) {
                System.out.println("The path is open :)");
                return chain.filter(modifiedExchange);
            }

            if (!request.getCookies().containsKey("jwtAuth")) {
                System.out.println("No jwtAuth cookie found :(");
                return onError(modifiedExchange, "Missing authorization cookie", HttpStatus.UNAUTHORIZED);
            }

            String token = request.getCookies().getFirst("jwtAuth").getValue();

            try {
                jwtUtil.validateToken(token);

                String userRole = jwtUtil.getRoles(token);

                System.out.println("Found role: " + userRole);

                List<String> requiredRoles = validator.getRequiredRoles(path);

                if (!requiredRoles.isEmpty()) {
                    boolean hasAccess = requiredRoles.contains(userRole);
                    if (!hasAccess) {
                        return onError(modifiedExchange, "Access denied", HttpStatus.FORBIDDEN);
                    }
                }

            } catch (Exception e) {
                System.out.println("Invalid access...! REASON: " + e);
                return onError(modifiedExchange, "Token is invalid", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(modifiedExchange);
        });
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        response.getHeaders().add("Content-Type", "application/json");
        String errorMessage = "{\"error\": \"" + err + "\"}";
        return response.writeWith(Mono.just(response.bufferFactory().wrap(errorMessage.getBytes())));
    }

    public static class Config {}
}