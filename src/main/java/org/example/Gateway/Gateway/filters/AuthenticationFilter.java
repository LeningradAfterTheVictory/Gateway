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

            if (!validator.isSecured.test(request)) {
                return chain.filter(exchange);
            }

            if (!request.getCookies().containsKey("jwtAuth")) {
                return onError(exchange, "Missing authorization cookie", HttpStatus.UNAUTHORIZED);
            }

            String token = request.getCookies().getFirst("jwtAuth").getValue();

            try {
                jwtUtil.validateToken(token);

                String userRole = jwtUtil.getRoles(token);

                List<String> requiredRoles = validator.getRequiredRoles(path);

                if (!requiredRoles.isEmpty()) {
                    boolean hasAccess = requiredRoles.contains(userRole);
                    if (!hasAccess) {
                        return onError(exchange, "Access denied", HttpStatus.FORBIDDEN);
                    }
                }

            } catch (Exception e) {
                System.out.println("Invalid access...! REASON: " + e);
                return onError(exchange, "Token is invalid", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
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