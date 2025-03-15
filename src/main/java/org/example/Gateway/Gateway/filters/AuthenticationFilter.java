package org.example.Gateway.Gateway.filters;

import org.example.Gateway.Gateway.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

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
                throw new RuntimeException("Missing authorization cookie");
            }

            String token = request.getCookies().getFirst("jwtAuth").getValue();

            try {
                jwtUtil.validateToken(token);

                String userRole = jwtUtil.getRoles(token);

                List<String> requiredRoles = validator.getRequiredRoles(path);
                
                if (!requiredRoles.isEmpty()) {
                    boolean hasAccess = requiredRoles.contains(userRole);
                    if (!hasAccess) {
                        throw new RuntimeException("Access denied");
                    }
                }

            } catch (Exception e) {
                System.out.println("Invalid access...! REASON: " + e);
                throw new RuntimeException("Unauthorized access to application");
            }

            return chain.filter(exchange);
        });
    }

    public static class Config {}
}