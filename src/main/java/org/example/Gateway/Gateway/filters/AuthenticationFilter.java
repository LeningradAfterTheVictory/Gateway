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

            // Пропустить проверку для открытых эндпоинтов
            if (!validator.isSecured.test(request)) {
                return chain.filter(exchange);
            }

            // Проверка наличия токена
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                throw new RuntimeException("Missing authorization header");
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            String token = (authHeader != null && authHeader.startsWith("Bearer "))
                    ? authHeader.substring(7)
                    : null;

            try {
                // Валидация токена
                jwtUtil.validateToken(token);

                // Извлечение ролей из токена
                String userRole = jwtUtil.getRoles(token);

                // Получение требуемых ролей для маршрута
                List<String> requiredRoles = validator.getRequiredRoles(path);

                // Проверка ролей
                if (!requiredRoles.isEmpty()) {
                    boolean hasAccess = requiredRoles.contains(userRole);
                    if (!hasAccess) {
                        throw new RuntimeException("Access denied");
                    }
                }

            } catch (Exception e) {
                System.out.println("invalid access...! REASON: " + e);
                throw new RuntimeException("un authorized access to application");
            }

            return chain.filter(exchange);
        });
    }

    public static class Config {}
}