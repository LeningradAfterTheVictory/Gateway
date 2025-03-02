package org.example.Gateway.Gateway.filters;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.*;
import java.util.function.Predicate;

@Component
public class RouteValidator {

    // Список открытых эндпоинтов (не требуют аутентификации)
    public static final List<String> openApiEndpoints = List.of(
            "/api/authentication/**"
    );

    // Маппинг маршрутов и требуемых ролей
    private static final Map<String, List<String>> roleRequirements = Map.of(
            "/request/**", List.of("USER", "ADMIN"),
            "/files/**", List.of("USER", "ADMIN"),
            "/api/attractions/**", List.of("USER", "ADMIN"),
            "/api/routes/**", List.of("USER", "ADMIN"),
            "/api/categories/**", List.of("USER", "ADMIN"),
            "/api/user/**", List.of("USER", "ADMIN")
    );

    // Предикат для проверки защищенности маршрута
    public Predicate<ServerHttpRequest> isSecured =
            request -> openApiEndpoints.stream()
                    .noneMatch(uri -> new AntPathMatcher().match(uri, request.getURI().getPath()));

    // Метод для получения требуемых ролей по URL
    public List<String> getRequiredRoles(String path) {
        AntPathMatcher pathMatcher = new AntPathMatcher();
        for (Map.Entry<String, List<String>> entry : roleRequirements.entrySet()) {
            if (pathMatcher.match(entry.getKey(), path)) {
                return entry.getValue();
            }
        }
        return Collections.emptyList(); // Если роли не требуются
    }
}