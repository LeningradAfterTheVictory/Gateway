package org.example.Gateway.Gateway.filters;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.*;
import java.util.function.Predicate;

@Component
public class RouteValidator {

    public static final List<String> openApiEndpoints = List.of(
            "/api/authentication/**",

            // {id:\d+}
            "/api/user/getUser/**",

            "/api/favorites/routes/**",
            "/api/favorites/buildings/**",

            "/api/files/download",
            "/api/files/list",

            "/api/attractions/filter",
            "/api/attractions/attraction/**",
            "/api/attractions/**/routes",
            "/api/attractions/get-all",

            "/api/categories/category/**",
            "/api/categories/get-all",

            "/api/routes/route/**",
            "/api/routes/get-all",
            "/api/routes/routeByCategory/**",
            "/api/routes/**/computed",
            "/api/routes/computeWalkingRoute",
            "/api/routes/computeWalkingRouteList"
    );

    // Маппинг маршрутов и требуемых ролей
    private static final Map<String, List<String>> roleRequirements = Map.of(
            "/request/**", List.of("USER", "ADMIN"),
            "/files/**", List.of("ADMIN"),
            "/api/attractions/**", List.of("USER", "ADMIN"),
            "/api/routes/**", List.of("USER", "ADMIN"),
            "/api/categories/**", List.of("USER", "ADMIN"),
            "/api/user/**", List.of("USER", "ADMIN"),
            "/api/favorites/**", List.of("USER", "ADMIN")
    );

    // Предикат для проверки защищенности маршрута
    public Predicate<ServerHttpRequest> isSecured =
            request -> {
                String path = request.getURI().getPath();
                boolean isOpen = openApiEndpoints.stream()
                        .anyMatch(uri -> {
                            boolean match = new AntPathMatcher().match(uri, path);
                            if (match) {
                                System.out.println("Matched open endpoint: " + uri + " with path: " + path);
                            }
                            return match;
                        });
                return !isOpen;
            };

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
