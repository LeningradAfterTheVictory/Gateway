package org.example.Gateway.Gateway.filters;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import java.util.*;
import java.util.function.Predicate;

@Component
public class RouteValidator {

    public static final List<String> openApiEndpoints = List.of(
            "/authentication/register",
            "/authentication/token",

            // {id:\d+}
            "/user/getUser/**",

            "/favorites/routes",
            "/favorites/buildings",

            "/files/download",
            "/files/list",

            "/attractions/filter",
            "/attractions/attraction/**",
            "/attractions/**/routes",
            "/attractions/get-all",

            "/categories/category/**",
            "/categories/get-all",

            "/routes/route/**",
            "/routes/get-all",
            "/routes/routeByCategory/**",
            "/routes/**/computed",
            "/routes/computeWalkingRoute",
            "/routes/computeWalkingRoutesList"
    );

    // Маппинг маршрутов и требуемых ролей
    private static final Map<String, List<String>> roleRequirements = Map.of(
            "/request/**", List.of("USER", "ADMIN"),
            "/files/**", List.of("ADMIN"),
            "/attractions/**", List.of("USER", "ADMIN"),
            "/routes/**", List.of("USER", "ADMIN"),
            "/categories/**", List.of("USER", "ADMIN"),
            "/user/**", List.of("USER", "ADMIN"),
            "/favorites/**", List.of("USER", "ADMIN"),
            "/authentication/**", List.of("USER", "ADMIN")
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
