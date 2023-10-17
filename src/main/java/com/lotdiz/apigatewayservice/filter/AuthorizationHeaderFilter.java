package com.lotdiz.apigatewayservice.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import lombok.Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.PathContainer;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;


import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

@Component
public class AuthorizationHeaderFilter
    extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
  private final Logger logger = LoggerFactory.getLogger(AuthorizationHeaderFilter.class);

  private final Environment env;

  public AuthorizationHeaderFilter(Environment env) {
    super(Config.class);
    this.env = env;
  }

  @Override
  public GatewayFilter apply(Config config) {
    return ((exchange, chain) -> {
      logger.info("AuthorizationHeaderFilter here");

      ServerHttpRequest request = exchange.getRequest();

      if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
        return onError(exchange, "no authorization header", HttpStatus.UNAUTHORIZED);
      }

      String jwtHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
      String jwt = jwtHeader.replace("Bearer ", "");

      String secret = env.getProperty("jwt.secret");
      byte[] keyBytes = Decoders.BASE64.decode(secret);
      SecretKey key = Keys.hmacShaKeyFor(keyBytes);
      Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwt).getBody();
      String username = claims.get("username", String.class);

      if (username == null) {
        return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
      }
      // Token 정보를 까서 memberId를 header에 저장
      String memberId = claims.get("memberId", String.class);
      logger.info("memberId: " + memberId);

      HttpHeaders originHeaders = request.getHeaders();
      // 새로운 HttpHeaders 객체 생성
      HttpHeaders newHeaders = new HttpHeaders();

      newHeaders.set("memberId", memberId);
      newHeaders.addAll(originHeaders);

      ServerHttpRequest modifiedRequest = request.mutate().headers((h) -> h.addAll(newHeaders)).build();

      ServerWebExchange modifiedExchange = exchange.mutate().request(modifiedRequest).build();

      // if path = /admin-service/** -> Role 확인 (admin인지)
      PathPatternParser pathPatternParser = new PathPatternParser();
      PathPattern pathPattern = pathPatternParser.parse("/admin-service/**");
      PathContainer pathContainer =
          PathContainer.parsePath(request.getPath().pathWithinApplication().value());
      if (pathPattern.matches(pathContainer)) {
        String auth = claims.get("auth", String.class);
        if (!auth.equals("ADMIN")) { // admin 이 아니면 403
          return onError(exchange, "Not Admin", HttpStatus.FORBIDDEN);
        }
      }

      logger.info("AuthorizationHeader Filter End");
      return chain.filter(modifiedExchange);
    });
  }


  private Mono<Void> onError(ServerWebExchange exchange, String error, HttpStatus httpStatus) {
    ServerHttpResponse response = exchange.getResponse();
    response.setStatusCode(httpStatus);

    logger.error(error);

    return response.setComplete();
  }

  @Data
  public static class Config {}
}