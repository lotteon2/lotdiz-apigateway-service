package com.lotdiz.apigatewayservice.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;

@Slf4j
@Component
public class OptionalAuthorizationHeaderFilter
    extends AbstractGatewayFilterFactory<OptionalAuthorizationHeaderFilter.Config> {

  @Value("${jwt.secret}")
  private String secret;

  public OptionalAuthorizationHeaderFilter() {
    super(Config.class);
  }

  @Override
  public GatewayFilter apply(Config config) {
    return ((exchange, chain) -> {
      ServerHttpRequest request = exchange.getRequest();
      if (request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
        if (request.getHeaders().get(HttpHeaders.AUTHORIZATION) == null) {
          return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
        }
        String jwtHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
        String jwt = jwtHeader.replace("Bearer ", "");

        byte[] keyBytes = Decoders.BASE64.decode(secret);
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);

        Claims claims = checkValid(jwt, key); // 토큰 유효성 검사

        String username = claims.get("username", String.class);

        if (username == null) {
          return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
        }

        // Token 정보를 까서 memberId를 header에 저장
        String memberId = claims.get("memberId", String.class);
        exchange.getRequest().mutate().header("memberId", memberId).build();

        return chain.filter(exchange);
      } else {
        return chain.filter(exchange);
      }
    });
  }

  private Claims checkValid(String jwt, SecretKey key) {
    try {
      return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(jwt).getBody();
    } catch (IllegalArgumentException e) {
      throw new RuntimeException("잘못된 JWT 토큰입니다.");
    } catch (ExpiredJwtException e) {
      throw new RuntimeException("만료된 JWT 토큰입니다.");
    } catch (SignatureException e) {
      throw new RuntimeException("잘못된 JWT 서명입니다.");
    }
  }

  private Mono<Void> onError(ServerWebExchange exchange, String error, HttpStatus httpStatus) {
    ServerHttpResponse response = exchange.getResponse();
    response.setStatusCode(httpStatus);

    log.error(error);

    return response.setComplete();
  }

  @Data
  public static class Config {}
}
