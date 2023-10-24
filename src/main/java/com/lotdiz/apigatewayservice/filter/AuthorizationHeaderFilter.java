package com.lotdiz.apigatewayservice.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import javax.crypto.SecretKey;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
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

@Slf4j
@Component
public class AuthorizationHeaderFilter
    extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

  @Value("${jwt.secret}")
  private String secret;

  public AuthorizationHeaderFilter() {
    super(Config.class);
  }

  @Override
  public GatewayFilter apply(Config config) {
    return ((exchange, chain) -> {
      log.info("AuthorizationHeaderFilter here");

      ServerHttpRequest request = exchange.getRequest();

      PathPatternParser pathPatternParser = new PathPatternParser();
      PathPattern pathPattern = null;
      PathContainer pathContainer =
          PathContainer.parsePath(request.getPath().pathWithinApplication().value());
      log.info("path: " + request.getPath().pathWithinApplication().value());

      if(request.getPath().pathWithinApplication().value().equals("/member-service/api/sign-in")) {
        log.info("sign-in 요청");
        return chain.filter(exchange);
      }

      String username = null;
      if (request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) { // 로그인 중
        String jwtHeader = request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
        String jwt = jwtHeader.replace("Bearer ", "");

        byte[] keyBytes = Decoders.BASE64.decode(secret);
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);

        Claims claims = checkValid(jwt, key); // 토큰 유효성 검사

        username = claims.get("username", String.class);

        if (username == null) {
          return onError(exchange, "JWT token is not valid", HttpStatus.UNAUTHORIZED);
        }

        // Token 정보를 까서 memberId를 header에 저장
        String memberId = claims.get("memberId", String.class);
        log.info("memberId: " + memberId);
        exchange.getRequest().mutate().header("memberId", memberId).build();

        // if path = /admin-service/** -> Role 확인 (admin인지)
        pathPattern = pathPatternParser.parse("/api/admin/**");
        if (pathPattern.matches(pathContainer)) {
          String auth = claims.get("auth", String.class);
          if (!auth.equals("ADMIN")) { // admin 이 아니면 403
            return onError(exchange, "Not Admin", HttpStatus.FORBIDDEN);
          }
        }
      } else { // 비로그인 중
        // project는 비로그인이어도 갈 수 있는 페이지가 존재.
        pathPattern = pathPatternParser.parse("/api/projects/**");
        String curPath = request.getPath().toString();
        log.info("curPath: " + curPath);
        if (pathPattern.matches(pathContainer)) { // if, access MSA is project-service
          if (!curPath.contains("support-signature") && !curPath.contains("makers")) {
            username = "NON_MEMBER";
          } else {
            return onError(exchange, "no authorization header", HttpStatus.UNAUTHORIZED);
          }
        } else {
          return onError(exchange, "no authorization header", HttpStatus.UNAUTHORIZED);
        }
      }
      log.info("AuthorizationHeader Filter End");
      return chain.filter(exchange);
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
