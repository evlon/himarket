/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.alibaba.himarket.core.security;

import com.alibaba.himarket.core.constant.CommonConstants;
import com.alibaba.himarket.dto.result.developer.DeveloperResult;
import com.alibaba.himarket.service.DeveloperService;
import com.alibaba.himarket.support.common.Strings;
import com.alibaba.himarket.support.enums.UserType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates a request from identity headers injected by the API gateway.
 *
 * <p>This is the gateway-trust half of the "one login, everywhere" model: Higress validates the
 * Keycloak token once (against the realm JWKS) and forwards the caller's identity in headers; this
 * filter turns those headers into a Spring Security authentication so the rest of the application
 * sees the same principal it would get from a HiMarket JWT.
 *
 * <p><b>Trust boundary.</b> The headers are trusted only because {@code himarket-server} is
 * unreachable except through the gateway. Nothing here verifies a signature, so a client that can
 * reach this process directly can forge any identity. Deployments MUST keep the server on a
 * network the gateway is the only ingress to; see {@code header-auth.enabled}.
 *
 * <p><b>The header is a routing key, not an authority.</b> Only the {@code preferred_username} is
 * read, and it is used solely to look up an existing {@code developer_external_identity} row. A
 * caller who names an identity that has never logged in gets no authentication at all — the filter
 * never creates an account, because a self-asserted header must not be able to mint one.
 *
 * <p>Runs before {@link JwtAuthenticationFilter} in the chain but leaves an existing authentication
 * untouched: when a request carries a valid HiMarket JWT the JWT wins, so the two authentication
 * paths cannot both write the security context for one request.
 */
@Slf4j
public class HeaderAuthenticationFilter extends OncePerRequestFilter {

    /** Gateway-injected claim holding the Keycloak {@code preferred_username}. */
    public static final String USERNAME_HEADER = "x-user-username";

    /** Identity-provider key that {@code developer_external_identity.provider} stores. */
    public static final String EXTERNAL_PROVIDER = "corp-sso";

    private final DeveloperService developerService;

    public HeaderAuthenticationFilter(DeveloperService developerService) {
        this.developerService = developerService;
    }

    @Override
    protected void doFilterInternal(
            @NotNull HttpServletRequest request,
            @NotNull HttpServletResponse response,
            @NotNull FilterChain chain)
            throws IOException, ServletException {

        // A HiMarket JWT already authenticated this request; do not overwrite it with a header.
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            chain.doFilter(request, response);
            return;
        }

        String username = request.getHeader(USERNAME_HEADER);
        if (Strings.isBlank(username)) {
            chain.doFilter(request, response);
            return;
        }

        try {
            authenticate(username.trim());
        } catch (Exception e) {
            // A failure here must not reject the request: the JWT filter still runs afterwards and
            // a request that carries a valid HiMarket token must keep working. Leaving the context
            // empty lets the authorization rules decide, which is the same outcome as no header.
            log.debug("Header authentication failed for username={}", username, e);
            SecurityContextHolder.clearContext();
        }
        chain.doFilter(request, response);
    }

    /**
     * Looks up the developer bound to this identity provider username and installs it as the
     * request principal.
     *
     * @param username the {@code preferred_username} the gateway forwarded
     */
    private void authenticate(String username) {
        DeveloperResult developer =
                developerService.getExternalDeveloper(EXTERNAL_PROVIDER, username);
        if (developer == null) {
            // No account bound to this identity: never create one from a header.
            log.debug(
                    "No external developer bound for provider={} username={}",
                    EXTERNAL_PROVIDER,
                    username);
            return;
        }

        String role = CommonConstants.ROLE_PREFIX + UserType.DEVELOPER.name();
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        developer.getDeveloperId(),
                        null,
                        Collections.singletonList(new SimpleGrantedAuthority(role)));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        log.debug(
                "Header-authenticated developerId={} username={}",
                developer.getDeveloperId(),
                username);
    }
}
