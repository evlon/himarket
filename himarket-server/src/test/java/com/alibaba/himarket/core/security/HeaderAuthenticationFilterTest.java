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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.alibaba.himarket.dto.result.developer.DeveloperResult;
import com.alibaba.himarket.service.DeveloperService;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Behaviour of the gateway-trust authentication filter.
 *
 * <p>The cases that matter are the ones where a request must end up
 * <em>unauthenticated</em>: a forged header, an unknown identity, or a downstream failure. Getting
 * any of those wrong turns "the gateway vouches for this caller" into "anyone who can send a header
 * is logged in", which is the whole risk this filter carries.
 */
class HeaderAuthenticationFilterTest {

    private DeveloperService developerService;
    private HeaderAuthenticationFilter filter;
    private FilterChain chain;

    @BeforeEach
    void setUp() {
        developerService = mock(DeveloperService.class);
        filter = new HeaderAuthenticationFilter(developerService);
        chain = mock(FilterChain.class);
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private MockHttpServletRequest requestWithUsername(String username) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        if (username != null) {
            request.addHeader(HeaderAuthenticationFilter.USERNAME_HEADER, username);
        }
        return request;
    }

    private DeveloperResult developer(String id) {
        DeveloperResult result = new DeveloperResult();
        result.setDeveloperId(id);
        return result;
    }

    @Test
    @DisplayName("known identity authenticates as its developer")
    void knownIdentityAuthenticates() throws Exception {
        when(developerService.getExternalDeveloper(
                        HeaderAuthenticationFilter.EXTERNAL_PROVIDER, "niukunliang"))
                .thenReturn(developer("dev-1"));

        filter.doFilter(requestWithUsername("niukunliang"), new MockHttpServletResponse(), chain);

        var authentication = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(authentication, "a bound identity must authenticate");
        assertEquals("dev-1", authentication.getPrincipal());
        assertEquals(
                "ROLE_DEVELOPER", authentication.getAuthorities().iterator().next().getAuthority());
    }

    @Test
    @DisplayName("unknown identity stays unauthenticated and creates no account")
    void unknownIdentityStaysUnauthenticated() throws Exception {
        when(developerService.getExternalDeveloper(any(), any())).thenReturn(null);

        filter.doFilter(
                requestWithUsername("never-logged-in"), new MockHttpServletResponse(), chain);

        assertNull(
                SecurityContextHolder.getContext().getAuthentication(),
                "a header naming an unbound identity must not authenticate");
    }

    @Test
    @DisplayName("blank header is ignored without a lookup")
    void blankHeaderIgnored() throws Exception {
        filter.doFilter(requestWithUsername("   "), new MockHttpServletResponse(), chain);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    @DisplayName("absent header is ignored")
    void absentHeaderIgnored() throws Exception {
        filter.doFilter(requestWithUsername(null), new MockHttpServletResponse(), chain);
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    @DisplayName("a lookup failure leaves the request unauthenticated")
    void lookupFailureStaysUnauthenticated() throws Exception {
        when(developerService.getExternalDeveloper(any(), any()))
                .thenThrow(new RuntimeException("database unavailable"));

        filter.doFilter(requestWithUsername("niukunliang"), new MockHttpServletResponse(), chain);

        assertNull(
                SecurityContextHolder.getContext().getAuthentication(),
                "an error must not be treated as a successful authentication");
    }

    @Test
    @DisplayName("an existing JWT authentication is never overwritten")
    void existingAuthenticationWins() throws Exception {
        var jwtAuthentication =
                new UsernamePasswordAuthenticationToken(
                        "jwt-user", null, java.util.Collections.emptyList());
        SecurityContextHolder.getContext().setAuthentication(jwtAuthentication);

        when(developerService.getExternalDeveloper(any(), any()))
                .thenReturn(developer("dev-header"));

        filter.doFilter(requestWithUsername("niukunliang"), new MockHttpServletResponse(), chain);

        var after = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(after);
        assertEquals(
                "jwt-user",
                after.getPrincipal(),
                "a request with a valid HiMarket JWT must keep the JWT principal");
    }
}
