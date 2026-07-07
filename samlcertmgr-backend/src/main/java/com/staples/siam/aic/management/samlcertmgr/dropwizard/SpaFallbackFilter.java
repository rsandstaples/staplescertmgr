package com.staples.siam.aic.management.samlcertmgr.dropwizard;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Supports HTML5 history-mode client-side routing (React Router's
 * {@code BrowserRouter}).
 *
 * <p>
 * The {@code AssetsBundle} that serves the built frontend only knows how
 * to resolve files that actually exist under the bundled {@code /webapp}
 * classpath directory (plus the configured index file for the literal
 * {@code "/"} path). It has no concept of client-side routes such as
 * {@code /register} or {@code /login} — those paths exist only in the React
 * Router route table, not as files on disk, so the asset servlet returns 404
 * for them.
 *
 * <p>
 * This filter runs ahead of the asset servlet on every initial
 * (non-forwarded) request. Any GET request that is not an API call (the
 * JAX-RS root path is {@code /api/*}) and whose final path segment has no
 * file extension is treated as a client-side route and forwarded to
 * {@code /index.html} so the SPA can resolve it. Real static assets (e.g.
 * {@code /assets/main-abc123.js}, {@code /favicon.ico}) always have a file
 * extension on their last segment and pass through untouched.
 *
 * <p>
 * The filter is mapped only to the {@code REQUEST} dispatcher type, so
 * the internal forward to {@code /index.html} is not re-evaluated by this
 * filter — it goes straight to the asset servlet, which serves the file
 * normally.
 */
public class SpaFallbackFilter implements Filter {

    private static final String INDEX_PATH = "/index.html";
    private static final String API_PREFIX = "/api/";

    @Override
    public void init(FilterConfig filterConfig) {
        // no-op
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;

        if (isSpaRoute(req)) {
            req.getRequestDispatcher(INDEX_PATH).forward(request, response);
            return;
        }

        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        // no-op
    }

    private boolean isSpaRoute(HttpServletRequest req) {
        if (!"GET".equalsIgnoreCase(req.getMethod()))
            return false;

        String path = req.getRequestURI();
        if (path.equals("/api") || path.startsWith(API_PREFIX))
            return false;

        String lastSegment = path.substring(path.lastIndexOf('/') + 1);
        return !lastSegment.contains(".");
    }
}
