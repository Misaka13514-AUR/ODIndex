const config = {
  /**
   * You can use this tool http://heymind.github.io/tools/microsoft-graph-api-auth
   * to get following params: client_id, client_secret, initial_refresh_token & redirect_uri.
   * The initial_refresh_token will be stored and updated in KV.
   */
  "initial_refresh_token": "", // Store your initial refresh token here
  "client_id": "",
  "client_secret": "",
  "redirect_uri": "http://localhost",
  /**
   * The base path for indexing, all files and subfolders are public by this tool. For example `/Share`.
   */
  base: "/aur",
  /**
   * Feature Caching
   * Enable Cloudflare cache for path pattern listed below.
   * Cache rules:
   * - Entire File Cache  0 < file_size < entireFileCacheLimit
   * - Chunked Cache     entireFileCacheLimit  <= file_size < chunkedCacheLimit
   * - No Cache ( redirect to OneDrive Server )   others
   * 
   * Difference between `Entire File Cache` and `Chunked Cache`
   * 
   * `Entire File Cache` requires the entire file to be transferred to the Cloudflare server before 
   * the first byte is sent to a client.
   * 
   * `Chunked Cache` would stream the file content to the client while caching it.
   * But there is no exact Content-Length in the response headers. (Content-Length: chunked)
   */
  "cache": {
    "enable": false,
    "entireFileCacheLimit": 10000000, // 10MB
    "chunkedCacheLimit": 100000000,   // 100MB
    "paths": ["/Images"]
  },
  /**
   * Feature Thumbnail
   * Show a thumbnail of an image by ?thumbnail=small (small, medium, large)
   * more details: https://docs.microsoft.com/en-us/onedrive/developer/rest-api/api/driveitem_list_thumbnails?view=odsp-graph-online#size-options
   * example: https://storage.idx0.workers.dev/Images/def.png?thumbnail=mediumSquare
   */
  "thumbnail": {
    "enable": true
  },
  /**
   * Small File Upload ( <= 4MB )
   * example: POST https://storage.idx0.workers.dev/Images/?upload=<filename>&key=<secret_key>
   */
  "upload": {
    "enable": false,
    "key": "your_secret_1key_here"
  },
  /**
   * Feature Proxy Download
   * Use Cloudflare as a relay to speed up download. (especially in Mainland China)
   * This is a global setting. If true, all downloads are proxied.
   * If false, all downloads are direct redirects to OneDrive.
   */
  "proxyDownload": {
    "enable": false
  },
  /**
   * KV Namespace binding. Make sure to configure this in your wrangler.toml or Cloudflare dashboard.
   */
  "kv_binding": "TOKEN_KV" // KV binding name
};

/**
 * Basic authentication.
 * Disabled by default (Issue #29)
 * 
 * AUTH_ENABLED   to enable auth set true
 * NAME           user name
 * PASS           password
 */
const AUTH_ENABLED = false;
const NAME = "admin";
const PASS = "password";

/**
 * RegExp for basic auth credentials
 *
 * credentials = auth-scheme 1*SP token68
 * auth-scheme = "Basic" ; case insensitive
 * token68     = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
 */
const CREDENTIALS_REGEXP = /^ *(?:[Bb][Aa][Ss][Ii][Cc]) +([A-Za-z0-9._~+/-]+=*) *$/;

/**
 * RegExp for basic auth user/pass
 *
 * user-pass   = userid ":" password
 * userid      = *<TEXT excluding ":">
 * password    = *TEXT
 */
const USER_PASS_REGEXP = /^([^:]*):(.*)$/;

/**
 * Object to represent user credentials.
 */
const Credentials = function (name, pass) {
  this.name = name;
  this.pass = pass;
};

/**
 * Parse basic auth to object.
 */
const parseAuthHeader = function (string) {
  if (typeof string !== 'string') return undefined;
  // parse header
  const match = CREDENTIALS_REGEXP.exec(string);
  if (!match) return undefined;
  // decode user pass
  const userPass = USER_PASS_REGEXP.exec(atob(match[1]));
  if (!userPass) return undefined;
  // return credentials object
  return new Credentials(userPass[1], userPass[2]);
};

const unauthorizedResponse = function (body) {
  return new Response(
    body || "Unauthorized",
    {
      status: 401,
      statusText: "Authentication required.",
      headers: { "WWW-Authenticate": 'Basic realm="User Visible Realm"' }
    }
  );
};

async function authWrapper(request) {
  if (!AUTH_ENABLED) {
    return handleRequest(request);
  }
  const credentials = parseAuthHeader(request.headers.get("Authorization"));
  if (!credentials || credentials.name !== NAME || credentials.pass !== PASS) {
    return unauthorizedResponse();
  }
  return handleRequest(request);
}

addEventListener('fetch', event => {
  event.respondWith(authWrapper(event.request));
});

/**
 * Current access token (in-memory cache for the duration of a single request burst)
 */
let _accessToken = null;
let _accessTokenExpiresAt = 0; // Timestamp in milliseconds

/**
 * Cloudflare cache instance
 */
let cfCache = caches.default;

/**
 * Get KV store reference.
 * This function assumes the binding name is defined in config.kv_binding.
 */
function getKV() {
  const bindingName = config.kv_binding;
  if (typeof globalThis[bindingName] === 'undefined') {
    // This error will appear if the KV namespace is not bound to the Worker
    console.error(`KV Namespace '${bindingName}' is not bound. Please check your wrangler.toml or Cloudflare dashboard.`);
    // Fallback to a mock KV for local testing or if KV is not essential for some paths,
    // but token storage IS essential. So we throw.
    throw new Error(`KV Namespace '${bindingName}' not available.`);
  }
  return globalThis[bindingName];
}

/**
 * Get access token for Microsoft Graph API endpoints. Refresh token if needed.
 * Tokens are stored in and retrieved from KV store.
 */
async function getAccessToken() {
  const KV = getKV();
  const now = Date.now();

  if (_accessToken && now < _accessTokenExpiresAt) {
    return _accessToken;
  }

  // Try to get a valid access token from KV
  const storedAccessToken = await KV.get("ACCESS_TOKEN");
  const storedAccessTokenExpiresAt = parseInt(await KV.get("ACCESS_TOKEN_EXPIRES_AT") || "0");

  if (storedAccessToken && now < storedAccessTokenExpiresAt) {
    _accessToken = storedAccessToken;
    _accessTokenExpiresAt = storedAccessTokenExpiresAt;
    console.info("Using access_token from KV.");
    return _accessToken;
  }

  // Access token is invalid or expired, try to refresh
  let refreshToken = await KV.get("REFRESH_TOKEN");
  if (!refreshToken) {
    refreshToken = config.initial_refresh_token;
    if (!refreshToken) {
      throw "Refresh token not found in KV and no initial_refresh_token configured.";
    }
  }

  const resp = await fetch("https://login.microsoftonline.com/common/oauth2/v2.0/token", {
    method: "POST",
    body: `client_id=${encodeURIComponent(config.client_id)}&redirect_uri=${encodeURIComponent(config.redirect_uri)}&client_secret=${encodeURIComponent(config.client_secret)}&refresh_token=${encodeURIComponent(refreshToken)}&grant_type=refresh_token`,
    headers: { "Content-Type": "application/x-www-form-urlencoded" }
  });

  if (!resp.ok) {
    // If refresh fails, clear stored tokens to force re-auth or use initial next time
    await KV.delete("ACCESS_TOKEN");
    await KV.delete("ACCESS_TOKEN_EXPIRES_AT");
    // Potentially delete REFRESH_TOKEN too if it's confirmed invalid
    // await KV.delete("REFRESH_TOKEN");
    console.error("Failed to refresh access token. Response:", await resp.text());
    throw `getAccessToken error: ${resp.status} ${resp.statusText}`;
  }

  const data = await resp.json();
  _accessToken = data.access_token;
  // Expires_in is in seconds, convert to milliseconds for expiry timestamp
  // Subtract 60 seconds as a buffer
  _accessTokenExpiresAt = now + (data.expires_in - 60) * 1000;

  await KV.put("ACCESS_TOKEN", _accessToken, { expirationTtl: data.expires_in });
  await KV.put("ACCESS_TOKEN_EXPIRES_AT", _accessTokenExpiresAt.toString(), { expirationTtl: data.expires_in });

  if (data.refresh_token) {
    await KV.put("REFRESH_TOKEN", data.refresh_token);
    console.info("access_token and refresh_token updated in KV.");
  } else {
    console.info("access_token updated in KV (refresh_token was not renewed by Microsoft).");
  }

  return _accessToken;
}

/**
 * Cache downloadUrl according to caching rules.
 * @param {Request} request client's request 
 * @param {integer} fileSize 
 * @param {string} downloadUrl 
 * @param {function} fallback handle function if the rules are not satisfied
 */
async function setCache(request, fileSize, downloadUrl, fallback) {
  if (fileSize < config.cache.entireFileCacheLimit) {
    console.info(`Cache entire file ${request.url}`);
    const remoteResp = await fetch(downloadUrl);
    if (!remoteResp.ok) return fallback(downloadUrl); // Don't cache errors
    const resp = new Response(remoteResp.body, {
      headers: {
        "Content-Type": remoteResp.headers.get("Content-Type"),
        "ETag": remoteResp.headers.get("ETag"),
      },
      status: remoteResp.status,
      statusText: remoteResp.statusText,
    });
    await cfCache.put(request, resp.clone());
    return resp;

  } else if (fileSize < config.cache.chunkedCacheLimit) {
    console.info(`Chunk cache file ${request.url}`);
    const remoteResp = await fetch(downloadUrl);
    if (!remoteResp.ok) return fallback(downloadUrl); // Don't cache errors
    let { readable, writable } = new TransformStream();
    remoteResp.body.pipeTo(writable);
    const resp = new Response(readable, {
      headers: {
        "Content-Type": remoteResp.headers.get("Content-Type"),
        "ETag": remoteResp.headers.get("ETag")
      },
      status: remoteResp.status,
      statusText: remoteResp.statusText
    });
    await cfCache.put(request, resp.clone());
    return resp;

  } else {
    console.info(`No cache ${request.url} because file_size(${fileSize}) > limit(${config.cache.chunkedCacheLimit})`);
    return await fallback(downloadUrl);
  }
}

/**
 * Redirect to the download URL.
 * @param {string} downloadUrl 
 */
async function directDownload(downloadUrl) {
  console.info(`DirectDownload -> ${downloadUrl}`);
  // The downloadUrl from Graph often starts with "https://" or "http://", no need to slice 'https://' (which is 6 chars)
  return new Response(null, {
    status: 302,
    headers: { "Location": downloadUrl }
  });
}

/**
 * Download a file using Cloudflare as a relay.
 * @param {string} downloadUrl
 */
async function proxiedDownload(accessToken, graphPathForContent) {
  console.info(`ProxyDownload for path -> ${graphPathForContent}`);
  const contentUrl = `https://graph.microsoft.com/v1.0/me/drive/root:${graphPathForContent}:/content`;

  const remoteResp = await fetch(contentUrl, {
    headers: { "Authorization": `Bearer ${accessToken}` }
  });

  if (!remoteResp.ok) {
    const errorText = await remoteResp.text();
    console.error(`Proxied download failed for ${graphPathForContent}: ${remoteResp.status} ${errorText}`);
    return new Response(`Error fetching file from OneDrive: ${remoteResp.status} ${errorText}`, {
      status: remoteResp.status,
      headers: { 'Content-Type': 'text/plain' }
    });
  }

  // For chunked streaming, we don't know the exact Content-Length beforehand from /content
  // OneDrive might provide it, or might use chunked encoding itself.
  // We will stream it as it comes.
  let { readable, writable } = new TransformStream();
  remoteResp.body.pipeTo(writable);

  const responseHeaders = new Headers(remoteResp.headers);
  // Ensure we don't pass through problematic headers like 'transfer-encoding' if we are re-streaming
  responseHeaders.delete('transfer-encoding');

  return new Response(readable, {
    status: remoteResp.status,
    statusText: remoteResp.statusText,
    headers: responseHeaders
  });
}

async function handleFile(request, accessToken, graphPathForContent, downloadUrl, { fileSize = 0 }) {
  const pathname = new URL(request.url).pathname; // For cache path matching

  if (config.proxyDownload.enable) { // Global proxy setting
    const proxiedFileResponse = await proxiedDownload(accessToken, graphPathForContent);
    // If caching is enabled and path matches, try to cache the proxied response
    if (config.cache && config.cache.enable &&
        config.cache.paths.some(p => pathname.startsWith(p))) {
      // To cache a proxied response, we need a new response with a clone of its body
      // because the body can only be read once.
      // This is a bit tricky as proxiedDownload already returns a Response.
      // We'd need to read its body to cache, then serve. Let's simplify:
      // Caching for proxied downloads can be complex if we want to cache the stream.
      // For simplicity, if proxy is on, and cache is on, we might fetch twice (once for cache, once for user)
      // Or, if proxy is on, we just proxy and don't engage our custom CF cache for now.
      // The setCache function expects a downloadUrl it can fetch.
      // The proxiedDownload function *is* the fetch.
      // Let's make `setCache` compatible with `proxiedDownload` returning a response directly.
      //
      // Simplification: If proxying, the `downloadUrl` param to `setCache` would be the Graph `/content` URL.
      // `setCache` would then fetch this URL, and the fallback `proxiedDownload` wouldn't be used in that specific call.
      // `directDownload` is still used if proxy is off.

      if (fileSize > 0) { // Only possible to cache if file size is known
        // For proxied downloads, the 'downloadUrl' for caching purposes is the /content endpoint
        const contentUrl = `https://graph.microsoft.com/v1.0/me/drive/root${graphPathForContent}:/content`;
        return setCache(request, fileSize, contentUrl, async (finalUrlToFetch) => {
          // Fallback for setCache if not caching, should still be proxied if enabled
          return proxiedDownload(accessToken, graphPathForContent);
        });
      }
    }
    return proxiedFileResponse; // Serve proxied file directly if not caching or no file size
  } else { // Not proxying, use direct download (redirect)
    if (config.cache && config.cache.enable &&
        config.cache.paths.some(p => pathname.startsWith(p)) &&
        fileSize > 0 && downloadUrl) { // downloadUrl is required for caching
      return setCache(request, fileSize, downloadUrl, directDownload);
    }
    return directDownload(downloadUrl);
  }
}

async function handleUpload(request, accessToken, graphPath, filename) {
  const url = `https://graph.microsoft.com/v1.0/me/drive/root${graphPath.endsWith('/') ? graphPath.slice(0, -1) : graphPath}/${filename}:/content`;
  return fetch(url, {
    method: "PUT",
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      // Pass through client's content-type, length etc.
      "Content-Type": request.headers.get("Content-Type"),
      "Content-Length": request.headers.get("Content-Length"),
    },
    body: request.body
  });
}

/**
 * Prepares a path for the Microsoft Graph API by:
 * 1. Combining with config.base
 * 2. Removing leading/trailing slashes for consistency (Graph usually wants /root:path_without_leading_slash:)
 * 3. Doubling colons in path segments as per Graph API spec (e.g., "file:name.txt" becomes "file::name.txt")
 * Returns a path like "/Documents/file::name.txt" (without the leading /root: or trailing :)
 */
function prepareGraphPath(rawPathname) {
  let fullPath = config.base + rawPathname;

  // Normalize: remove leading/trailing slashes, then re-add leading if not root
  fullPath = fullPath.replace(/^\/+|\/+$/g, ''); // Remove all leading/trailing slashes

  // Double colons for Graph API path segments
  // Note: This assumes colons are only in filenames, not directory names.
  // If directory names can have colons, this logic might need adjustment.
  const segments = fullPath.split('/');
  const encodedSegments = segments.map(segment => segment.replace(/:/g, '::'));
  let graphPath = encodedSegments.join('/');

  if (graphPath === "" || graphPath === "/") { // Root path
    return ""; // Represents the root of the drive for /root calls
  }
  return `/${graphPath}`; // Prepends a slash if it's not the root, e.g. /FolderName/File.txt
}

/**
 * Handle `If-Modified-Since` requests.
 * Return 304 if the file hasn't been modified since the given date.
 */
async function handleIfModifiedSince(request, fileLastModified) {
  const ifModifiedSince = request.headers.get('If-Modified-Since');
  if (ifModifiedSince) {
    try {
      if (new Date(fileLastModified) <= new Date(ifModifiedSince)) {
        return new Response(null, { status: 304 });
      }
    } catch (e) { console.warn("Error parsing If-Modified-Since date:", e); }
  }
  return null;
}

async function handleRequest(request) {
  if (config.cache.enable) {
    const maybeResponse = await cfCache.match(request);
    if (maybeResponse) {
      console.info(`Cache HIT for ${request.url}`);
      return maybeResponse;
    }
    console.info(`Cache MISS for ${request.url}`);
  }

  const accessToken = await getAccessToken();
  const urlObject = new URL(request.url);
  const rawPathname = decodeURIComponent(urlObject.pathname).replace(/:/g, '：'); // Use decoded pathname

  // Prepare graph path (e.g., /Share/MyFolder/MyDoc::WithColon.docx)
  // This path is used for Graph API calls, without /root: prefix.
  const graphPath = prepareGraphPath(rawPathname);

  // Construct the Graph API item path specifier (e.g., ":/Share/MyFolder/MyDoc::WithColon.docx:")
  // Or an empty string for the root.
  const graphItemPathSpecifier = graphPath ? `:${graphPath}:` : "";

  const thumbnailSize = config.thumbnail.enable ? urlObject.searchParams.get("thumbnail") : null;

  if (thumbnailSize) {
    const thumbnailUrl = `https://graph.microsoft.com/v1.0/me/drive/root${graphItemPathSpecifier}/thumbnails/0/${thumbnailSize}/content`;
    // Thumbnails are usually small; could be proxied or redirected.
    // For simplicity, we'll proxy them if proxying is enabled, or redirect.
    // We won't apply complex caching rules to thumbnails here, but CF default cache might still apply.
    if (config.proxyDownload.enable) {
      const thumbResp = await fetch(thumbnailUrl, { headers: { "Authorization": `Bearer ${accessToken}` } });
      return new Response(thumbResp.body, thumbResp); // Stream it
    } else {
      // Fetch to get the actual redirect URL from OneDrive for the thumbnail
      const resp = await fetch(thumbnailUrl, {
        headers: { "Authorization": `Bearer ${accessToken}` },
        redirect: "manual"
      });
      // Check if it's a redirect (302) to the actual image URL
      if (resp.status === 302 || resp.status === 307) {
        return new Response(null, { status: 302, headers: { 'Location': resp.headers.get('Location') } });
      }
      // If not a redirect, it might be the content directly (less common for thumbnails) or an error
      return resp;
    }
  }

  // Fetch item metadata and children (for folders)
  // For pagination, we request children and @odata.nextLink
  // 1. First only fetch the metadata of the current object (without expand)
  const selectFields = "name,eTag,size,id,folder,file,lastModifiedDateTime,@microsoft.graph.downloadUrl";
  let metadataUrl = `https://graph.microsoft.com/v1.0/me/drive/root${graphItemPathSpecifier}?select=${selectFields}`;
  let responseData;

  try {
    const respMeta = await fetch(metadataUrl, {
      headers: { "Authorization": `Bearer ${accessToken}` }
    });
    if (!respMeta.ok) {
      const errorData = await respMeta.json();
      throw { status: respMeta.status, ...errorData.error };
    }
    responseData = await respMeta.json();
  } catch (error) {
    console.error("Graph API metadata error:", error);
    const status = error.status || (error.code === "ItemNotFound" ? 404 : 500);
    return new Response(
      JSON.stringify(error.message ? { code: error.code, message: error.message } : error),
      { status: status, headers: { 'content-type': 'application/json' } }
    );
  }

  // 2. If it is a file, directly handle file download/render
  if ("file" in responseData) {
    const modifiedResponse = await handleIfModifiedSince(request, responseData.lastModifiedDateTime);
    if (modifiedResponse) return modifiedResponse;
    return handleFile(
      request,
      accessToken,
      graphPath,
      responseData["@microsoft.graph.downloadUrl"],
      { fileSize: responseData["size"] }
    );
  }

  // 3. If it is a folder, separately fetch children and handle pagination
  if ("folder" in responseData) {
    // 3.1 If it is an upload (POST), logic remains unchanged
    if (config.upload.enable && request.method === "POST") {
      const urlObject = new URL(request.url);
      const filename = urlObject.searchParams.get("upload");
      const key = urlObject.searchParams.get("key");
      if (filename && key === config.upload.key) {
        return handleUpload(request, accessToken, graphPath, decodeURIComponent(filename));
      } else {
        return new Response("Bad request for upload.", { status: 400 });
      }
    }

    // 3.2 Retrieve all children (pagination logic)
    let allChildren = [];
    let childrenUrl = `https://graph.microsoft.com/v1.0/me/drive/root${graphItemPathSpecifier}/children?select=${selectFields}&top=200`;
    try {
      while (childrenUrl) {
        const respChildren = await fetch(childrenUrl, {
          headers: { "Authorization": `Bearer ${accessToken}` }
        });
        if (!respChildren.ok) {
          const errorData = await respChildren.json();
          console.error("Error fetching children page:", errorData);
          break; // or throw, depending on requirements
        }
        const dataChildren = await respChildren.json();
        // dataChildren.value is the array of items for this page
        if (Array.isArray(dataChildren.value)) {
          allChildren.push(...dataChildren.value);
        }
        // Check for the next page link
        childrenUrl = dataChildren['@odata.nextLink'] || null;
      }
      // Finally attach the children array to responseData.children
      responseData.children = allChildren;
    } catch (error) {
      console.error("Graph API children paging error:", error);
      // Directly provide the currently read allChildren to the client, which is a 'partially successful' approach
      responseData.children = allChildren;
    }

    // 3.3 Ensure URL ends with a slash (so relative links work properly)
    const urlObject2 = new URL(request.url);
    if (!urlObject2.pathname.endsWith("/")) {
      return Response.redirect(urlObject2.pathname + "/" + urlObject2.search, 301);
    }

    // 4. Render as an HTML directory listing
    return new Response(
      renderFolderIndex(responseData.children, decodeURIComponent(new URL(request.url).pathname)),
      {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'content-type': 'text/html; charset=utf-8'
        }
      }
    );
  }

  // 5. If it is neither a file nor a folder, throw an error
  console.error("Unknown item type from Graph API:", responseData);
  return new Response(
    JSON.stringify({ error: "Unknown item type", data: responseData }),
    { status: 500, headers: { 'content-type': 'application/json' } }
  );
}

/**
 * Format bytes into a human-readable string.
 * Converts bytes to KB, MB, GB, etc. with one decimal place.
 * @param {number} bytes 
 * @returns {string}
 */
function formatBytes(bytes) {
  if (bytes == null || isNaN(bytes)) return '-';
  const thresh = 1024;
  if (bytes < thresh) return bytes + ' B';
  const units = ['KB', 'MB', 'GB', 'TB'];
  let u = -1;
  let val = bytes;
  while (val >= thresh && u < units.length - 1) {
    val = val / thresh;
    u++;
  }
  return val.toFixed(1) + ' ' + units[u];
}

/**
 * Render Folder Index as a proper HTML table
 * @param {Array} items - Array of item objects from Graph API
 * @param {string} currentPath - The current decoded path being viewed (e.g., "/Documents/Subfolder")
 */
function renderFolderIndex(items, currentPath) {
  // Sort items: folders first, then files, then by name
  items.sort((a, b) => {
    const isDirA = !!a.folder;
    const isDirB = !!b.folder;
    if (isDirA && !isDirB) return -1;
    if (!isDirA && isDirB) return 1;
    return a.name.localeCompare(b.name);
  });

  let html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Index of ${currentPath === '/' || currentPath === '' ? '/' : currentPath.replace(/::/g, ':')}</title>
  <style>
    body { font-family: Arial, sans-serif; padding: 20px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 8px 12px; text-align: left; }
    th { border-bottom: 2px solid #666; }
    tr:nth-child(even) { background-color: #f9f9f9; }
    a { text-decoration: none; color: #0066cc; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
<h1>Welcome to the Apeiria Arch Linux Repository!</h1>
<ul>
  <li><a href="https://github.com/Misaka13514-AUR/repo#usage">Usage</a></li>
  <li><a href="https://github.com/Misaka13514-AUR/repo">PKGBUILD git repository</a></li>
  <li><a href="https://build.apeiria.net/">Build logs</a></li>
  <li><a href="https://github.com/Misaka13514-AUR/repo/issues">Report issue</a></li>
</ul>
<hr>
<h1>Index of ${currentPath === '/' || currentPath === '' ? '/' : currentPath.replace(/::/g, ':')}</h1>
<hr>
<table>
  <thead>
    <tr>
      <th>Name</th>
      <th>Last Modified</th>
      <th style="text-align: right;">Size</th>
    </tr>
  </thead>
  <tbody>
`;

  if (currentPath !== '/' && currentPath !== '') {
    html += `
    <tr>
      <td><a href="../">../</a></td>
      <td>-</td>
      <td style="text-align: right;">-</td>
    </tr>
`;
  }

  items.forEach(item => {
    // Graph API's `name` field has original colons. URLs should use them or %3A.
    // Our `prepareGraphPath` handles `::` for API calls, but links should be standard.
    const displayName = item.name.replace(/：/g, ':'); // Revert for display if it was internal `::`
    const encodedName = encodeURIComponent(displayName); // Standard URL encoding for href

    const href = item.folder ? `${encodedName}/` : `${encodedName}`;
    const sizeText = item.folder ? '-' : formatBytes(item.size);

    // Format lastModifiedDateTime (e.g., "2023-08-15T10:30:00Z") to "15-Aug-2023 10:30"
    let modDate = '-';
    if (item.lastModifiedDateTime) {
      try {
        const d = new Date(item.lastModifiedDateTime);
        const day = d.getDate().toString().padStart(2, '0');
        const month = d.toLocaleString('en-GB', { month: 'short' });
        const year = d.getFullYear();
        const time = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false });
        modDate = `${day}-${month}-${year} ${time}`;
      } catch (e) {
        console.warn("Date format error for", item.lastModifiedDateTime);
      }
    }

    html += `
    <tr>
      <td><a href="${href}">${displayName}${item.folder ? '/' : ''}</a></td>
      <td>${modDate}</td>
      <td style="text-align: right;">${sizeText}</td>
    </tr>
`;
  });

  html += `
  </tbody>
</table>
<hr>
</body>
</html>`;

  return html;
}
