backend default {
  .host = "127.0.0.1";
  .port = "8080";
}

acl purge {
  # Web server with plugin which will issue PURGE requests
  "localhost";
}

sub vcl_recv {
  if (req.request == "PURGE") {
    if (!client.ip ~ purge) {
      error 405 "Not allowed.";
    }
    ban("req.url ~ ^" + req.url + "$ && req.http.host == " + req.http.host);
  }

  # Normalize content-encoding
  if (req.http.Accept-Encoding) {
    if (req.url ~ "\.(jpg|png|gif|gz|tgz|bz2|lzma|tbz)(\?.*|)$") {
      remove req.http.Accept-Encoding;
    } elsif (req.http.Accept-Encoding ~ "gzip") {
      set req.http.Accept-Encoding = "gzip";
    } elsif (req.http.Accept-Encoding ~ "deflate") {
      set req.http.Accept-Encoding = "deflate";
    } else {
      remove req.http.Accept-Encoding;
    }
  }

  # Remove cookies and query string for real static files
  if (req.url ~ "\.(bz2|css|flv|gif|gz|ico|jpeg|jpg|js|lzma|mp3|mp4|pdf|png|swf|tbz|tgz|txt|zip)(\?.*|)$") {
    unset req.http.cookie;
    set req.url = regsub(req.url, "\?.*$", "");
  }

  if (req.url ~ "wp-(login|admin|comments-post.php|cron.php)" ||
      req.url ~ "preview=true" ||
      req.url ~ "xmlrpc.php") {
    return (pass);
  }

  return (lookup);
}

sub vcl_fetch {
  # Don't cache backend
  if (req.url ~ "wp-(login|admin|comments-post.php|cron.php)" ||
      req.url ~ "preview=true" ||
      req.url ~ "xmlrpc.php") {
    # Dont modify anything, it's (pass) object
  } else {
    unset beresp.http.set-cookie;

    if (beresp.status == 307) {
      # Don't cache temporary redirects like ?repeat=w3tc
      set beresp.ttl = 0h;
    } else if (req.url ~ "\.(bz2|css|flv|gif|gz|ico|jpeg|jpg|js|lzma|mp3|mp4|pdf|png|swf|tbz|tgz|txt|zip)$") {
      set beresp.ttl = 30d;
    } else {
      set beresp.ttl = 4h;
    }
  }
}

sub vcl_hit {
  if (req.request == "PURGE") {
    purge;
    error 200 "Purged.";
  }
}

sub vcl_miss {
  if (req.request == "PURGE") {
    purge;
    error 200 "Purged.";
  }
}
