<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

class RedirectHelper
{
    /**
     * Does a safe redirect to an admin page.
     *
     * @param string $url The url to be redirected to.
     */
    public static function safe($url)
    {
        nocache_headers();
        \wp_safe_redirect($url);
        exit;
    }
}
