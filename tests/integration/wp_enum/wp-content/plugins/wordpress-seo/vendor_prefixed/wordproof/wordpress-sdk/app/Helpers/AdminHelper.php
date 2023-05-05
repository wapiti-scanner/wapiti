<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

class AdminHelper
{
    /**
     * Returns the current admin url of the user.
     *
     * @return null|string The current admin url of the logged in user.
     */
    public static function currentUrl()
    {
        if (isset($_SERVER['REQUEST_URI'])) {
            $requestUri = \esc_url_raw(\wp_unslash($_SERVER['REQUEST_URI']));
            return \admin_url(\sprintf(\basename($requestUri)));
        }
        return null;
    }
}
