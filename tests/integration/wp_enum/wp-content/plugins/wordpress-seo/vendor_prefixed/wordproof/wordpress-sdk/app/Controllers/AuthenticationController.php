<?php

namespace YoastSEO_Vendor\WordProof\SDK\Controllers;

use YoastSEO_Vendor\WordProof\SDK\Support\Authentication;
class AuthenticationController
{
    /**
     * Triggers the authentication flow.
     *
     * @param null $redirectUrl
     */
    public function authenticate($redirectUrl = null)
    {
        return \YoastSEO_Vendor\WordProof\SDK\Support\Authentication::authorize($redirectUrl);
    }
    /**
     * Adds admin page that redirects to the authentication flow.
     */
    public function addRedirectPage()
    {
        \add_submenu_page(null, 'WordProof Authenticate', 'WordProof Authenticate', 'publish_pages', 'wordproof-redirect-authenticate', [$this, 'redirectPageContent']);
    }
    /**
     * The content for the redirect page.
     */
    public function redirectPageContent()
    {
    }
    /**
     * Gets triggered by the 'load-admin_page_' hook of the redirect page
     */
    public function redirectOnLoad()
    {
        \do_action('wordproof_authenticate', \admin_url('admin.php?page=wordproof-close-after-redirect'));
    }
    /**
     * Adds self destruct admin page.
     */
    public function addSelfDestructPage()
    {
        \add_submenu_page(null, 'WordProof After Authenticate', 'WordProof After Authenticate', 'publish_pages', 'wordproof-close-after-redirect', [$this, 'closeOnLoadContent']);
    }
    /**
     * Adds a script to the loaded page to close on load.
     */
    public function closeOnLoadContent()
    {
        echo '<script type="text/javascript">';
        echo 'window.close();';
        echo '</script>';
    }
}
