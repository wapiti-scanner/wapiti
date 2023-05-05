<?php

namespace YoastSEO_Vendor\WordProof\SDK\Controllers;

use YoastSEO_Vendor\WordProof\SDK\Support\Settings;
class SettingsController
{
    /**
     * Redirects user to the settings page. Returns false if not authenticated.
     *
     * @param null|string $redirectUrl
     * @return false
     */
    public function redirect($redirectUrl = null)
    {
        return \YoastSEO_Vendor\WordProof\SDK\Support\Settings::redirect($redirectUrl);
    }
    /**
     * Adds admin page that will redirect the user to a predefined url.
     *
     * @action admin_menu
     */
    public function addRedirectPage()
    {
        \add_submenu_page(null, 'WordProof Settings', 'WordProof Settings', 'publish_pages', 'wordproof-redirect-settings', [$this, 'redirectPageContent']);
    }
    /**
     * The content for the redirect page. Triggered by addRedirectPage().
     */
    public function redirectPageContent()
    {
        return;
    }
    /**
     * Redirects user on admin page load to the settings page on the WordProof My.
     *
     * @action load-admin_page_settings
     */
    public function redirectOnLoad()
    {
        $closeWindowUrl = \admin_url('admin.php?page=wordproof-close-after-redirect');
        if ($this->redirect($closeWindowUrl) === \false) {
            \do_action('wordproof_authenticate', $closeWindowUrl);
        }
    }
}
