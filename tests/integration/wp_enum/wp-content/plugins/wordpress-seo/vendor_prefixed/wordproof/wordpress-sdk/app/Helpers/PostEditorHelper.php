<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

use YoastSEO_Vendor\WordProof\SDK\Translations\TranslationsInterface;
class PostEditorHelper
{
    /**
     * Returns the post editor that is in use.
     *
     * @return bool The post editor the user is using..
     */
    public static function getPostEditor()
    {
        if (!\function_exists('YoastSEO_Vendor\\get_current_screen')) {
            return null;
        }
        $screen = \get_current_screen();
        if (!self::isPostEdit($screen->base)) {
            return null;
        }
        // Start with Elementor, otherwise the block editor will be returned.
        $action = \filter_input(\INPUT_GET, 'action', \FILTER_SANITIZE_STRING);
        if ($action === 'elementor') {
            return 'elementor';
        }
        if (\method_exists($screen, 'is_block_editor') && $screen->is_block_editor()) {
            return 'block';
        }
        return 'classic';
    }
    /**
     * Returns if the page is a post edit page.
     *
     * @param string $page The page to check.
     * @return bool If the current page is a post edit page.
     */
    public static function isPostEdit($page)
    {
        return \in_array($page, self::getPostEditPages(), \true);
    }
    /**
     * Returns an array of edit page hooks.
     *
     * @return array Post edit page hooks.
     */
    public static function getPostEditPages()
    {
        return ['post.php', 'post', 'post-new.php', 'post-new'];
    }
    /**
     * Returns the data that should be added to the post editor.
     *
     * @param TranslationsInterface $translations The implemented translations interface.
     *
     * @return array[] The post editor data.
     */
    public static function getPostEditorData(\YoastSEO_Vendor\WordProof\SDK\Translations\TranslationsInterface $translations)
    {
        global $post;
        $postId = isset($post->ID) ? $post->ID : null;
        $postType = isset($post->post_type) ? $post->post_type : null;
        $translations = ['no_balance' => $translations->getNoBalanceNotice(), 'timestamp_success' => $translations->getTimestampSuccessNotice(), 'timestamp_failed' => $translations->getTimestampFailedNotice(), 'webhook_failed' => $translations->getWebhookFailedNotice(), 'not_authenticated' => $translations->getNotAuthenticatedNotice(), 'open_authentication_button_text' => $translations->getOpenAuthenticationButtonText(), 'open_settings_button_text' => $translations->getOpenSettingsButtonText(), 'contact_wordproof_support_button_text' => $translations->getContactWordProofSupportButtonText()];
        return ['data' => ['origin' => \YoastSEO_Vendor\WordProof\SDK\Helpers\EnvironmentHelper::url(), 'is_authenticated' => \YoastSEO_Vendor\WordProof\SDK\Helpers\AuthenticationHelper::isAuthenticated(), 'popup_redirect_authentication_url' => \admin_url('admin.php?page=wordproof-redirect-authenticate'), 'popup_redirect_settings_url' => \admin_url('admin.php?page=wordproof-redirect-settings'), 'settings' => \YoastSEO_Vendor\WordProof\SDK\Helpers\SettingsHelper::get(), 'current_post_id' => $postId, 'current_post_type' => $postType, 'post_editor' => self::getPostEditor(), 'translations' => $translations, 'balance' => \YoastSEO_Vendor\WordProof\SDK\Helpers\OptionsHelper::get('balance')]];
    }
    /**
     * Returns the current post type.
     *
     * @return null|string The current post type.
     */
    public static function getCurrentPostType()
    {
        global $post, $typenow, $current_screen;
        if ($post && $post->post_type) {
            return $post->post_type;
        }
        if ($typenow) {
            return $typenow;
        }
        if ($current_screen && $current_screen->post_type) {
            return $current_screen->post_type;
        }
        // phpcs:disable WordPress.Security.NonceVerification
        if (isset($_REQUEST['post_type'])) {
            return \sanitize_key($_REQUEST['post_type']);
        }
        // phpcs:enable WordPress.Security.NonceVerification
        return null;
    }
}
