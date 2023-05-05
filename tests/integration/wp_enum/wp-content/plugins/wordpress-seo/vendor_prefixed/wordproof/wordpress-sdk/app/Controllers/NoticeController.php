<?php

namespace YoastSEO_Vendor\WordProof\SDK\Controllers;

use YoastSEO_Vendor\WordProof\SDK\Helpers\ClassicNoticeHelper;
use YoastSEO_Vendor\WordProof\SDK\Helpers\TransientHelper;
use YoastSEO_Vendor\WordProof\SDK\Translations\TranslationsInterface;
class NoticeController
{
    /**
     * @var string[] The screens on which notices should be rendered.
     */
    private $screens = ['post'];
    /**
     * @var TranslationsInterface The translations objects,
     */
    private $translations;
    public function __construct(\YoastSEO_Vendor\WordProof\SDK\Translations\TranslationsInterface $translations)
    {
        $this->translations = $translations;
    }
    /**
     * Showing notices for the classic editor and delete them so they are only shown once.
     *
     * @action admin_notices
     */
    public function show()
    {
        $screen = \get_current_screen();
        if (!\in_array($screen->base, $this->screens, \true)) {
            return;
        }
        $notice = \YoastSEO_Vendor\WordProof\SDK\Helpers\TransientHelper::getOnce(\YoastSEO_Vendor\WordProof\SDK\Helpers\ClassicNoticeHelper::$transientKey);
        if (!isset($notice) || !$notice) {
            return;
        }
        switch ($notice) {
            case 'no_balance':
                $type = 'error';
                $message = $this->translations->getNoBalanceNotice();
                $buttonText = $this->translations->getOpenSettingsButtonText();
                $buttonEventName = 'wordproof:open_settings';
                break;
            case 'timestamp_success':
                $type = 'success';
                $message = $this->translations->getTimestampSuccessNotice();
                break;
            case 'timestamp_failed':
                $type = 'error';
                $message = $this->translations->getTimestampFailedNotice();
                break;
            case 'not_authenticated':
                $type = 'error';
                $message = $this->translations->getNotAuthenticatedNotice();
                $buttonText = $this->translations->getOpenAuthenticationButtonText();
                $buttonEventName = 'wordproof:open_authentication';
                break;
            default:
                break;
        }
        if (isset($message) && isset($type)) {
            $noticeClass = 'notice-' . $type;
            echo \sprintf('<div class="notice %1$s is-dismissible"><p>%2$s</p>', \esc_attr($noticeClass), \esc_html($message));
            if (isset($buttonText) && isset($buttonEventName)) {
                echo \sprintf('<p><button class="button button-primary" onclick="window.dispatchEvent( new window.CustomEvent( \'%2$s\' ) )">%1$s</button></p>', \esc_html($buttonText), \esc_attr($buttonEventName));
            }
            echo '</div>';
        }
    }
}
