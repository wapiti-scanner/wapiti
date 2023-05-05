<?php

namespace YoastSEO_Vendor\WordProof\SDK\Translations;

class DefaultTranslations implements \YoastSEO_Vendor\WordProof\SDK\Translations\TranslationsInterface
{
    public function getNoBalanceNotice()
    {
        return \sprintf(
            /* translators: %s expands to WordProof. */
            __('You are out of timestamps. Please upgrade your account by opening the %s settings.', 'wordproof'),
            'WordProof'
        );
    }
    public function getTimestampFailedNotice()
    {
        return \sprintf(
            /* translators: %s expands to WordProof. */
            __('%1$s failed to timestamp this page. Please check if you\'re correctly authenticated with %1$s and try to save this page again.', 'wordproof'),
            'WordProof'
        );
    }
    public function getTimestampSuccessNotice()
    {
        return \sprintf(
            /* translators: %s expands to WordProof. */
            __('%s has successfully timestamped this page.', 'wordproof'),
            'WordProof'
        );
    }
    public function getWebhookFailedNotice()
    {
        /* translators: %s expands to WordProof. */
        return \sprintf(__('The timestamp is not retrieved by your site. Please try again or contact %1$s support.', 'wordproof'), 'WordProof');
    }
    public function getNotAuthenticatedNotice()
    {
        /* translators: %s expands to WordProof. */
        return \sprintf(__('The timestamp is not created because you need to authenticate with %s first.', 'wordproof'), 'WordProof');
    }
    public function getOpenAuthenticationButtonText()
    {
        return __('Authenticate', 'wordproof');
    }
    public function getOpenSettingsButtonText()
    {
        return __('Open settings', 'wordproof');
    }
    public function getContactWordProofSupportButtonText()
    {
        return \sprintf(
            /* translators: %s expands to WordProof. */
            __('Contact %s support.', 'wordproof'),
            'WordProof'
        );
    }
}
