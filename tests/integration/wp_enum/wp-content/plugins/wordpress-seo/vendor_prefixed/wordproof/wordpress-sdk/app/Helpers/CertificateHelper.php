<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

class CertificateHelper
{
    /**
     * Returns if the certificate should be displayed for this page.
     *
     * @return false If the certificate should be shown.
     */
    public static function show()
    {
        if (!\is_singular()) {
            return \false;
        }
        if (!\is_main_query()) {
            return \false;
        }
        if (\post_password_required()) {
            return \false;
        }
        global $post;
        return \apply_filters('wordproof_timestamp_show_certificate', \YoastSEO_Vendor\WordProof\SDK\Helpers\PostMetaHelper::has($post->ID, '_wordproof_schema'), $post);
    }
}
