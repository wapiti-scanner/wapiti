<?php

namespace YoastSEO_Vendor\WordProof\SDK\Controllers;

use YoastSEO_Vendor\WordProof\SDK\Helpers\ClassicNoticeHelper;
use YoastSEO_Vendor\WordProof\SDK\Helpers\PostMetaHelper;
use YoastSEO_Vendor\WordProof\SDK\Helpers\TimestampHelper;
use YoastSEO_Vendor\WordProof\SDK\Helpers\TransientHelper;
class TimestampController
{
    /**
     * Timestamp an post triggered by custom action.
     *
     * @param integer $postId The post id to be timestamped.
     * @action wordproof_timestamp
     */
    public static function timestamp($postId)
    {
        $post = \get_post(\intval($postId));
        return \YoastSEO_Vendor\WordProof\SDK\Helpers\TimestampHelper::debounce($post);
    }
    /**
     * Timestamp new posts except those inserted by the API.
     *
     * @param integer $postId The post id to be timestamped.
     * @param \WP_Post $post The post to be timestamped.
     * @action wp_insert_post
     */
    public function timestampAfterPostRequest($postId, $post)
    {
        if (\defined('REST_REQUEST') && \REST_REQUEST) {
            return;
        }
        $response = \YoastSEO_Vendor\WordProof\SDK\Helpers\TimestampHelper::debounce($post);
        \YoastSEO_Vendor\WordProof\SDK\Helpers\ClassicNoticeHelper::addTimestampNotice($response);
        return $response;
    }
    /**
     * Timestamp new attachments.
     *
     * @param integer $postId The post id to be timestamped.
     *
     * @action add_attachment|edit_attachment
     */
    public function timestampAfterAttachmentRequest($postId)
    {
        $post = \get_post($postId);
        $this->timestampAfterPostRequest($postId, $post);
    }
    /**
     * Timestamp posts inserted by the API.
     *
     * @param \WP_Post $post The post to be timestamped.
     * @action rest_after_insert_post
     */
    public function timestampAfterRestApiRequest($post)
    {
        return \YoastSEO_Vendor\WordProof\SDK\Helpers\TimestampHelper::debounce($post);
    }
    /**
     * Removes action to timestamp post on insert if Elementor is used.
     */
    public function beforeElementorSave()
    {
        \remove_action('rest_after_insert_post', [$this, 'timestampAfterRestApiRequest']);
        \remove_action('wp_insert_post', [$this, 'timestampAfterPostRequest'], \PHP_INT_MAX);
    }
    /**
     * Syncs timestamp override post meta keys.
     *
     * @param $metaId
     * @param $postId
     * @param $metaKey
     * @param $metaValue
     */
    public function syncPostMetaTimestampOverrides($metaId, $postId, $metaKey, $metaValue)
    {
        $timestampablePostMetaKeys = \apply_filters('wordproof_timestamp_post_meta_key_overrides', ['_wordproof_timestamp']);
        if (\in_array($metaKey, $timestampablePostMetaKeys, \true) && \count($timestampablePostMetaKeys) > 1) {
            $arrayKey = \array_search($metaKey, $timestampablePostMetaKeys, \true);
            unset($timestampablePostMetaKeys[$arrayKey]);
            \YoastSEO_Vendor\WordProof\SDK\Helpers\TransientHelper::set('wordproof_debounce_post_meta_sync_' . $metaKey . '_' . $postId, \true, 5);
            foreach ($timestampablePostMetaKeys as $key) {
                \YoastSEO_Vendor\WordProof\SDK\Helpers\TransientHelper::debounce($postId, 'post_meta_sync_' . $key, function () use($postId, $key, $metaValue) {
                    return \YoastSEO_Vendor\WordProof\SDK\Helpers\PostMetaHelper::update($postId, $key, $metaValue);
                });
            }
        }
    }
}
