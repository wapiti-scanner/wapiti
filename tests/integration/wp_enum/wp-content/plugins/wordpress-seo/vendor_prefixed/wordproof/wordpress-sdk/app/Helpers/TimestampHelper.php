<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

use YoastSEO_Vendor\WordProof\SDK\DataTransferObjects\TimestampData;
use YoastSEO_Vendor\WordProof\SDK\Support\Timestamp;
class TimestampHelper
{
    public static function debounce(\WP_Post $post)
    {
        $key = 'wordproof_timestamped_debounce_' . $post->id;
        $data = \YoastSEO_Vendor\WordProof\SDK\DataTransferObjects\TimestampData::fromPost($post);
        $transient = \YoastSEO_Vendor\WordProof\SDK\Helpers\TransientHelper::get($key);
        if ($transient) {
            return new \WP_REST_Response($transient, $transient->status);
        }
        $response = self::shouldBeTimestamped($post, $data);
        if (\is_bool($response) && $response === \false) {
            $response = (object) ['status' => 200, 'message' => 'Post should not be timestamped'];
            return new \WP_REST_Response($response, $response->status);
        }
        if (\is_array($response) && $response['timestamp'] === \false) {
            $response = (object) ['status' => 400, 'message' => 'Post should not be timestamped', 'error' => 'not_authenticated'];
            return new \WP_REST_Response($response, $response->status);
        }
        $response = \YoastSEO_Vendor\WordProof\SDK\Support\Timestamp::sendPostRequest($data);
        if ($response === \false) {
            $response = (object) ['status' => 400, 'message' => 'Something went wrong.', 'error' => 'timestamp_failed'];
            return new \WP_REST_Response($response, $response->status);
        }
        $response->status = 201;
        \YoastSEO_Vendor\WordProof\SDK\Helpers\TransientHelper::set($key, $response, 5);
        return new \WP_REST_Response($response, $response->status);
    }
    public static function shouldBeTimestamped(\WP_Post $post, $data)
    {
        if (!\YoastSEO_Vendor\WordProof\SDK\Helpers\AuthenticationHelper::isAuthenticated()) {
            if (self::hasPostMetaOverrideSetToTrue($post)) {
                return ['timestamp' => \false, 'notice' => 'not_authenticated'];
            }
            return \false;
        }
        if ($post->post_type !== 'attachment' && $post->post_content === '') {
            return \false;
        }
        if ($post->post_type === 'attachment' && \get_attached_file($post->ID) === \false) {
            return \false;
        }
        if (!\in_array($post->post_status, ['publish', 'inherit'], \true)) {
            return \false;
        }
        if (\YoastSEO_Vendor\WordProof\SDK\Helpers\SettingsHelper::postTypeIsInSelectedPostTypes($post->post_type)) {
            return \true;
        }
        if (self::hasPostMetaOverrideSetToTrue($post)) {
            return \true;
        }
        return \false;
    }
    private static function hasPostMetaOverrideSetToTrue(\WP_Post $post)
    {
        $timestampablePostMetaKeys = \apply_filters('wordproof_timestamp_post_meta_key_overrides', ['_wordproof_timestamp']);
        //Do not use PostMeta helper
        $meta = \get_post_meta($post->ID);
        foreach ($timestampablePostMetaKeys as $key) {
            if (!isset($meta[$key])) {
                continue;
            }
            if (\is_array($meta[$key])) {
                $value = \boolval($meta[$key][0]);
            } else {
                $value = \boolval($meta[$key]);
            }
            if (!$value) {
                continue;
            }
            return \true;
        }
        return \false;
    }
}
