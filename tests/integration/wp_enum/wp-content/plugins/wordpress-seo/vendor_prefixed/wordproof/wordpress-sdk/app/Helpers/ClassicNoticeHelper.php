<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

class ClassicNoticeHelper
{
    /**
     * @var string The key used for the transient to save the single notice.
     */
    public static $transientKey = 'wordproof_notice';
    /**
     * Add a new transient with a notice key.
     *
     * @param string $noticeKey The noticeKey that should be displayed to the user.
     */
    public static function add($noticeKey)
    {
        \YoastSEO_Vendor\WordProof\SDK\Helpers\TransientHelper::set(self::$transientKey, $noticeKey);
    }
    /**
     * Add new notice depending on the timestamp response.
     *
     * @param \WP_REST_Response $response The timestamp response.
     */
    public static function addTimestampNotice($response)
    {
        $notice = self::getNoticeKeyForTimestampResponse($response->get_data());
        if ($notice) {
            self::add($notice);
        }
    }
    /**
     * Retrieve notice key for the timestamp response data.
     *
     * @param object $data The timestamp response data.
     * @return string The notice key for this response data.
     */
    private static function getNoticeKeyForTimestampResponse($data)
    {
        if (isset($data->error) && $data->error === 'not_authenticated') {
            return 'not_authenticated';
        }
        if (isset($data->balance) && $data->balance === 0) {
            return 'no_balance';
        }
        if (isset($data->hash)) {
            return 'timestamp_success';
        }
        if (isset($data->error) && $data->error === 'timestamp_failed') {
            return 'timestamp_failed';
        }
        return null;
    }
}
