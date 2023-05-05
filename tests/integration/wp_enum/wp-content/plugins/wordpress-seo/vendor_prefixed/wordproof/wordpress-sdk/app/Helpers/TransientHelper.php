<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

use YoastSEO_Vendor\WordProof\SDK\DataTransferObjects\TimestampData;
class TransientHelper
{
    /**
     * Set transient.
     *
     * @param $key
     * @param $value
     * @param int $expiration
     * @return bool
     */
    public static function set($key, $value, $expiration = 0)
    {
        return \set_transient($key, $value, $expiration);
    }
    /**
     * Returns and deletes site transient by key.
     *
     * @param $key
     * @return mixed
     */
    public static function getOnce($key)
    {
        $value = \get_transient($key);
        \delete_transient($key);
        return $value;
    }
    /**
     * Returns the transient by key.
     *
     * @param $key
     * @return mixed
     */
    public static function get($key)
    {
        return \get_transient($key);
    }
    /**
     * Debounce callback for post id.
     *
     * @param $postId
     * @param $action
     * @param $callback
     * @return mixed
     */
    public static function debounce($postId, $action, $callback)
    {
        $key = 'wordproof_debounce_' . $action . '_' . $postId;
        $transient = \YoastSEO_Vendor\WordProof\SDK\Helpers\TransientHelper::get($key);
        if ($transient) {
            return $transient;
        } else {
            \YoastSEO_Vendor\WordProof\SDK\Helpers\TransientHelper::set($key, \true, 4);
            $result = $callback();
            return $result;
        }
    }
}
