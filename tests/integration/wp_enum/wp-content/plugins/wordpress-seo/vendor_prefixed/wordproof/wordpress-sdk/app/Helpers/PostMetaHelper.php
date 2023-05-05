<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

class PostMetaHelper
{
    /**
     * @param integer $postId The post id for which the meta should be set.
     * @param string $key The key for the post meta.
     * @param mixed $value The value for the post meta.
     * @return integer|boolean Returns the post meta id or false on failure.
     */
    public static function add($postId, $key, $value, $single = \false)
    {
        return \add_post_meta($postId, $key, $value, $single);
    }
    /**
     * @param integer $postId The post id for which the meta should be set.
     * @param string $key The key for the post meta.
     * @param mixed $value The value for the post meta.
     * @return integer|boolean Returns the post meta id or false on failure.
     */
    public static function update($postId, $key, $value)
    {
        return \update_post_meta($postId, $key, $value);
    }
    /**
     * @param integer $postId The post id for which the meta should be set.
     * @param string $key The key for the post meta.
     * @param bool $single If a single result should be returned.
     * @return mixed Returns the post meta data or false on failure.
     */
    public static function get($postId, $key, $single = \true)
    {
        return \get_post_meta($postId, $key, $single);
    }
    /**
     * @param integer $postId The post id for which the meta should be set.
     * @param string $key The key for the post meta.
     * @return boolean Returns if the post meta key exists for the post id.
     */
    public static function has($postId, $key)
    {
        return \boolval(self::get($postId, $key));
    }
}
