<?php

namespace YoastSEO_Vendor\WordProof\SDK\Config;

abstract class Config
{
    /**
     * Try to return config values using the dot syntax.
     *
     * @param string|null $key The key of the config using the dot syntax.
     * @return array|mixed Returns the entire config array if not found, otherwise the value itself.
     */
    public static function get($key = null)
    {
        if (!isset($key)) {
            return static::values();
        }
        $keys = \explode('.', $key);
        $value = static::values();
        foreach ($keys as $key) {
            if (isset($value[$key])) {
                $value = $value[$key];
            } else {
                return \false;
            }
        }
        return $value;
    }
    /**
     * Should return an array with the config.
     *
     * @return array An array containing the config values.
     */
    protected static function values()
    {
        return [];
    }
}
