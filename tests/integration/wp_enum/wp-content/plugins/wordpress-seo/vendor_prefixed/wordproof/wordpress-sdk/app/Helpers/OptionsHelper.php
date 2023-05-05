<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

use YoastSEO_Vendor\WordProof\SDK\Config\OptionsConfig;
class OptionsHelper
{
    private static $prefix = 'wordproof_';
    /**
     * Sets site option while properly sanitizing the data.
     *
     * @param string $key The key to set.
     * @param mixed $value The value to save.
     * @return bool If update_option succeeded.
     */
    public static function set($key, $value)
    {
        if (self::optionContainsOptions($key)) {
            $sanitizedValue = self::secureOptionWithOptions($key, $value, 'sanitize');
            return \update_option(self::$prefix . $key, (object) $sanitizedValue);
        } else {
            $option = self::getOptionFromConfig($key);
            $sanitizedValue = \YoastSEO_Vendor\WordProof\SDK\Helpers\SanitizeHelper::sanitize($value, $option['escape']);
            return \update_option(self::$prefix . $key, $sanitizedValue);
        }
    }
    /**
     * Deletes the site options.
     *
     * @param string $key The key to be deleted.
     * @return mixed
     */
    public static function delete($key)
    {
        return \delete_option(self::$prefix . $key);
    }
    /**
     * Retrieves the site option while properly escaping the data.
     *
     * @param string $key The site option.
     * @return array|bool|int|object|string
     */
    public static function get($key)
    {
        $option = self::getOptionFromConfig($key);
        $value = \get_option(self::$prefix . $key);
        if (self::optionContainsOptions($key)) {
            return self::secureOptionWithOptions($key, $value, 'escape');
        } else {
            return \YoastSEO_Vendor\WordProof\SDK\Helpers\EscapeHelper::escape($value, $option['escape']);
        }
    }
    /**
     * Returns all site options as object.
     *
     * @return object
     */
    public static function all()
    {
        $optionKeys = \array_keys(\YoastSEO_Vendor\WordProof\SDK\Config\OptionsConfig::get());
        foreach ($optionKeys as $key) {
            $options[$key] = self::get($key);
        }
        return (object) $options;
    }
    /**
     * Deletes all site options.
     */
    public static function reset()
    {
        $optionKeys = \array_keys(\YoastSEO_Vendor\WordProof\SDK\Config\OptionsConfig::get());
        foreach ($optionKeys as $key) {
            self::delete($key);
        }
    }
    /**
     * Deletes authentication options.
     */
    public static function resetAuthentication()
    {
        $optionKeys = ['access_token', 'source_id'];
        foreach ($optionKeys as $key) {
            self::delete($key);
        }
    }
    /**
     * Retrieves the access token.
     *
     * @return string|null
     */
    public static function accessToken()
    {
        return self::get('access_token');
    }
    /**
     * Retrieves the source id.
     *
     * @return integer|null
     */
    public static function sourceId()
    {
        return self::get('source_id');
    }
    /**
     * Sets the access token.
     *
     * @param string|null $value The access token to be set.
     * @return bool
     */
    public static function setAccessToken($value)
    {
        return self::set('access_token', $value);
    }
    /**
     * Sets the source id.
     *
     * @param integer|null $value The source id to be set.
     * @return bool
     */
    public static function setSourceId($value)
    {
        return self::set('source_id', $value);
    }
    /**
     * Retrieves the option settings from the config.
     *
     * @param string $key The option key.
     * @return array|false|mixed
     */
    private static function getOptionFromConfig($key)
    {
        $option = \YoastSEO_Vendor\WordProof\SDK\Config\OptionsConfig::get($key);
        if ($option && \array_key_exists('escape', $option) && \array_key_exists('default', $option)) {
            return $option;
        }
        return \false;
    }
    /**
     * Returns if the given option key contains options itself.
     *
     * @param string $key The option key to be checked.
     * @return bool
     */
    private static function optionContainsOptions($key)
    {
        $option = \YoastSEO_Vendor\WordProof\SDK\Config\OptionsConfig::get($key);
        return $option && \array_key_exists('options', $option);
    }
    /**
     * Loops through an option that contains options to either sanitize or escape the result.
     *
     * @param $key
     * @param $value
     * @param string $method
     * @return array|object
     */
    private static function secureOptionWithOptions($key, $value, $method = 'sanitize')
    {
        $isObject = \is_object($value);
        if (\is_object($value)) {
            $value = (array) $value;
        }
        if (\is_array($value)) {
            $values = [];
            foreach ($value as $optionKey => $optionValue) {
                $optionConfig = self::getOptionFromConfig($key . '.options.' . $optionKey);
                if (!$optionConfig) {
                    continue;
                }
                if ($method === 'escape') {
                    $securedValue = \YoastSEO_Vendor\WordProof\SDK\Helpers\EscapeHelper::escape($optionValue, $optionConfig['escape']);
                } else {
                    $securedValue = \YoastSEO_Vendor\WordProof\SDK\Helpers\SanitizeHelper::sanitize($optionValue, $optionConfig['escape']);
                }
                $values[$optionKey] = $securedValue;
            }
            if ($isObject) {
                return (object) $values;
            }
            return $values;
        }
        return [];
    }
}
