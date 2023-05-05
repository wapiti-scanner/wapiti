<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

class SanitizeHelper
{
    /**
     * Returns the value sanitized according to the escape function set in the class.
     *
     * @param mixed $value The value to be sanitized.
     * @param string $sanitizeKey The sanitize function to be used.
     *
     * @return array|bool|int|string
     */
    public static function sanitize($value, $sanitizeKey)
    {
        if (\is_array($value)) {
            return self::sanitizeArray($value, $sanitizeKey);
        }
        if (\is_object($value)) {
            return (object) self::sanitizeArray((array) $value, $sanitizeKey);
        }
        return self::sanitizeSingleValue($value, $sanitizeKey);
    }
    /**
     * Loops through the array to sanitize the values inside.
     *
     * @param array $array The array with values to be escaped.
     * @param string $sanitizeKey The sanitize function to be used.
     * @return array Array with escapes values.
     */
    private static function sanitizeArray($array, $sanitizeKey)
    {
        $values = [];
        foreach ($array as $key => $value) {
            $values[$key] = self::sanitizeSingleValue($value, $sanitizeKey);
        }
        return $values;
    }
    /**
     * Sanitize a single value using an escape function set in the class.
     *
     * @param string $value The value to be sanitized.
     * @param string $sanitizeKey The sanitize function to be used.
     * @return bool|int|string The sanitized value.
     */
    private static function sanitizeSingleValue($value, $sanitizeKey)
    {
        switch ($sanitizeKey) {
            case 'integer':
                return \intval($value);
            case 'boolean':
                return \boolval($value);
            case 'html_class':
                return \sanitize_html_class($value);
            case 'email':
                return \sanitize_email($value);
            case 'url':
                return \esc_url_raw($value);
            case 'key':
                return \sanitize_key($value);
            case 'text_field':
            default:
                return \sanitize_text_field($value);
        }
    }
}
