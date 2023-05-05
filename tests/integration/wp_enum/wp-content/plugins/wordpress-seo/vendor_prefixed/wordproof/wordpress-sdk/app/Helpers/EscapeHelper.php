<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

class EscapeHelper
{
    /**
     * Returns the value escaped according to the escape function set in the class.
     *
     * @param mixed $value The value to be sanitized.
     * @param string $escapeKey The escape function to be used.
     *
     * @return array|bool|int|string
     */
    public static function escape($value, $escapeKey)
    {
        if (\is_array($value)) {
            return self::escapeArray($value, $escapeKey);
        }
        if (\is_object($value)) {
            return (object) self::escapeArray((array) $value, $escapeKey);
        }
        return self::escapeSingleValue($value, $escapeKey);
    }
    /**
     * Loops through the array to escape the values inside.
     *
     * @param array $array The array with values to be escaped.
     * @param string $escapeKey The escape function to be used.
     * @return array Array with escapes values.
     */
    private static function escapeArray($array, $escapeKey)
    {
        $values = [];
        foreach ($array as $key => $value) {
            $values[$key] = self::escapeSingleValue($value, $escapeKey);
        }
        return $values;
    }
    /**
     * Escapes a single value using an escape function set in the class.
     *
     * @param string $value The value to be escaped.
     * @param string $escapeKey The escape function to be used.
     * @return bool|int|string The escaped value.
     */
    private static function escapeSingleValue($value, $escapeKey)
    {
        switch ($escapeKey) {
            case 'integer':
                return \intval($value);
            case 'boolean':
                return \boolval($value);
            case 'html_class':
                return \esc_html_class($value);
            case 'email':
                return \esc_email($value);
            case 'url':
                return \esc_url_raw($value);
            case 'key':
                return \esc_key($value);
            case 'text_field':
            default:
                return \esc_html($value);
        }
    }
}
