<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

class StringHelper
{
    /**
     * Replace the last occurrence.
     *
     * @param string $search
     * @param string $replace
     * @param string $subject
     * @return string
     */
    public static function lastReplace($search, $replace, $subject)
    {
        $pos = \strrpos($subject, $search);
        if ($pos !== \false) {
            $subject = \substr_replace($subject, $replace, $pos, \strlen($search));
        }
        return $subject;
    }
    /**
     * PascalCase to snake_case
     *
     * @param $string
     * @return string
     */
    public static function toUnderscore($string)
    {
        return \strtolower(\preg_replace('/(?<!^)[A-Z]/', '_$0', $string));
    }
}
