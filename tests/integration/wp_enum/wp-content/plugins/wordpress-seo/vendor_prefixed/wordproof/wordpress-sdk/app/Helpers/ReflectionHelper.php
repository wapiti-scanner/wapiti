<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

use YoastSEO_Vendor\WordProof\SDK\WordPressSDK;
class ReflectionHelper
{
    /**
     * @param class $instance The class from which to get the name.
     * @return false|string
     */
    public static function name($instance)
    {
        if ($instance instanceof \YoastSEO_Vendor\WordProof\SDK\WordPressSDK) {
            $reflector = new \ReflectionClass($instance);
            return $reflector->getName();
        }
        return \false;
    }
}
