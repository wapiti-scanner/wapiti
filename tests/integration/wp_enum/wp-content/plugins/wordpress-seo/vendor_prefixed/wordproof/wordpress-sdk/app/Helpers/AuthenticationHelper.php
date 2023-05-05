<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

class AuthenticationHelper
{
    /**
     * Removes all the options set by WordProof.
     *
     * @return void
     */
    public static function logout()
    {
        \YoastSEO_Vendor\WordProof\SDK\Helpers\OptionsHelper::resetAuthentication();
    }
    /**
     * Returns if the user is authenticated.
     *
     * @return bool If the user is authenticated.
     */
    public static function isAuthenticated()
    {
        $options = \YoastSEO_Vendor\WordProof\SDK\Helpers\OptionsHelper::all();
        return $options->access_token && $options->source_id;
    }
}
