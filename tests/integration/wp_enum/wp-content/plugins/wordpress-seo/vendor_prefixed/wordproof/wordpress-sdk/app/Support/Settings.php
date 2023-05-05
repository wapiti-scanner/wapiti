<?php

namespace YoastSEO_Vendor\WordProof\SDK\Support;

use YoastSEO_Vendor\WordProof\SDK\Helpers\AuthenticationHelper;
use YoastSEO_Vendor\WordProof\SDK\Helpers\OptionsHelper;
use YoastSEO_Vendor\WordProof\SDK\Helpers\AppConfigHelper;
class Settings
{
    public static function redirect($redirectUrl = null)
    {
        if (!\YoastSEO_Vendor\WordProof\SDK\Helpers\AuthenticationHelper::isAuthenticated()) {
            return \false;
        }
        $options = \YoastSEO_Vendor\WordProof\SDK\Helpers\OptionsHelper::all();
        if (!$options->source_id) {
            return \false;
        }
        $endpoint = "/sources/" . $options->source_id . "/settings";
        if (\YoastSEO_Vendor\WordProof\SDK\Helpers\AppConfigHelper::getPartner() === 'yoast') {
            $endpoint = '/yoast/dashboard';
        }
        \YoastSEO_Vendor\WordProof\SDK\Support\Authentication::redirect($endpoint, ['redirect_uri' => $redirectUrl, 'partner' => \YoastSEO_Vendor\WordProof\SDK\Helpers\AppConfigHelper::getPartner(), 'source_id' => $options->source_id, 'access_token_login' => $options->access_token]);
    }
}
