<?php

namespace YoastSEO_Vendor\WordProof\SDK\Helpers;

use YoastSEO_Vendor\WordProof\SDK\Config\EnvironmentConfig;
class EnvironmentHelper
{
    public static function url()
    {
        $appConfig = \YoastSEO_Vendor\WordProof\SDK\Helpers\AppConfigHelper::getAppConfig();
        if ($appConfig->getWordProofUrl()) {
            return $appConfig->getWordProofUrl();
        }
        return self::get('url');
    }
    public static function client()
    {
        $appConfig = \YoastSEO_Vendor\WordProof\SDK\Helpers\AppConfigHelper::getAppConfig();
        if ($appConfig->getOauthClient()) {
            return $appConfig->getOauthClient();
        }
        return self::get('client');
    }
    public static function sslVerify()
    {
        return !\YoastSEO_Vendor\WordProof\SDK\Helpers\EnvironmentHelper::development();
    }
    public static function development()
    {
        return \YoastSEO_Vendor\WordProof\SDK\Helpers\AppConfigHelper::getEnvironment() === 'development';
    }
    public static function get($key)
    {
        $envConfig = self::environmentConfig();
        if ($envConfig && isset($envConfig[$key])) {
            return $envConfig[$key];
        }
        return null;
    }
    private static function environmentConfig()
    {
        $env = \YoastSEO_Vendor\WordProof\SDK\Helpers\AppConfigHelper::getEnvironment();
        return \YoastSEO_Vendor\WordProof\SDK\Config\EnvironmentConfig::get($env);
    }
}
