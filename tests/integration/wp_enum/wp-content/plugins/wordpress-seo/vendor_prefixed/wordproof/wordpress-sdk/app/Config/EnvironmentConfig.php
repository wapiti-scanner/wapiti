<?php

namespace YoastSEO_Vendor\WordProof\SDK\Config;

class EnvironmentConfig extends \YoastSEO_Vendor\WordProof\SDK\Config\Config
{
    /**
     * Returns an array with the environment config.
     *
     * @return array
     */
    protected static function values()
    {
        return ['staging' => ['url' => 'https://staging.wordproof.com', 'client' => 78], 'production' => ['url' => 'https://my.wordproof.com', 'client' => 79]];
    }
}
