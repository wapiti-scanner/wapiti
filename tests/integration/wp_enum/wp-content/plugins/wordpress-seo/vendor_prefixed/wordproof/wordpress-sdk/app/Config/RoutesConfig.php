<?php

namespace YoastSEO_Vendor\WordProof\SDK\Config;

class RoutesConfig extends \YoastSEO_Vendor\WordProof\SDK\Config\Config
{
    /**
     * Returns an array with the environment config.
     *
     * @return array
     */
    protected static function values()
    {
        return ['hashInput' => ['endpoint' => '/posts/(?P<id>\\d+)/hashinput/(?P<hash>[a-fA-F0-9]{64})', 'method' => 'get'], 'authenticate' => ['endpoint' => '/oauth/authenticate', 'method' => 'post'], 'timestamp' => ['endpoint' => '/posts/(?P<id>\\d+)/timestamp', 'method' => 'post'], 'timestamp.transaction.latest' => ['endpoint' => '/posts/(?P<id>\\d+)/timestamp/transaction/latest', 'method' => 'get'], 'webhook' => ['endpoint' => '/webhook', 'method' => 'get'], 'settings' => ['endpoint' => '/settings', 'method' => 'get'], 'saveSettings' => ['endpoint' => '/settings', 'method' => 'POST'], 'authentication' => ['endpoint' => '/authentication', 'method' => 'post'], 'authentication.destroy' => ['endpoint' => '/oauth/destroy', 'method' => 'post']];
    }
}
