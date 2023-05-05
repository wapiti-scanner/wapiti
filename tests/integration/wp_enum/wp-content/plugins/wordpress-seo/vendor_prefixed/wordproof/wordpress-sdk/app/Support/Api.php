<?php

namespace YoastSEO_Vendor\WordProof\SDK\Support;

use YoastSEO_Vendor\WordProof\SDK\Helpers\EnvironmentHelper;
use YoastSEO_Vendor\WordProof\SDK\Helpers\OptionsHelper;
class Api
{
    /**
     * @param string $endpoint
     * @param array $body
     * @return mixed
     */
    public static function post($endpoint, $body = [])
    {
        $location = \YoastSEO_Vendor\WordProof\SDK\Helpers\EnvironmentHelper::url() . $endpoint;
        $body = \wp_json_encode($body);
        $accessToken = \YoastSEO_Vendor\WordProof\SDK\Helpers\OptionsHelper::accessToken();
        $headers = ['Content-Type' => 'application/json', 'Accept' => 'application/json'];
        $headers = $accessToken ? \array_merge($headers, ['Authorization' => 'Bearer ' . $accessToken]) : $headers;
        $options = ['body' => $body, 'headers' => $headers, 'timeout' => 60, 'redirection' => 5, 'blocking' => \true, 'data_format' => 'body', 'sslverify' => \YoastSEO_Vendor\WordProof\SDK\Helpers\EnvironmentHelper::sslVerify()];
        $request = \wp_remote_post($location, $options);
        $status = \wp_remote_retrieve_response_code($request);
        if ($status < 200 || $status >= 300) {
            return \false;
        }
        return \json_decode(\wp_remote_retrieve_body($request));
    }
}
