<?php

namespace YoastSEO_Vendor\WordProof\SDK\Support;

use YoastSEO_Vendor\WordProof\SDK\Helpers\AuthenticationHelper;
use YoastSEO_Vendor\WordProof\SDK\Helpers\OptionsHelper;
use YoastSEO_Vendor\WordProof\SDK\Helpers\PostMetaHelper;
class Timestamp
{
    /**
     * @param array $data
     *
     * @return mixed
     */
    public static function sendPostRequest($data)
    {
        $sourceId = \YoastSEO_Vendor\WordProof\SDK\Helpers\OptionsHelper::sourceId();
        $endpoint = '/api/sources/' . $sourceId . '/timestamps';
        $response = \YoastSEO_Vendor\WordProof\SDK\Support\Api::post($endpoint, $data);
        if (!$response || !isset($response->hash)) {
            //            AuthenticationHelper::logout(); // TODO Only if response is unauthenticated
            return \false;
        }
        if (isset($response->balance)) {
            \YoastSEO_Vendor\WordProof\SDK\Helpers\OptionsHelper::set('balance', $response->balance);
        }
        $key = '_wordproof_hash_input_' . $response->hash;
        \YoastSEO_Vendor\WordProof\SDK\Helpers\PostMetaHelper::update($data['uid'], $key, \json_decode($response->hash_input));
        return $response;
    }
}
