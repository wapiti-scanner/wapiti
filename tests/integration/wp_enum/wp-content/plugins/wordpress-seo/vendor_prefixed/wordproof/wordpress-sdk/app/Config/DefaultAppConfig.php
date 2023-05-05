<?php

namespace YoastSEO_Vendor\WordProof\SDK\Config;

class DefaultAppConfig implements \YoastSEO_Vendor\WordProof\SDK\Config\AppConfigInterface
{
    /**
     * @return string
     */
    public function getPartner()
    {
        return 'wordproof';
    }
    /**
     * @return string
     */
    public function getEnvironment()
    {
        return 'production';
    }
    /**
     * @return boolean
     */
    public function getLoadUikitFromCdn()
    {
        return \true;
    }
    /**
     * @return null
     */
    public function getOauthClient()
    {
        return null;
    }
    /**
     * @return null
     */
    public function getWordProofUrl()
    {
        return null;
    }
    /**
     * @return null
     */
    public function getScriptsFileOverwrite()
    {
        return null;
    }
}
