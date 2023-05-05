<?php

namespace YoastSEO_Vendor\WordProof\SDK\Config;

interface AppConfigInterface
{
    /**
     * Your partner name.
     *
     * @default wordproof
     * @return string
     */
    public function getPartner();
    /**
     * The WordProof environment used. Either staging or production.
     *
     * @default production
     * @return string
     */
    public function getEnvironment();
    /**
     * The WordProof environment used. Either staging or production.
     *
     * @default true
     * @return boolean
     */
    public function getLoadUikitFromCdn();
    /**
     * Only used for local development.
     *
     * @return integer
     */
    public function getOauthClient();
    /**
     * Only used for local development.
     *
     * @return string
     */
    public function getWordProofUrl();
    /**
     * Only used for local development.
     *
     * @return string
     */
    public function getScriptsFileOverwrite();
}
