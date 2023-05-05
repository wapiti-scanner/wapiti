<?php

namespace YoastSEO_Vendor\WordProof\SDK\Config;

class ScriptsConfig extends \YoastSEO_Vendor\WordProof\SDK\Config\Config
{
    /**
     * Returns an array with the environment config.
     *
     * @return array
     */
    protected static function values()
    {
        return ['data' => ['dependencies' => ['wp-data', 'lodash', 'wp-api-fetch'], 'type' => 'js'], 'wordproof-block-editor' => ['dependencies' => ['wp-i18n', 'wp-element', 'wp-components', 'wp-editor', 'wp-edit-post', 'wp-data', 'lodash', 'wordproof-data'], 'type' => 'js'], 'wordproof-elementor-editor' => ['dependencies' => ['wp-i18n', 'wp-element', 'wp-components', 'wp-editor', 'wp-edit-post', 'wp-data', 'lodash', 'wordproof-data', 'elementor-common'], 'type' => 'js'], 'wordproof-classic-editor' => ['dependencies' => ['wp-i18n', 'wp-element', 'wp-components', 'wp-editor', 'wp-edit-post', 'wp-data', 'lodash', 'wordproof-data'], 'type' => 'js']];
    }
}
