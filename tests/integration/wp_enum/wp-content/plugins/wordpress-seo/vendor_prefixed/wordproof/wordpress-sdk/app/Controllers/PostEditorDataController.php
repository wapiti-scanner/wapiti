<?php

namespace YoastSEO_Vendor\WordProof\SDK\Controllers;

use YoastSEO_Vendor\WordProof\SDK\Helpers\AssetHelper;
use YoastSEO_Vendor\WordProof\SDK\Helpers\PostEditorHelper;
use YoastSEO_Vendor\WordProof\SDK\Translations\TranslationsInterface;
class PostEditorDataController
{
    /**
     * @var TranslationsInterface The translations objects,
     */
    private $translations;
    /**
     * PostEditorDataController constructor.
     *
     * @param TranslationsInterface $translations The implemented translations interface.
     */
    public function __construct(\YoastSEO_Vendor\WordProof\SDK\Translations\TranslationsInterface $translations)
    {
        $this->translations = $translations;
    }
    /**
     * Add script for post edit pages.
     *
     * @param string $hook The current page.
     */
    public function addScript($hook)
    {
        $loadWordProofData = \apply_filters('wordproof_load_data_on_pages', \YoastSEO_Vendor\WordProof\SDK\Helpers\PostEditorHelper::getPostEditPages());
        if (\in_array($hook, $loadWordProofData, \true)) {
            $this->enqueueAndLocalizeScript();
        }
    }
    /**
     * Localizes the elementor script.
     */
    public function addScriptForElementor()
    {
        $this->enqueueAndLocalizeScript();
    }
    /**
     * Enqueues and localizes data script.
     */
    private function enqueueAndLocalizeScript()
    {
        $data = \YoastSEO_Vendor\WordProof\SDK\Helpers\PostEditorHelper::getPostEditorData($this->translations);
        $data = \apply_filters('wordproof_data', $data);
        \YoastSEO_Vendor\WordProof\SDK\Helpers\AssetHelper::enqueue('data');
        \YoastSEO_Vendor\WordProof\SDK\Helpers\AssetHelper::localize('data', 'wordproofSdk', $data);
    }
}
