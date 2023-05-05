<?php

namespace YoastSEO_Vendor\WordProof\SDK;

use YoastSEO_Vendor\WordProof\SDK\Config\DefaultAppConfig;
use YoastSEO_Vendor\WordProof\SDK\Config\AppConfigInterface;
use YoastSEO_Vendor\WordProof\SDK\Controllers\NoticeController;
use YoastSEO_Vendor\WordProof\SDK\Controllers\PostEditorDataController;
use YoastSEO_Vendor\WordProof\SDK\Controllers\PostEditorTimestampController;
use YoastSEO_Vendor\WordProof\SDK\Controllers\RestApiController;
use YoastSEO_Vendor\WordProof\SDK\Controllers\AuthenticationController;
use YoastSEO_Vendor\WordProof\SDK\Controllers\CertificateController;
use YoastSEO_Vendor\WordProof\SDK\Controllers\SettingsController;
use YoastSEO_Vendor\WordProof\SDK\Controllers\TimestampController;
use YoastSEO_Vendor\WordProof\SDK\Support\Loader;
use YoastSEO_Vendor\WordProof\SDK\Translations\DefaultTranslations;
use YoastSEO_Vendor\WordProof\SDK\Translations\TranslationsInterface;
class WordPressSDK
{
    /**
     * The version of this SDK
     * @var string
     */
    public $version = '1.3.2';
    /**
     * @var null|WordPressSDK
     */
    private static $instance = null;
    /**
     * Loader responsible for the WordPress hooks
     * @var Loader
     */
    private $loader;
    /**
     * Appconfig object
     * @var AppConfigInterface
     */
    public $appConfig;
    /**
     * Translations object
     * @var TranslationsInterface
     */
    private $translations;
    /**
     * WordPressSDK constructor.
     *
     * @return WordPressSDK|void
     *
     * @throws \Exception
     */
    public function __construct(\YoastSEO_Vendor\WordProof\SDK\Config\AppConfigInterface $appConfig = null, \YoastSEO_Vendor\WordProof\SDK\Translations\TranslationsInterface $translations = null)
    {
        if (\defined('WORDPROOF_TIMESTAMP_SDK_VERSION')) {
            return;
        }
        $this->loader = new \YoastSEO_Vendor\WordProof\SDK\Support\Loader();
        $this->appConfig = $appConfig ?: new \YoastSEO_Vendor\WordProof\SDK\Config\DefaultAppConfig();
        $this->translations = $translations ?: new \YoastSEO_Vendor\WordProof\SDK\Translations\DefaultTranslations();
        $this->authentication();
        $this->api();
        $this->timestamp();
        $this->settings();
        $this->postEditorData();
        $this->notices();
        if (!\defined('WORDPROOF_TIMESTAMP_SDK_FILE')) {
            \define('WORDPROOF_TIMESTAMP_SDK_FILE', __FILE__);
        }
        if (!\defined('WORDPROOF_TIMESTAMP_SDK_VERSION')) {
            \define('WORDPROOF_TIMESTAMP_SDK_VERSION', $this->version);
        }
        return $this;
    }
    /**
     * Singleton implementation of WordPress SDK.
     *
     * @param AppConfigInterface|null $appConfig
     * @param TranslationsInterface|null $translations
     * @return WordPressSDK|null Returns the WordPress SDK instance.
     * @throws \Exception
     */
    public static function getInstance(\YoastSEO_Vendor\WordProof\SDK\Config\AppConfigInterface $appConfig = null, \YoastSEO_Vendor\WordProof\SDK\Translations\TranslationsInterface $translations = null)
    {
        if (self::$instance === null) {
            self::$instance = new \YoastSEO_Vendor\WordProof\SDK\WordPressSDK($appConfig, $translations);
        }
        return self::$instance;
    }
    /**
     * Runs the loader and initializes the class.
     *
     * @return $this
     */
    public function initialize()
    {
        $this->loader->run();
        return $this;
    }
    /**
     * Initializes the authentication feature.
     */
    private function authentication()
    {
        $class = new \YoastSEO_Vendor\WordProof\SDK\Controllers\AuthenticationController();
        $this->loader->addAction('wordproof_authenticate', $class, 'authenticate');
        $this->loader->addAction('admin_menu', $class, 'addRedirectPage');
        $this->loader->addAction('admin_menu', $class, 'addSelfDestructPage');
        $this->loader->addAction('load-admin_page_wordproof-redirect-authenticate', $class, 'redirectOnLoad');
    }
    /**
     * Initializes the api feature.
     */
    private function api()
    {
        $class = new \YoastSEO_Vendor\WordProof\SDK\Controllers\RestApiController();
        $this->loader->addAction('rest_api_init', $class, 'init');
    }
    /**
     * Adds hooks to timestamp posts on new inserts or on a custom action.
     */
    private function timestamp()
    {
        $class = new \YoastSEO_Vendor\WordProof\SDK\Controllers\TimestampController();
        $this->loader->addAction('added_post_meta', $class, 'syncPostMetaTimestampOverrides', \PHP_INT_MAX, 4);
        $this->loader->addAction('updated_post_meta', $class, 'syncPostMetaTimestampOverrides', \PHP_INT_MAX, 4);
        $this->loader->addAction('rest_after_insert_post', $class, 'timestampAfterRestApiRequest');
        $this->loader->addAction('wp_insert_post', $class, 'timestampAfterPostRequest', \PHP_INT_MAX, 2);
        $this->loader->addAction('edit_attachment', $class, 'timestampAfterAttachmentRequest', \PHP_INT_MAX);
        $this->loader->addAction('add_attachment', $class, 'timestampAfterAttachmentRequest', \PHP_INT_MAX);
        $this->loader->addAction('wordproof_timestamp', $class, 'timestamp');
        $this->loader->addAction('elementor/document/before_save', $class, 'beforeElementorSave');
    }
    /**
     * Adds admin pages that redirect to the WordProof My settings page.
     */
    private function settings()
    {
        $class = new \YoastSEO_Vendor\WordProof\SDK\Controllers\SettingsController();
        $this->loader->addAction('wordproof_settings', $class, 'redirect');
        $this->loader->addAction('admin_menu', $class, 'addRedirectPage');
        $this->loader->addAction('load-admin_page_wordproof-redirect-settings', $class, 'redirectOnLoad');
    }
    /**
     * Registers and localizes post editor scripts.
     */
    private function postEditorData()
    {
        $class = new \YoastSEO_Vendor\WordProof\SDK\Controllers\PostEditorDataController($this->translations);
        $this->loader->addAction('admin_enqueue_scripts', $class, 'addScript');
        $this->loader->addAction('elementor/editor/before_enqueue_scripts', $class, 'addScriptForElementor');
    }
    /**
     * Initializes the notices feature.
     */
    private function notices()
    {
        $class = new \YoastSEO_Vendor\WordProof\SDK\Controllers\NoticeController($this->translations);
        $this->loader->addAction('admin_notices', $class, 'show');
    }
    /**
     * Optional feature to include the schema and certificate to the page.
     *
     * @return $this
     */
    public function certificate()
    {
        $class = new \YoastSEO_Vendor\WordProof\SDK\Controllers\CertificateController();
        $this->loader->addAction('wp_head', $class, 'head');
        $this->loader->addFilter('the_content', $class, 'certificateTag');
        return $this;
    }
    /**
     * Optional feature to timestamp with JS in the post editor.
     *
     * @return $this
     */
    public function timestampInPostEditor()
    {
        $class = new \YoastSEO_Vendor\WordProof\SDK\Controllers\PostEditorTimestampController();
        // Gutenberg
        $this->loader->addAction('init', $class, 'registerPostMeta', \PHP_INT_MAX);
        $this->loader->addAction('enqueue_block_editor_assets', $class, 'enqueueBlockEditorScript');
        // Classic editor
        $this->loader->addAction('add_meta_boxes', $class, 'addMetaboxToClassicEditor');
        $this->loader->addAction('save_post', $class, 'saveClassicMetaboxPostMeta');
        $this->loader->addAction('edit_attachment', $class, 'saveClassicMetaboxPostMeta');
        $this->loader->addAction('admin_enqueue_scripts', $class, 'enqueueClassicEditorScript');
        // Elementor
        $this->loader->addAction('elementor/editor/after_enqueue_scripts', $class, 'enqueueElementorEditorScript');
        $this->loader->addAction('elementor/documents/register_controls', $class, 'registerControl');
        $this->loader->addAction('elementor/editor/after_save', $class, 'elementorSave');
        return $this;
    }
}
