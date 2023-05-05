<?php

namespace YoastSEO_Vendor\WordProof\SDK\Controllers;

use YoastSEO_Vendor\WordProof\SDK\Helpers\AssetHelper;
use YoastSEO_Vendor\WordProof\SDK\Helpers\PostEditorHelper;
use YoastSEO_Vendor\WordProof\SDK\Helpers\PostMetaHelper;
use YoastSEO_Vendor\WordProof\SDK\Helpers\PostTypeHelper;
class PostEditorTimestampController
{
    private $metaKey = '_wordproof_timestamp';
    private $classicEditorNonceKey = 'wordproof_timestamp_classic_nonce';
    /**
     * Registers post meta for all public post types.
     *
     * @action init
     */
    public function registerPostMeta()
    {
        foreach (\YoastSEO_Vendor\WordProof\SDK\Helpers\PostTypeHelper::getPublicPostTypes() as $postType) {
            register_post_meta($postType, $this->metaKey, ['show_in_rest' => \true, 'single' => \true, 'type' => 'boolean', 'default' => \false, 'supports' => ['editor', 'title', 'custom-fields'], 'auth_callback' => [$this, 'userCanEditPosts']]);
        }
    }
    /**
     * Returns if the current user can edit posts.
     *
     * @return boolean
     */
    public function userCanEditPosts()
    {
        return \current_user_can('edit_posts');
    }
    /**
     * Enqueues the wordproof-block-editor script.
     *
     * @action enqueue_block_editor_assets
     * @script wordproof-block-editor
     */
    public function enqueueBlockEditorScript()
    {
        \YoastSEO_Vendor\WordProof\SDK\Helpers\AssetHelper::enqueue('wordproof-block-editor');
    }
    /**
     * Enqueues the wordproof-elementor-editor script.
     *
     * @action elementor/editor/after_enqueue_scripts
     * @script wordproof-elementor-editor
     */
    public function enqueueElementorEditorScript()
    {
        \YoastSEO_Vendor\WordProof\SDK\Helpers\AssetHelper::enqueue('wordproof-elementor-editor');
    }
    /**
     * Enqueues the wordproof-classic-editor script.
     *
     * @action admin_enqueue_scripts
     * @script wordproof-classic-editor
     */
    public function enqueueClassicEditorScript($hook)
    {
        if (!\YoastSEO_Vendor\WordProof\SDK\Helpers\PostEditorHelper::isPostEdit($hook)) {
            return;
        }
        if (\YoastSEO_Vendor\WordProof\SDK\Helpers\PostEditorHelper::getPostEditor() === 'classic') {
            \YoastSEO_Vendor\WordProof\SDK\Helpers\AssetHelper::enqueue('wordproof-classic-editor');
        }
    }
    /**
     * Add Metabox to classic editor.
     *
     * @action add_meta_boxes
     */
    public function addMetaboxToClassicEditor()
    {
        foreach (\YoastSEO_Vendor\WordProof\SDK\Helpers\PostTypeHelper::getPublicPostTypes() as $postType) {
            \add_meta_box('wordproof_timestamp_metabox', 'WordProof Timestamp', [$this, 'classicMetaboxHtml'], $postType, 'side', 'default', ['__back_compat_meta_box' => \true]);
        }
    }
    /**
     * Save the meta box meta value for the classic editor.
     *
     * @param integer $postId The post ID.
     * @action save_post
     */
    public function saveClassicMetaboxPostMeta($postId)
    {
        if (\array_key_exists($this->classicEditorNonceKey, $_POST)) {
            if (\wp_verify_nonce(\sanitize_key($_POST[$this->classicEditorNonceKey]), 'save_post')) {
                \update_post_meta($postId, $this->metaKey, \array_key_exists($this->metaKey, $_POST));
            }
        }
    }
    /**
     * Display the meta box HTML to Classic Editor users.
     *
     * @param \WP_Post $post Post object.
     */
    public function classicMetaboxHtml($post)
    {
        $value = \YoastSEO_Vendor\WordProof\SDK\Helpers\PostMetaHelper::get($post->ID, $this->metaKey);
        \wp_nonce_field('save_post', $this->classicEditorNonceKey);
        ?>
    
        <div id="wordproof-toggle">
            <input type="checkbox" id="<?php 
        echo \esc_attr($this->metaKey);
        ?>" name="<?php 
        echo \esc_attr($this->metaKey);
        ?>"
                   value="1" <?php 
        echo \boolval($value) ? 'checked' : '';
        ?>>
            <label for="<?php 
        echo \esc_attr($this->metaKey);
        ?>">Timestamp this post</label>
            <div id="wordproof-action-link"></div>
        </div>
        <?php 
    }
    /**
     * Registers control for the Elementor editor.
     *
     * @param \Elementor\Core\DocumentTypes\PageBase $document The PageBase document instance.
     *
     * @action elementor/documents/register_controls
     */
    public function registerControl($document)
    {
        if (!$document instanceof \Elementor\Core\DocumentTypes\PageBase || !$document::get_property('has_elements')) {
            return;
        }
        // Add Metabox
        $document->start_controls_section('wordproof_timestamp_section', ['label' => \esc_html__('WordProof Timestamp', 'wordproof'), 'tab' => \Elementor\Controls_Manager::TAB_SETTINGS]);
        // Get meta value
        $postId = $document->get_id();
        $metaValue = \YoastSEO_Vendor\WordProof\SDK\Helpers\PostMetaHelper::get($postId, $this->metaKey, \true);
        // Override elementor value
        $pageSettingsManager = \Elementor\Core\Settings\Manager::get_settings_managers('page');
        $pageSettingsModel = $pageSettingsManager->get_model($postId);
        $pageSettingsModel->set_settings($this->metaKey, \boolval($metaValue) ? 'yes' : '');
        // Add Switcher
        $document->add_control($this->metaKey, ['label' => \esc_html__('Timestamp this post', 'wordproof'), 'type' => \Elementor\Controls_Manager::SWITCHER, 'default' => 'no']);
        $document->end_controls_section();
    }
    /**
     * @param integer $postId
     * @action elementor/document/save/data
     */
    public function elementorSave($postId)
    {
        if (\get_post_type($postId) !== 'page') {
            return;
        }
        $pageSettingsManager = \Elementor\Core\Settings\Manager::get_settings_managers('page');
        $pageSettingsModel = $pageSettingsManager->get_model($postId);
        $value = $pageSettingsModel->get_settings($this->metaKey);
        // Update meta key with Elementor value.
        \YoastSEO_Vendor\WordProof\SDK\Helpers\PostMetaHelper::update($postId, $this->metaKey, $value === 'yes');
    }
}
