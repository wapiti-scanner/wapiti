<?php

namespace Yoast\WP\SEO\Generated;

use YoastSEO_Vendor\Symfony\Component\DependencyInjection\Argument\RewindableGenerator;
use YoastSEO_Vendor\Symfony\Component\DependencyInjection\ContainerInterface;
use YoastSEO_Vendor\Symfony\Component\DependencyInjection\Container;
use YoastSEO_Vendor\Symfony\Component\DependencyInjection\Exception\InvalidArgumentException;
use YoastSEO_Vendor\Symfony\Component\DependencyInjection\Exception\LogicException;
use YoastSEO_Vendor\Symfony\Component\DependencyInjection\Exception\RuntimeException;
use YoastSEO_Vendor\Symfony\Component\DependencyInjection\ParameterBag\FrozenParameterBag;

/**
 * This class has been auto-generated
 * by the Symfony Dependency Injection Component.
 *
 * @final since Symfony 3.3
 */
class Cached_Container extends Container
{
    private $parameters = [];
    private $targetDirs = [];

    public function __construct()
    {
        $this->services = [];
        $this->normalizedIds = [
            'wpseo_addon_manager' => 'WPSEO_Addon_Manager',
            'wpseo_admin_asset_manager' => 'WPSEO_Admin_Asset_Manager',
            'wpseo_breadcrumbs' => 'WPSEO_Breadcrumbs',
            'wpseo_frontend' => 'WPSEO_Frontend',
            'wpseo_replace_vars' => 'WPSEO_Replace_Vars',
            'wpseo_shortlinker' => 'WPSEO_Shortlinker',
            'wpseo_utils' => 'WPSEO_Utils',
            'yoast\\wp\\lib\\migrations\\adapter' => 'Yoast\\WP\\Lib\\Migrations\\Adapter',
            'yoast\\wp\\seo\\actions\\addon_installation\\addon_activate_action' => 'Yoast\\WP\\SEO\\Actions\\Addon_Installation\\Addon_Activate_Action',
            'yoast\\wp\\seo\\actions\\addon_installation\\addon_install_action' => 'Yoast\\WP\\SEO\\Actions\\Addon_Installation\\Addon_Install_Action',
            'yoast\\wp\\seo\\actions\\alert_dismissal_action' => 'Yoast\\WP\\SEO\\Actions\\Alert_Dismissal_Action',
            'yoast\\wp\\seo\\actions\\configuration\\first_time_configuration_action' => 'Yoast\\WP\\SEO\\Actions\\Configuration\\First_Time_Configuration_Action',
            'yoast\\wp\\seo\\actions\\importing\\aioseo\\aioseo_cleanup_action' => 'Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Cleanup_Action',
            'yoast\\wp\\seo\\actions\\importing\\aioseo\\aioseo_custom_archive_settings_importing_action' => 'Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Custom_Archive_Settings_Importing_Action',
            'yoast\\wp\\seo\\actions\\importing\\aioseo\\aioseo_default_archive_settings_importing_action' => 'Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Default_Archive_Settings_Importing_Action',
            'yoast\\wp\\seo\\actions\\importing\\aioseo\\aioseo_general_settings_importing_action' => 'Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_General_Settings_Importing_Action',
            'yoast\\wp\\seo\\actions\\importing\\aioseo\\aioseo_posts_importing_action' => 'Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posts_Importing_Action',
            'yoast\\wp\\seo\\actions\\importing\\aioseo\\aioseo_posttype_defaults_settings_importing_action' => 'Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posttype_Defaults_Settings_Importing_Action',
            'yoast\\wp\\seo\\actions\\importing\\aioseo\\aioseo_taxonomy_settings_importing_action' => 'Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Taxonomy_Settings_Importing_Action',
            'yoast\\wp\\seo\\actions\\importing\\aioseo\\aioseo_validate_data_action' => 'Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Validate_Data_Action',
            'yoast\\wp\\seo\\actions\\importing\\deactivate_conflicting_plugins_action' => 'Yoast\\WP\\SEO\\Actions\\Importing\\Deactivate_Conflicting_Plugins_Action',
            'yoast\\wp\\seo\\actions\\indexables\\indexable_head_action' => 'Yoast\\WP\\SEO\\Actions\\Indexables\\Indexable_Head_Action',
            'yoast\\wp\\seo\\actions\\indexables_page_action' => 'Yoast\\WP\\SEO\\Actions\\Indexables_Page_Action',
            'yoast\\wp\\seo\\actions\\indexing\\indexable_general_indexation_action' => 'Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_General_Indexation_Action',
            'yoast\\wp\\seo\\actions\\indexing\\indexable_indexing_complete_action' => 'Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Indexing_Complete_Action',
            'yoast\\wp\\seo\\actions\\indexing\\indexable_post_indexation_action' => 'Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Indexation_Action',
            'yoast\\wp\\seo\\actions\\indexing\\indexable_post_type_archive_indexation_action' => 'Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Type_Archive_Indexation_Action',
            'yoast\\wp\\seo\\actions\\indexing\\indexable_term_indexation_action' => 'Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Term_Indexation_Action',
            'yoast\\wp\\seo\\actions\\indexing\\indexing_complete_action' => 'Yoast\\WP\\SEO\\Actions\\Indexing\\Indexing_Complete_Action',
            'yoast\\wp\\seo\\actions\\indexing\\indexing_prepare_action' => 'Yoast\\WP\\SEO\\Actions\\Indexing\\Indexing_Prepare_Action',
            'yoast\\wp\\seo\\actions\\indexing\\post_link_indexing_action' => 'Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action',
            'yoast\\wp\\seo\\actions\\indexing\\term_link_indexing_action' => 'Yoast\\WP\\SEO\\Actions\\Indexing\\Term_Link_Indexing_Action',
            'yoast\\wp\\seo\\actions\\integrations_action' => 'Yoast\\WP\\SEO\\Actions\\Integrations_Action',
            'yoast\\wp\\seo\\actions\\semrush\\semrush_login_action' => 'Yoast\\WP\\SEO\\Actions\\SEMrush\\SEMrush_Login_Action',
            'yoast\\wp\\seo\\actions\\semrush\\semrush_options_action' => 'Yoast\\WP\\SEO\\Actions\\SEMrush\\SEMrush_Options_Action',
            'yoast\\wp\\seo\\actions\\semrush\\semrush_phrases_action' => 'Yoast\\WP\\SEO\\Actions\\SEMrush\\SEMrush_Phrases_Action',
            'yoast\\wp\\seo\\actions\\settings_introduction_action' => 'Yoast\\WP\\SEO\\Actions\\Settings_Introduction_Action',
            'yoast\\wp\\seo\\actions\\wincher\\wincher_account_action' => 'Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Account_Action',
            'yoast\\wp\\seo\\actions\\wincher\\wincher_keyphrases_action' => 'Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Keyphrases_Action',
            'yoast\\wp\\seo\\actions\\wincher\\wincher_login_action' => 'Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Login_Action',
            'yoast\\wp\\seo\\builders\\indexable_author_builder' => 'Yoast\\WP\\SEO\\Builders\\Indexable_Author_Builder',
            'yoast\\wp\\seo\\builders\\indexable_builder' => 'Yoast\\WP\\SEO\\Builders\\Indexable_Builder',
            'yoast\\wp\\seo\\builders\\indexable_date_archive_builder' => 'Yoast\\WP\\SEO\\Builders\\Indexable_Date_Archive_Builder',
            'yoast\\wp\\seo\\builders\\indexable_hierarchy_builder' => 'Yoast\\WP\\SEO\\Builders\\Indexable_Hierarchy_Builder',
            'yoast\\wp\\seo\\builders\\indexable_home_page_builder' => 'Yoast\\WP\\SEO\\Builders\\Indexable_Home_Page_Builder',
            'yoast\\wp\\seo\\builders\\indexable_link_builder' => 'Yoast\\WP\\SEO\\Builders\\Indexable_Link_Builder',
            'yoast\\wp\\seo\\builders\\indexable_post_builder' => 'Yoast\\WP\\SEO\\Builders\\Indexable_Post_Builder',
            'yoast\\wp\\seo\\builders\\indexable_post_type_archive_builder' => 'Yoast\\WP\\SEO\\Builders\\Indexable_Post_Type_Archive_Builder',
            'yoast\\wp\\seo\\builders\\indexable_system_page_builder' => 'Yoast\\WP\\SEO\\Builders\\Indexable_System_Page_Builder',
            'yoast\\wp\\seo\\builders\\indexable_term_builder' => 'Yoast\\WP\\SEO\\Builders\\Indexable_Term_Builder',
            'yoast\\wp\\seo\\builders\\primary_term_builder' => 'Yoast\\WP\\SEO\\Builders\\Primary_Term_Builder',
            'yoast\\wp\\seo\\commands\\cleanup_command' => 'Yoast\\WP\\SEO\\Commands\\Cleanup_Command',
            'yoast\\wp\\seo\\commands\\index_command' => 'Yoast\\WP\\SEO\\Commands\\Index_Command',
            'yoast\\wp\\seo\\conditionals\\addon_installation_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Addon_Installation_Conditional',
            'yoast\\wp\\seo\\conditionals\\admin\\doing_post_quick_edit_save_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Admin\\Doing_Post_Quick_Edit_Save_Conditional',
            'yoast\\wp\\seo\\conditionals\\admin\\estimated_reading_time_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Admin\\Estimated_Reading_Time_Conditional',
            'yoast\\wp\\seo\\conditionals\\admin\\licenses_page_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Admin\\Licenses_Page_Conditional',
            'yoast\\wp\\seo\\conditionals\\admin\\non_network_admin_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Admin\\Non_Network_Admin_Conditional',
            'yoast\\wp\\seo\\conditionals\\admin\\post_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Admin\\Post_Conditional',
            'yoast\\wp\\seo\\conditionals\\admin\\posts_overview_or_ajax_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Admin\\Posts_Overview_Or_Ajax_Conditional',
            'yoast\\wp\\seo\\conditionals\\admin_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Admin_Conditional',
            'yoast\\wp\\seo\\conditionals\\attachment_redirections_enabled_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Attachment_Redirections_Enabled_Conditional',
            'yoast\\wp\\seo\\conditionals\\development_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Development_Conditional',
            'yoast\\wp\\seo\\conditionals\\front_end_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Front_End_Conditional',
            'yoast\\wp\\seo\\conditionals\\front_end_inspector_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Front_End_Inspector_Conditional',
            'yoast\\wp\\seo\\conditionals\\get_request_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Get_Request_Conditional',
            'yoast\\wp\\seo\\conditionals\\headless_rest_endpoints_enabled_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Headless_Rest_Endpoints_Enabled_Conditional',
            'yoast\\wp\\seo\\conditionals\\import_tool_selected_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Import_Tool_Selected_Conditional',
            'yoast\\wp\\seo\\conditionals\\indexables_page_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Indexables_Page_Conditional',
            'yoast\\wp\\seo\\conditionals\\jetpack_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Jetpack_Conditional',
            'yoast\\wp\\seo\\conditionals\\migrations_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Migrations_Conditional',
            'yoast\\wp\\seo\\conditionals\\new_settings_ui_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\New_Settings_Ui_Conditional',
            'yoast\\wp\\seo\\conditionals\\news_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\News_Conditional',
            'yoast\\wp\\seo\\conditionals\\no_tool_selected_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\No_Tool_Selected_Conditional',
            'yoast\\wp\\seo\\conditionals\\non_multisite_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Non_Multisite_Conditional',
            'yoast\\wp\\seo\\conditionals\\not_admin_ajax_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Not_Admin_Ajax_Conditional',
            'yoast\\wp\\seo\\conditionals\\open_graph_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Open_Graph_Conditional',
            'yoast\\wp\\seo\\conditionals\\premium_active_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Premium_Active_Conditional',
            'yoast\\wp\\seo\\conditionals\\premium_inactive_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Premium_Inactive_Conditional',
            'yoast\\wp\\seo\\conditionals\\primary_category_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Primary_Category_Conditional',
            'yoast\\wp\\seo\\conditionals\\robots_txt_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Robots_Txt_Conditional',
            'yoast\\wp\\seo\\conditionals\\schema_blocks_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Schema_Blocks_Conditional',
            'yoast\\wp\\seo\\conditionals\\semrush_enabled_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\SEMrush_Enabled_Conditional',
            'yoast\\wp\\seo\\conditionals\\settings_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Settings_Conditional',
            'yoast\\wp\\seo\\conditionals\\should_index_links_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Should_Index_Links_Conditional',
            'yoast\\wp\\seo\\conditionals\\text_formality_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Text_Formality_Conditional',
            'yoast\\wp\\seo\\conditionals\\the_events_calendar_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\The_Events_Calendar_Conditional',
            'yoast\\wp\\seo\\conditionals\\third_party\\coauthors_plus_activated_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\CoAuthors_Plus_Activated_Conditional',
            'yoast\\wp\\seo\\conditionals\\third_party\\coauthors_plus_flag_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\CoAuthors_Plus_Flag_Conditional',
            'yoast\\wp\\seo\\conditionals\\third_party\\elementor_activated_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Elementor_Activated_Conditional',
            'yoast\\wp\\seo\\conditionals\\third_party\\elementor_edit_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Elementor_Edit_Conditional',
            'yoast\\wp\\seo\\conditionals\\third_party\\jetpack_boost_active_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Jetpack_Boost_Active_Conditional',
            'yoast\\wp\\seo\\conditionals\\third_party\\jetpack_boost_not_premium_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Jetpack_Boost_Not_Premium_Conditional',
            'yoast\\wp\\seo\\conditionals\\third_party\\polylang_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Polylang_Conditional',
            'yoast\\wp\\seo\\conditionals\\third_party\\translatepress_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\TranslatePress_Conditional',
            'yoast\\wp\\seo\\conditionals\\third_party\\w3_total_cache_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\W3_Total_Cache_Conditional',
            'yoast\\wp\\seo\\conditionals\\third_party\\wordproof_integration_active_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Wordproof_Integration_Active_Conditional',
            'yoast\\wp\\seo\\conditionals\\third_party\\wordproof_plugin_inactive_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Wordproof_Plugin_Inactive_Conditional',
            'yoast\\wp\\seo\\conditionals\\third_party\\wpml_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\WPML_Conditional',
            'yoast\\wp\\seo\\conditionals\\third_party\\wpml_wpseo_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\WPML_WPSEO_Conditional',
            'yoast\\wp\\seo\\conditionals\\updated_importer_framework_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Updated_Importer_Framework_Conditional',
            'yoast\\wp\\seo\\conditionals\\user_can_manage_wpseo_options_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\User_Can_Manage_Wpseo_Options_Conditional',
            'yoast\\wp\\seo\\conditionals\\user_can_publish_posts_and_pages_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\User_Can_Publish_Posts_And_Pages_Conditional',
            'yoast\\wp\\seo\\conditionals\\web_stories_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Web_Stories_Conditional',
            'yoast\\wp\\seo\\conditionals\\wincher_automatically_track_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Wincher_Automatically_Track_Conditional',
            'yoast\\wp\\seo\\conditionals\\wincher_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Wincher_Conditional',
            'yoast\\wp\\seo\\conditionals\\wincher_enabled_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Wincher_Enabled_Conditional',
            'yoast\\wp\\seo\\conditionals\\wincher_token_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Wincher_Token_Conditional',
            'yoast\\wp\\seo\\conditionals\\woocommerce_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\WooCommerce_Conditional',
            'yoast\\wp\\seo\\conditionals\\wp_robots_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\WP_Robots_Conditional',
            'yoast\\wp\\seo\\conditionals\\xmlrpc_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\XMLRPC_Conditional',
            'yoast\\wp\\seo\\conditionals\\yoast_admin_and_dashboard_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Yoast_Admin_And_Dashboard_Conditional',
            'yoast\\wp\\seo\\conditionals\\yoast_tools_page_conditional' => 'Yoast\\WP\\SEO\\Conditionals\\Yoast_Tools_Page_Conditional',
            'yoast\\wp\\seo\\config\\badge_group_names' => 'Yoast\\WP\\SEO\\Config\\Badge_Group_Names',
            'yoast\\wp\\seo\\config\\conflicting_plugins' => 'Yoast\\WP\\SEO\\Config\\Conflicting_Plugins',
            'yoast\\wp\\seo\\config\\indexing_reasons' => 'Yoast\\WP\\SEO\\Config\\Indexing_Reasons',
            'yoast\\wp\\seo\\config\\migration_status' => 'Yoast\\WP\\SEO\\Config\\Migration_Status',
            'yoast\\wp\\seo\\config\\migrations\\addcollationtotables' => 'Yoast\\WP\\SEO\\Config\\Migrations\\AddCollationToTables',
            'yoast\\wp\\seo\\config\\migrations\\addcolumnstoindexables' => 'Yoast\\WP\\SEO\\Config\\Migrations\\AddColumnsToIndexables',
            'yoast\\wp\\seo\\config\\migrations\\addestimatedreadingtime' => 'Yoast\\WP\\SEO\\Config\\Migrations\\AddEstimatedReadingTime',
            'yoast\\wp\\seo\\config\\migrations\\addhasancestorscolumn' => 'Yoast\\WP\\SEO\\Config\\Migrations\\AddHasAncestorsColumn',
            'yoast\\wp\\seo\\config\\migrations\\addindexableobjectidandtypeindex' => 'Yoast\\WP\\SEO\\Config\\Migrations\\AddIndexableObjectIdAndTypeIndex',
            'yoast\\wp\\seo\\config\\migrations\\addindexesforprominentwordsonindexables' => 'Yoast\\WP\\SEO\\Config\\Migrations\\AddIndexesForProminentWordsOnIndexables',
            'yoast\\wp\\seo\\config\\migrations\\addobjecttimestamps' => 'Yoast\\WP\\SEO\\Config\\Migrations\\AddObjectTimestamps',
            'yoast\\wp\\seo\\config\\migrations\\addversioncolumntoindexables' => 'Yoast\\WP\\SEO\\Config\\Migrations\\AddVersionColumnToIndexables',
            'yoast\\wp\\seo\\config\\migrations\\breadcrumbtitleandhierarchyreset' => 'Yoast\\WP\\SEO\\Config\\Migrations\\BreadcrumbTitleAndHierarchyReset',
            'yoast\\wp\\seo\\config\\migrations\\clearindexabletables' => 'Yoast\\WP\\SEO\\Config\\Migrations\\ClearIndexableTables',
            'yoast\\wp\\seo\\config\\migrations\\createindexablesubpagesindex' => 'Yoast\\WP\\SEO\\Config\\Migrations\\CreateIndexableSubpagesIndex',
            'yoast\\wp\\seo\\config\\migrations\\createseolinkstable' => 'Yoast\\WP\\SEO\\Config\\Migrations\\CreateSEOLinksTable',
            'yoast\\wp\\seo\\config\\migrations\\deleteduplicateindexables' => 'Yoast\\WP\\SEO\\Config\\Migrations\\DeleteDuplicateIndexables',
            'yoast\\wp\\seo\\config\\migrations\\expandindexablecolumnlengths' => 'Yoast\\WP\\SEO\\Config\\Migrations\\ExpandIndexableColumnLengths',
            'yoast\\wp\\seo\\config\\migrations\\expandindexableidcolumnlengths' => 'Yoast\\WP\\SEO\\Config\\Migrations\\ExpandIndexableIDColumnLengths',
            'yoast\\wp\\seo\\config\\migrations\\expandprimarytermidcolumnlengths' => 'Yoast\\WP\\SEO\\Config\\Migrations\\ExpandPrimaryTermIDColumnLengths',
            'yoast\\wp\\seo\\config\\migrations\\replacepermalinkhashindex' => 'Yoast\\WP\\SEO\\Config\\Migrations\\ReplacePermalinkHashIndex',
            'yoast\\wp\\seo\\config\\migrations\\resetindexablehierarchytable' => 'Yoast\\WP\\SEO\\Config\\Migrations\\ResetIndexableHierarchyTable',
            'yoast\\wp\\seo\\config\\migrations\\truncateindexabletables' => 'Yoast\\WP\\SEO\\Config\\Migrations\\TruncateIndexableTables',
            'yoast\\wp\\seo\\config\\migrations\\wpyoastdropindexablemetatableifexists' => 'Yoast\\WP\\SEO\\Config\\Migrations\\WpYoastDropIndexableMetaTableIfExists',
            'yoast\\wp\\seo\\config\\migrations\\wpyoastindexable' => 'Yoast\\WP\\SEO\\Config\\Migrations\\WpYoastIndexable',
            'yoast\\wp\\seo\\config\\migrations\\wpyoastindexablehierarchy' => 'Yoast\\WP\\SEO\\Config\\Migrations\\WpYoastIndexableHierarchy',
            'yoast\\wp\\seo\\config\\migrations\\wpyoastprimaryterm' => 'Yoast\\WP\\SEO\\Config\\Migrations\\WpYoastPrimaryTerm',
            'yoast\\wp\\seo\\config\\researcher_languages' => 'Yoast\\WP\\SEO\\Config\\Researcher_Languages',
            'yoast\\wp\\seo\\config\\schema_ids' => 'Yoast\\WP\\SEO\\Config\\Schema_IDs',
            'yoast\\wp\\seo\\config\\schema_types' => 'Yoast\\WP\\SEO\\Config\\Schema_Types',
            'yoast\\wp\\seo\\config\\semrush_client' => 'Yoast\\WP\\SEO\\Config\\SEMrush_Client',
            'yoast\\wp\\seo\\config\\wincher_client' => 'Yoast\\WP\\SEO\\Config\\Wincher_Client',
            'yoast\\wp\\seo\\config\\wordproof_app_config' => 'Yoast\\WP\\SEO\\Config\\Wordproof_App_Config',
            'yoast\\wp\\seo\\config\\wordproof_translations' => 'Yoast\\WP\\SEO\\Config\\Wordproof_Translations',
            'yoast\\wp\\seo\\context\\meta_tags_context' => 'Yoast\\WP\\SEO\\Context\\Meta_Tags_Context',
            'yoast\\wp\\seo\\generators\\breadcrumbs_generator' => 'Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator',
            'yoast\\wp\\seo\\generators\\open_graph_image_generator' => 'Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator',
            'yoast\\wp\\seo\\generators\\open_graph_locale_generator' => 'Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator',
            'yoast\\wp\\seo\\generators\\schema\\article' => 'Yoast\\WP\\SEO\\Generators\\Schema\\Article',
            'yoast\\wp\\seo\\generators\\schema\\author' => 'Yoast\\WP\\SEO\\Generators\\Schema\\Author',
            'yoast\\wp\\seo\\generators\\schema\\breadcrumb' => 'Yoast\\WP\\SEO\\Generators\\Schema\\Breadcrumb',
            'yoast\\wp\\seo\\generators\\schema\\faq' => 'Yoast\\WP\\SEO\\Generators\\Schema\\FAQ',
            'yoast\\wp\\seo\\generators\\schema\\howto' => 'Yoast\\WP\\SEO\\Generators\\Schema\\HowTo',
            'yoast\\wp\\seo\\generators\\schema\\main_image' => 'Yoast\\WP\\SEO\\Generators\\Schema\\Main_Image',
            'yoast\\wp\\seo\\generators\\schema\\organization' => 'Yoast\\WP\\SEO\\Generators\\Schema\\Organization',
            'yoast\\wp\\seo\\generators\\schema\\person' => 'Yoast\\WP\\SEO\\Generators\\Schema\\Person',
            'yoast\\wp\\seo\\generators\\schema\\third_party\\coauthor' => 'Yoast\\WP\\SEO\\Generators\\Schema\\Third_Party\\CoAuthor',
            'yoast\\wp\\seo\\generators\\schema\\third_party\\events_calendar_schema' => 'Yoast\\WP\\SEO\\Generators\\Schema\\Third_Party\\Events_Calendar_Schema',
            'yoast\\wp\\seo\\generators\\schema\\webpage' => 'Yoast\\WP\\SEO\\Generators\\Schema\\WebPage',
            'yoast\\wp\\seo\\generators\\schema\\website' => 'Yoast\\WP\\SEO\\Generators\\Schema\\Website',
            'yoast\\wp\\seo\\generators\\schema_generator' => 'Yoast\\WP\\SEO\\Generators\\Schema_Generator',
            'yoast\\wp\\seo\\generators\\twitter_image_generator' => 'Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator',
            'yoast\\wp\\seo\\helpers\\aioseo_helper' => 'Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper',
            'yoast\\wp\\seo\\helpers\\asset_helper' => 'Yoast\\WP\\SEO\\Helpers\\Asset_Helper',
            'yoast\\wp\\seo\\helpers\\attachment_cleanup_helper' => 'Yoast\\WP\\SEO\\Helpers\\Attachment_Cleanup_Helper',
            'yoast\\wp\\seo\\helpers\\author_archive_helper' => 'Yoast\\WP\\SEO\\Helpers\\Author_Archive_Helper',
            'yoast\\wp\\seo\\helpers\\blocks_helper' => 'Yoast\\WP\\SEO\\Helpers\\Blocks_Helper',
            'yoast\\wp\\seo\\helpers\\capability_helper' => 'Yoast\\WP\\SEO\\Helpers\\Capability_Helper',
            'yoast\\wp\\seo\\helpers\\crawl_cleanup_helper' => 'Yoast\\WP\\SEO\\Helpers\\Crawl_Cleanup_Helper',
            'yoast\\wp\\seo\\helpers\\curl_helper' => 'Yoast\\WP\\SEO\\Helpers\\Curl_Helper',
            'yoast\\wp\\seo\\helpers\\current_page_helper' => 'Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper',
            'yoast\\wp\\seo\\helpers\\date_helper' => 'Yoast\\WP\\SEO\\Helpers\\Date_Helper',
            'yoast\\wp\\seo\\helpers\\environment_helper' => 'Yoast\\WP\\SEO\\Helpers\\Environment_Helper',
            'yoast\\wp\\seo\\helpers\\first_time_configuration_notice_helper' => 'Yoast\\WP\\SEO\\Helpers\\First_Time_Configuration_Notice_Helper',
            'yoast\\wp\\seo\\helpers\\home_url_helper' => 'Yoast\\WP\\SEO\\Helpers\\Home_Url_Helper',
            'yoast\\wp\\seo\\helpers\\image_helper' => 'Yoast\\WP\\SEO\\Helpers\\Image_Helper',
            'yoast\\wp\\seo\\helpers\\import_cursor_helper' => 'Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper',
            'yoast\\wp\\seo\\helpers\\import_helper' => 'Yoast\\WP\\SEO\\Helpers\\Import_Helper',
            'yoast\\wp\\seo\\helpers\\indexable_helper' => 'Yoast\\WP\\SEO\\Helpers\\Indexable_Helper',
            'yoast\\wp\\seo\\helpers\\indexable_to_postmeta_helper' => 'Yoast\\WP\\SEO\\Helpers\\Indexable_To_Postmeta_Helper',
            'yoast\\wp\\seo\\helpers\\indexables_page_helper' => 'Yoast\\WP\\SEO\\Helpers\\Indexables_Page_Helper',
            'yoast\\wp\\seo\\helpers\\indexing_helper' => 'Yoast\\WP\\SEO\\Helpers\\Indexing_Helper',
            'yoast\\wp\\seo\\helpers\\language_helper' => 'Yoast\\WP\\SEO\\Helpers\\Language_Helper',
            'yoast\\wp\\seo\\helpers\\meta_helper' => 'Yoast\\WP\\SEO\\Helpers\\Meta_Helper',
            'yoast\\wp\\seo\\helpers\\notification_helper' => 'Yoast\\WP\\SEO\\Helpers\\Notification_Helper',
            'yoast\\wp\\seo\\helpers\\open_graph\\image_helper' => 'Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper',
            'yoast\\wp\\seo\\helpers\\open_graph\\values_helper' => 'Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper',
            'yoast\\wp\\seo\\helpers\\options_helper' => 'Yoast\\WP\\SEO\\Helpers\\Options_Helper',
            'yoast\\wp\\seo\\helpers\\pagination_helper' => 'Yoast\\WP\\SEO\\Helpers\\Pagination_Helper',
            'yoast\\wp\\seo\\helpers\\permalink_helper' => 'Yoast\\WP\\SEO\\Helpers\\Permalink_Helper',
            'yoast\\wp\\seo\\helpers\\post_helper' => 'Yoast\\WP\\SEO\\Helpers\\Post_Helper',
            'yoast\\wp\\seo\\helpers\\post_type_helper' => 'Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper',
            'yoast\\wp\\seo\\helpers\\primary_term_helper' => 'Yoast\\WP\\SEO\\Helpers\\Primary_Term_Helper',
            'yoast\\wp\\seo\\helpers\\product_helper' => 'Yoast\\WP\\SEO\\Helpers\\Product_Helper',
            'yoast\\wp\\seo\\helpers\\redirect_helper' => 'Yoast\\WP\\SEO\\Helpers\\Redirect_Helper',
            'yoast\\wp\\seo\\helpers\\request_helper' => 'Yoast\\WP\\SEO\\Helpers\\Request_Helper',
            'yoast\\wp\\seo\\helpers\\require_file_helper' => 'Yoast\\WP\\SEO\\Helpers\\Require_File_Helper',
            'yoast\\wp\\seo\\helpers\\robots_helper' => 'Yoast\\WP\\SEO\\Helpers\\Robots_Helper',
            'yoast\\wp\\seo\\helpers\\robots_txt_helper' => 'Yoast\\WP\\SEO\\Helpers\\Robots_Txt_Helper',
            'yoast\\wp\\seo\\helpers\\sanitization_helper' => 'Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper',
            'yoast\\wp\\seo\\helpers\\schema\\article_helper' => 'Yoast\\WP\\SEO\\Helpers\\Schema\\Article_Helper',
            'yoast\\wp\\seo\\helpers\\schema\\html_helper' => 'Yoast\\WP\\SEO\\Helpers\\Schema\\HTML_Helper',
            'yoast\\wp\\seo\\helpers\\schema\\id_helper' => 'Yoast\\WP\\SEO\\Helpers\\Schema\\ID_Helper',
            'yoast\\wp\\seo\\helpers\\schema\\image_helper' => 'Yoast\\WP\\SEO\\Helpers\\Schema\\Image_Helper',
            'yoast\\wp\\seo\\helpers\\schema\\language_helper' => 'Yoast\\WP\\SEO\\Helpers\\Schema\\Language_Helper',
            'yoast\\wp\\seo\\helpers\\schema\\replace_vars_helper' => 'Yoast\\WP\\SEO\\Helpers\\Schema\\Replace_Vars_Helper',
            'yoast\\wp\\seo\\helpers\\score_icon_helper' => 'Yoast\\WP\\SEO\\Helpers\\Score_Icon_Helper',
            'yoast\\wp\\seo\\helpers\\short_link_helper' => 'Yoast\\WP\\SEO\\Helpers\\Short_Link_Helper',
            'yoast\\wp\\seo\\helpers\\site_helper' => 'Yoast\\WP\\SEO\\Helpers\\Site_Helper',
            'yoast\\wp\\seo\\helpers\\social_profiles_helper' => 'Yoast\\WP\\SEO\\Helpers\\Social_Profiles_Helper',
            'yoast\\wp\\seo\\helpers\\string_helper' => 'Yoast\\WP\\SEO\\Helpers\\String_Helper',
            'yoast\\wp\\seo\\helpers\\taxonomy_helper' => 'Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper',
            'yoast\\wp\\seo\\helpers\\twitter\\image_helper' => 'Yoast\\WP\\SEO\\Helpers\\Twitter\\Image_Helper',
            'yoast\\wp\\seo\\helpers\\url_helper' => 'Yoast\\WP\\SEO\\Helpers\\Url_Helper',
            'yoast\\wp\\seo\\helpers\\user_helper' => 'Yoast\\WP\\SEO\\Helpers\\User_Helper',
            'yoast\\wp\\seo\\helpers\\wincher_helper' => 'Yoast\\WP\\SEO\\Helpers\\Wincher_Helper',
            'yoast\\wp\\seo\\helpers\\woocommerce_helper' => 'Yoast\\WP\\SEO\\Helpers\\Woocommerce_Helper',
            'yoast\\wp\\seo\\helpers\\wordpress_helper' => 'Yoast\\WP\\SEO\\Helpers\\Wordpress_Helper',
            'yoast\\wp\\seo\\helpers\\wordproof_helper' => 'Yoast\\WP\\SEO\\Helpers\\Wordproof_Helper',
            'yoast\\wp\\seo\\helpers\\wpdb_helper' => 'Yoast\\WP\\SEO\\Helpers\\Wpdb_Helper',
            'yoast\\wp\\seo\\initializers\\crawl_cleanup_permalinks' => 'Yoast\\WP\\SEO\\Initializers\\Crawl_Cleanup_Permalinks',
            'yoast\\wp\\seo\\initializers\\disable_core_sitemaps' => 'Yoast\\WP\\SEO\\Initializers\\Disable_Core_Sitemaps',
            'yoast\\wp\\seo\\initializers\\migration_runner' => 'Yoast\\WP\\SEO\\Initializers\\Migration_Runner',
            'yoast\\wp\\seo\\initializers\\woocommerce' => 'Yoast\\WP\\SEO\\Initializers\\Woocommerce',
            'yoast\\wp\\seo\\integrations\\admin\\activation_cleanup_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Activation_Cleanup_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\addon_installation\\dialog_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Addon_Installation\\Dialog_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\addon_installation\\installation_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Addon_Installation\\Installation_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\admin_columns_cache_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Admin_Columns_Cache_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\background_indexing_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Background_Indexing_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\crawl_settings_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Crawl_Settings_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\cron_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Cron_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\deactivated_premium_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Deactivated_Premium_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\disable_concatenate_scripts_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Disable_Concatenate_Scripts_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\first_time_configuration_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\First_Time_Configuration_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\first_time_configuration_notice_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\First_Time_Configuration_Notice_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\fix_news_dependencies_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Fix_News_Dependencies_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\health_check_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Health_Check_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\helpscout_beacon' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\HelpScout_Beacon',
            'yoast\\wp\\seo\\integrations\\admin\\import_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Import_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\indexables_exclude_taxonomy_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Indexables_Exclude_Taxonomy_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\indexables_page_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Indexables_Page_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\indexing_notification_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Indexing_Notification_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\indexing_tool_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Indexing_Tool_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\installation_success_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Installation_Success_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\integrations_page' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Integrations_Page',
            'yoast\\wp\\seo\\integrations\\admin\\link_count_columns_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Link_Count_Columns_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\menu_badge_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Menu_Badge_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\migration_error_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Migration_Error_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\old_configuration_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Old_Configuration_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\old_premium_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Old_Premium_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\redirect_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Redirect_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\redirects_page_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Redirects_Page_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\social_templates_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Social_Templates_Integration',
            'yoast\\wp\\seo\\integrations\\admin\\workouts_integration' => 'Yoast\\WP\\SEO\\Integrations\\Admin\\Workouts_Integration',
            'yoast\\wp\\seo\\integrations\\alerts\\jetpack_boost_pre_publish' => 'Yoast\\WP\\SEO\\Integrations\\Alerts\\Jetpack_Boost_Pre_Publish',
            'yoast\\wp\\seo\\integrations\\alerts\\webinar_promo_notification' => 'Yoast\\WP\\SEO\\Integrations\\Alerts\\Webinar_Promo_Notification',
            'yoast\\wp\\seo\\integrations\\blocks\\breadcrumbs_block' => 'Yoast\\WP\\SEO\\Integrations\\Blocks\\Breadcrumbs_Block',
            'yoast\\wp\\seo\\integrations\\blocks\\internal_linking_category' => 'Yoast\\WP\\SEO\\Integrations\\Blocks\\Internal_Linking_Category',
            'yoast\\wp\\seo\\integrations\\blocks\\structured_data_blocks' => 'Yoast\\WP\\SEO\\Integrations\\Blocks\\Structured_Data_Blocks',
            'yoast\\wp\\seo\\integrations\\breadcrumbs_integration' => 'Yoast\\WP\\SEO\\Integrations\\Breadcrumbs_Integration',
            'yoast\\wp\\seo\\integrations\\cleanup_integration' => 'Yoast\\WP\\SEO\\Integrations\\Cleanup_Integration',
            'yoast\\wp\\seo\\integrations\\duplicate_post_integration' => 'Yoast\\WP\\SEO\\Integrations\\Duplicate_Post_Integration',
            'yoast\\wp\\seo\\integrations\\estimated_reading_time' => 'Yoast\\WP\\SEO\\Integrations\\Estimated_Reading_Time',
            'yoast\\wp\\seo\\integrations\\exclude_attachment_post_type' => 'Yoast\\WP\\SEO\\Integrations\\Exclude_Attachment_Post_Type',
            'yoast\\wp\\seo\\integrations\\exclude_oembed_cache_post_type' => 'Yoast\\WP\\SEO\\Integrations\\Exclude_Oembed_Cache_Post_Type',
            'yoast\\wp\\seo\\integrations\\feature_flag_integration' => 'Yoast\\WP\\SEO\\Integrations\\Feature_Flag_Integration',
            'yoast\\wp\\seo\\integrations\\front_end\\backwards_compatibility' => 'Yoast\\WP\\SEO\\Integrations\\Front_End\\Backwards_Compatibility',
            'yoast\\wp\\seo\\integrations\\front_end\\category_term_description' => 'Yoast\\WP\\SEO\\Integrations\\Front_End\\Category_Term_Description',
            'yoast\\wp\\seo\\integrations\\front_end\\comment_link_fixer' => 'Yoast\\WP\\SEO\\Integrations\\Front_End\\Comment_Link_Fixer',
            'yoast\\wp\\seo\\integrations\\front_end\\crawl_cleanup_basic' => 'Yoast\\WP\\SEO\\Integrations\\Front_End\\Crawl_Cleanup_Basic',
            'yoast\\wp\\seo\\integrations\\front_end\\crawl_cleanup_rss' => 'Yoast\\WP\\SEO\\Integrations\\Front_End\\Crawl_Cleanup_Rss',
            'yoast\\wp\\seo\\integrations\\front_end\\crawl_cleanup_searches' => 'Yoast\\WP\\SEO\\Integrations\\Front_End\\Crawl_Cleanup_Searches',
            'yoast\\wp\\seo\\integrations\\front_end\\feed_improvements' => 'Yoast\\WP\\SEO\\Integrations\\Front_End\\Feed_Improvements',
            'yoast\\wp\\seo\\integrations\\front_end\\force_rewrite_title' => 'Yoast\\WP\\SEO\\Integrations\\Front_End\\Force_Rewrite_Title',
            'yoast\\wp\\seo\\integrations\\front_end\\handle_404' => 'Yoast\\WP\\SEO\\Integrations\\Front_End\\Handle_404',
            'yoast\\wp\\seo\\integrations\\front_end\\indexing_controls' => 'Yoast\\WP\\SEO\\Integrations\\Front_End\\Indexing_Controls',
            'yoast\\wp\\seo\\integrations\\front_end\\open_graph_oembed' => 'Yoast\\WP\\SEO\\Integrations\\Front_End\\Open_Graph_OEmbed',
            'yoast\\wp\\seo\\integrations\\front_end\\redirects' => 'Yoast\\WP\\SEO\\Integrations\\Front_End\\Redirects',
            'yoast\\wp\\seo\\integrations\\front_end\\robots_txt_integration' => 'Yoast\\WP\\SEO\\Integrations\\Front_End\\Robots_Txt_Integration',
            'yoast\\wp\\seo\\integrations\\front_end\\rss_footer_embed' => 'Yoast\\WP\\SEO\\Integrations\\Front_End\\RSS_Footer_Embed',
            'yoast\\wp\\seo\\integrations\\front_end\\schema_accessibility_feature' => 'Yoast\\WP\\SEO\\Integrations\\Front_End\\Schema_Accessibility_Feature',
            'yoast\\wp\\seo\\integrations\\front_end\\wp_robots_integration' => 'Yoast\\WP\\SEO\\Integrations\\Front_End\\WP_Robots_Integration',
            'yoast\\wp\\seo\\integrations\\front_end_integration' => 'Yoast\\WP\\SEO\\Integrations\\Front_End_Integration',
            'yoast\\wp\\seo\\integrations\\primary_category' => 'Yoast\\WP\\SEO\\Integrations\\Primary_Category',
            'yoast\\wp\\seo\\integrations\\schema_blocks' => 'Yoast\\WP\\SEO\\Integrations\\Schema_Blocks',
            'yoast\\wp\\seo\\integrations\\settings_integration' => 'Yoast\\WP\\SEO\\Integrations\\Settings_Integration',
            'yoast\\wp\\seo\\integrations\\third_party\\amp' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\AMP',
            'yoast\\wp\\seo\\integrations\\third_party\\bbpress' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\BbPress',
            'yoast\\wp\\seo\\integrations\\third_party\\coauthors_plus' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\CoAuthors_Plus',
            'yoast\\wp\\seo\\integrations\\third_party\\elementor' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Elementor',
            'yoast\\wp\\seo\\integrations\\third_party\\exclude_elementor_post_types' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Exclude_Elementor_Post_Types',
            'yoast\\wp\\seo\\integrations\\third_party\\exclude_woocommerce_post_types' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Exclude_WooCommerce_Post_Types',
            'yoast\\wp\\seo\\integrations\\third_party\\jetpack' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Jetpack',
            'yoast\\wp\\seo\\integrations\\third_party\\the_events_calendar' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\The_Events_Calendar',
            'yoast\\wp\\seo\\integrations\\third_party\\w3_total_cache' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\W3_Total_Cache',
            'yoast\\wp\\seo\\integrations\\third_party\\web_stories' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Web_Stories',
            'yoast\\wp\\seo\\integrations\\third_party\\web_stories_post_edit' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Web_Stories_Post_Edit',
            'yoast\\wp\\seo\\integrations\\third_party\\wincher' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Wincher',
            'yoast\\wp\\seo\\integrations\\third_party\\wincher_publish' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Wincher_Publish',
            'yoast\\wp\\seo\\integrations\\third_party\\woocommerce' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\WooCommerce',
            'yoast\\wp\\seo\\integrations\\third_party\\woocommerce_permalinks' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Woocommerce_Permalinks',
            'yoast\\wp\\seo\\integrations\\third_party\\woocommerce_post_edit' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\WooCommerce_Post_Edit',
            'yoast\\wp\\seo\\integrations\\third_party\\wordproof' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Wordproof',
            'yoast\\wp\\seo\\integrations\\third_party\\wordproof_integration_toggle' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Wordproof_Integration_Toggle',
            'yoast\\wp\\seo\\integrations\\third_party\\wpml' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\WPML',
            'yoast\\wp\\seo\\integrations\\third_party\\wpml_wpseo_notification' => 'Yoast\\WP\\SEO\\Integrations\\Third_Party\\WPML_WPSEO_Notification',
            'yoast\\wp\\seo\\integrations\\uninstall_integration' => 'Yoast\\WP\\SEO\\Integrations\\Uninstall_Integration',
            'yoast\\wp\\seo\\integrations\\watchers\\addon_update_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Addon_Update_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\auto_update_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Auto_Update_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_ancestor_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Ancestor_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_attachment_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Attachment_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_author_archive_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Author_Archive_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_author_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Author_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_category_permalink_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Category_Permalink_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_date_archive_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Date_Archive_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_home_page_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Home_Page_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_homeurl_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_HomeUrl_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_permalink_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Permalink_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_post_meta_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Meta_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_post_type_archive_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Type_Archive_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_post_type_change_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Type_Change_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_post_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_static_home_page_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Static_Home_Page_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_system_page_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_System_Page_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_taxonomy_change_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Taxonomy_Change_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\indexable_term_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Term_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\option_titles_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Option_Titles_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\option_wpseo_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Option_Wpseo_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\primary_category_quick_edit_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Primary_Category_Quick_Edit_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\primary_term_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Primary_Term_Watcher',
            'yoast\\wp\\seo\\integrations\\watchers\\search_engines_discouraged_watcher' => 'Yoast\\WP\\SEO\\Integrations\\Watchers\\Search_Engines_Discouraged_Watcher',
            'yoast\\wp\\seo\\integrations\\xmlrpc' => 'Yoast\\WP\\SEO\\Integrations\\XMLRPC',
            'yoast\\wp\\seo\\loader' => 'Yoast\\WP\\SEO\\Loader',
            'yoast\\wp\\seo\\loggers\\logger' => 'Yoast\\WP\\SEO\\Loggers\\Logger',
            'yoast\\wp\\seo\\memoizers\\meta_tags_context_memoizer' => 'Yoast\\WP\\SEO\\Memoizers\\Meta_Tags_Context_Memoizer',
            'yoast\\wp\\seo\\memoizers\\presentation_memoizer' => 'Yoast\\WP\\SEO\\Memoizers\\Presentation_Memoizer',
            'yoast\\wp\\seo\\presentations\\abstract_presentation' => 'Yoast\\WP\\SEO\\Presentations\\Abstract_Presentation',
            'yoast\\wp\\seo\\presentations\\indexable_author_archive_presentation' => 'Yoast\\WP\\SEO\\Presentations\\Indexable_Author_Archive_Presentation',
            'yoast\\wp\\seo\\presentations\\indexable_date_archive_presentation' => 'Yoast\\WP\\SEO\\Presentations\\Indexable_Date_Archive_Presentation',
            'yoast\\wp\\seo\\presentations\\indexable_error_page_presentation' => 'Yoast\\WP\\SEO\\Presentations\\Indexable_Error_Page_Presentation',
            'yoast\\wp\\seo\\presentations\\indexable_home_page_presentation' => 'Yoast\\WP\\SEO\\Presentations\\Indexable_Home_Page_Presentation',
            'yoast\\wp\\seo\\presentations\\indexable_post_type_archive_presentation' => 'Yoast\\WP\\SEO\\Presentations\\Indexable_Post_Type_Archive_Presentation',
            'yoast\\wp\\seo\\presentations\\indexable_post_type_presentation' => 'Yoast\\WP\\SEO\\Presentations\\Indexable_Post_Type_Presentation',
            'yoast\\wp\\seo\\presentations\\indexable_presentation' => 'Yoast\\WP\\SEO\\Presentations\\Indexable_Presentation',
            'yoast\\wp\\seo\\presentations\\indexable_search_result_page_presentation' => 'Yoast\\WP\\SEO\\Presentations\\Indexable_Search_Result_Page_Presentation',
            'yoast\\wp\\seo\\presentations\\indexable_static_home_page_presentation' => 'Yoast\\WP\\SEO\\Presentations\\Indexable_Static_Home_Page_Presentation',
            'yoast\\wp\\seo\\presentations\\indexable_static_posts_page_presentation' => 'Yoast\\WP\\SEO\\Presentations\\Indexable_Static_Posts_Page_Presentation',
            'yoast\\wp\\seo\\presentations\\indexable_term_archive_presentation' => 'Yoast\\WP\\SEO\\Presentations\\Indexable_Term_Archive_Presentation',
            'yoast\\wp\\seo\\repositories\\indexable_hierarchy_repository' => 'Yoast\\WP\\SEO\\Repositories\\Indexable_Hierarchy_Repository',
            'yoast\\wp\\seo\\repositories\\indexable_repository' => 'Yoast\\WP\\SEO\\Repositories\\Indexable_Repository',
            'yoast\\wp\\seo\\repositories\\primary_term_repository' => 'Yoast\\WP\\SEO\\Repositories\\Primary_Term_Repository',
            'yoast\\wp\\seo\\repositories\\seo_links_repository' => 'Yoast\\WP\\SEO\\Repositories\\SEO_Links_Repository',
            'yoast\\wp\\seo\\routes\\alert_dismissal_route' => 'Yoast\\WP\\SEO\\Routes\\Alert_Dismissal_Route',
            'yoast\\wp\\seo\\routes\\first_time_configuration_route' => 'Yoast\\WP\\SEO\\Routes\\First_Time_Configuration_Route',
            'yoast\\wp\\seo\\routes\\importing_route' => 'Yoast\\WP\\SEO\\Routes\\Importing_Route',
            'yoast\\wp\\seo\\routes\\indexables_head_route' => 'Yoast\\WP\\SEO\\Routes\\Indexables_Head_Route',
            'yoast\\wp\\seo\\routes\\indexables_page_route' => 'Yoast\\WP\\SEO\\Routes\\Indexables_Page_Route',
            'yoast\\wp\\seo\\routes\\indexing_route' => 'Yoast\\WP\\SEO\\Routes\\Indexing_Route',
            'yoast\\wp\\seo\\routes\\integrations_route' => 'Yoast\\WP\\SEO\\Routes\\Integrations_Route',
            'yoast\\wp\\seo\\routes\\meta_search_route' => 'Yoast\\WP\\SEO\\Routes\\Meta_Search_Route',
            'yoast\\wp\\seo\\routes\\semrush_route' => 'Yoast\\WP\\SEO\\Routes\\SEMrush_Route',
            'yoast\\wp\\seo\\routes\\settings_introduction_route' => 'Yoast\\WP\\SEO\\Routes\\Settings_Introduction_Route',
            'yoast\\wp\\seo\\routes\\supported_features_route' => 'Yoast\\WP\\SEO\\Routes\\Supported_Features_Route',
            'yoast\\wp\\seo\\routes\\wincher_route' => 'Yoast\\WP\\SEO\\Routes\\Wincher_Route',
            'yoast\\wp\\seo\\routes\\workouts_route' => 'Yoast\\WP\\SEO\\Routes\\Workouts_Route',
            'yoast\\wp\\seo\\routes\\yoast_head_rest_field' => 'Yoast\\WP\\SEO\\Routes\\Yoast_Head_REST_Field',
            'yoast\\wp\\seo\\schema_templates\\assets\\icons' => 'Yoast\\WP\\SEO\\Schema_Templates\\Assets\\Icons',
            'yoast\\wp\\seo\\services\\health_check\\default_tagline_check' => 'Yoast\\WP\\SEO\\Services\\Health_Check\\Default_Tagline_Check',
            'yoast\\wp\\seo\\services\\health_check\\default_tagline_reports' => 'Yoast\\WP\\SEO\\Services\\Health_Check\\Default_Tagline_Reports',
            'yoast\\wp\\seo\\services\\health_check\\default_tagline_runner' => 'Yoast\\WP\\SEO\\Services\\Health_Check\\Default_Tagline_Runner',
            'yoast\\wp\\seo\\services\\health_check\\links_table_check' => 'Yoast\\WP\\SEO\\Services\\Health_Check\\Links_Table_Check',
            'yoast\\wp\\seo\\services\\health_check\\links_table_reports' => 'Yoast\\WP\\SEO\\Services\\Health_Check\\Links_Table_Reports',
            'yoast\\wp\\seo\\services\\health_check\\links_table_runner' => 'Yoast\\WP\\SEO\\Services\\Health_Check\\Links_Table_Runner',
            'yoast\\wp\\seo\\services\\health_check\\myyoast_api_request_factory' => 'Yoast\\WP\\SEO\\Services\\Health_Check\\MyYoast_Api_Request_Factory',
            'yoast\\wp\\seo\\services\\health_check\\page_comments_check' => 'Yoast\\WP\\SEO\\Services\\Health_Check\\Page_Comments_Check',
            'yoast\\wp\\seo\\services\\health_check\\page_comments_reports' => 'Yoast\\WP\\SEO\\Services\\Health_Check\\Page_Comments_Reports',
            'yoast\\wp\\seo\\services\\health_check\\page_comments_runner' => 'Yoast\\WP\\SEO\\Services\\Health_Check\\Page_Comments_Runner',
            'yoast\\wp\\seo\\services\\health_check\\postname_permalink_check' => 'Yoast\\WP\\SEO\\Services\\Health_Check\\Postname_Permalink_Check',
            'yoast\\wp\\seo\\services\\health_check\\postname_permalink_reports' => 'Yoast\\WP\\SEO\\Services\\Health_Check\\Postname_Permalink_Reports',
            'yoast\\wp\\seo\\services\\health_check\\postname_permalink_runner' => 'Yoast\\WP\\SEO\\Services\\Health_Check\\Postname_Permalink_Runner',
            'yoast\\wp\\seo\\services\\health_check\\report_builder' => 'Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder',
            'yoast\\wp\\seo\\services\\health_check\\report_builder_factory' => 'Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder_Factory',
            'yoast\\wp\\seo\\services\\importing\\aioseo\\aioseo_replacevar_service' => 'Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service',
            'yoast\\wp\\seo\\services\\importing\\aioseo\\aioseo_robots_provider_service' => 'Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service',
            'yoast\\wp\\seo\\services\\importing\\aioseo\\aioseo_robots_transformer_service' => 'Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service',
            'yoast\\wp\\seo\\services\\importing\\aioseo\\aioseo_social_images_provider_service' => 'Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Social_Images_Provider_Service',
            'yoast\\wp\\seo\\services\\importing\\conflicting_plugins_service' => 'Yoast\\WP\\SEO\\Services\\Importing\\Conflicting_Plugins_Service',
            'yoast\\wp\\seo\\services\\importing\\importable_detector_service' => 'Yoast\\WP\\SEO\\Services\\Importing\\Importable_Detector_Service',
            'yoast\\wp\\seo\\services\\indexables\\indexable_version_manager' => 'Yoast\\WP\\SEO\\Services\\Indexables\\Indexable_Version_Manager',
            'yoast\\wp\\seo\\surfaces\\classes_surface' => 'Yoast\\WP\\SEO\\Surfaces\\Classes_Surface',
            'yoast\\wp\\seo\\surfaces\\helpers_surface' => 'Yoast\\WP\\SEO\\Surfaces\\Helpers_Surface',
            'yoast\\wp\\seo\\surfaces\\meta_surface' => 'Yoast\\WP\\SEO\\Surfaces\\Meta_Surface',
            'yoast\\wp\\seo\\surfaces\\open_graph_helpers_surface' => 'Yoast\\WP\\SEO\\Surfaces\\Open_Graph_Helpers_Surface',
            'yoast\\wp\\seo\\surfaces\\schema_helpers_surface' => 'Yoast\\WP\\SEO\\Surfaces\\Schema_Helpers_Surface',
            'yoast\\wp\\seo\\surfaces\\twitter_helpers_surface' => 'Yoast\\WP\\SEO\\Surfaces\\Twitter_Helpers_Surface',
            'yoast\\wp\\seo\\values\\images' => 'Yoast\\WP\\SEO\\Values\\Images',
            'yoast\\wp\\seo\\values\\indexables\\indexable_builder_versions' => 'Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions',
            'yoast\\wp\\seo\\values\\open_graph\\images' => 'Yoast\\WP\\SEO\\Values\\Open_Graph\\Images',
            'yoast\\wp\\seo\\wrappers\\wp_query_wrapper' => 'Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper',
            'yoast\\wp\\seo\\wrappers\\wp_remote_handler' => 'Yoast\\WP\\SEO\\Wrappers\\WP_Remote_Handler',
            'yoast\\wp\\seo\\wrappers\\wp_rewrite_wrapper' => 'Yoast\\WP\\SEO\\Wrappers\\WP_Rewrite_Wrapper',
            'yoast_notification_center' => 'Yoast_Notification_Center',
            'yoastseo_vendor\\symfony\\component\\dependencyinjection\\containerinterface' => 'YoastSEO_Vendor\\YoastSEO_Vendor\\Symfony\\Component\\DependencyInjection\\ContainerInterface',
        ];
        $this->methodMap = [
            'WPSEO_Addon_Manager' => 'getWPSEOAddonManagerService',
            'WPSEO_Admin_Asset_Manager' => 'getWPSEOAdminAssetManagerService',
            'WPSEO_Breadcrumbs' => 'getWPSEOBreadcrumbsService',
            'WPSEO_Frontend' => 'getWPSEOFrontendService',
            'WPSEO_Replace_Vars' => 'getWPSEOReplaceVarsService',
            'WPSEO_Shortlinker' => 'getWPSEOShortlinkerService',
            'WPSEO_Utils' => 'getWPSEOUtilsService',
            'Yoast\\WP\\Lib\\Migrations\\Adapter' => 'getAdapterService',
            'Yoast\\WP\\SEO\\Actions\\Addon_Installation\\Addon_Activate_Action' => 'getAddonActivateActionService',
            'Yoast\\WP\\SEO\\Actions\\Addon_Installation\\Addon_Install_Action' => 'getAddonInstallActionService',
            'Yoast\\WP\\SEO\\Actions\\Alert_Dismissal_Action' => 'getAlertDismissalActionService',
            'Yoast\\WP\\SEO\\Actions\\Configuration\\First_Time_Configuration_Action' => 'getFirstTimeConfigurationActionService',
            'Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Cleanup_Action' => 'getAioseoCleanupActionService',
            'Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Custom_Archive_Settings_Importing_Action' => 'getAioseoCustomArchiveSettingsImportingActionService',
            'Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Default_Archive_Settings_Importing_Action' => 'getAioseoDefaultArchiveSettingsImportingActionService',
            'Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_General_Settings_Importing_Action' => 'getAioseoGeneralSettingsImportingActionService',
            'Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posts_Importing_Action' => 'getAioseoPostsImportingActionService',
            'Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posttype_Defaults_Settings_Importing_Action' => 'getAioseoPosttypeDefaultsSettingsImportingActionService',
            'Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Taxonomy_Settings_Importing_Action' => 'getAioseoTaxonomySettingsImportingActionService',
            'Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Validate_Data_Action' => 'getAioseoValidateDataActionService',
            'Yoast\\WP\\SEO\\Actions\\Importing\\Deactivate_Conflicting_Plugins_Action' => 'getDeactivateConflictingPluginsActionService',
            'Yoast\\WP\\SEO\\Actions\\Indexables\\Indexable_Head_Action' => 'getIndexableHeadActionService',
            'Yoast\\WP\\SEO\\Actions\\Indexables_Page_Action' => 'getIndexablesPageActionService',
            'Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_General_Indexation_Action' => 'getIndexableGeneralIndexationActionService',
            'Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Indexing_Complete_Action' => 'getIndexableIndexingCompleteActionService',
            'Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Indexation_Action' => 'getIndexablePostIndexationActionService',
            'Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Type_Archive_Indexation_Action' => 'getIndexablePostTypeArchiveIndexationActionService',
            'Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Term_Indexation_Action' => 'getIndexableTermIndexationActionService',
            'Yoast\\WP\\SEO\\Actions\\Indexing\\Indexing_Complete_Action' => 'getIndexingCompleteActionService',
            'Yoast\\WP\\SEO\\Actions\\Indexing\\Indexing_Prepare_Action' => 'getIndexingPrepareActionService',
            'Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action' => 'getPostLinkIndexingActionService',
            'Yoast\\WP\\SEO\\Actions\\Indexing\\Term_Link_Indexing_Action' => 'getTermLinkIndexingActionService',
            'Yoast\\WP\\SEO\\Actions\\Integrations_Action' => 'getIntegrationsActionService',
            'Yoast\\WP\\SEO\\Actions\\SEMrush\\SEMrush_Login_Action' => 'getSEMrushLoginActionService',
            'Yoast\\WP\\SEO\\Actions\\SEMrush\\SEMrush_Options_Action' => 'getSEMrushOptionsActionService',
            'Yoast\\WP\\SEO\\Actions\\SEMrush\\SEMrush_Phrases_Action' => 'getSEMrushPhrasesActionService',
            'Yoast\\WP\\SEO\\Actions\\Settings_Introduction_Action' => 'getSettingsIntroductionActionService',
            'Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Account_Action' => 'getWincherAccountActionService',
            'Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Keyphrases_Action' => 'getWincherKeyphrasesActionService',
            'Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Login_Action' => 'getWincherLoginActionService',
            'Yoast\\WP\\SEO\\Builders\\Indexable_Author_Builder' => 'getIndexableAuthorBuilderService',
            'Yoast\\WP\\SEO\\Builders\\Indexable_Builder' => 'getIndexableBuilderService',
            'Yoast\\WP\\SEO\\Builders\\Indexable_Date_Archive_Builder' => 'getIndexableDateArchiveBuilderService',
            'Yoast\\WP\\SEO\\Builders\\Indexable_Hierarchy_Builder' => 'getIndexableHierarchyBuilderService',
            'Yoast\\WP\\SEO\\Builders\\Indexable_Home_Page_Builder' => 'getIndexableHomePageBuilderService',
            'Yoast\\WP\\SEO\\Builders\\Indexable_Link_Builder' => 'getIndexableLinkBuilderService',
            'Yoast\\WP\\SEO\\Builders\\Indexable_Post_Builder' => 'getIndexablePostBuilderService',
            'Yoast\\WP\\SEO\\Builders\\Indexable_Post_Type_Archive_Builder' => 'getIndexablePostTypeArchiveBuilderService',
            'Yoast\\WP\\SEO\\Builders\\Indexable_System_Page_Builder' => 'getIndexableSystemPageBuilderService',
            'Yoast\\WP\\SEO\\Builders\\Indexable_Term_Builder' => 'getIndexableTermBuilderService',
            'Yoast\\WP\\SEO\\Builders\\Primary_Term_Builder' => 'getPrimaryTermBuilderService',
            'Yoast\\WP\\SEO\\Commands\\Cleanup_Command' => 'getCleanupCommandService',
            'Yoast\\WP\\SEO\\Commands\\Index_Command' => 'getIndexCommandService',
            'Yoast\\WP\\SEO\\Conditionals\\Addon_Installation_Conditional' => 'getAddonInstallationConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Admin\\Doing_Post_Quick_Edit_Save_Conditional' => 'getDoingPostQuickEditSaveConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Admin\\Estimated_Reading_Time_Conditional' => 'getEstimatedReadingTimeConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Admin\\Licenses_Page_Conditional' => 'getLicensesPageConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Admin\\Non_Network_Admin_Conditional' => 'getNonNetworkAdminConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Admin\\Post_Conditional' => 'getPostConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Admin\\Posts_Overview_Or_Ajax_Conditional' => 'getPostsOverviewOrAjaxConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Admin_Conditional' => 'getAdminConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Attachment_Redirections_Enabled_Conditional' => 'getAttachmentRedirectionsEnabledConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Development_Conditional' => 'getDevelopmentConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Front_End_Conditional' => 'getFrontEndConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Front_End_Inspector_Conditional' => 'getFrontEndInspectorConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Get_Request_Conditional' => 'getGetRequestConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Headless_Rest_Endpoints_Enabled_Conditional' => 'getHeadlessRestEndpointsEnabledConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Import_Tool_Selected_Conditional' => 'getImportToolSelectedConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Indexables_Page_Conditional' => 'getIndexablesPageConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Jetpack_Conditional' => 'getJetpackConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Migrations_Conditional' => 'getMigrationsConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\New_Settings_Ui_Conditional' => 'getNewSettingsUiConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\News_Conditional' => 'getNewsConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\No_Tool_Selected_Conditional' => 'getNoToolSelectedConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Non_Multisite_Conditional' => 'getNonMultisiteConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Not_Admin_Ajax_Conditional' => 'getNotAdminAjaxConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Open_Graph_Conditional' => 'getOpenGraphConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Premium_Active_Conditional' => 'getPremiumActiveConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Premium_Inactive_Conditional' => 'getPremiumInactiveConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Primary_Category_Conditional' => 'getPrimaryCategoryConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Robots_Txt_Conditional' => 'getRobotsTxtConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\SEMrush_Enabled_Conditional' => 'getSEMrushEnabledConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Schema_Blocks_Conditional' => 'getSchemaBlocksConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Settings_Conditional' => 'getSettingsConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Should_Index_Links_Conditional' => 'getShouldIndexLinksConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Text_Formality_Conditional' => 'getTextFormalityConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\The_Events_Calendar_Conditional' => 'getTheEventsCalendarConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\CoAuthors_Plus_Activated_Conditional' => 'getCoAuthorsPlusActivatedConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\CoAuthors_Plus_Flag_Conditional' => 'getCoAuthorsPlusFlagConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Elementor_Activated_Conditional' => 'getElementorActivatedConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Elementor_Edit_Conditional' => 'getElementorEditConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Jetpack_Boost_Active_Conditional' => 'getJetpackBoostActiveConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Jetpack_Boost_Not_Premium_Conditional' => 'getJetpackBoostNotPremiumConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Polylang_Conditional' => 'getPolylangConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\TranslatePress_Conditional' => 'getTranslatePressConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\W3_Total_Cache_Conditional' => 'getW3TotalCacheConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\WPML_Conditional' => 'getWPMLConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\WPML_WPSEO_Conditional' => 'getWPMLWPSEOConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Wordproof_Integration_Active_Conditional' => 'getWordproofIntegrationActiveConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Wordproof_Plugin_Inactive_Conditional' => 'getWordproofPluginInactiveConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Updated_Importer_Framework_Conditional' => 'getUpdatedImporterFrameworkConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\User_Can_Manage_Wpseo_Options_Conditional' => 'getUserCanManageWpseoOptionsConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\User_Can_Publish_Posts_And_Pages_Conditional' => 'getUserCanPublishPostsAndPagesConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\WP_Robots_Conditional' => 'getWPRobotsConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Web_Stories_Conditional' => 'getWebStoriesConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Wincher_Automatically_Track_Conditional' => 'getWincherAutomaticallyTrackConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Wincher_Conditional' => 'getWincherConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Wincher_Enabled_Conditional' => 'getWincherEnabledConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Wincher_Token_Conditional' => 'getWincherTokenConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\WooCommerce_Conditional' => 'getWooCommerceConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\XMLRPC_Conditional' => 'getXMLRPCConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Yoast_Admin_And_Dashboard_Conditional' => 'getYoastAdminAndDashboardConditionalService',
            'Yoast\\WP\\SEO\\Conditionals\\Yoast_Tools_Page_Conditional' => 'getYoastToolsPageConditionalService',
            'Yoast\\WP\\SEO\\Config\\Badge_Group_Names' => 'getBadgeGroupNamesService',
            'Yoast\\WP\\SEO\\Config\\Conflicting_Plugins' => 'getConflictingPluginsService',
            'Yoast\\WP\\SEO\\Config\\Indexing_Reasons' => 'getIndexingReasonsService',
            'Yoast\\WP\\SEO\\Config\\Migration_Status' => 'getMigrationStatusService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\AddCollationToTables' => 'getAddCollationToTablesService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\AddColumnsToIndexables' => 'getAddColumnsToIndexablesService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\AddEstimatedReadingTime' => 'getAddEstimatedReadingTimeService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\AddHasAncestorsColumn' => 'getAddHasAncestorsColumnService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\AddIndexableObjectIdAndTypeIndex' => 'getAddIndexableObjectIdAndTypeIndexService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\AddIndexesForProminentWordsOnIndexables' => 'getAddIndexesForProminentWordsOnIndexablesService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\AddObjectTimestamps' => 'getAddObjectTimestampsService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\AddVersionColumnToIndexables' => 'getAddVersionColumnToIndexablesService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\BreadcrumbTitleAndHierarchyReset' => 'getBreadcrumbTitleAndHierarchyResetService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\ClearIndexableTables' => 'getClearIndexableTablesService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\CreateIndexableSubpagesIndex' => 'getCreateIndexableSubpagesIndexService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\CreateSEOLinksTable' => 'getCreateSEOLinksTableService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\DeleteDuplicateIndexables' => 'getDeleteDuplicateIndexablesService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\ExpandIndexableColumnLengths' => 'getExpandIndexableColumnLengthsService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\ExpandIndexableIDColumnLengths' => 'getExpandIndexableIDColumnLengthsService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\ExpandPrimaryTermIDColumnLengths' => 'getExpandPrimaryTermIDColumnLengthsService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\ReplacePermalinkHashIndex' => 'getReplacePermalinkHashIndexService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\ResetIndexableHierarchyTable' => 'getResetIndexableHierarchyTableService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\TruncateIndexableTables' => 'getTruncateIndexableTablesService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\WpYoastDropIndexableMetaTableIfExists' => 'getWpYoastDropIndexableMetaTableIfExistsService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\WpYoastIndexable' => 'getWpYoastIndexableService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\WpYoastIndexableHierarchy' => 'getWpYoastIndexableHierarchyService',
            'Yoast\\WP\\SEO\\Config\\Migrations\\WpYoastPrimaryTerm' => 'getWpYoastPrimaryTermService',
            'Yoast\\WP\\SEO\\Config\\Researcher_Languages' => 'getResearcherLanguagesService',
            'Yoast\\WP\\SEO\\Config\\SEMrush_Client' => 'getSEMrushClientService',
            'Yoast\\WP\\SEO\\Config\\Schema_IDs' => 'getSchemaIDsService',
            'Yoast\\WP\\SEO\\Config\\Schema_Types' => 'getSchemaTypesService',
            'Yoast\\WP\\SEO\\Config\\Wincher_Client' => 'getWincherClientService',
            'Yoast\\WP\\SEO\\Config\\Wordproof_App_Config' => 'getWordproofAppConfigService',
            'Yoast\\WP\\SEO\\Config\\Wordproof_Translations' => 'getWordproofTranslationsService',
            'Yoast\\WP\\SEO\\Context\\Meta_Tags_Context' => 'getMetaTagsContextService',
            'Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator' => 'getBreadcrumbsGeneratorService',
            'Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator' => 'getOpenGraphImageGeneratorService',
            'Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator' => 'getOpenGraphLocaleGeneratorService',
            'Yoast\\WP\\SEO\\Generators\\Schema\\Article' => 'getArticleService',
            'Yoast\\WP\\SEO\\Generators\\Schema\\Author' => 'getAuthorService',
            'Yoast\\WP\\SEO\\Generators\\Schema\\Breadcrumb' => 'getBreadcrumbService',
            'Yoast\\WP\\SEO\\Generators\\Schema\\FAQ' => 'getFAQService',
            'Yoast\\WP\\SEO\\Generators\\Schema\\HowTo' => 'getHowToService',
            'Yoast\\WP\\SEO\\Generators\\Schema\\Main_Image' => 'getMainImageService',
            'Yoast\\WP\\SEO\\Generators\\Schema\\Organization' => 'getOrganizationService',
            'Yoast\\WP\\SEO\\Generators\\Schema\\Person' => 'getPersonService',
            'Yoast\\WP\\SEO\\Generators\\Schema\\Third_Party\\CoAuthor' => 'getCoAuthorService',
            'Yoast\\WP\\SEO\\Generators\\Schema\\Third_Party\\Events_Calendar_Schema' => 'getEventsCalendarSchemaService',
            'Yoast\\WP\\SEO\\Generators\\Schema\\WebPage' => 'getWebPageService',
            'Yoast\\WP\\SEO\\Generators\\Schema\\Website' => 'getWebsiteService',
            'Yoast\\WP\\SEO\\Generators\\Schema_Generator' => 'getSchemaGeneratorService',
            'Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator' => 'getTwitterImageGeneratorService',
            'Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper' => 'getAioseoHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Asset_Helper' => 'getAssetHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Attachment_Cleanup_Helper' => 'getAttachmentCleanupHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Author_Archive_Helper' => 'getAuthorArchiveHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Blocks_Helper' => 'getBlocksHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Capability_Helper' => 'getCapabilityHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Crawl_Cleanup_Helper' => 'getCrawlCleanupHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Curl_Helper' => 'getCurlHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper' => 'getCurrentPageHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Date_Helper' => 'getDateHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Environment_Helper' => 'getEnvironmentHelperService',
            'Yoast\\WP\\SEO\\Helpers\\First_Time_Configuration_Notice_Helper' => 'getFirstTimeConfigurationNoticeHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Home_Url_Helper' => 'getHomeUrlHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Image_Helper' => 'getImageHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper' => 'getImportCursorHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Import_Helper' => 'getImportHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Indexable_Helper' => 'getIndexableHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Indexable_To_Postmeta_Helper' => 'getIndexableToPostmetaHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Indexables_Page_Helper' => 'getIndexablesPageHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Indexing_Helper' => 'getIndexingHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Language_Helper' => 'getLanguageHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Meta_Helper' => 'getMetaHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Notification_Helper' => 'getNotificationHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper' => 'getImageHelper2Service',
            'Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper' => 'getValuesHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Options_Helper' => 'getOptionsHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Pagination_Helper' => 'getPaginationHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Permalink_Helper' => 'getPermalinkHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Post_Helper' => 'getPostHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper' => 'getPostTypeHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Primary_Term_Helper' => 'getPrimaryTermHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Product_Helper' => 'getProductHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Redirect_Helper' => 'getRedirectHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Request_Helper' => 'getRequestHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Require_File_Helper' => 'getRequireFileHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Robots_Helper' => 'getRobotsHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Robots_Txt_Helper' => 'getRobotsTxtHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper' => 'getSanitizationHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Schema\\Article_Helper' => 'getArticleHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Schema\\HTML_Helper' => 'getHTMLHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Schema\\ID_Helper' => 'getIDHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Schema\\Image_Helper' => 'getImageHelper3Service',
            'Yoast\\WP\\SEO\\Helpers\\Schema\\Language_Helper' => 'getLanguageHelper2Service',
            'Yoast\\WP\\SEO\\Helpers\\Schema\\Replace_Vars_Helper' => 'getReplaceVarsHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Score_Icon_Helper' => 'getScoreIconHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Short_Link_Helper' => 'getShortLinkHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Site_Helper' => 'getSiteHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Social_Profiles_Helper' => 'getSocialProfilesHelperService',
            'Yoast\\WP\\SEO\\Helpers\\String_Helper' => 'getStringHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper' => 'getTaxonomyHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Twitter\\Image_Helper' => 'getImageHelper4Service',
            'Yoast\\WP\\SEO\\Helpers\\Url_Helper' => 'getUrlHelperService',
            'Yoast\\WP\\SEO\\Helpers\\User_Helper' => 'getUserHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Wincher_Helper' => 'getWincherHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Woocommerce_Helper' => 'getWoocommerceHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Wordpress_Helper' => 'getWordpressHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Wordproof_Helper' => 'getWordproofHelperService',
            'Yoast\\WP\\SEO\\Helpers\\Wpdb_Helper' => 'getWpdbHelperService',
            'Yoast\\WP\\SEO\\Initializers\\Crawl_Cleanup_Permalinks' => 'getCrawlCleanupPermalinksService',
            'Yoast\\WP\\SEO\\Initializers\\Disable_Core_Sitemaps' => 'getDisableCoreSitemapsService',
            'Yoast\\WP\\SEO\\Initializers\\Migration_Runner' => 'getMigrationRunnerService',
            'Yoast\\WP\\SEO\\Initializers\\Woocommerce' => 'getWoocommerceService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Activation_Cleanup_Integration' => 'getActivationCleanupIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Addon_Installation\\Dialog_Integration' => 'getDialogIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Addon_Installation\\Installation_Integration' => 'getInstallationIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Admin_Columns_Cache_Integration' => 'getAdminColumnsCacheIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Background_Indexing_Integration' => 'getBackgroundIndexingIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Crawl_Settings_Integration' => 'getCrawlSettingsIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Cron_Integration' => 'getCronIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Deactivated_Premium_Integration' => 'getDeactivatedPremiumIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Disable_Concatenate_Scripts_Integration' => 'getDisableConcatenateScriptsIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\First_Time_Configuration_Integration' => 'getFirstTimeConfigurationIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\First_Time_Configuration_Notice_Integration' => 'getFirstTimeConfigurationNoticeIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Fix_News_Dependencies_Integration' => 'getFixNewsDependenciesIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Health_Check_Integration' => 'getHealthCheckIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\HelpScout_Beacon' => 'getHelpScoutBeaconService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Import_Integration' => 'getImportIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Indexables_Exclude_Taxonomy_Integration' => 'getIndexablesExcludeTaxonomyIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Indexables_Page_Integration' => 'getIndexablesPageIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Indexing_Notification_Integration' => 'getIndexingNotificationIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Indexing_Tool_Integration' => 'getIndexingToolIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Installation_Success_Integration' => 'getInstallationSuccessIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Integrations_Page' => 'getIntegrationsPageService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Link_Count_Columns_Integration' => 'getLinkCountColumnsIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Menu_Badge_Integration' => 'getMenuBadgeIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Migration_Error_Integration' => 'getMigrationErrorIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Old_Configuration_Integration' => 'getOldConfigurationIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Old_Premium_Integration' => 'getOldPremiumIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Redirect_Integration' => 'getRedirectIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Redirects_Page_Integration' => 'getRedirectsPageIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Social_Templates_Integration' => 'getSocialTemplatesIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Admin\\Workouts_Integration' => 'getWorkoutsIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Alerts\\Jetpack_Boost_Pre_Publish' => 'getJetpackBoostPrePublishService',
            'Yoast\\WP\\SEO\\Integrations\\Alerts\\Webinar_Promo_Notification' => 'getWebinarPromoNotificationService',
            'Yoast\\WP\\SEO\\Integrations\\Blocks\\Breadcrumbs_Block' => 'getBreadcrumbsBlockService',
            'Yoast\\WP\\SEO\\Integrations\\Blocks\\Internal_Linking_Category' => 'getInternalLinkingCategoryService',
            'Yoast\\WP\\SEO\\Integrations\\Blocks\\Structured_Data_Blocks' => 'getStructuredDataBlocksService',
            'Yoast\\WP\\SEO\\Integrations\\Breadcrumbs_Integration' => 'getBreadcrumbsIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Cleanup_Integration' => 'getCleanupIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Duplicate_Post_Integration' => 'getDuplicatePostIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Estimated_Reading_Time' => 'getEstimatedReadingTimeService',
            'Yoast\\WP\\SEO\\Integrations\\Exclude_Attachment_Post_Type' => 'getExcludeAttachmentPostTypeService',
            'Yoast\\WP\\SEO\\Integrations\\Exclude_Oembed_Cache_Post_Type' => 'getExcludeOembedCachePostTypeService',
            'Yoast\\WP\\SEO\\Integrations\\Feature_Flag_Integration' => 'getFeatureFlagIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Front_End\\Backwards_Compatibility' => 'getBackwardsCompatibilityService',
            'Yoast\\WP\\SEO\\Integrations\\Front_End\\Category_Term_Description' => 'getCategoryTermDescriptionService',
            'Yoast\\WP\\SEO\\Integrations\\Front_End\\Comment_Link_Fixer' => 'getCommentLinkFixerService',
            'Yoast\\WP\\SEO\\Integrations\\Front_End\\Crawl_Cleanup_Basic' => 'getCrawlCleanupBasicService',
            'Yoast\\WP\\SEO\\Integrations\\Front_End\\Crawl_Cleanup_Rss' => 'getCrawlCleanupRssService',
            'Yoast\\WP\\SEO\\Integrations\\Front_End\\Crawl_Cleanup_Searches' => 'getCrawlCleanupSearchesService',
            'Yoast\\WP\\SEO\\Integrations\\Front_End\\Feed_Improvements' => 'getFeedImprovementsService',
            'Yoast\\WP\\SEO\\Integrations\\Front_End\\Force_Rewrite_Title' => 'getForceRewriteTitleService',
            'Yoast\\WP\\SEO\\Integrations\\Front_End\\Handle_404' => 'getHandle404Service',
            'Yoast\\WP\\SEO\\Integrations\\Front_End\\Indexing_Controls' => 'getIndexingControlsService',
            'Yoast\\WP\\SEO\\Integrations\\Front_End\\Open_Graph_OEmbed' => 'getOpenGraphOEmbedService',
            'Yoast\\WP\\SEO\\Integrations\\Front_End\\RSS_Footer_Embed' => 'getRSSFooterEmbedService',
            'Yoast\\WP\\SEO\\Integrations\\Front_End\\Redirects' => 'getRedirectsService',
            'Yoast\\WP\\SEO\\Integrations\\Front_End\\Robots_Txt_Integration' => 'getRobotsTxtIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Front_End\\Schema_Accessibility_Feature' => 'getSchemaAccessibilityFeatureService',
            'Yoast\\WP\\SEO\\Integrations\\Front_End\\WP_Robots_Integration' => 'getWPRobotsIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Front_End_Integration' => 'getFrontEndIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Primary_Category' => 'getPrimaryCategoryService',
            'Yoast\\WP\\SEO\\Integrations\\Schema_Blocks' => 'getSchemaBlocksService',
            'Yoast\\WP\\SEO\\Integrations\\Settings_Integration' => 'getSettingsIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\AMP' => 'getAMPService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\BbPress' => 'getBbPressService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\CoAuthors_Plus' => 'getCoAuthorsPlusService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Elementor' => 'getElementorService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Exclude_Elementor_Post_Types' => 'getExcludeElementorPostTypesService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Exclude_WooCommerce_Post_Types' => 'getExcludeWooCommercePostTypesService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Jetpack' => 'getJetpackService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\The_Events_Calendar' => 'getTheEventsCalendarService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\W3_Total_Cache' => 'getW3TotalCacheService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\WPML' => 'getWPMLService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\WPML_WPSEO_Notification' => 'getWPMLWPSEONotificationService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Web_Stories' => 'getWebStoriesService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Web_Stories_Post_Edit' => 'getWebStoriesPostEditService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Wincher' => 'getWincherService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Wincher_Publish' => 'getWincherPublishService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\WooCommerce' => 'getWooCommerce2Service',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\WooCommerce_Post_Edit' => 'getWooCommercePostEditService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Woocommerce_Permalinks' => 'getWoocommercePermalinksService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Wordproof' => 'getWordproofService',
            'Yoast\\WP\\SEO\\Integrations\\Third_Party\\Wordproof_Integration_Toggle' => 'getWordproofIntegrationToggleService',
            'Yoast\\WP\\SEO\\Integrations\\Uninstall_Integration' => 'getUninstallIntegrationService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Addon_Update_Watcher' => 'getAddonUpdateWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Auto_Update_Watcher' => 'getAutoUpdateWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Ancestor_Watcher' => 'getIndexableAncestorWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Attachment_Watcher' => 'getIndexableAttachmentWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Author_Archive_Watcher' => 'getIndexableAuthorArchiveWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Author_Watcher' => 'getIndexableAuthorWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Category_Permalink_Watcher' => 'getIndexableCategoryPermalinkWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Date_Archive_Watcher' => 'getIndexableDateArchiveWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_HomeUrl_Watcher' => 'getIndexableHomeUrlWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Home_Page_Watcher' => 'getIndexableHomePageWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Permalink_Watcher' => 'getIndexablePermalinkWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Meta_Watcher' => 'getIndexablePostMetaWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Type_Archive_Watcher' => 'getIndexablePostTypeArchiveWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Type_Change_Watcher' => 'getIndexablePostTypeChangeWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Watcher' => 'getIndexablePostWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Static_Home_Page_Watcher' => 'getIndexableStaticHomePageWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_System_Page_Watcher' => 'getIndexableSystemPageWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Taxonomy_Change_Watcher' => 'getIndexableTaxonomyChangeWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Term_Watcher' => 'getIndexableTermWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Option_Titles_Watcher' => 'getOptionTitlesWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Option_Wpseo_Watcher' => 'getOptionWpseoWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Primary_Category_Quick_Edit_Watcher' => 'getPrimaryCategoryQuickEditWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Primary_Term_Watcher' => 'getPrimaryTermWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\Watchers\\Search_Engines_Discouraged_Watcher' => 'getSearchEnginesDiscouragedWatcherService',
            'Yoast\\WP\\SEO\\Integrations\\XMLRPC' => 'getXMLRPCService',
            'Yoast\\WP\\SEO\\Loader' => 'getLoaderService',
            'Yoast\\WP\\SEO\\Loggers\\Logger' => 'getLoggerService',
            'Yoast\\WP\\SEO\\Memoizers\\Meta_Tags_Context_Memoizer' => 'getMetaTagsContextMemoizerService',
            'Yoast\\WP\\SEO\\Memoizers\\Presentation_Memoizer' => 'getPresentationMemoizerService',
            'Yoast\\WP\\SEO\\Presentations\\Abstract_Presentation' => 'getAbstractPresentationService',
            'Yoast\\WP\\SEO\\Presentations\\Indexable_Author_Archive_Presentation' => 'getIndexableAuthorArchivePresentationService',
            'Yoast\\WP\\SEO\\Presentations\\Indexable_Date_Archive_Presentation' => 'getIndexableDateArchivePresentationService',
            'Yoast\\WP\\SEO\\Presentations\\Indexable_Error_Page_Presentation' => 'getIndexableErrorPagePresentationService',
            'Yoast\\WP\\SEO\\Presentations\\Indexable_Home_Page_Presentation' => 'getIndexableHomePagePresentationService',
            'Yoast\\WP\\SEO\\Presentations\\Indexable_Post_Type_Archive_Presentation' => 'getIndexablePostTypeArchivePresentationService',
            'Yoast\\WP\\SEO\\Presentations\\Indexable_Post_Type_Presentation' => 'getIndexablePostTypePresentationService',
            'Yoast\\WP\\SEO\\Presentations\\Indexable_Presentation' => 'getIndexablePresentationService',
            'Yoast\\WP\\SEO\\Presentations\\Indexable_Search_Result_Page_Presentation' => 'getIndexableSearchResultPagePresentationService',
            'Yoast\\WP\\SEO\\Presentations\\Indexable_Static_Home_Page_Presentation' => 'getIndexableStaticHomePagePresentationService',
            'Yoast\\WP\\SEO\\Presentations\\Indexable_Static_Posts_Page_Presentation' => 'getIndexableStaticPostsPagePresentationService',
            'Yoast\\WP\\SEO\\Presentations\\Indexable_Term_Archive_Presentation' => 'getIndexableTermArchivePresentationService',
            'Yoast\\WP\\SEO\\Repositories\\Indexable_Hierarchy_Repository' => 'getIndexableHierarchyRepositoryService',
            'Yoast\\WP\\SEO\\Repositories\\Indexable_Repository' => 'getIndexableRepositoryService',
            'Yoast\\WP\\SEO\\Repositories\\Primary_Term_Repository' => 'getPrimaryTermRepositoryService',
            'Yoast\\WP\\SEO\\Repositories\\SEO_Links_Repository' => 'getSEOLinksRepositoryService',
            'Yoast\\WP\\SEO\\Routes\\Alert_Dismissal_Route' => 'getAlertDismissalRouteService',
            'Yoast\\WP\\SEO\\Routes\\First_Time_Configuration_Route' => 'getFirstTimeConfigurationRouteService',
            'Yoast\\WP\\SEO\\Routes\\Importing_Route' => 'getImportingRouteService',
            'Yoast\\WP\\SEO\\Routes\\Indexables_Head_Route' => 'getIndexablesHeadRouteService',
            'Yoast\\WP\\SEO\\Routes\\Indexables_Page_Route' => 'getIndexablesPageRouteService',
            'Yoast\\WP\\SEO\\Routes\\Indexing_Route' => 'getIndexingRouteService',
            'Yoast\\WP\\SEO\\Routes\\Integrations_Route' => 'getIntegrationsRouteService',
            'Yoast\\WP\\SEO\\Routes\\Meta_Search_Route' => 'getMetaSearchRouteService',
            'Yoast\\WP\\SEO\\Routes\\SEMrush_Route' => 'getSEMrushRouteService',
            'Yoast\\WP\\SEO\\Routes\\Settings_Introduction_Route' => 'getSettingsIntroductionRouteService',
            'Yoast\\WP\\SEO\\Routes\\Supported_Features_Route' => 'getSupportedFeaturesRouteService',
            'Yoast\\WP\\SEO\\Routes\\Wincher_Route' => 'getWincherRouteService',
            'Yoast\\WP\\SEO\\Routes\\Workouts_Route' => 'getWorkoutsRouteService',
            'Yoast\\WP\\SEO\\Routes\\Yoast_Head_REST_Field' => 'getYoastHeadRESTFieldService',
            'Yoast\\WP\\SEO\\Schema_Templates\\Assets\\Icons' => 'getIconsService',
            'Yoast\\WP\\SEO\\Services\\Health_Check\\Default_Tagline_Check' => 'getDefaultTaglineCheckService',
            'Yoast\\WP\\SEO\\Services\\Health_Check\\Default_Tagline_Reports' => 'getDefaultTaglineReportsService',
            'Yoast\\WP\\SEO\\Services\\Health_Check\\Default_Tagline_Runner' => 'getDefaultTaglineRunnerService',
            'Yoast\\WP\\SEO\\Services\\Health_Check\\Links_Table_Check' => 'getLinksTableCheckService',
            'Yoast\\WP\\SEO\\Services\\Health_Check\\Links_Table_Reports' => 'getLinksTableReportsService',
            'Yoast\\WP\\SEO\\Services\\Health_Check\\Links_Table_Runner' => 'getLinksTableRunnerService',
            'Yoast\\WP\\SEO\\Services\\Health_Check\\MyYoast_Api_Request_Factory' => 'getMyYoastApiRequestFactoryService',
            'Yoast\\WP\\SEO\\Services\\Health_Check\\Page_Comments_Check' => 'getPageCommentsCheckService',
            'Yoast\\WP\\SEO\\Services\\Health_Check\\Page_Comments_Reports' => 'getPageCommentsReportsService',
            'Yoast\\WP\\SEO\\Services\\Health_Check\\Page_Comments_Runner' => 'getPageCommentsRunnerService',
            'Yoast\\WP\\SEO\\Services\\Health_Check\\Postname_Permalink_Check' => 'getPostnamePermalinkCheckService',
            'Yoast\\WP\\SEO\\Services\\Health_Check\\Postname_Permalink_Reports' => 'getPostnamePermalinkReportsService',
            'Yoast\\WP\\SEO\\Services\\Health_Check\\Postname_Permalink_Runner' => 'getPostnamePermalinkRunnerService',
            'Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder' => 'getReportBuilderService',
            'Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder_Factory' => 'getReportBuilderFactoryService',
            'Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service' => 'getAioseoReplacevarServiceService',
            'Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service' => 'getAioseoRobotsProviderServiceService',
            'Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service' => 'getAioseoRobotsTransformerServiceService',
            'Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Social_Images_Provider_Service' => 'getAioseoSocialImagesProviderServiceService',
            'Yoast\\WP\\SEO\\Services\\Importing\\Conflicting_Plugins_Service' => 'getConflictingPluginsServiceService',
            'Yoast\\WP\\SEO\\Services\\Importing\\Importable_Detector_Service' => 'getImportableDetectorServiceService',
            'Yoast\\WP\\SEO\\Services\\Indexables\\Indexable_Version_Manager' => 'getIndexableVersionManagerService',
            'Yoast\\WP\\SEO\\Surfaces\\Classes_Surface' => 'getClassesSurfaceService',
            'Yoast\\WP\\SEO\\Surfaces\\Helpers_Surface' => 'getHelpersSurfaceService',
            'Yoast\\WP\\SEO\\Surfaces\\Meta_Surface' => 'getMetaSurfaceService',
            'Yoast\\WP\\SEO\\Surfaces\\Open_Graph_Helpers_Surface' => 'getOpenGraphHelpersSurfaceService',
            'Yoast\\WP\\SEO\\Surfaces\\Schema_Helpers_Surface' => 'getSchemaHelpersSurfaceService',
            'Yoast\\WP\\SEO\\Surfaces\\Twitter_Helpers_Surface' => 'getTwitterHelpersSurfaceService',
            'Yoast\\WP\\SEO\\Values\\Images' => 'getImagesService',
            'Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions' => 'getIndexableBuilderVersionsService',
            'Yoast\\WP\\SEO\\Values\\Open_Graph\\Images' => 'getImages2Service',
            'Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper' => 'getWPQueryWrapperService',
            'Yoast\\WP\\SEO\\Wrappers\\WP_Remote_Handler' => 'getWPRemoteHandlerService',
            'Yoast\\WP\\SEO\\Wrappers\\WP_Rewrite_Wrapper' => 'getWPRewriteWrapperService',
            'Yoast_Notification_Center' => 'getYoastNotificationCenterService',
            'wpdb' => 'getWpdbService',
        ];
        $this->privates = [
            'YoastSEO_Vendor\\YoastSEO_Vendor\\Symfony\\Component\\DependencyInjection\\ContainerInterface' => true,
            'wpdb' => true,
        ];
        $this->aliases = [
            'YoastSEO_Vendor\\YoastSEO_Vendor\\Symfony\\Component\\DependencyInjection\\ContainerInterface' => 'service_container',
        ];
    }

    public function getRemovedIds()
    {
        return [
            'Psr\\Container\\ContainerInterface' => true,
            'YoastSEO_Vendor\\Symfony\\Component\\DependencyInjection\\ContainerInterface' => true,
            'YoastSEO_Vendor\\YoastSEO_Vendor\\Symfony\\Component\\DependencyInjection\\ContainerInterface' => true,
            'Yoast\\WP\\SEO\\Presenters\\Robots_Txt_Presenter' => true,
            'wpdb' => true,
        ];
    }

    public function compile()
    {
        throw new LogicException('You cannot compile a dumped container that was already compiled.');
    }

    public function isCompiled()
    {
        return true;
    }

    public function isFrozen()
    {
        @trigger_error(sprintf('The %s() method is deprecated since Symfony 3.3 and will be removed in 4.0. Use the isCompiled() method instead.', __METHOD__), E_USER_DEPRECATED);

        return true;
    }

    /**
     * Gets the public 'WPSEO_Addon_Manager' shared service.
     *
     * @return \WPSEO_Addon_Manager
     */
    protected function getWPSEOAddonManagerService()
    {
        return $this->services['WPSEO_Addon_Manager'] = \Yoast\WP\SEO\WordPress\Wrapper::get_addon_manager();
    }

    /**
     * Gets the public 'WPSEO_Admin_Asset_Manager' shared service.
     *
     * @return \WPSEO_Admin_Asset_Manager
     */
    protected function getWPSEOAdminAssetManagerService()
    {
        return $this->services['WPSEO_Admin_Asset_Manager'] = \Yoast\WP\SEO\WordPress\Wrapper::get_admin_asset_manager();
    }

    /**
     * Gets the public 'WPSEO_Breadcrumbs' shared autowired service.
     *
     * @return \WPSEO_Breadcrumbs
     */
    protected function getWPSEOBreadcrumbsService()
    {
        return $this->services['WPSEO_Breadcrumbs'] = new \WPSEO_Breadcrumbs();
    }

    /**
     * Gets the public 'WPSEO_Frontend' shared autowired service.
     *
     * @return \WPSEO_Frontend
     */
    protected function getWPSEOFrontendService()
    {
        return $this->services['WPSEO_Frontend'] = new \WPSEO_Frontend();
    }

    /**
     * Gets the public 'WPSEO_Replace_Vars' shared service.
     *
     * @return \WPSEO_Replace_Vars
     */
    protected function getWPSEOReplaceVarsService()
    {
        return $this->services['WPSEO_Replace_Vars'] = \Yoast\WP\SEO\WordPress\Wrapper::get_replace_vars();
    }

    /**
     * Gets the public 'WPSEO_Shortlinker' shared service.
     *
     * @return \WPSEO_Shortlinker
     */
    protected function getWPSEOShortlinkerService()
    {
        return $this->services['WPSEO_Shortlinker'] = \Yoast\WP\SEO\WordPress\Wrapper::get_shortlinker();
    }

    /**
     * Gets the public 'WPSEO_Utils' shared service.
     *
     * @return \WPSEO_Utils
     */
    protected function getWPSEOUtilsService()
    {
        return $this->services['WPSEO_Utils'] = \Yoast\WP\SEO\WordPress\Wrapper::get_utils();
    }

    /**
     * Gets the public 'Yoast\WP\Lib\Migrations\Adapter' shared autowired service.
     *
     * @return \Yoast\WP\Lib\Migrations\Adapter
     */
    protected function getAdapterService()
    {
        return $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Addon_Installation\Addon_Activate_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Addon_Installation\Addon_Activate_Action
     */
    protected function getAddonActivateActionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Actions\\Addon_Installation\\Addon_Activate_Action'] = new \Yoast\WP\SEO\Actions\Addon_Installation\Addon_Activate_Action(${($_ = isset($this->services['WPSEO_Addon_Manager']) ? $this->services['WPSEO_Addon_Manager'] : $this->getWPSEOAddonManagerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Require_File_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Require_File_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Require_File_Helper'] = new \Yoast\WP\SEO\Helpers\Require_File_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Addon_Installation\Addon_Install_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Addon_Installation\Addon_Install_Action
     */
    protected function getAddonInstallActionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Actions\\Addon_Installation\\Addon_Install_Action'] = new \Yoast\WP\SEO\Actions\Addon_Installation\Addon_Install_Action(${($_ = isset($this->services['WPSEO_Addon_Manager']) ? $this->services['WPSEO_Addon_Manager'] : $this->getWPSEOAddonManagerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Require_File_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Require_File_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Require_File_Helper'] = new \Yoast\WP\SEO\Helpers\Require_File_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Alert_Dismissal_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Alert_Dismissal_Action
     */
    protected function getAlertDismissalActionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Actions\\Alert_Dismissal_Action'] = new \Yoast\WP\SEO\Actions\Alert_Dismissal_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] = new \Yoast\WP\SEO\Helpers\User_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Configuration\First_Time_Configuration_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Configuration\First_Time_Configuration_Action
     */
    protected function getFirstTimeConfigurationActionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Actions\\Configuration\\First_Time_Configuration_Action'] = new \Yoast\WP\SEO\Actions\Configuration\First_Time_Configuration_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Social_Profiles_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Social_Profiles_Helper'] : $this->getSocialProfilesHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Cleanup_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Cleanup_Action
     */
    protected function getAioseoCleanupActionService()
    {
        $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Cleanup_Action'] = $instance = new \Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Cleanup_Action(${($_ = isset($this->services['wpdb']) ? $this->services['wpdb'] : $this->getWpdbService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});

        $instance->set_aioseo_helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper'] : $this->getAioseoHelperService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Custom_Archive_Settings_Importing_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Custom_Archive_Settings_Importing_Action
     */
    protected function getAioseoCustomArchiveSettingsImportingActionService()
    {
        $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Custom_Archive_Settings_Importing_Action'] = $instance = new \Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Custom_Archive_Settings_Importing_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper'] : $this->getImportCursorHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper'] = new \Yoast\WP\SEO\Helpers\Sanitization_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service'] : ($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service'] = new \Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Replacevar_Service())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service'] : $this->getAioseoRobotsProviderServiceService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service'] : $this->getAioseoRobotsTransformerServiceService()) && false ?: '_'});

        $instance->set_import_helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Import_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Helper'] = new \Yoast\WP\SEO\Helpers\Import_Helper())) && false ?: '_'});
        $instance->set_aioseo_helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper'] : $this->getAioseoHelperService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Default_Archive_Settings_Importing_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Default_Archive_Settings_Importing_Action
     */
    protected function getAioseoDefaultArchiveSettingsImportingActionService()
    {
        $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Default_Archive_Settings_Importing_Action'] = $instance = new \Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Default_Archive_Settings_Importing_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper'] : $this->getImportCursorHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper'] = new \Yoast\WP\SEO\Helpers\Sanitization_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service'] : ($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service'] = new \Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Replacevar_Service())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service'] : $this->getAioseoRobotsProviderServiceService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service'] : $this->getAioseoRobotsTransformerServiceService()) && false ?: '_'});

        $instance->set_import_helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Import_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Helper'] = new \Yoast\WP\SEO\Helpers\Import_Helper())) && false ?: '_'});
        $instance->set_aioseo_helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper'] : $this->getAioseoHelperService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_General_Settings_Importing_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_General_Settings_Importing_Action
     */
    protected function getAioseoGeneralSettingsImportingActionService()
    {
        $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_General_Settings_Importing_Action'] = $instance = new \Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_General_Settings_Importing_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper'] : $this->getImportCursorHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper'] = new \Yoast\WP\SEO\Helpers\Sanitization_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service'] : ($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service'] = new \Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Replacevar_Service())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service'] : $this->getAioseoRobotsProviderServiceService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service'] : $this->getAioseoRobotsTransformerServiceService()) && false ?: '_'});

        $instance->set_import_helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Import_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Helper'] = new \Yoast\WP\SEO\Helpers\Import_Helper())) && false ?: '_'});
        $instance->set_aioseo_helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper'] : $this->getAioseoHelperService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Posts_Importing_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Posts_Importing_Action
     */
    protected function getAioseoPostsImportingActionService()
    {
        $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posts_Importing_Action'] = $instance = new \Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Posts_Importing_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['wpdb']) ? $this->services['wpdb'] : $this->getWpdbService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper'] : $this->getImportCursorHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_To_Postmeta_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_To_Postmeta_Helper'] : $this->getIndexableToPostmetaHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper'] = new \Yoast\WP\SEO\Helpers\Sanitization_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service'] : ($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service'] = new \Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Replacevar_Service())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service'] : $this->getAioseoRobotsProviderServiceService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service'] : $this->getAioseoRobotsTransformerServiceService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Social_Images_Provider_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Social_Images_Provider_Service'] : $this->getAioseoSocialImagesProviderServiceService()) && false ?: '_'});

        $instance->set_aioseo_helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper'] : $this->getAioseoHelperService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Posttype_Defaults_Settings_Importing_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Posttype_Defaults_Settings_Importing_Action
     */
    protected function getAioseoPosttypeDefaultsSettingsImportingActionService()
    {
        $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posttype_Defaults_Settings_Importing_Action'] = $instance = new \Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Posttype_Defaults_Settings_Importing_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper'] : $this->getImportCursorHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper'] = new \Yoast\WP\SEO\Helpers\Sanitization_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service'] : ($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service'] = new \Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Replacevar_Service())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service'] : $this->getAioseoRobotsProviderServiceService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service'] : $this->getAioseoRobotsTransformerServiceService()) && false ?: '_'});

        $instance->set_import_helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Import_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Helper'] = new \Yoast\WP\SEO\Helpers\Import_Helper())) && false ?: '_'});
        $instance->set_aioseo_helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper'] : $this->getAioseoHelperService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Taxonomy_Settings_Importing_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Taxonomy_Settings_Importing_Action
     */
    protected function getAioseoTaxonomySettingsImportingActionService()
    {
        $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Taxonomy_Settings_Importing_Action'] = $instance = new \Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Taxonomy_Settings_Importing_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper'] : $this->getImportCursorHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper'] = new \Yoast\WP\SEO\Helpers\Sanitization_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service'] : ($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service'] = new \Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Replacevar_Service())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service'] : $this->getAioseoRobotsProviderServiceService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service'] : $this->getAioseoRobotsTransformerServiceService()) && false ?: '_'});

        $instance->set_import_helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Import_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Helper'] = new \Yoast\WP\SEO\Helpers\Import_Helper())) && false ?: '_'});
        $instance->set_aioseo_helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper'] : $this->getAioseoHelperService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Validate_Data_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Validate_Data_Action
     */
    protected function getAioseoValidateDataActionService()
    {
        $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Validate_Data_Action'] = $instance = new \Yoast\WP\SEO\Actions\Importing\Aioseo\Aioseo_Validate_Data_Action(${($_ = isset($this->services['wpdb']) ? $this->services['wpdb'] : $this->getWpdbService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Custom_Archive_Settings_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Custom_Archive_Settings_Importing_Action'] : $this->getAioseoCustomArchiveSettingsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Default_Archive_Settings_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Default_Archive_Settings_Importing_Action'] : $this->getAioseoDefaultArchiveSettingsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_General_Settings_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_General_Settings_Importing_Action'] : $this->getAioseoGeneralSettingsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posttype_Defaults_Settings_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posttype_Defaults_Settings_Importing_Action'] : $this->getAioseoPosttypeDefaultsSettingsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Taxonomy_Settings_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Taxonomy_Settings_Importing_Action'] : $this->getAioseoTaxonomySettingsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posts_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posts_Importing_Action'] : $this->getAioseoPostsImportingActionService()) && false ?: '_'});

        $instance->set_aioseo_helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper'] : $this->getAioseoHelperService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Importing\Deactivate_Conflicting_Plugins_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Importing\Deactivate_Conflicting_Plugins_Action
     */
    protected function getDeactivateConflictingPluginsActionService()
    {
        $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Deactivate_Conflicting_Plugins_Action'] = $instance = new \Yoast\WP\SEO\Actions\Importing\Deactivate_Conflicting_Plugins_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper'] : $this->getImportCursorHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper'] = new \Yoast\WP\SEO\Helpers\Sanitization_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service'] : ($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service'] = new \Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Replacevar_Service())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service'] : $this->getAioseoRobotsProviderServiceService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service'] : $this->getAioseoRobotsTransformerServiceService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Conflicting_Plugins_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Conflicting_Plugins_Service'] : ($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Conflicting_Plugins_Service'] = new \Yoast\WP\SEO\Services\Importing\Conflicting_Plugins_Service())) && false ?: '_'});

        $instance->set_aioseo_helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper'] : $this->getAioseoHelperService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Indexables\Indexable_Head_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Indexables\Indexable_Head_Action
     */
    protected function getIndexableHeadActionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Actions\\Indexables\\Indexable_Head_Action'] = new \Yoast\WP\SEO\Actions\Indexables\Indexable_Head_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Surfaces\\Meta_Surface']) ? $this->services['Yoast\\WP\\SEO\\Surfaces\\Meta_Surface'] : $this->getMetaSurfaceService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Indexables_Page_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Indexables_Page_Action
     *
     * @deprecated Yoast\WP\SEO\Actions\Indexables_Page_Action is deprecated since version 20.4!
     */
    protected function getIndexablesPageActionService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Actions\\Indexables_Page_Action is deprecated since version 20.4!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Actions\\Indexables_Page_Action'] = new \Yoast\WP\SEO\Actions\Indexables_Page_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexables_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexables_Page_Helper'] : $this->getIndexablesPageHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Indexing\Indexable_General_Indexation_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Indexing\Indexable_General_Indexation_Action
     */
    protected function getIndexableGeneralIndexationActionService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_General_Indexation_Action'])) {
            return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_General_Indexation_Action'];
        }

        return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_General_Indexation_Action'] = new \Yoast\WP\SEO\Actions\Indexing\Indexable_General_Indexation_Action($a);
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Indexing\Indexable_Indexing_Complete_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Indexing\Indexable_Indexing_Complete_Action
     */
    protected function getIndexableIndexingCompleteActionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Indexing_Complete_Action'] = new \Yoast\WP\SEO\Actions\Indexing\Indexable_Indexing_Complete_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Indexing\Indexable_Post_Indexation_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Indexing\Indexable_Post_Indexation_Action
     */
    protected function getIndexablePostIndexationActionService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Indexation_Action'])) {
            return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Indexation_Action'];
        }
        $b = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper'] : $this->getPostHelperService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Indexation_Action'])) {
            return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Indexation_Action'];
        }

        return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Indexation_Action'] = new \Yoast\WP\SEO\Actions\Indexing\Indexable_Post_Indexation_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, $a, ${($_ = isset($this->services['wpdb']) ? $this->services['wpdb'] : $this->getWpdbService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions']) ? $this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] : ($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] = new \Yoast\WP\SEO\Values\Indexables\Indexable_Builder_Versions())) && false ?: '_'}, $b);
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Indexing\Indexable_Post_Type_Archive_Indexation_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Indexing\Indexable_Post_Type_Archive_Indexation_Action
     */
    protected function getIndexablePostTypeArchiveIndexationActionService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Type_Archive_Indexation_Action'])) {
            return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Type_Archive_Indexation_Action'];
        }
        $b = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'] : $this->getIndexableBuilderService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Type_Archive_Indexation_Action'])) {
            return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Type_Archive_Indexation_Action'];
        }

        return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Type_Archive_Indexation_Action'] = new \Yoast\WP\SEO\Actions\Indexing\Indexable_Post_Type_Archive_Indexation_Action($a, $b, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions']) ? $this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] : ($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] = new \Yoast\WP\SEO\Values\Indexables\Indexable_Builder_Versions())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Indexing\Indexable_Term_Indexation_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Indexing\Indexable_Term_Indexation_Action
     */
    protected function getIndexableTermIndexationActionService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Term_Indexation_Action'])) {
            return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Term_Indexation_Action'];
        }

        return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Term_Indexation_Action'] = new \Yoast\WP\SEO\Actions\Indexing\Indexable_Term_Indexation_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper'] : $this->getTaxonomyHelperService()) && false ?: '_'}, $a, ${($_ = isset($this->services['wpdb']) ? $this->services['wpdb'] : $this->getWpdbService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions']) ? $this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] : ($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] = new \Yoast\WP\SEO\Values\Indexables\Indexable_Builder_Versions())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Indexing\Indexing_Complete_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Indexing\Indexing_Complete_Action
     */
    protected function getIndexingCompleteActionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexing_Complete_Action'] = new \Yoast\WP\SEO\Actions\Indexing\Indexing_Complete_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper'] : $this->getIndexingHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Indexing\Indexing_Prepare_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Indexing\Indexing_Prepare_Action
     */
    protected function getIndexingPrepareActionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexing_Prepare_Action'] = new \Yoast\WP\SEO\Actions\Indexing\Indexing_Prepare_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper'] : $this->getIndexingHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Indexing\Post_Link_Indexing_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Indexing\Post_Link_Indexing_Action
     */
    protected function getPostLinkIndexingActionService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Link_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Link_Builder'] : $this->getIndexableLinkBuilderService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action'])) {
            return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action'];
        }
        $b = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action'])) {
            return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action'];
        }

        $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action'] = $instance = new \Yoast\WP\SEO\Actions\Indexing\Post_Link_Indexing_Action($a, $b, ${($_ = isset($this->services['wpdb']) ? $this->services['wpdb'] : $this->getWpdbService()) && false ?: '_'});

        $instance->set_helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Indexing\Term_Link_Indexing_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Indexing\Term_Link_Indexing_Action
     */
    protected function getTermLinkIndexingActionService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Link_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Link_Builder'] : $this->getIndexableLinkBuilderService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Term_Link_Indexing_Action'])) {
            return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Term_Link_Indexing_Action'];
        }
        $b = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Term_Link_Indexing_Action'])) {
            return $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Term_Link_Indexing_Action'];
        }

        $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Term_Link_Indexing_Action'] = $instance = new \Yoast\WP\SEO\Actions\Indexing\Term_Link_Indexing_Action($a, $b, ${($_ = isset($this->services['wpdb']) ? $this->services['wpdb'] : $this->getWpdbService()) && false ?: '_'});

        $instance->set_helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper'] : $this->getTaxonomyHelperService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Integrations_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Integrations_Action
     */
    protected function getIntegrationsActionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Actions\\Integrations_Action'] = new \Yoast\WP\SEO\Actions\Integrations_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\SEMrush\SEMrush_Login_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\SEMrush\SEMrush_Login_Action
     */
    protected function getSEMrushLoginActionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Actions\\SEMrush\\SEMrush_Login_Action'] = new \Yoast\WP\SEO\Actions\SEMrush\SEMrush_Login_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Config\\SEMrush_Client']) ? $this->services['Yoast\\WP\\SEO\\Config\\SEMrush_Client'] : $this->getSEMrushClientService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\SEMrush\SEMrush_Options_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\SEMrush\SEMrush_Options_Action
     */
    protected function getSEMrushOptionsActionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Actions\\SEMrush\\SEMrush_Options_Action'] = new \Yoast\WP\SEO\Actions\SEMrush\SEMrush_Options_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\SEMrush\SEMrush_Phrases_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\SEMrush\SEMrush_Phrases_Action
     */
    protected function getSEMrushPhrasesActionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Actions\\SEMrush\\SEMrush_Phrases_Action'] = new \Yoast\WP\SEO\Actions\SEMrush\SEMrush_Phrases_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Config\\SEMrush_Client']) ? $this->services['Yoast\\WP\\SEO\\Config\\SEMrush_Client'] : $this->getSEMrushClientService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Settings_Introduction_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Settings_Introduction_Action
     */
    protected function getSettingsIntroductionActionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Actions\\Settings_Introduction_Action'] = new \Yoast\WP\SEO\Actions\Settings_Introduction_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] = new \Yoast\WP\SEO\Helpers\User_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Wincher\Wincher_Account_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Wincher\Wincher_Account_Action
     */
    protected function getWincherAccountActionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Account_Action'] = new \Yoast\WP\SEO\Actions\Wincher\Wincher_Account_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Config\\Wincher_Client']) ? $this->services['Yoast\\WP\\SEO\\Config\\Wincher_Client'] : $this->getWincherClientService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Wincher\Wincher_Keyphrases_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Wincher\Wincher_Keyphrases_Action
     */
    protected function getWincherKeyphrasesActionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Keyphrases_Action'] = new \Yoast\WP\SEO\Actions\Wincher\Wincher_Keyphrases_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Config\\Wincher_Client']) ? $this->services['Yoast\\WP\\SEO\\Config\\Wincher_Client'] : $this->getWincherClientService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Actions\Wincher\Wincher_Login_Action' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Actions\Wincher\Wincher_Login_Action
     */
    protected function getWincherLoginActionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Login_Action'] = new \Yoast\WP\SEO\Actions\Wincher\Wincher_Login_Action(${($_ = isset($this->services['Yoast\\WP\\SEO\\Config\\Wincher_Client']) ? $this->services['Yoast\\WP\\SEO\\Config\\Wincher_Client'] : $this->getWincherClientService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Builders\Indexable_Author_Builder' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Builders\Indexable_Author_Builder
     */
    protected function getIndexableAuthorBuilderService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper'] : $this->getPostHelperService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Author_Builder'])) {
            return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Author_Builder'];
        }

        $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Author_Builder'] = $instance = new \Yoast\WP\SEO\Builders\Indexable_Author_Builder(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Author_Archive_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Author_Archive_Helper'] : $this->getAuthorArchiveHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions']) ? $this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] : ($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] = new \Yoast\WP\SEO\Values\Indexables\Indexable_Builder_Versions())) && false ?: '_'}, $a, ${($_ = isset($this->services['wpdb']) ? $this->services['wpdb'] : $this->getWpdbService()) && false ?: '_'});

        $instance->set_social_image_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper'] : $this->getImageHelper2Service()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Twitter\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Twitter\\Image_Helper'] : $this->getImageHelper4Service()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Builders\Indexable_Builder' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Builders\Indexable_Builder
     */
    protected function getIndexableBuilderService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Author_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Author_Builder'] : $this->getIndexableAuthorBuilderService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'])) {
            return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'];
        }
        $b = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Post_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Post_Builder'] : $this->getIndexablePostBuilderService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'])) {
            return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'];
        }
        $c = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Term_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Term_Builder'] : $this->getIndexableTermBuilderService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'])) {
            return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'];
        }
        $d = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Home_Page_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Home_Page_Builder'] : $this->getIndexableHomePageBuilderService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'])) {
            return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'];
        }
        $e = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Post_Type_Archive_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Post_Type_Archive_Builder'] : $this->getIndexablePostTypeArchiveBuilderService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'])) {
            return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'];
        }
        $f = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Hierarchy_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Hierarchy_Builder'] : $this->getIndexableHierarchyBuilderService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'])) {
            return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'];
        }
        $g = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'])) {
            return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'];
        }
        $h = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Link_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Link_Builder'] : $this->getIndexableLinkBuilderService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'])) {
            return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'];
        }

        $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'] = $instance = new \Yoast\WP\SEO\Builders\Indexable_Builder($a, $b, $c, $d, $e, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Date_Archive_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Date_Archive_Builder'] : $this->getIndexableDateArchiveBuilderService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_System_Page_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_System_Page_Builder'] : $this->getIndexableSystemPageBuilderService()) && false ?: '_'}, $f, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Primary_Term_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Primary_Term_Builder'] : $this->getPrimaryTermBuilderService()) && false ?: '_'}, $g, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Indexables\\Indexable_Version_Manager']) ? $this->services['Yoast\\WP\\SEO\\Services\\Indexables\\Indexable_Version_Manager'] : $this->getIndexableVersionManagerService()) && false ?: '_'}, $h);

        $instance->set_indexable_repository(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Builders\Indexable_Date_Archive_Builder' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Builders\Indexable_Date_Archive_Builder
     */
    protected function getIndexableDateArchiveBuilderService()
    {
        return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Date_Archive_Builder'] = new \Yoast\WP\SEO\Builders\Indexable_Date_Archive_Builder(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions']) ? $this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] : ($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] = new \Yoast\WP\SEO\Values\Indexables\Indexable_Builder_Versions())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Builders\Indexable_Hierarchy_Builder' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Builders\Indexable_Hierarchy_Builder
     */
    protected function getIndexableHierarchyBuilderService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Hierarchy_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Hierarchy_Repository'] : $this->getIndexableHierarchyRepositoryService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Hierarchy_Builder'])) {
            return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Hierarchy_Builder'];
        }
        $b = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper'] : $this->getPostHelperService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Hierarchy_Builder'])) {
            return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Hierarchy_Builder'];
        }

        $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Hierarchy_Builder'] = $instance = new \Yoast\WP\SEO\Builders\Indexable_Hierarchy_Builder($a, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Primary_Term_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Primary_Term_Repository'] : ($this->services['Yoast\\WP\\SEO\\Repositories\\Primary_Term_Repository'] = new \Yoast\WP\SEO\Repositories\Primary_Term_Repository())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, $b);

        $instance->set_indexable_repository(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Builders\Indexable_Home_Page_Builder' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Builders\Indexable_Home_Page_Builder
     */
    protected function getIndexableHomePageBuilderService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper'] : $this->getPostHelperService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Home_Page_Builder'])) {
            return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Home_Page_Builder'];
        }

        $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Home_Page_Builder'] = $instance = new \Yoast\WP\SEO\Builders\Indexable_Home_Page_Builder(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions']) ? $this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] : ($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] = new \Yoast\WP\SEO\Values\Indexables\Indexable_Builder_Versions())) && false ?: '_'}, $a, ${($_ = isset($this->services['wpdb']) ? $this->services['wpdb'] : $this->getWpdbService()) && false ?: '_'});

        $instance->set_social_image_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper'] : $this->getImageHelper2Service()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Twitter\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Twitter\\Image_Helper'] : $this->getImageHelper4Service()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Builders\Indexable_Link_Builder' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Builders\Indexable_Link_Builder
     */
    protected function getIndexableLinkBuilderService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper'] : $this->getPostHelperService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Link_Builder'])) {
            return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Link_Builder'];
        }

        $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Link_Builder'] = $instance = new \Yoast\WP\SEO\Builders\Indexable_Link_Builder(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\SEO_Links_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\SEO_Links_Repository'] : ($this->services['Yoast\\WP\\SEO\\Repositories\\SEO_Links_Repository'] = new \Yoast\WP\SEO\Repositories\SEO_Links_Repository())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, $a, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});

        $instance->set_dependencies(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Builders\Indexable_Post_Builder' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Builders\Indexable_Post_Builder
     */
    protected function getIndexablePostBuilderService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper'] : $this->getPostHelperService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Post_Builder'])) {
            return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Post_Builder'];
        }

        $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Post_Builder'] = $instance = new \Yoast\WP\SEO\Builders\Indexable_Post_Builder($a, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions']) ? $this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] : ($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] = new \Yoast\WP\SEO\Values\Indexables\Indexable_Builder_Versions())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Meta_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Meta_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Meta_Helper'] = new \Yoast\WP\SEO\Helpers\Meta_Helper())) && false ?: '_'});

        $instance->set_indexable_repository(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'});
        $instance->set_social_image_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper'] : $this->getImageHelper2Service()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Twitter\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Twitter\\Image_Helper'] : $this->getImageHelper4Service()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Builders\Indexable_Post_Type_Archive_Builder' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Builders\Indexable_Post_Type_Archive_Builder
     */
    protected function getIndexablePostTypeArchiveBuilderService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper'] : $this->getPostHelperService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Post_Type_Archive_Builder'])) {
            return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Post_Type_Archive_Builder'];
        }

        return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Post_Type_Archive_Builder'] = new \Yoast\WP\SEO\Builders\Indexable_Post_Type_Archive_Builder(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions']) ? $this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] : ($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] = new \Yoast\WP\SEO\Values\Indexables\Indexable_Builder_Versions())) && false ?: '_'}, $a, ${($_ = isset($this->services['wpdb']) ? $this->services['wpdb'] : $this->getWpdbService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Builders\Indexable_System_Page_Builder' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Builders\Indexable_System_Page_Builder
     */
    protected function getIndexableSystemPageBuilderService()
    {
        return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_System_Page_Builder'] = new \Yoast\WP\SEO\Builders\Indexable_System_Page_Builder(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions']) ? $this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] : ($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] = new \Yoast\WP\SEO\Values\Indexables\Indexable_Builder_Versions())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Builders\Indexable_Term_Builder' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Builders\Indexable_Term_Builder
     */
    protected function getIndexableTermBuilderService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper'] : $this->getPostHelperService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Term_Builder'])) {
            return $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Term_Builder'];
        }

        $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Term_Builder'] = $instance = new \Yoast\WP\SEO\Builders\Indexable_Term_Builder(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper'] : $this->getTaxonomyHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions']) ? $this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] : ($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] = new \Yoast\WP\SEO\Values\Indexables\Indexable_Builder_Versions())) && false ?: '_'}, $a, ${($_ = isset($this->services['wpdb']) ? $this->services['wpdb'] : $this->getWpdbService()) && false ?: '_'});

        $instance->set_social_image_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper'] : $this->getImageHelper2Service()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Twitter\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Twitter\\Image_Helper'] : $this->getImageHelper4Service()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Builders\Primary_Term_Builder' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Builders\Primary_Term_Builder
     */
    protected function getPrimaryTermBuilderService()
    {
        return $this->services['Yoast\\WP\\SEO\\Builders\\Primary_Term_Builder'] = new \Yoast\WP\SEO\Builders\Primary_Term_Builder(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Primary_Term_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Primary_Term_Repository'] : ($this->services['Yoast\\WP\\SEO\\Repositories\\Primary_Term_Repository'] = new \Yoast\WP\SEO\Repositories\Primary_Term_Repository())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Primary_Term_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Primary_Term_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Primary_Term_Helper'] = new \Yoast\WP\SEO\Helpers\Primary_Term_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Meta_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Meta_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Meta_Helper'] = new \Yoast\WP\SEO\Helpers\Meta_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Commands\Cleanup_Command' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Commands\Cleanup_Command
     */
    protected function getCleanupCommandService()
    {
        return $this->services['Yoast\\WP\\SEO\\Commands\\Cleanup_Command'] = new \Yoast\WP\SEO\Commands\Cleanup_Command(${($_ = isset($this->services['Yoast\\WP\\SEO\\Integrations\\Cleanup_Integration']) ? $this->services['Yoast\\WP\\SEO\\Integrations\\Cleanup_Integration'] : $this->getCleanupIntegrationService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Commands\Index_Command' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Commands\Index_Command
     */
    protected function getIndexCommandService()
    {
        return $this->services['Yoast\\WP\\SEO\\Commands\\Index_Command'] = new \Yoast\WP\SEO\Commands\Index_Command(${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Indexation_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Indexation_Action'] : $this->getIndexablePostIndexationActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Term_Indexation_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Term_Indexation_Action'] : $this->getIndexableTermIndexationActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Type_Archive_Indexation_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Type_Archive_Indexation_Action'] : $this->getIndexablePostTypeArchiveIndexationActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_General_Indexation_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_General_Indexation_Action'] : $this->getIndexableGeneralIndexationActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Indexing_Complete_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Indexing_Complete_Action'] : $this->getIndexableIndexingCompleteActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexing_Prepare_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexing_Prepare_Action'] : $this->getIndexingPrepareActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action'] : $this->getPostLinkIndexingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Term_Link_Indexing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Term_Link_Indexing_Action'] : $this->getTermLinkIndexingActionService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Addon_Installation_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Addon_Installation_Conditional
     */
    protected function getAddonInstallationConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Addon_Installation_Conditional'] = new \Yoast\WP\SEO\Conditionals\Addon_Installation_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Admin\Doing_Post_Quick_Edit_Save_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Admin\Doing_Post_Quick_Edit_Save_Conditional
     */
    protected function getDoingPostQuickEditSaveConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Admin\\Doing_Post_Quick_Edit_Save_Conditional'] = new \Yoast\WP\SEO\Conditionals\Admin\Doing_Post_Quick_Edit_Save_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Admin\Estimated_Reading_Time_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Admin\Estimated_Reading_Time_Conditional
     */
    protected function getEstimatedReadingTimeConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Admin\\Estimated_Reading_Time_Conditional'] = new \Yoast\WP\SEO\Conditionals\Admin\Estimated_Reading_Time_Conditional(${($_ = isset($this->services['Yoast\\WP\\SEO\\Conditionals\\Admin\\Post_Conditional']) ? $this->services['Yoast\\WP\\SEO\\Conditionals\\Admin\\Post_Conditional'] : ($this->services['Yoast\\WP\\SEO\\Conditionals\\Admin\\Post_Conditional'] = new \Yoast\WP\SEO\Conditionals\Admin\Post_Conditional())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Admin\Licenses_Page_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Admin\Licenses_Page_Conditional
     */
    protected function getLicensesPageConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Admin\\Licenses_Page_Conditional'] = new \Yoast\WP\SEO\Conditionals\Admin\Licenses_Page_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Admin\Non_Network_Admin_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Admin\Non_Network_Admin_Conditional
     */
    protected function getNonNetworkAdminConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Admin\\Non_Network_Admin_Conditional'] = new \Yoast\WP\SEO\Conditionals\Admin\Non_Network_Admin_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Admin\Post_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Admin\Post_Conditional
     */
    protected function getPostConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Admin\\Post_Conditional'] = new \Yoast\WP\SEO\Conditionals\Admin\Post_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Admin\Posts_Overview_Or_Ajax_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Admin\Posts_Overview_Or_Ajax_Conditional
     */
    protected function getPostsOverviewOrAjaxConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Admin\\Posts_Overview_Or_Ajax_Conditional'] = new \Yoast\WP\SEO\Conditionals\Admin\Posts_Overview_Or_Ajax_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Admin_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Admin_Conditional
     */
    protected function getAdminConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Admin_Conditional'] = new \Yoast\WP\SEO\Conditionals\Admin_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Attachment_Redirections_Enabled_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Attachment_Redirections_Enabled_Conditional
     */
    protected function getAttachmentRedirectionsEnabledConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Attachment_Redirections_Enabled_Conditional'] = new \Yoast\WP\SEO\Conditionals\Attachment_Redirections_Enabled_Conditional(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Development_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Development_Conditional
     */
    protected function getDevelopmentConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Development_Conditional'] = new \Yoast\WP\SEO\Conditionals\Development_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Front_End_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Front_End_Conditional
     */
    protected function getFrontEndConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Front_End_Conditional'] = new \Yoast\WP\SEO\Conditionals\Front_End_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Front_End_Inspector_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Front_End_Inspector_Conditional
     *
     * @deprecated Yoast\WP\SEO\Conditionals\Front_End_Inspector_Conditional is deprecated since version 19.5!
     */
    protected function getFrontEndInspectorConditionalService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Conditionals\\Front_End_Inspector_Conditional is deprecated since version 19.5!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Front_End_Inspector_Conditional'] = new \Yoast\WP\SEO\Conditionals\Front_End_Inspector_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Get_Request_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Get_Request_Conditional
     */
    protected function getGetRequestConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Get_Request_Conditional'] = new \Yoast\WP\SEO\Conditionals\Get_Request_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Headless_Rest_Endpoints_Enabled_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Headless_Rest_Endpoints_Enabled_Conditional
     */
    protected function getHeadlessRestEndpointsEnabledConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Headless_Rest_Endpoints_Enabled_Conditional'] = new \Yoast\WP\SEO\Conditionals\Headless_Rest_Endpoints_Enabled_Conditional(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Import_Tool_Selected_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Import_Tool_Selected_Conditional
     */
    protected function getImportToolSelectedConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Import_Tool_Selected_Conditional'] = new \Yoast\WP\SEO\Conditionals\Import_Tool_Selected_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Indexables_Page_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Indexables_Page_Conditional
     *
     * @deprecated Yoast\WP\SEO\Conditionals\Indexables_Page_Conditional is deprecated since version 20.4!
     */
    protected function getIndexablesPageConditionalService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Conditionals\\Indexables_Page_Conditional is deprecated since version 20.4!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Indexables_Page_Conditional'] = new \Yoast\WP\SEO\Conditionals\Indexables_Page_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Jetpack_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Jetpack_Conditional
     */
    protected function getJetpackConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Jetpack_Conditional'] = new \Yoast\WP\SEO\Conditionals\Jetpack_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Migrations_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Migrations_Conditional
     */
    protected function getMigrationsConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Migrations_Conditional'] = new \Yoast\WP\SEO\Conditionals\Migrations_Conditional(${($_ = isset($this->services['Yoast\\WP\\SEO\\Config\\Migration_Status']) ? $this->services['Yoast\\WP\\SEO\\Config\\Migration_Status'] : ($this->services['Yoast\\WP\\SEO\\Config\\Migration_Status'] = new \Yoast\WP\SEO\Config\Migration_Status())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\New_Settings_Ui_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\New_Settings_Ui_Conditional
     */
    protected function getNewSettingsUiConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\New_Settings_Ui_Conditional'] = new \Yoast\WP\SEO\Conditionals\New_Settings_Ui_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\News_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\News_Conditional
     */
    protected function getNewsConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\News_Conditional'] = new \Yoast\WP\SEO\Conditionals\News_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\No_Tool_Selected_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\No_Tool_Selected_Conditional
     */
    protected function getNoToolSelectedConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\No_Tool_Selected_Conditional'] = new \Yoast\WP\SEO\Conditionals\No_Tool_Selected_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Non_Multisite_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Non_Multisite_Conditional
     */
    protected function getNonMultisiteConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Non_Multisite_Conditional'] = new \Yoast\WP\SEO\Conditionals\Non_Multisite_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Not_Admin_Ajax_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Not_Admin_Ajax_Conditional
     */
    protected function getNotAdminAjaxConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Not_Admin_Ajax_Conditional'] = new \Yoast\WP\SEO\Conditionals\Not_Admin_Ajax_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Open_Graph_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Open_Graph_Conditional
     */
    protected function getOpenGraphConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Open_Graph_Conditional'] = new \Yoast\WP\SEO\Conditionals\Open_Graph_Conditional(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Premium_Active_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Premium_Active_Conditional
     */
    protected function getPremiumActiveConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Premium_Active_Conditional'] = new \Yoast\WP\SEO\Conditionals\Premium_Active_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Premium_Inactive_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Premium_Inactive_Conditional
     */
    protected function getPremiumInactiveConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Premium_Inactive_Conditional'] = new \Yoast\WP\SEO\Conditionals\Premium_Inactive_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Primary_Category_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Primary_Category_Conditional
     */
    protected function getPrimaryCategoryConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Primary_Category_Conditional'] = new \Yoast\WP\SEO\Conditionals\Primary_Category_Conditional(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Robots_Txt_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Robots_Txt_Conditional
     */
    protected function getRobotsTxtConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Robots_Txt_Conditional'] = new \Yoast\WP\SEO\Conditionals\Robots_Txt_Conditional(${($_ = isset($this->services['Yoast\\WP\\SEO\\Conditionals\\Front_End_Conditional']) ? $this->services['Yoast\\WP\\SEO\\Conditionals\\Front_End_Conditional'] : ($this->services['Yoast\\WP\\SEO\\Conditionals\\Front_End_Conditional'] = new \Yoast\WP\SEO\Conditionals\Front_End_Conditional())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\SEMrush_Enabled_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\SEMrush_Enabled_Conditional
     */
    protected function getSEMrushEnabledConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\SEMrush_Enabled_Conditional'] = new \Yoast\WP\SEO\Conditionals\SEMrush_Enabled_Conditional(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Schema_Blocks_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Schema_Blocks_Conditional
     *
     * @deprecated Yoast\WP\SEO\Conditionals\Schema_Blocks_Conditional is deprecated since version 20.5!
     */
    protected function getSchemaBlocksConditionalService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Conditionals\\Schema_Blocks_Conditional is deprecated since version 20.5!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Schema_Blocks_Conditional'] = new \Yoast\WP\SEO\Conditionals\Schema_Blocks_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Settings_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Settings_Conditional
     */
    protected function getSettingsConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Settings_Conditional'] = new \Yoast\WP\SEO\Conditionals\Settings_Conditional(${($_ = isset($this->services['Yoast\\WP\\SEO\\Conditionals\\User_Can_Manage_Wpseo_Options_Conditional']) ? $this->services['Yoast\\WP\\SEO\\Conditionals\\User_Can_Manage_Wpseo_Options_Conditional'] : ($this->services['Yoast\\WP\\SEO\\Conditionals\\User_Can_Manage_Wpseo_Options_Conditional'] = new \Yoast\WP\SEO\Conditionals\User_Can_Manage_Wpseo_Options_Conditional())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Should_Index_Links_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Should_Index_Links_Conditional
     */
    protected function getShouldIndexLinksConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Should_Index_Links_Conditional'] = new \Yoast\WP\SEO\Conditionals\Should_Index_Links_Conditional(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Text_Formality_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Text_Formality_Conditional
     */
    protected function getTextFormalityConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Text_Formality_Conditional'] = new \Yoast\WP\SEO\Conditionals\Text_Formality_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\The_Events_Calendar_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\The_Events_Calendar_Conditional
     *
     * @deprecated Yoast\WP\SEO\Conditionals\The_Events_Calendar_Conditional is deprecated since version 19.12!
     */
    protected function getTheEventsCalendarConditionalService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Conditionals\\The_Events_Calendar_Conditional is deprecated since version 19.12!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Conditionals\\The_Events_Calendar_Conditional'] = new \Yoast\WP\SEO\Conditionals\The_Events_Calendar_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Third_Party\CoAuthors_Plus_Activated_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Third_Party\CoAuthors_Plus_Activated_Conditional
     *
     * @deprecated Yoast\WP\SEO\Conditionals\Third_Party\CoAuthors_Plus_Activated_Conditional is deprecated since version 19.12!
     */
    protected function getCoAuthorsPlusActivatedConditionalService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Conditionals\\Third_Party\\CoAuthors_Plus_Activated_Conditional is deprecated since version 19.12!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Third_Party\\CoAuthors_Plus_Activated_Conditional'] = new \Yoast\WP\SEO\Conditionals\Third_Party\CoAuthors_Plus_Activated_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Third_Party\CoAuthors_Plus_Flag_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Third_Party\CoAuthors_Plus_Flag_Conditional
     *
     * @deprecated Yoast\WP\SEO\Conditionals\Third_Party\CoAuthors_Plus_Flag_Conditional is deprecated since version 19.12!
     */
    protected function getCoAuthorsPlusFlagConditionalService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Conditionals\\Third_Party\\CoAuthors_Plus_Flag_Conditional is deprecated since version 19.12!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Third_Party\\CoAuthors_Plus_Flag_Conditional'] = new \Yoast\WP\SEO\Conditionals\Third_Party\CoAuthors_Plus_Flag_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Third_Party\Elementor_Activated_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Third_Party\Elementor_Activated_Conditional
     */
    protected function getElementorActivatedConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Elementor_Activated_Conditional'] = new \Yoast\WP\SEO\Conditionals\Third_Party\Elementor_Activated_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Third_Party\Elementor_Edit_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Third_Party\Elementor_Edit_Conditional
     */
    protected function getElementorEditConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Elementor_Edit_Conditional'] = new \Yoast\WP\SEO\Conditionals\Third_Party\Elementor_Edit_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Third_Party\Jetpack_Boost_Active_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Third_Party\Jetpack_Boost_Active_Conditional
     */
    protected function getJetpackBoostActiveConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Jetpack_Boost_Active_Conditional'] = new \Yoast\WP\SEO\Conditionals\Third_Party\Jetpack_Boost_Active_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Third_Party\Jetpack_Boost_Not_Premium_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Third_Party\Jetpack_Boost_Not_Premium_Conditional
     */
    protected function getJetpackBoostNotPremiumConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Jetpack_Boost_Not_Premium_Conditional'] = new \Yoast\WP\SEO\Conditionals\Third_Party\Jetpack_Boost_Not_Premium_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Third_Party\Polylang_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Third_Party\Polylang_Conditional
     */
    protected function getPolylangConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Polylang_Conditional'] = new \Yoast\WP\SEO\Conditionals\Third_Party\Polylang_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Third_Party\TranslatePress_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Third_Party\TranslatePress_Conditional
     */
    protected function getTranslatePressConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Third_Party\\TranslatePress_Conditional'] = new \Yoast\WP\SEO\Conditionals\Third_Party\TranslatePress_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Third_Party\W3_Total_Cache_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Third_Party\W3_Total_Cache_Conditional
     */
    protected function getW3TotalCacheConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Third_Party\\W3_Total_Cache_Conditional'] = new \Yoast\WP\SEO\Conditionals\Third_Party\W3_Total_Cache_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Third_Party\WPML_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Third_Party\WPML_Conditional
     */
    protected function getWPMLConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Third_Party\\WPML_Conditional'] = new \Yoast\WP\SEO\Conditionals\Third_Party\WPML_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Third_Party\WPML_WPSEO_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Third_Party\WPML_WPSEO_Conditional
     */
    protected function getWPMLWPSEOConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Third_Party\\WPML_WPSEO_Conditional'] = new \Yoast\WP\SEO\Conditionals\Third_Party\WPML_WPSEO_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Third_Party\Wordproof_Integration_Active_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Third_Party\Wordproof_Integration_Active_Conditional
     */
    protected function getWordproofIntegrationActiveConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Wordproof_Integration_Active_Conditional'] = new \Yoast\WP\SEO\Conditionals\Third_Party\Wordproof_Integration_Active_Conditional(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Wordproof_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Wordproof_Helper'] : $this->getWordproofHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Third_Party\Wordproof_Plugin_Inactive_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Third_Party\Wordproof_Plugin_Inactive_Conditional
     */
    protected function getWordproofPluginInactiveConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Third_Party\\Wordproof_Plugin_Inactive_Conditional'] = new \Yoast\WP\SEO\Conditionals\Third_Party\Wordproof_Plugin_Inactive_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Updated_Importer_Framework_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Updated_Importer_Framework_Conditional
     */
    protected function getUpdatedImporterFrameworkConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Updated_Importer_Framework_Conditional'] = new \Yoast\WP\SEO\Conditionals\Updated_Importer_Framework_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\User_Can_Manage_Wpseo_Options_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\User_Can_Manage_Wpseo_Options_Conditional
     */
    protected function getUserCanManageWpseoOptionsConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\User_Can_Manage_Wpseo_Options_Conditional'] = new \Yoast\WP\SEO\Conditionals\User_Can_Manage_Wpseo_Options_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\User_Can_Publish_Posts_And_Pages_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\User_Can_Publish_Posts_And_Pages_Conditional
     */
    protected function getUserCanPublishPostsAndPagesConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\User_Can_Publish_Posts_And_Pages_Conditional'] = new \Yoast\WP\SEO\Conditionals\User_Can_Publish_Posts_And_Pages_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\WP_Robots_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\WP_Robots_Conditional
     */
    protected function getWPRobotsConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\WP_Robots_Conditional'] = new \Yoast\WP\SEO\Conditionals\WP_Robots_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Web_Stories_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Web_Stories_Conditional
     */
    protected function getWebStoriesConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Web_Stories_Conditional'] = new \Yoast\WP\SEO\Conditionals\Web_Stories_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Wincher_Automatically_Track_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Wincher_Automatically_Track_Conditional
     */
    protected function getWincherAutomaticallyTrackConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Wincher_Automatically_Track_Conditional'] = new \Yoast\WP\SEO\Conditionals\Wincher_Automatically_Track_Conditional(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Wincher_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Wincher_Conditional
     */
    protected function getWincherConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Wincher_Conditional'] = new \Yoast\WP\SEO\Conditionals\Wincher_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Wincher_Enabled_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Wincher_Enabled_Conditional
     */
    protected function getWincherEnabledConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Wincher_Enabled_Conditional'] = new \Yoast\WP\SEO\Conditionals\Wincher_Enabled_Conditional(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Wincher_Token_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Wincher_Token_Conditional
     */
    protected function getWincherTokenConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Wincher_Token_Conditional'] = new \Yoast\WP\SEO\Conditionals\Wincher_Token_Conditional(${($_ = isset($this->services['Yoast\\WP\\SEO\\Config\\Wincher_Client']) ? $this->services['Yoast\\WP\\SEO\\Config\\Wincher_Client'] : $this->getWincherClientService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\WooCommerce_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\WooCommerce_Conditional
     */
    protected function getWooCommerceConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\WooCommerce_Conditional'] = new \Yoast\WP\SEO\Conditionals\WooCommerce_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\XMLRPC_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\XMLRPC_Conditional
     */
    protected function getXMLRPCConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\XMLRPC_Conditional'] = new \Yoast\WP\SEO\Conditionals\XMLRPC_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Yoast_Admin_And_Dashboard_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Yoast_Admin_And_Dashboard_Conditional
     */
    protected function getYoastAdminAndDashboardConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Yoast_Admin_And_Dashboard_Conditional'] = new \Yoast\WP\SEO\Conditionals\Yoast_Admin_And_Dashboard_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Conditionals\Yoast_Tools_Page_Conditional' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Conditionals\Yoast_Tools_Page_Conditional
     */
    protected function getYoastToolsPageConditionalService()
    {
        return $this->services['Yoast\\WP\\SEO\\Conditionals\\Yoast_Tools_Page_Conditional'] = new \Yoast\WP\SEO\Conditionals\Yoast_Tools_Page_Conditional();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Badge_Group_Names' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Badge_Group_Names
     */
    protected function getBadgeGroupNamesService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Badge_Group_Names'] = new \Yoast\WP\SEO\Config\Badge_Group_Names();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Conflicting_Plugins' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Conflicting_Plugins
     */
    protected function getConflictingPluginsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Conflicting_Plugins'] = new \Yoast\WP\SEO\Config\Conflicting_Plugins();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Indexing_Reasons' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Indexing_Reasons
     */
    protected function getIndexingReasonsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Indexing_Reasons'] = new \Yoast\WP\SEO\Config\Indexing_Reasons();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migration_Status' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migration_Status
     */
    protected function getMigrationStatusService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migration_Status'] = new \Yoast\WP\SEO\Config\Migration_Status();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\AddCollationToTables' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\AddCollationToTables
     */
    protected function getAddCollationToTablesService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\AddCollationToTables'] = new \Yoast\WP\SEO\Config\Migrations\AddCollationToTables(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\AddColumnsToIndexables' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\AddColumnsToIndexables
     */
    protected function getAddColumnsToIndexablesService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\AddColumnsToIndexables'] = new \Yoast\WP\SEO\Config\Migrations\AddColumnsToIndexables(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\AddEstimatedReadingTime' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\AddEstimatedReadingTime
     */
    protected function getAddEstimatedReadingTimeService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\AddEstimatedReadingTime'] = new \Yoast\WP\SEO\Config\Migrations\AddEstimatedReadingTime(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\AddHasAncestorsColumn' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\AddHasAncestorsColumn
     */
    protected function getAddHasAncestorsColumnService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\AddHasAncestorsColumn'] = new \Yoast\WP\SEO\Config\Migrations\AddHasAncestorsColumn(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\AddIndexableObjectIdAndTypeIndex' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\AddIndexableObjectIdAndTypeIndex
     */
    protected function getAddIndexableObjectIdAndTypeIndexService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\AddIndexableObjectIdAndTypeIndex'] = new \Yoast\WP\SEO\Config\Migrations\AddIndexableObjectIdAndTypeIndex(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\AddIndexesForProminentWordsOnIndexables' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\AddIndexesForProminentWordsOnIndexables
     */
    protected function getAddIndexesForProminentWordsOnIndexablesService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\AddIndexesForProminentWordsOnIndexables'] = new \Yoast\WP\SEO\Config\Migrations\AddIndexesForProminentWordsOnIndexables(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\AddObjectTimestamps' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\AddObjectTimestamps
     */
    protected function getAddObjectTimestampsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\AddObjectTimestamps'] = new \Yoast\WP\SEO\Config\Migrations\AddObjectTimestamps(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\AddVersionColumnToIndexables' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\AddVersionColumnToIndexables
     */
    protected function getAddVersionColumnToIndexablesService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\AddVersionColumnToIndexables'] = new \Yoast\WP\SEO\Config\Migrations\AddVersionColumnToIndexables(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\BreadcrumbTitleAndHierarchyReset' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\BreadcrumbTitleAndHierarchyReset
     */
    protected function getBreadcrumbTitleAndHierarchyResetService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\BreadcrumbTitleAndHierarchyReset'] = new \Yoast\WP\SEO\Config\Migrations\BreadcrumbTitleAndHierarchyReset(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\ClearIndexableTables' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\ClearIndexableTables
     */
    protected function getClearIndexableTablesService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\ClearIndexableTables'] = new \Yoast\WP\SEO\Config\Migrations\ClearIndexableTables(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\CreateIndexableSubpagesIndex' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\CreateIndexableSubpagesIndex
     */
    protected function getCreateIndexableSubpagesIndexService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\CreateIndexableSubpagesIndex'] = new \Yoast\WP\SEO\Config\Migrations\CreateIndexableSubpagesIndex(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\CreateSEOLinksTable' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\CreateSEOLinksTable
     */
    protected function getCreateSEOLinksTableService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\CreateSEOLinksTable'] = new \Yoast\WP\SEO\Config\Migrations\CreateSEOLinksTable(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\DeleteDuplicateIndexables' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\DeleteDuplicateIndexables
     */
    protected function getDeleteDuplicateIndexablesService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\DeleteDuplicateIndexables'] = new \Yoast\WP\SEO\Config\Migrations\DeleteDuplicateIndexables(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\ExpandIndexableColumnLengths' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\ExpandIndexableColumnLengths
     */
    protected function getExpandIndexableColumnLengthsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\ExpandIndexableColumnLengths'] = new \Yoast\WP\SEO\Config\Migrations\ExpandIndexableColumnLengths(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\ExpandIndexableIDColumnLengths' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\ExpandIndexableIDColumnLengths
     */
    protected function getExpandIndexableIDColumnLengthsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\ExpandIndexableIDColumnLengths'] = new \Yoast\WP\SEO\Config\Migrations\ExpandIndexableIDColumnLengths(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\ExpandPrimaryTermIDColumnLengths' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\ExpandPrimaryTermIDColumnLengths
     */
    protected function getExpandPrimaryTermIDColumnLengthsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\ExpandPrimaryTermIDColumnLengths'] = new \Yoast\WP\SEO\Config\Migrations\ExpandPrimaryTermIDColumnLengths(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\ReplacePermalinkHashIndex' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\ReplacePermalinkHashIndex
     */
    protected function getReplacePermalinkHashIndexService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\ReplacePermalinkHashIndex'] = new \Yoast\WP\SEO\Config\Migrations\ReplacePermalinkHashIndex(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\ResetIndexableHierarchyTable' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\ResetIndexableHierarchyTable
     */
    protected function getResetIndexableHierarchyTableService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\ResetIndexableHierarchyTable'] = new \Yoast\WP\SEO\Config\Migrations\ResetIndexableHierarchyTable(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\TruncateIndexableTables' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\TruncateIndexableTables
     */
    protected function getTruncateIndexableTablesService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\TruncateIndexableTables'] = new \Yoast\WP\SEO\Config\Migrations\TruncateIndexableTables(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\WpYoastDropIndexableMetaTableIfExists' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\WpYoastDropIndexableMetaTableIfExists
     */
    protected function getWpYoastDropIndexableMetaTableIfExistsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\WpYoastDropIndexableMetaTableIfExists'] = new \Yoast\WP\SEO\Config\Migrations\WpYoastDropIndexableMetaTableIfExists(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\WpYoastIndexable' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\WpYoastIndexable
     */
    protected function getWpYoastIndexableService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\WpYoastIndexable'] = new \Yoast\WP\SEO\Config\Migrations\WpYoastIndexable(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\WpYoastIndexableHierarchy' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\WpYoastIndexableHierarchy
     */
    protected function getWpYoastIndexableHierarchyService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\WpYoastIndexableHierarchy'] = new \Yoast\WP\SEO\Config\Migrations\WpYoastIndexableHierarchy(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Migrations\WpYoastPrimaryTerm' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Migrations\WpYoastPrimaryTerm
     */
    protected function getWpYoastPrimaryTermService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Migrations\\WpYoastPrimaryTerm'] = new \Yoast\WP\SEO\Config\Migrations\WpYoastPrimaryTerm(${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Researcher_Languages' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Researcher_Languages
     */
    protected function getResearcherLanguagesService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Researcher_Languages'] = new \Yoast\WP\SEO\Config\Researcher_Languages();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\SEMrush_Client' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\SEMrush_Client
     */
    protected function getSEMrushClientService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\SEMrush_Client'] = new \Yoast\WP\SEO\Config\SEMrush_Client(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Remote_Handler']) ? $this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Remote_Handler'] : ($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Remote_Handler'] = new \Yoast\WP\SEO\Wrappers\WP_Remote_Handler())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Schema_IDs' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Schema_IDs
     */
    protected function getSchemaIDsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Schema_IDs'] = new \Yoast\WP\SEO\Config\Schema_IDs();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Schema_Types' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Schema_Types
     */
    protected function getSchemaTypesService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Schema_Types'] = new \Yoast\WP\SEO\Config\Schema_Types();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Wincher_Client' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Wincher_Client
     */
    protected function getWincherClientService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Wincher_Client'] = new \Yoast\WP\SEO\Config\Wincher_Client(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Remote_Handler']) ? $this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Remote_Handler'] : ($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Remote_Handler'] = new \Yoast\WP\SEO\Wrappers\WP_Remote_Handler())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Wordproof_App_Config' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Wordproof_App_Config
     */
    protected function getWordproofAppConfigService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Wordproof_App_Config'] = new \Yoast\WP\SEO\Config\Wordproof_App_Config();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Config\Wordproof_Translations' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Config\Wordproof_Translations
     */
    protected function getWordproofTranslationsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Config\\Wordproof_Translations'] = new \Yoast\WP\SEO\Config\Wordproof_Translations();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Context\Meta_Tags_Context' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Context\Meta_Tags_Context
     */
    protected function getMetaTagsContextService()
    {
        return $this->services['Yoast\\WP\\SEO\\Context\\Meta_Tags_Context'] = new \Yoast\WP\SEO\Context\Meta_Tags_Context(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\ID_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\ID_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\ID_Helper'] = new \Yoast\WP\SEO\Helpers\Schema\ID_Helper())) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Replace_Vars']) ? $this->services['WPSEO_Replace_Vars'] : $this->getWPSEOReplaceVarsService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Site_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Site_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Site_Helper'] = new \Yoast\WP\SEO\Helpers\Site_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] = new \Yoast\WP\SEO\Helpers\User_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] = new \Yoast\WP\SEO\Helpers\Permalink_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Breadcrumbs_Generator' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Breadcrumbs_Generator
     */
    protected function getBreadcrumbsGeneratorService()
    {
        return $this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator'] = new \Yoast\WP\SEO\Generators\Breadcrumbs_Generator(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper'] : $this->getPaginationHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Open_Graph_Image_Generator' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Open_Graph_Image_Generator
     */
    protected function getOpenGraphImageGeneratorService()
    {
        return $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator'] = new \Yoast\WP\SEO\Generators\Open_Graph_Image_Generator(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper'] : $this->getImageHelper2Service()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Open_Graph_Locale_Generator' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Open_Graph_Locale_Generator
     */
    protected function getOpenGraphLocaleGeneratorService()
    {
        return $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] = new \Yoast\WP\SEO\Generators\Open_Graph_Locale_Generator();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Schema\Article' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Schema\Article
     */
    protected function getArticleService()
    {
        return $this->services['Yoast\\WP\\SEO\\Generators\\Schema\\Article'] = new \Yoast\WP\SEO\Generators\Schema\Article();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Schema\Author' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Schema\Author
     */
    protected function getAuthorService()
    {
        return $this->services['Yoast\\WP\\SEO\\Generators\\Schema\\Author'] = new \Yoast\WP\SEO\Generators\Schema\Author();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Schema\Breadcrumb' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Schema\Breadcrumb
     */
    protected function getBreadcrumbService()
    {
        return $this->services['Yoast\\WP\\SEO\\Generators\\Schema\\Breadcrumb'] = new \Yoast\WP\SEO\Generators\Schema\Breadcrumb();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Schema\FAQ' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Schema\FAQ
     */
    protected function getFAQService()
    {
        return $this->services['Yoast\\WP\\SEO\\Generators\\Schema\\FAQ'] = new \Yoast\WP\SEO\Generators\Schema\FAQ();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Schema\HowTo' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Schema\HowTo
     */
    protected function getHowToService()
    {
        return $this->services['Yoast\\WP\\SEO\\Generators\\Schema\\HowTo'] = new \Yoast\WP\SEO\Generators\Schema\HowTo();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Schema\Main_Image' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Schema\Main_Image
     */
    protected function getMainImageService()
    {
        return $this->services['Yoast\\WP\\SEO\\Generators\\Schema\\Main_Image'] = new \Yoast\WP\SEO\Generators\Schema\Main_Image();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Schema\Organization' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Schema\Organization
     */
    protected function getOrganizationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Generators\\Schema\\Organization'] = new \Yoast\WP\SEO\Generators\Schema\Organization();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Schema\Person' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Schema\Person
     */
    protected function getPersonService()
    {
        return $this->services['Yoast\\WP\\SEO\\Generators\\Schema\\Person'] = new \Yoast\WP\SEO\Generators\Schema\Person();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Schema\Third_Party\CoAuthor' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Schema\Third_Party\CoAuthor
     *
     * @deprecated Yoast\WP\SEO\Generators\Schema\Third_Party\CoAuthor is deprecated since version 19.12!
     */
    protected function getCoAuthorService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Generators\\Schema\\Third_Party\\CoAuthor is deprecated since version 19.12!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Generators\\Schema\\Third_Party\\CoAuthor'] = new \Yoast\WP\SEO\Generators\Schema\Third_Party\CoAuthor();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Schema\Third_Party\Events_Calendar_Schema' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Schema\Third_Party\Events_Calendar_Schema
     *
     * @deprecated Yoast\WP\SEO\Generators\Schema\Third_Party\Events_Calendar_Schema is deprecated since version 19.12!
     */
    protected function getEventsCalendarSchemaService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Generators\\Schema\\Third_Party\\Events_Calendar_Schema is deprecated since version 19.12!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Generators\\Schema\\Third_Party\\Events_Calendar_Schema'] = new \Yoast\WP\SEO\Generators\Schema\Third_Party\Events_Calendar_Schema();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Schema\WebPage' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Schema\WebPage
     */
    protected function getWebPageService()
    {
        return $this->services['Yoast\\WP\\SEO\\Generators\\Schema\\WebPage'] = new \Yoast\WP\SEO\Generators\Schema\WebPage();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Schema\Website' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Schema\Website
     */
    protected function getWebsiteService()
    {
        return $this->services['Yoast\\WP\\SEO\\Generators\\Schema\\Website'] = new \Yoast\WP\SEO\Generators\Schema\Website();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Schema_Generator' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Schema_Generator
     */
    protected function getSchemaGeneratorService()
    {
        return $this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator'] = new \Yoast\WP\SEO\Generators\Schema_Generator(${($_ = isset($this->services['Yoast\\WP\\SEO\\Surfaces\\Helpers_Surface']) ? $this->services['Yoast\\WP\\SEO\\Surfaces\\Helpers_Surface'] : $this->getHelpersSurfaceService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\Replace_Vars_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\Replace_Vars_Helper'] : $this->getReplaceVarsHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Generators\Twitter_Image_Generator' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Generators\Twitter_Image_Generator
     */
    protected function getTwitterImageGeneratorService()
    {
        return $this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator'] = new \Yoast\WP\SEO\Generators\Twitter_Image_Generator(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Twitter\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Twitter\\Image_Helper'] : $this->getImageHelper4Service()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Aioseo_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Aioseo_Helper
     */
    protected function getAioseoHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper'] = new \Yoast\WP\SEO\Helpers\Aioseo_Helper(${($_ = isset($this->services['wpdb']) ? $this->services['wpdb'] : $this->getWpdbService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Wpdb_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Wpdb_Helper'] : $this->getWpdbHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Asset_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Asset_Helper
     */
    protected function getAssetHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Asset_Helper'] = new \Yoast\WP\SEO\Helpers\Asset_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Attachment_Cleanup_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Attachment_Cleanup_Helper
     */
    protected function getAttachmentCleanupHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Attachment_Cleanup_Helper'] = new \Yoast\WP\SEO\Helpers\Attachment_Cleanup_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Author_Archive_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Author_Archive_Helper
     */
    protected function getAuthorArchiveHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Author_Archive_Helper'] = new \Yoast\WP\SEO\Helpers\Author_Archive_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Blocks_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Blocks_Helper
     */
    protected function getBlocksHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Blocks_Helper'] = new \Yoast\WP\SEO\Helpers\Blocks_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper'] : $this->getPostHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Capability_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Capability_Helper
     */
    protected function getCapabilityHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Capability_Helper'] = new \Yoast\WP\SEO\Helpers\Capability_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Crawl_Cleanup_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Crawl_Cleanup_Helper
     */
    protected function getCrawlCleanupHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Crawl_Cleanup_Helper'] = new \Yoast\WP\SEO\Helpers\Crawl_Cleanup_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper'] = new \Yoast\WP\SEO\Helpers\Redirect_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Curl_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Curl_Helper
     */
    protected function getCurlHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Curl_Helper'] = new \Yoast\WP\SEO\Helpers\Curl_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Current_Page_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Current_Page_Helper
     */
    protected function getCurrentPageHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] = new \Yoast\WP\SEO\Helpers\Current_Page_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper']) ? $this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper'] : ($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper'] = new \Yoast\WP\SEO\Wrappers\WP_Query_Wrapper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Date_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Date_Helper
     */
    protected function getDateHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper'] = new \Yoast\WP\SEO\Helpers\Date_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Environment_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Environment_Helper
     */
    protected function getEnvironmentHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Environment_Helper'] = new \Yoast\WP\SEO\Helpers\Environment_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\First_Time_Configuration_Notice_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\First_Time_Configuration_Notice_Helper
     */
    protected function getFirstTimeConfigurationNoticeHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\First_Time_Configuration_Notice_Helper'] = new \Yoast\WP\SEO\Helpers\First_Time_Configuration_Notice_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper'] : $this->getIndexingHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Home_Url_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Home_Url_Helper
     */
    protected function getHomeUrlHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Home_Url_Helper'] = new \Yoast\WP\SEO\Helpers\Home_Url_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Image_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Image_Helper
     */
    protected function getImageHelperService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'])) {
            return $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'];
        }

        return $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] = new \Yoast\WP\SEO\Helpers\Image_Helper($a, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\SEO_Links_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\SEO_Links_Repository'] : ($this->services['Yoast\\WP\\SEO\\Repositories\\SEO_Links_Repository'] = new \Yoast\WP\SEO\Repositories\SEO_Links_Repository())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Import_Cursor_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Import_Cursor_Helper
     */
    protected function getImportCursorHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Import_Cursor_Helper'] = new \Yoast\WP\SEO\Helpers\Import_Cursor_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Import_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Import_Helper
     */
    protected function getImportHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Import_Helper'] = new \Yoast\WP\SEO\Helpers\Import_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Indexable_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Indexable_Helper
     */
    protected function getIndexableHelperService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper'] : $this->getIndexingHelperService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'])) {
            return $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'];
        }

        $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] = $instance = new \Yoast\WP\SEO\Helpers\Indexable_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Environment_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Environment_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Environment_Helper'] = new \Yoast\WP\SEO\Helpers\Environment_Helper())) && false ?: '_'}, $a);

        $instance->set_indexable_repository(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Indexable_To_Postmeta_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Indexable_To_Postmeta_Helper
     */
    protected function getIndexableToPostmetaHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_To_Postmeta_Helper'] = new \Yoast\WP\SEO\Helpers\Indexable_To_Postmeta_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Meta_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Meta_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Meta_Helper'] = new \Yoast\WP\SEO\Helpers\Meta_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Indexables_Page_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Indexables_Page_Helper
     *
     * @deprecated Yoast\WP\SEO\Helpers\Indexables_Page_Helper is deprecated since version 20.4!
     */
    protected function getIndexablesPageHelperService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Helpers\\Indexables_Page_Helper is deprecated since version 20.4!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Helpers\\Indexables_Page_Helper'] = new \Yoast\WP\SEO\Helpers\Indexables_Page_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Indexing_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Indexing_Helper
     */
    protected function getIndexingHelperService()
    {
        $this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper'] = $instance = new \Yoast\WP\SEO\Helpers\Indexing_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper'] = new \Yoast\WP\SEO\Helpers\Date_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast_Notification_Center']) ? $this->services['Yoast_Notification_Center'] : $this->getYoastNotificationCenterService()) && false ?: '_'});

        $instance->set_indexing_actions(${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Indexation_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Indexation_Action'] : $this->getIndexablePostIndexationActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Term_Indexation_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Term_Indexation_Action'] : $this->getIndexableTermIndexationActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Type_Archive_Indexation_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Type_Archive_Indexation_Action'] : $this->getIndexablePostTypeArchiveIndexationActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_General_Indexation_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_General_Indexation_Action'] : $this->getIndexableGeneralIndexationActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action'] : $this->getPostLinkIndexingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Term_Link_Indexing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Term_Link_Indexing_Action'] : $this->getTermLinkIndexingActionService()) && false ?: '_'});
        $instance->set_indexable_repository(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Language_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Language_Helper
     */
    protected function getLanguageHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Language_Helper'] = new \Yoast\WP\SEO\Helpers\Language_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Meta_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Meta_Helper
     */
    protected function getMetaHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Meta_Helper'] = new \Yoast\WP\SEO\Helpers\Meta_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Notification_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Notification_Helper
     */
    protected function getNotificationHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Notification_Helper'] = new \Yoast\WP\SEO\Helpers\Notification_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Open_Graph\Image_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Open_Graph\Image_Helper
     */
    protected function getImageHelper2Service()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper'])) {
            return $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper'];
        }

        return $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper'] = new \Yoast\WP\SEO\Helpers\Open_Graph\Image_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, $a);
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Open_Graph\Values_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Open_Graph\Values_Helper
     */
    protected function getValuesHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] = new \Yoast\WP\SEO\Helpers\Open_Graph\Values_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Options_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Options_Helper
     */
    protected function getOptionsHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Pagination_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Pagination_Helper
     */
    protected function getPaginationHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper'] = new \Yoast\WP\SEO\Helpers\Pagination_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Rewrite_Wrapper']) ? $this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Rewrite_Wrapper'] : ($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Rewrite_Wrapper'] = new \Yoast\WP\SEO\Wrappers\WP_Rewrite_Wrapper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper']) ? $this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper'] : ($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper'] = new \Yoast\WP\SEO\Wrappers\WP_Query_Wrapper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Permalink_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Permalink_Helper
     */
    protected function getPermalinkHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] = new \Yoast\WP\SEO\Helpers\Permalink_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Post_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Post_Helper
     */
    protected function getPostHelperService()
    {
        $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper'] = $instance = new \Yoast\WP\SEO\Helpers\Post_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\String_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\String_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\String_Helper'] = new \Yoast\WP\SEO\Helpers\String_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'});

        $instance->set_indexable_repository(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Post_Type_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Post_Type_Helper
     */
    protected function getPostTypeHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] = new \Yoast\WP\SEO\Helpers\Post_Type_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Primary_Term_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Primary_Term_Helper
     */
    protected function getPrimaryTermHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Primary_Term_Helper'] = new \Yoast\WP\SEO\Helpers\Primary_Term_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Product_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Product_Helper
     */
    protected function getProductHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] = new \Yoast\WP\SEO\Helpers\Product_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Redirect_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Redirect_Helper
     */
    protected function getRedirectHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper'] = new \Yoast\WP\SEO\Helpers\Redirect_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Request_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Request_Helper
     */
    protected function getRequestHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Request_Helper'] = new \Yoast\WP\SEO\Helpers\Request_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Require_File_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Require_File_Helper
     */
    protected function getRequireFileHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Require_File_Helper'] = new \Yoast\WP\SEO\Helpers\Require_File_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Robots_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Robots_Helper
     */
    protected function getRobotsHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Robots_Helper'] = new \Yoast\WP\SEO\Helpers\Robots_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper'] : $this->getTaxonomyHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Robots_Txt_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Robots_Txt_Helper
     */
    protected function getRobotsTxtHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Robots_Txt_Helper'] = new \Yoast\WP\SEO\Helpers\Robots_Txt_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Sanitization_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Sanitization_Helper
     */
    protected function getSanitizationHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Sanitization_Helper'] = new \Yoast\WP\SEO\Helpers\Sanitization_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Schema\Article_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Schema\Article_Helper
     */
    protected function getArticleHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\Article_Helper'] = new \Yoast\WP\SEO\Helpers\Schema\Article_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Schema\HTML_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Schema\HTML_Helper
     */
    protected function getHTMLHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\HTML_Helper'] = new \Yoast\WP\SEO\Helpers\Schema\HTML_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Schema\ID_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Schema\ID_Helper
     */
    protected function getIDHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\ID_Helper'] = new \Yoast\WP\SEO\Helpers\Schema\ID_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Schema\Image_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Schema\Image_Helper
     */
    protected function getImageHelper3Service()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\Image_Helper'] = new \Yoast\WP\SEO\Helpers\Schema\Image_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\HTML_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\HTML_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\HTML_Helper'] = new \Yoast\WP\SEO\Helpers\Schema\HTML_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\Language_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\Language_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\Language_Helper'] = new \Yoast\WP\SEO\Helpers\Schema\Language_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Schema\Language_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Schema\Language_Helper
     */
    protected function getLanguageHelper2Service()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\Language_Helper'] = new \Yoast\WP\SEO\Helpers\Schema\Language_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Schema\Replace_Vars_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Schema\Replace_Vars_Helper
     */
    protected function getReplaceVarsHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\Replace_Vars_Helper'] = new \Yoast\WP\SEO\Helpers\Schema\Replace_Vars_Helper(${($_ = isset($this->services['WPSEO_Replace_Vars']) ? $this->services['WPSEO_Replace_Vars'] : $this->getWPSEOReplaceVarsService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\ID_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\ID_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\ID_Helper'] = new \Yoast\WP\SEO\Helpers\Schema\ID_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper'] = new \Yoast\WP\SEO\Helpers\Date_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Score_Icon_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Score_Icon_Helper
     */
    protected function getScoreIconHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Score_Icon_Helper'] = new \Yoast\WP\SEO\Helpers\Score_Icon_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Robots_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Robots_Helper'] : $this->getRobotsHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Short_Link_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Short_Link_Helper
     */
    protected function getShortLinkHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Short_Link_Helper'] = new \Yoast\WP\SEO\Helpers\Short_Link_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] = new \Yoast\WP\SEO\Helpers\Product_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Site_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Site_Helper
     */
    protected function getSiteHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Site_Helper'] = new \Yoast\WP\SEO\Helpers\Site_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Social_Profiles_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Social_Profiles_Helper
     */
    protected function getSocialProfilesHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Social_Profiles_Helper'] = new \Yoast\WP\SEO\Helpers\Social_Profiles_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\String_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\String_Helper
     */
    protected function getStringHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\String_Helper'] = new \Yoast\WP\SEO\Helpers\String_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Taxonomy_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Taxonomy_Helper
     */
    protected function getTaxonomyHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper'] = new \Yoast\WP\SEO\Helpers\Taxonomy_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\String_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\String_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\String_Helper'] = new \Yoast\WP\SEO\Helpers\String_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Twitter\Image_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Twitter\Image_Helper
     */
    protected function getImageHelper4Service()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Helpers\\Twitter\\Image_Helper'])) {
            return $this->services['Yoast\\WP\\SEO\\Helpers\\Twitter\\Image_Helper'];
        }

        return $this->services['Yoast\\WP\\SEO\\Helpers\\Twitter\\Image_Helper'] = new \Yoast\WP\SEO\Helpers\Twitter\Image_Helper($a);
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Url_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Url_Helper
     */
    protected function getUrlHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\User_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\User_Helper
     */
    protected function getUserHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] = new \Yoast\WP\SEO\Helpers\User_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Wincher_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Wincher_Helper
     */
    protected function getWincherHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Wincher_Helper'] = new \Yoast\WP\SEO\Helpers\Wincher_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Woocommerce_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Woocommerce_Helper
     */
    protected function getWoocommerceHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Woocommerce_Helper'] = new \Yoast\WP\SEO\Helpers\Woocommerce_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Wordpress_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Wordpress_Helper
     */
    protected function getWordpressHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Wordpress_Helper'] = new \Yoast\WP\SEO\Helpers\Wordpress_Helper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Wordproof_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Wordproof_Helper
     */
    protected function getWordproofHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Wordproof_Helper'] = new \Yoast\WP\SEO\Helpers\Wordproof_Helper(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Woocommerce_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Woocommerce_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Woocommerce_Helper'] = new \Yoast\WP\SEO\Helpers\Woocommerce_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Helpers\Wpdb_Helper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Helpers\Wpdb_Helper
     */
    protected function getWpdbHelperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Helpers\\Wpdb_Helper'] = new \Yoast\WP\SEO\Helpers\Wpdb_Helper(${($_ = isset($this->services['wpdb']) ? $this->services['wpdb'] : $this->getWpdbService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Initializers\Crawl_Cleanup_Permalinks' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Initializers\Crawl_Cleanup_Permalinks
     */
    protected function getCrawlCleanupPermalinksService()
    {
        return $this->services['Yoast\\WP\\SEO\\Initializers\\Crawl_Cleanup_Permalinks'] = new \Yoast\WP\SEO\Initializers\Crawl_Cleanup_Permalinks(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper'] = new \Yoast\WP\SEO\Helpers\Redirect_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Crawl_Cleanup_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Crawl_Cleanup_Helper'] : $this->getCrawlCleanupHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Initializers\Disable_Core_Sitemaps' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Initializers\Disable_Core_Sitemaps
     */
    protected function getDisableCoreSitemapsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Initializers\\Disable_Core_Sitemaps'] = new \Yoast\WP\SEO\Initializers\Disable_Core_Sitemaps(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper'] = new \Yoast\WP\SEO\Helpers\Redirect_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Initializers\Migration_Runner' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Initializers\Migration_Runner
     */
    protected function getMigrationRunnerService()
    {
        return $this->services['Yoast\\WP\\SEO\\Initializers\\Migration_Runner'] = new \Yoast\WP\SEO\Initializers\Migration_Runner(${($_ = isset($this->services['Yoast\\WP\\SEO\\Config\\Migration_Status']) ? $this->services['Yoast\\WP\\SEO\\Config\\Migration_Status'] : ($this->services['Yoast\\WP\\SEO\\Config\\Migration_Status'] = new \Yoast\WP\SEO\Config\Migration_Status())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Loader']) ? $this->services['Yoast\\WP\\SEO\\Loader'] : $this->getLoaderService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter']) ? $this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] : ($this->services['Yoast\\WP\\Lib\\Migrations\\Adapter'] = new \Yoast\WP\Lib\Migrations\Adapter())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Initializers\Woocommerce' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Initializers\Woocommerce
     */
    protected function getWoocommerceService()
    {
        return $this->services['Yoast\\WP\\SEO\\Initializers\\Woocommerce'] = new \Yoast\WP\SEO\Initializers\Woocommerce();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Activation_Cleanup_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Activation_Cleanup_Integration
     */
    protected function getActivationCleanupIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Activation_Cleanup_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Activation_Cleanup_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Addon_Installation\Dialog_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Addon_Installation\Dialog_Integration
     */
    protected function getDialogIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Addon_Installation\\Dialog_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Addon_Installation\Dialog_Integration(${($_ = isset($this->services['WPSEO_Addon_Manager']) ? $this->services['WPSEO_Addon_Manager'] : $this->getWPSEOAddonManagerService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Addon_Installation\Installation_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Addon_Installation\Installation_Integration
     */
    protected function getInstallationIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Addon_Installation\\Installation_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Addon_Installation\Installation_Integration(${($_ = isset($this->services['WPSEO_Addon_Manager']) ? $this->services['WPSEO_Addon_Manager'] : $this->getWPSEOAddonManagerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Addon_Installation\\Addon_Activate_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Addon_Installation\\Addon_Activate_Action'] : $this->getAddonActivateActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Addon_Installation\\Addon_Install_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Addon_Installation\\Addon_Install_Action'] : $this->getAddonInstallActionService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Admin_Columns_Cache_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Admin_Columns_Cache_Integration
     */
    protected function getAdminColumnsCacheIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Admin_Columns_Cache_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Admin_Columns_Cache_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Background_Indexing_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Background_Indexing_Integration
     */
    protected function getBackgroundIndexingIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Background_Indexing_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Background_Indexing_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Indexation_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Indexation_Action'] : $this->getIndexablePostIndexationActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Term_Indexation_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Term_Indexation_Action'] : $this->getIndexableTermIndexationActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Type_Archive_Indexation_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Type_Archive_Indexation_Action'] : $this->getIndexablePostTypeArchiveIndexationActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_General_Indexation_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_General_Indexation_Action'] : $this->getIndexableGeneralIndexationActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Indexing_Complete_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Indexing_Complete_Action'] : $this->getIndexableIndexingCompleteActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action'] : $this->getPostLinkIndexingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Term_Link_Indexing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Term_Link_Indexing_Action'] : $this->getTermLinkIndexingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper'] : $this->getIndexingHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Crawl_Settings_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Crawl_Settings_Integration
     */
    protected function getCrawlSettingsIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Crawl_Settings_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Crawl_Settings_Integration(${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Shortlinker']) ? $this->services['WPSEO_Shortlinker'] : $this->getWPSEOShortlinkerService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Cron_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Cron_Integration
     */
    protected function getCronIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Cron_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Cron_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper'] = new \Yoast\WP\SEO\Helpers\Date_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Deactivated_Premium_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Deactivated_Premium_Integration
     */
    protected function getDeactivatedPremiumIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Deactivated_Premium_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Deactivated_Premium_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Disable_Concatenate_Scripts_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Disable_Concatenate_Scripts_Integration
     */
    protected function getDisableConcatenateScriptsIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Disable_Concatenate_Scripts_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Disable_Concatenate_Scripts_Integration();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\First_Time_Configuration_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\First_Time_Configuration_Integration
     */
    protected function getFirstTimeConfigurationIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\First_Time_Configuration_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\First_Time_Configuration_Integration(${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Addon_Manager']) ? $this->services['WPSEO_Addon_Manager'] : $this->getWPSEOAddonManagerService()) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Shortlinker']) ? $this->services['WPSEO_Shortlinker'] : $this->getWPSEOShortlinkerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Social_Profiles_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Social_Profiles_Helper'] : $this->getSocialProfilesHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] = new \Yoast\WP\SEO\Helpers\Product_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Context\\Meta_Tags_Context']) ? $this->services['Yoast\\WP\\SEO\\Context\\Meta_Tags_Context'] : $this->getMetaTagsContextService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\First_Time_Configuration_Notice_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\First_Time_Configuration_Notice_Integration
     */
    protected function getFirstTimeConfigurationNoticeIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\First_Time_Configuration_Notice_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\First_Time_Configuration_Notice_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\First_Time_Configuration_Notice_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\First_Time_Configuration_Notice_Helper'] : $this->getFirstTimeConfigurationNoticeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Fix_News_Dependencies_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Fix_News_Dependencies_Integration
     */
    protected function getFixNewsDependenciesIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Fix_News_Dependencies_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Fix_News_Dependencies_Integration();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Health_Check_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Health_Check_Integration
     */
    protected function getHealthCheckIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Health_Check_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Health_Check_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Default_Tagline_Check']) ? $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Default_Tagline_Check'] : $this->getDefaultTaglineCheckService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Links_Table_Check']) ? $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Links_Table_Check'] : $this->getLinksTableCheckService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Page_Comments_Check']) ? $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Page_Comments_Check'] : $this->getPageCommentsCheckService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Postname_Permalink_Check']) ? $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Postname_Permalink_Check'] : $this->getPostnamePermalinkCheckService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\HelpScout_Beacon' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\HelpScout_Beacon
     */
    protected function getHelpScoutBeaconService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\HelpScout_Beacon'] = new \Yoast\WP\SEO\Integrations\Admin\HelpScout_Beacon(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Config\\Migration_Status']) ? $this->services['Yoast\\WP\\SEO\\Config\\Migration_Status'] : ($this->services['Yoast\\WP\\SEO\\Config\\Migration_Status'] = new \Yoast\WP\SEO\Config\Migration_Status())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Import_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Import_Integration
     */
    protected function getImportIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Import_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Import_Integration(${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Importable_Detector_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Importable_Detector_Service'] : $this->getImportableDetectorServiceService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Routes\\Importing_Route']) ? $this->services['Yoast\\WP\\SEO\\Routes\\Importing_Route'] : $this->getImportingRouteService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Indexables_Exclude_Taxonomy_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Indexables_Exclude_Taxonomy_Integration
     */
    protected function getIndexablesExcludeTaxonomyIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Indexables_Exclude_Taxonomy_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Indexables_Exclude_Taxonomy_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Indexables_Page_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Indexables_Page_Integration
     *
     * @deprecated Yoast\WP\SEO\Integrations\Admin\Indexables_Page_Integration is deprecated since version 20.4!
     */
    protected function getIndexablesPageIntegrationService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Integrations\\Admin\\Indexables_Page_Integration is deprecated since version 20.4!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Indexables_Page_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Indexables_Page_Integration(${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Addon_Manager']) ? $this->services['WPSEO_Addon_Manager'] : $this->getWPSEOAddonManagerService()) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Shortlinker']) ? $this->services['WPSEO_Shortlinker'] : $this->getWPSEOShortlinkerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Short_Link_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Short_Link_Helper'] : $this->getShortLinkHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexables_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexables_Page_Helper'] : $this->getIndexablesPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] = new \Yoast\WP\SEO\Helpers\Product_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Indexing_Notification_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Indexing_Notification_Integration
     */
    protected function getIndexingNotificationIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Indexing_Notification_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Indexing_Notification_Integration(${($_ = isset($this->services['Yoast_Notification_Center']) ? $this->services['Yoast_Notification_Center'] : $this->getYoastNotificationCenterService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] = new \Yoast\WP\SEO\Helpers\Product_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Short_Link_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Short_Link_Helper'] : $this->getShortLinkHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Notification_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Notification_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Notification_Helper'] = new \Yoast\WP\SEO\Helpers\Notification_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper'] : $this->getIndexingHelperService()) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Addon_Manager']) ? $this->services['WPSEO_Addon_Manager'] : $this->getWPSEOAddonManagerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Environment_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Environment_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Environment_Helper'] = new \Yoast\WP\SEO\Helpers\Environment_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Indexing_Tool_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Indexing_Tool_Integration
     */
    protected function getIndexingToolIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Indexing_Tool_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Indexing_Tool_Integration(${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Short_Link_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Short_Link_Helper'] : $this->getShortLinkHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper'] : $this->getIndexingHelperService()) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Addon_Manager']) ? $this->services['WPSEO_Addon_Manager'] : $this->getWPSEOAddonManagerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] = new \Yoast\WP\SEO\Helpers\Product_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Importable_Detector_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Importable_Detector_Service'] : $this->getImportableDetectorServiceService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Routes\\Importing_Route']) ? $this->services['Yoast\\WP\\SEO\\Routes\\Importing_Route'] : $this->getImportingRouteService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Installation_Success_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Installation_Success_Integration
     */
    protected function getInstallationSuccessIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Installation_Success_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Installation_Success_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] = new \Yoast\WP\SEO\Helpers\Product_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Integrations_Page' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Integrations_Page
     */
    protected function getIntegrationsPageService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Integrations_Page'] = new \Yoast\WP\SEO\Integrations\Admin\Integrations_Page(${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Link_Count_Columns_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Link_Count_Columns_Integration
     */
    protected function getLinkCountColumnsIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Link_Count_Columns_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Link_Count_Columns_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['wpdb']) ? $this->services['wpdb'] : $this->getWpdbService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action'] : $this->getPostLinkIndexingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Admin_Columns_Cache_Integration']) ? $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Admin_Columns_Cache_Integration'] : $this->getAdminColumnsCacheIntegrationService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Menu_Badge_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Menu_Badge_Integration
     */
    protected function getMenuBadgeIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Menu_Badge_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Menu_Badge_Integration();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Migration_Error_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Migration_Error_Integration
     */
    protected function getMigrationErrorIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Migration_Error_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Migration_Error_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Config\\Migration_Status']) ? $this->services['Yoast\\WP\\SEO\\Config\\Migration_Status'] : ($this->services['Yoast\\WP\\SEO\\Config\\Migration_Status'] = new \Yoast\WP\SEO\Config\Migration_Status())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Old_Configuration_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Old_Configuration_Integration
     */
    protected function getOldConfigurationIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Old_Configuration_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Old_Configuration_Integration();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Old_Premium_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Old_Premium_Integration
     */
    protected function getOldPremiumIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Old_Premium_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Old_Premium_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] = new \Yoast\WP\SEO\Helpers\Product_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Capability_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Capability_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Capability_Helper'] = new \Yoast\WP\SEO\Helpers\Capability_Helper())) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Redirect_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Redirect_Integration
     */
    protected function getRedirectIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Redirect_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Redirect_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper'] = new \Yoast\WP\SEO\Helpers\Redirect_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Redirects_Page_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Redirects_Page_Integration
     */
    protected function getRedirectsPageIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Redirects_Page_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Redirects_Page_Integration();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Social_Templates_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Social_Templates_Integration
     *
     * @deprecated Yoast\WP\SEO\Integrations\Admin\Social_Templates_Integration is deprecated since version 20.3!
     */
    protected function getSocialTemplatesIntegrationService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Integrations\\Admin\\Social_Templates_Integration is deprecated since version 20.3!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Social_Templates_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Social_Templates_Integration();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Admin\Workouts_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Admin\Workouts_Integration
     */
    protected function getWorkoutsIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Admin\\Workouts_Integration'] = new \Yoast\WP\SEO\Integrations\Admin\Workouts_Integration(${($_ = isset($this->services['WPSEO_Addon_Manager']) ? $this->services['WPSEO_Addon_Manager'] : $this->getWPSEOAddonManagerService()) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] = new \Yoast\WP\SEO\Helpers\Product_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Alerts\Jetpack_Boost_Pre_Publish' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Alerts\Jetpack_Boost_Pre_Publish
     */
    protected function getJetpackBoostPrePublishService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Alerts\\Jetpack_Boost_Pre_Publish'] = new \Yoast\WP\SEO\Integrations\Alerts\Jetpack_Boost_Pre_Publish();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Alerts\Webinar_Promo_Notification' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Alerts\Webinar_Promo_Notification
     */
    protected function getWebinarPromoNotificationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Alerts\\Webinar_Promo_Notification'] = new \Yoast\WP\SEO\Integrations\Alerts\Webinar_Promo_Notification();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Blocks\Breadcrumbs_Block' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Blocks\Breadcrumbs_Block
     */
    protected function getBreadcrumbsBlockService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Blocks\\Breadcrumbs_Block'] = new \Yoast\WP\SEO\Integrations\Blocks\Breadcrumbs_Block(${($_ = isset($this->services['Yoast\\WP\\SEO\\Memoizers\\Meta_Tags_Context_Memoizer']) ? $this->services['Yoast\\WP\\SEO\\Memoizers\\Meta_Tags_Context_Memoizer'] : $this->getMetaTagsContextMemoizerService()) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Replace_Vars']) ? $this->services['WPSEO_Replace_Vars'] : $this->getWPSEOReplaceVarsService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Surfaces\\Helpers_Surface']) ? $this->services['Yoast\\WP\\SEO\\Surfaces\\Helpers_Surface'] : $this->getHelpersSurfaceService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Request_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Request_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Request_Helper'] = new \Yoast\WP\SEO\Helpers\Request_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Blocks\Internal_Linking_Category' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Blocks\Internal_Linking_Category
     */
    protected function getInternalLinkingCategoryService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Blocks\\Internal_Linking_Category'] = new \Yoast\WP\SEO\Integrations\Blocks\Internal_Linking_Category();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Blocks\Structured_Data_Blocks' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Blocks\Structured_Data_Blocks
     */
    protected function getStructuredDataBlocksService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Blocks\\Structured_Data_Blocks'] = new \Yoast\WP\SEO\Integrations\Blocks\Structured_Data_Blocks(${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Breadcrumbs_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Breadcrumbs_Integration
     */
    protected function getBreadcrumbsIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Breadcrumbs_Integration'] = new \Yoast\WP\SEO\Integrations\Breadcrumbs_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Surfaces\\Helpers_Surface']) ? $this->services['Yoast\\WP\\SEO\\Surfaces\\Helpers_Surface'] : $this->getHelpersSurfaceService()) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Replace_Vars']) ? $this->services['WPSEO_Replace_Vars'] : $this->getWPSEOReplaceVarsService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Memoizers\\Meta_Tags_Context_Memoizer']) ? $this->services['Yoast\\WP\\SEO\\Memoizers\\Meta_Tags_Context_Memoizer'] : $this->getMetaTagsContextMemoizerService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Cleanup_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Cleanup_Integration
     */
    protected function getCleanupIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Cleanup_Integration'] = new \Yoast\WP\SEO\Integrations\Cleanup_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper'] : $this->getTaxonomyHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Author_Archive_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Author_Archive_Helper'] : $this->getAuthorArchiveHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Duplicate_Post_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Duplicate_Post_Integration
     */
    protected function getDuplicatePostIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Duplicate_Post_Integration'] = new \Yoast\WP\SEO\Integrations\Duplicate_Post_Integration();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Estimated_Reading_Time' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Estimated_Reading_Time
     */
    protected function getEstimatedReadingTimeService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Estimated_Reading_Time'] = new \Yoast\WP\SEO\Integrations\Estimated_Reading_Time();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Exclude_Attachment_Post_Type' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Exclude_Attachment_Post_Type
     */
    protected function getExcludeAttachmentPostTypeService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Exclude_Attachment_Post_Type'] = new \Yoast\WP\SEO\Integrations\Exclude_Attachment_Post_Type();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Exclude_Oembed_Cache_Post_Type' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Exclude_Oembed_Cache_Post_Type
     */
    protected function getExcludeOembedCachePostTypeService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Exclude_Oembed_Cache_Post_Type'] = new \Yoast\WP\SEO\Integrations\Exclude_Oembed_Cache_Post_Type();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Feature_Flag_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Feature_Flag_Integration
     */
    protected function getFeatureFlagIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Feature_Flag_Integration'] = new \Yoast\WP\SEO\Integrations\Feature_Flag_Integration(${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Conditionals\\Addon_Installation_Conditional']) ? $this->services['Yoast\\WP\\SEO\\Conditionals\\Addon_Installation_Conditional'] : ($this->services['Yoast\\WP\\SEO\\Conditionals\\Addon_Installation_Conditional'] = new \Yoast\WP\SEO\Conditionals\Addon_Installation_Conditional())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Conditionals\\New_Settings_Ui_Conditional']) ? $this->services['Yoast\\WP\\SEO\\Conditionals\\New_Settings_Ui_Conditional'] : ($this->services['Yoast\\WP\\SEO\\Conditionals\\New_Settings_Ui_Conditional'] = new \Yoast\WP\SEO\Conditionals\New_Settings_Ui_Conditional())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Conditionals\\Text_Formality_Conditional']) ? $this->services['Yoast\\WP\\SEO\\Conditionals\\Text_Formality_Conditional'] : ($this->services['Yoast\\WP\\SEO\\Conditionals\\Text_Formality_Conditional'] = new \Yoast\WP\SEO\Conditionals\Text_Formality_Conditional())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Conditionals\\Updated_Importer_Framework_Conditional']) ? $this->services['Yoast\\WP\\SEO\\Conditionals\\Updated_Importer_Framework_Conditional'] : ($this->services['Yoast\\WP\\SEO\\Conditionals\\Updated_Importer_Framework_Conditional'] = new \Yoast\WP\SEO\Conditionals\Updated_Importer_Framework_Conditional())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End\Backwards_Compatibility' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End\Backwards_Compatibility
     */
    protected function getBackwardsCompatibilityService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End\\Backwards_Compatibility'] = new \Yoast\WP\SEO\Integrations\Front_End\Backwards_Compatibility(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End\Category_Term_Description' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End\Category_Term_Description
     */
    protected function getCategoryTermDescriptionService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End\\Category_Term_Description'] = new \Yoast\WP\SEO\Integrations\Front_End\Category_Term_Description();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End\Comment_Link_Fixer' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End\Comment_Link_Fixer
     */
    protected function getCommentLinkFixerService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End\\Comment_Link_Fixer'] = new \Yoast\WP\SEO\Integrations\Front_End\Comment_Link_Fixer(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper'] = new \Yoast\WP\SEO\Helpers\Redirect_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Robots_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Robots_Helper'] : $this->getRobotsHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End\Crawl_Cleanup_Basic' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End\Crawl_Cleanup_Basic
     */
    protected function getCrawlCleanupBasicService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End\\Crawl_Cleanup_Basic'] = new \Yoast\WP\SEO\Integrations\Front_End\Crawl_Cleanup_Basic(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End\Crawl_Cleanup_Rss' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End\Crawl_Cleanup_Rss
     */
    protected function getCrawlCleanupRssService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End\\Crawl_Cleanup_Rss'] = new \Yoast\WP\SEO\Integrations\Front_End\Crawl_Cleanup_Rss(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End\Crawl_Cleanup_Searches' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End\Crawl_Cleanup_Searches
     */
    protected function getCrawlCleanupSearchesService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End\\Crawl_Cleanup_Searches'] = new \Yoast\WP\SEO\Integrations\Front_End\Crawl_Cleanup_Searches(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper'] = new \Yoast\WP\SEO\Helpers\Redirect_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End\Feed_Improvements' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End\Feed_Improvements
     */
    protected function getFeedImprovementsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End\\Feed_Improvements'] = new \Yoast\WP\SEO\Integrations\Front_End\Feed_Improvements(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Surfaces\\Meta_Surface']) ? $this->services['Yoast\\WP\\SEO\\Surfaces\\Meta_Surface'] : $this->getMetaSurfaceService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End\Force_Rewrite_Title' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End\Force_Rewrite_Title
     */
    protected function getForceRewriteTitleService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End\\Force_Rewrite_Title'] = new \Yoast\WP\SEO\Integrations\Front_End\Force_Rewrite_Title(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper']) ? $this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper'] : ($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper'] = new \Yoast\WP\SEO\Wrappers\WP_Query_Wrapper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End\Handle_404' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End\Handle_404
     */
    protected function getHandle404Service()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End\\Handle_404'] = new \Yoast\WP\SEO\Integrations\Front_End\Handle_404(${($_ = isset($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper']) ? $this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper'] : ($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper'] = new \Yoast\WP\SEO\Wrappers\WP_Query_Wrapper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End\Indexing_Controls' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End\Indexing_Controls
     */
    protected function getIndexingControlsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End\\Indexing_Controls'] = new \Yoast\WP\SEO\Integrations\Front_End\Indexing_Controls(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Robots_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Robots_Helper'] : $this->getRobotsHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End\Open_Graph_OEmbed' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End\Open_Graph_OEmbed
     */
    protected function getOpenGraphOEmbedService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End\\Open_Graph_OEmbed'] = new \Yoast\WP\SEO\Integrations\Front_End\Open_Graph_OEmbed(${($_ = isset($this->services['Yoast\\WP\\SEO\\Surfaces\\Meta_Surface']) ? $this->services['Yoast\\WP\\SEO\\Surfaces\\Meta_Surface'] : $this->getMetaSurfaceService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End\RSS_Footer_Embed' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End\RSS_Footer_Embed
     */
    protected function getRSSFooterEmbedService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End\\RSS_Footer_Embed'] = new \Yoast\WP\SEO\Integrations\Front_End\RSS_Footer_Embed(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End\Redirects' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End\Redirects
     */
    protected function getRedirectsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End\\Redirects'] = new \Yoast\WP\SEO\Integrations\Front_End\Redirects(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Meta_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Meta_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Meta_Helper'] = new \Yoast\WP\SEO\Helpers\Meta_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Redirect_Helper'] = new \Yoast\WP\SEO\Helpers\Redirect_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End\Robots_Txt_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End\Robots_Txt_Integration
     */
    protected function getRobotsTxtIntegrationService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Robots_Txt_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Robots_Txt_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Robots_Txt_Helper'] = new \Yoast\WP\SEO\Helpers\Robots_Txt_Helper())) && false ?: '_'};

        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End\\Robots_Txt_Integration'] = new \Yoast\WP\SEO\Integrations\Front_End\Robots_Txt_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, $a, new \Yoast\WP\SEO\Presenters\Robots_Txt_Presenter($a));
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End\Schema_Accessibility_Feature' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End\Schema_Accessibility_Feature
     */
    protected function getSchemaAccessibilityFeatureService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End\\Schema_Accessibility_Feature'] = new \Yoast\WP\SEO\Integrations\Front_End\Schema_Accessibility_Feature();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End\WP_Robots_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End\WP_Robots_Integration
     */
    protected function getWPRobotsIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End\\WP_Robots_Integration'] = new \Yoast\WP\SEO\Integrations\Front_End\WP_Robots_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Memoizers\\Meta_Tags_Context_Memoizer']) ? $this->services['Yoast\\WP\\SEO\\Memoizers\\Meta_Tags_Context_Memoizer'] : $this->getMetaTagsContextMemoizerService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Front_End_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Front_End_Integration
     */
    protected function getFrontEndIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End_Integration'] = new \Yoast\WP\SEO\Integrations\Front_End_Integration(${($_ = isset($this->services['Yoast\\WP\\SEO\\Memoizers\\Meta_Tags_Context_Memoizer']) ? $this->services['Yoast\\WP\\SEO\\Memoizers\\Meta_Tags_Context_Memoizer'] : $this->getMetaTagsContextMemoizerService()) && false ?: '_'}, $this, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Request_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Request_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Request_Helper'] = new \Yoast\WP\SEO\Helpers\Request_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Surfaces\\Helpers_Surface']) ? $this->services['Yoast\\WP\\SEO\\Surfaces\\Helpers_Surface'] : $this->getHelpersSurfaceService()) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Replace_Vars']) ? $this->services['WPSEO_Replace_Vars'] : $this->getWPSEOReplaceVarsService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Primary_Category' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Primary_Category
     */
    protected function getPrimaryCategoryService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Primary_Category'] = new \Yoast\WP\SEO\Integrations\Primary_Category();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Schema_Blocks' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Schema_Blocks
     *
     * @deprecated Yoast\WP\SEO\Integrations\Schema_Blocks is deprecated since version 20.5!
     */
    protected function getSchemaBlocksService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Integrations\\Schema_Blocks is deprecated since version 20.5!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Integrations\\Schema_Blocks'] = new \Yoast\WP\SEO\Integrations\Schema_Blocks(${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Conditionals\\Schema_Blocks_Conditional']) ? $this->services['Yoast\\WP\\SEO\\Conditionals\\Schema_Blocks_Conditional'] : $this->getSchemaBlocksConditionalService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Short_Link_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Short_Link_Helper'] : $this->getShortLinkHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Settings_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Settings_Integration
     */
    protected function getSettingsIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Settings_Integration'] = new \Yoast\WP\SEO\Integrations\Settings_Integration(${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Replace_Vars']) ? $this->services['WPSEO_Replace_Vars'] : $this->getWPSEOReplaceVarsService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Config\\Schema_Types']) ? $this->services['Yoast\\WP\\SEO\\Config\\Schema_Types'] : ($this->services['Yoast\\WP\\SEO\\Config\\Schema_Types'] = new \Yoast\WP\SEO\Config\Schema_Types())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Language_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Language_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Language_Helper'] = new \Yoast\WP\SEO\Helpers\Language_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper'] : $this->getTaxonomyHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Product_Helper'] = new \Yoast\WP\SEO\Helpers\Product_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Woocommerce_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Woocommerce_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Woocommerce_Helper'] = new \Yoast\WP\SEO\Helpers\Woocommerce_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\Article_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\Article_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Schema\\Article_Helper'] = new \Yoast\WP\SEO\Helpers\Schema\Article_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] = new \Yoast\WP\SEO\Helpers\User_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Settings_Introduction_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Settings_Introduction_Action'] : $this->getSettingsIntroductionActionService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\AMP' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\AMP
     */
    protected function getAMPService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\AMP'] = new \Yoast\WP\SEO\Integrations\Third_Party\AMP(${($_ = isset($this->services['Yoast\\WP\\SEO\\Integrations\\Front_End_Integration']) ? $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End_Integration'] : $this->getFrontEndIntegrationService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\BbPress' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\BbPress
     */
    protected function getBbPressService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\BbPress'] = new \Yoast\WP\SEO\Integrations\Third_Party\BbPress(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\CoAuthors_Plus' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\CoAuthors_Plus
     *
     * @deprecated Yoast\WP\SEO\Integrations\Third_Party\CoAuthors_Plus is deprecated since version 19.12!
     */
    protected function getCoAuthorsPlusService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Integrations\\Third_Party\\CoAuthors_Plus is deprecated since version 19.12!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\CoAuthors_Plus'] = new \Yoast\WP\SEO\Integrations\Third_Party\CoAuthors_Plus(${($_ = isset($this->services['Yoast\\WP\\SEO\\Surfaces\\Helpers_Surface']) ? $this->services['Yoast\\WP\\SEO\\Surfaces\\Helpers_Surface'] : $this->getHelpersSurfaceService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\Elementor' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\Elementor
     */
    protected function getElementorService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\Elementor'] = new \Yoast\WP\SEO\Integrations\Third_Party\Elementor(${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Capability_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Capability_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Capability_Helper'] = new \Yoast\WP\SEO\Helpers\Capability_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\Exclude_Elementor_Post_Types' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\Exclude_Elementor_Post_Types
     */
    protected function getExcludeElementorPostTypesService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\Exclude_Elementor_Post_Types'] = new \Yoast\WP\SEO\Integrations\Third_Party\Exclude_Elementor_Post_Types();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\Exclude_WooCommerce_Post_Types' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\Exclude_WooCommerce_Post_Types
     */
    protected function getExcludeWooCommercePostTypesService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\Exclude_WooCommerce_Post_Types'] = new \Yoast\WP\SEO\Integrations\Third_Party\Exclude_WooCommerce_Post_Types();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\Jetpack' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\Jetpack
     */
    protected function getJetpackService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\Jetpack'] = new \Yoast\WP\SEO\Integrations\Third_Party\Jetpack();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\The_Events_Calendar' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\The_Events_Calendar
     *
     * @deprecated Yoast\WP\SEO\Integrations\Third_Party\The_Events_Calendar is deprecated since version 19.12!
     */
    protected function getTheEventsCalendarService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Integrations\\Third_Party\\The_Events_Calendar is deprecated since version 19.12!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\The_Events_Calendar'] = new \Yoast\WP\SEO\Integrations\Third_Party\The_Events_Calendar();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\W3_Total_Cache' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\W3_Total_Cache
     */
    protected function getW3TotalCacheService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\W3_Total_Cache'] = new \Yoast\WP\SEO\Integrations\Third_Party\W3_Total_Cache();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\WPML' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\WPML
     */
    protected function getWPMLService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\WPML'] = new \Yoast\WP\SEO\Integrations\Third_Party\WPML();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\WPML_WPSEO_Notification' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\WPML_WPSEO_Notification
     */
    protected function getWPMLWPSEONotificationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\WPML_WPSEO_Notification'] = new \Yoast\WP\SEO\Integrations\Third_Party\WPML_WPSEO_Notification(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Short_Link_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Short_Link_Helper'] : $this->getShortLinkHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast_Notification_Center']) ? $this->services['Yoast_Notification_Center'] : $this->getYoastNotificationCenterService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Conditionals\\Third_Party\\WPML_WPSEO_Conditional']) ? $this->services['Yoast\\WP\\SEO\\Conditionals\\Third_Party\\WPML_WPSEO_Conditional'] : ($this->services['Yoast\\WP\\SEO\\Conditionals\\Third_Party\\WPML_WPSEO_Conditional'] = new \Yoast\WP\SEO\Conditionals\Third_Party\WPML_WPSEO_Conditional())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\Web_Stories' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\Web_Stories
     */
    protected function getWebStoriesService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\Web_Stories'] = new \Yoast\WP\SEO\Integrations\Third_Party\Web_Stories(${($_ = isset($this->services['Yoast\\WP\\SEO\\Integrations\\Front_End_Integration']) ? $this->services['Yoast\\WP\\SEO\\Integrations\\Front_End_Integration'] : $this->getFrontEndIntegrationService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\Web_Stories_Post_Edit' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\Web_Stories_Post_Edit
     */
    protected function getWebStoriesPostEditService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\Web_Stories_Post_Edit'] = new \Yoast\WP\SEO\Integrations\Third_Party\Web_Stories_Post_Edit();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\Wincher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\Wincher
     */
    protected function getWincherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\Wincher'] = new \Yoast\WP\SEO\Integrations\Third_Party\Wincher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Wincher_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Wincher_Helper'] : $this->getWincherHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\Wincher_Publish' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\Wincher_Publish
     */
    protected function getWincherPublishService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\Wincher_Publish'] = new \Yoast\WP\SEO\Integrations\Third_Party\Wincher_Publish(${($_ = isset($this->services['Yoast\\WP\\SEO\\Conditionals\\Wincher_Enabled_Conditional']) ? $this->services['Yoast\\WP\\SEO\\Conditionals\\Wincher_Enabled_Conditional'] : $this->getWincherEnabledConditionalService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Keyphrases_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Keyphrases_Action'] : $this->getWincherKeyphrasesActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Account_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Account_Action'] : $this->getWincherAccountActionService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\WooCommerce' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\WooCommerce
     */
    protected function getWooCommerce2Service()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\WooCommerce'] = new \Yoast\WP\SEO\Integrations\Third_Party\WooCommerce(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Replace_Vars']) ? $this->services['WPSEO_Replace_Vars'] : $this->getWPSEOReplaceVarsService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Memoizers\\Meta_Tags_Context_Memoizer']) ? $this->services['Yoast\\WP\\SEO\\Memoizers\\Meta_Tags_Context_Memoizer'] : $this->getMetaTagsContextMemoizerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper'] : $this->getPaginationHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Woocommerce_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Woocommerce_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Woocommerce_Helper'] = new \Yoast\WP\SEO\Helpers\Woocommerce_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\WooCommerce_Post_Edit' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\WooCommerce_Post_Edit
     */
    protected function getWooCommercePostEditService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\WooCommerce_Post_Edit'] = new \Yoast\WP\SEO\Integrations\Third_Party\WooCommerce_Post_Edit();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\Woocommerce_Permalinks' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\Woocommerce_Permalinks
     */
    protected function getWoocommercePermalinksService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\Woocommerce_Permalinks'] = new \Yoast\WP\SEO\Integrations\Third_Party\Woocommerce_Permalinks(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\Wordproof' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\Wordproof
     */
    protected function getWordproofService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\Wordproof'] = new \Yoast\WP\SEO\Integrations\Third_Party\Wordproof(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Wordproof_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Wordproof_Helper'] : $this->getWordproofHelperService()) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Admin_Asset_Manager']) ? $this->services['WPSEO_Admin_Asset_Manager'] : $this->getWPSEOAdminAssetManagerService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Third_Party\Wordproof_Integration_Toggle' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Third_Party\Wordproof_Integration_Toggle
     */
    protected function getWordproofIntegrationToggleService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Third_Party\\Wordproof_Integration_Toggle'] = new \Yoast\WP\SEO\Integrations\Third_Party\Wordproof_Integration_Toggle(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Wordproof_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Wordproof_Helper'] : $this->getWordproofHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Uninstall_Integration' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Uninstall_Integration
     */
    protected function getUninstallIntegrationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Uninstall_Integration'] = new \Yoast\WP\SEO\Integrations\Uninstall_Integration();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Addon_Update_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Addon_Update_Watcher
     */
    protected function getAddonUpdateWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Addon_Update_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Addon_Update_Watcher();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Auto_Update_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Auto_Update_Watcher
     */
    protected function getAutoUpdateWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Auto_Update_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Auto_Update_Watcher(${($_ = isset($this->services['Yoast_Notification_Center']) ? $this->services['Yoast_Notification_Center'] : $this->getYoastNotificationCenterService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_Ancestor_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_Ancestor_Watcher
     */
    protected function getIndexableAncestorWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Ancestor_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_Ancestor_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Hierarchy_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Hierarchy_Builder'] : $this->getIndexableHierarchyBuilderService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Hierarchy_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Hierarchy_Repository'] : $this->getIndexableHierarchyRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['wpdb']) ? $this->services['wpdb'] : $this->getWpdbService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] = new \Yoast\WP\SEO\Helpers\Permalink_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_Attachment_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_Attachment_Watcher
     */
    protected function getIndexableAttachmentWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Attachment_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_Attachment_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper'] : $this->getIndexingHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Attachment_Cleanup_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Attachment_Cleanup_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Attachment_Cleanup_Helper'] = new \Yoast\WP\SEO\Helpers\Attachment_Cleanup_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast_Notification_Center']) ? $this->services['Yoast_Notification_Center'] : $this->getYoastNotificationCenterService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_Author_Archive_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_Author_Archive_Watcher
     */
    protected function getIndexableAuthorArchiveWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Author_Archive_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_Author_Archive_Watcher();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_Author_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_Author_Watcher
     */
    protected function getIndexableAuthorWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Author_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_Author_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'] : $this->getIndexableBuilderService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_Category_Permalink_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_Category_Permalink_Watcher
     */
    protected function getIndexableCategoryPermalinkWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Category_Permalink_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_Category_Permalink_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper'] : $this->getTaxonomyHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_Date_Archive_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_Date_Archive_Watcher
     */
    protected function getIndexableDateArchiveWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Date_Archive_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_Date_Archive_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'] : $this->getIndexableBuilderService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_HomeUrl_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_HomeUrl_Watcher
     */
    protected function getIndexableHomeUrlWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_HomeUrl_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_HomeUrl_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_Home_Page_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_Home_Page_Watcher
     */
    protected function getIndexableHomePageWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Home_Page_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_Home_Page_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'] : $this->getIndexableBuilderService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_Permalink_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_Permalink_Watcher
     */
    protected function getIndexablePermalinkWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Permalink_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_Permalink_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper'] : $this->getTaxonomyHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_Post_Meta_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_Post_Meta_Watcher
     */
    protected function getIndexablePostMetaWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Meta_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_Post_Meta_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Watcher']) ? $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Watcher'] : $this->getIndexablePostWatcherService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_Post_Type_Archive_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_Post_Type_Archive_Watcher
     */
    protected function getIndexablePostTypeArchiveWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Type_Archive_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_Post_Type_Archive_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'] : $this->getIndexableBuilderService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_Post_Type_Change_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_Post_Type_Change_Watcher
     */
    protected function getIndexablePostTypeChangeWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Type_Change_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_Post_Type_Change_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper'] : $this->getIndexingHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast_Notification_Center']) ? $this->services['Yoast_Notification_Center'] : $this->getYoastNotificationCenterService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_Post_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_Post_Watcher
     */
    protected function getIndexablePostWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_Post_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'] : $this->getIndexableBuilderService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Hierarchy_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Hierarchy_Repository'] : $this->getIndexableHierarchyRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Link_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Link_Builder'] : $this->getIndexableLinkBuilderService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Author_Archive_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Author_Archive_Helper'] : $this->getAuthorArchiveHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper'] : $this->getPostHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Loggers\\Logger']) ? $this->services['Yoast\\WP\\SEO\\Loggers\\Logger'] : ($this->services['Yoast\\WP\\SEO\\Loggers\\Logger'] = new \Yoast\WP\SEO\Loggers\Logger())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_Static_Home_Page_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_Static_Home_Page_Watcher
     */
    protected function getIndexableStaticHomePageWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Static_Home_Page_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_Static_Home_Page_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_System_Page_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_System_Page_Watcher
     */
    protected function getIndexableSystemPageWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_System_Page_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_System_Page_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'] : $this->getIndexableBuilderService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_Taxonomy_Change_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_Taxonomy_Change_Watcher
     */
    protected function getIndexableTaxonomyChangeWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Taxonomy_Change_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_Taxonomy_Change_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper'] : $this->getIndexingHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper'] : $this->getTaxonomyHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast_Notification_Center']) ? $this->services['Yoast_Notification_Center'] : $this->getYoastNotificationCenterService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Indexable_Term_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Indexable_Term_Watcher
     */
    protected function getIndexableTermWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Term_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Indexable_Term_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'] : $this->getIndexableBuilderService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Link_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Link_Builder'] : $this->getIndexableLinkBuilderService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Site_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Site_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Site_Helper'] = new \Yoast\WP\SEO\Helpers\Site_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Option_Titles_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Option_Titles_Watcher
     */
    protected function getOptionTitlesWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Option_Titles_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Option_Titles_Watcher();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Option_Wpseo_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Option_Wpseo_Watcher
     */
    protected function getOptionWpseoWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Option_Wpseo_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Option_Wpseo_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Wordproof_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Wordproof_Helper'] : $this->getWordproofHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Primary_Category_Quick_Edit_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Primary_Category_Quick_Edit_Watcher
     */
    protected function getPrimaryCategoryQuickEditWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Primary_Category_Quick_Edit_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Primary_Category_Quick_Edit_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Primary_Term_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Primary_Term_Repository'] : ($this->services['Yoast\\WP\\SEO\\Repositories\\Primary_Term_Repository'] = new \Yoast\WP\SEO\Repositories\Primary_Term_Repository())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Hierarchy_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Hierarchy_Builder'] : $this->getIndexableHierarchyBuilderService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Primary_Term_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Primary_Term_Watcher
     */
    protected function getPrimaryTermWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Primary_Term_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Primary_Term_Watcher(${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Primary_Term_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Primary_Term_Repository'] : ($this->services['Yoast\\WP\\SEO\\Repositories\\Primary_Term_Repository'] = new \Yoast\WP\SEO\Repositories\Primary_Term_Repository())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Site_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Site_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Site_Helper'] = new \Yoast\WP\SEO\Helpers\Site_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Primary_Term_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Primary_Term_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Primary_Term_Helper'] = new \Yoast\WP\SEO\Helpers\Primary_Term_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Primary_Term_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Primary_Term_Builder'] : $this->getPrimaryTermBuilderService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\Watchers\Search_Engines_Discouraged_Watcher' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\Watchers\Search_Engines_Discouraged_Watcher
     */
    protected function getSearchEnginesDiscouragedWatcherService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\Watchers\\Search_Engines_Discouraged_Watcher'] = new \Yoast\WP\SEO\Integrations\Watchers\Search_Engines_Discouraged_Watcher(${($_ = isset($this->services['Yoast_Notification_Center']) ? $this->services['Yoast_Notification_Center'] : $this->getYoastNotificationCenterService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Notification_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Notification_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Notification_Helper'] = new \Yoast\WP\SEO\Helpers\Notification_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Capability_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Capability_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Capability_Helper'] = new \Yoast\WP\SEO\Helpers\Capability_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Integrations\XMLRPC' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Integrations\XMLRPC
     */
    protected function getXMLRPCService()
    {
        return $this->services['Yoast\\WP\\SEO\\Integrations\\XMLRPC'] = new \Yoast\WP\SEO\Integrations\XMLRPC();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Loader' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Loader
     */
    protected function getLoaderService()
    {
        $this->services['Yoast\\WP\\SEO\\Loader'] = $instance = new \Yoast\WP\SEO\Loader($this);

        $instance->register_command('Yoast\\WP\\SEO\\Commands\\Cleanup_Command');
        $instance->register_command('Yoast\\WP\\SEO\\Commands\\Index_Command');
        $instance->register_migration('free', '20171228151840', 'Yoast\\WP\\SEO\\Config\\Migrations\\WpYoastIndexable');
        $instance->register_migration('free', '20171228151841', 'Yoast\\WP\\SEO\\Config\\Migrations\\WpYoastPrimaryTerm');
        $instance->register_migration('free', '20190529075038', 'Yoast\\WP\\SEO\\Config\\Migrations\\WpYoastDropIndexableMetaTableIfExists');
        $instance->register_migration('free', '20191011111109', 'Yoast\\WP\\SEO\\Config\\Migrations\\WpYoastIndexableHierarchy');
        $instance->register_migration('free', '20200408101900', 'Yoast\\WP\\SEO\\Config\\Migrations\\AddCollationToTables');
        $instance->register_migration('free', '20200420073606', 'Yoast\\WP\\SEO\\Config\\Migrations\\AddColumnsToIndexables');
        $instance->register_migration('free', '20200428123747', 'Yoast\\WP\\SEO\\Config\\Migrations\\BreadcrumbTitleAndHierarchyReset');
        $instance->register_migration('free', '20200428194858', 'Yoast\\WP\\SEO\\Config\\Migrations\\ExpandIndexableColumnLengths');
        $instance->register_migration('free', '20200429105310', 'Yoast\\WP\\SEO\\Config\\Migrations\\TruncateIndexableTables');
        $instance->register_migration('free', '20200430075614', 'Yoast\\WP\\SEO\\Config\\Migrations\\AddIndexableObjectIdAndTypeIndex');
        $instance->register_migration('free', '20200430150130', 'Yoast\\WP\\SEO\\Config\\Migrations\\ClearIndexableTables');
        $instance->register_migration('free', '20200507054848', 'Yoast\\WP\\SEO\\Config\\Migrations\\DeleteDuplicateIndexables');
        $instance->register_migration('free', '20200513133401', 'Yoast\\WP\\SEO\\Config\\Migrations\\ResetIndexableHierarchyTable');
        $instance->register_migration('free', '20200609154515', 'Yoast\\WP\\SEO\\Config\\Migrations\\AddHasAncestorsColumn');
        $instance->register_migration('free', '20200616130143', 'Yoast\\WP\\SEO\\Config\\Migrations\\ReplacePermalinkHashIndex');
        $instance->register_migration('free', '20200617122511', 'Yoast\\WP\\SEO\\Config\\Migrations\\CreateSEOLinksTable');
        $instance->register_migration('free', '20200702141921', 'Yoast\\WP\\SEO\\Config\\Migrations\\CreateIndexableSubpagesIndex');
        $instance->register_migration('free', '20200728095334', 'Yoast\\WP\\SEO\\Config\\Migrations\\AddIndexesForProminentWordsOnIndexables');
        $instance->register_migration('free', '20201202144329', 'Yoast\\WP\\SEO\\Config\\Migrations\\AddEstimatedReadingTime');
        $instance->register_migration('free', '20201216124002', 'Yoast\\WP\\SEO\\Config\\Migrations\\ExpandIndexableIDColumnLengths');
        $instance->register_migration('free', '20201216141134', 'Yoast\\WP\\SEO\\Config\\Migrations\\ExpandPrimaryTermIDColumnLengths');
        $instance->register_migration('free', '20210817092415', 'Yoast\\WP\\SEO\\Config\\Migrations\\AddVersionColumnToIndexables');
        $instance->register_migration('free', '20211020091404', 'Yoast\\WP\\SEO\\Config\\Migrations\\AddObjectTimestamps');
        $instance->register_initializer('Yoast\\WP\\SEO\\Initializers\\Crawl_Cleanup_Permalinks');
        $instance->register_initializer('Yoast\\WP\\SEO\\Initializers\\Disable_Core_Sitemaps');
        $instance->register_initializer('Yoast\\WP\\SEO\\Initializers\\Migration_Runner');
        $instance->register_initializer('Yoast\\WP\\SEO\\Initializers\\Woocommerce');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Activation_Cleanup_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Addon_Installation\\Dialog_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Addon_Installation\\Installation_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Admin_Columns_Cache_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Background_Indexing_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Crawl_Settings_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Cron_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Deactivated_Premium_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Disable_Concatenate_Scripts_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\First_Time_Configuration_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\First_Time_Configuration_Notice_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Fix_News_Dependencies_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Health_Check_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\HelpScout_Beacon');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Import_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Indexables_Exclude_Taxonomy_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Indexing_Notification_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Indexing_Tool_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Installation_Success_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Integrations_Page');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Link_Count_Columns_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Menu_Badge_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Migration_Error_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Old_Configuration_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Old_Premium_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Redirect_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Redirects_Page_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Admin\\Workouts_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Alerts\\Jetpack_Boost_Pre_Publish');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Alerts\\Webinar_Promo_Notification');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Blocks\\Internal_Linking_Category');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Blocks\\Breadcrumbs_Block');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Blocks\\Structured_Data_Blocks');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Breadcrumbs_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Cleanup_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Duplicate_Post_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Estimated_Reading_Time');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Exclude_Attachment_Post_Type');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Exclude_Oembed_Cache_Post_Type');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Feature_Flag_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End\\Backwards_Compatibility');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End\\Category_Term_Description');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End\\Comment_Link_Fixer');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End\\Crawl_Cleanup_Basic');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End\\Crawl_Cleanup_Rss');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End\\Crawl_Cleanup_Searches');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End\\Feed_Improvements');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End\\Force_Rewrite_Title');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End\\Handle_404');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End\\Indexing_Controls');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End\\Open_Graph_OEmbed');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End\\Redirects');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End\\Robots_Txt_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End\\RSS_Footer_Embed');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End\\Schema_Accessibility_Feature');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Front_End\\WP_Robots_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Primary_Category');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Settings_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\AMP');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\BbPress');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\Elementor');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\Exclude_Elementor_Post_Types');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\Exclude_WooCommerce_Post_Types');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\Jetpack');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\W3_Total_Cache');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\Web_Stories_Post_Edit');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\Web_Stories');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\Wincher_Publish');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\Wincher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\Woocommerce_Permalinks');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\WooCommerce_Post_Edit');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\WooCommerce');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\Wordproof_Integration_Toggle');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\Wordproof');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\WPML_WPSEO_Notification');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Third_Party\\WPML');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Uninstall_Integration');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Addon_Update_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Auto_Update_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Ancestor_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Attachment_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Author_Archive_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Author_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Category_Permalink_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Date_Archive_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Home_Page_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_HomeUrl_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Permalink_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Meta_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Type_Archive_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Type_Change_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Post_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Static_Home_Page_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_System_Page_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Taxonomy_Change_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Indexable_Term_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Option_Titles_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Option_Wpseo_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Primary_Category_Quick_Edit_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Primary_Term_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\Watchers\\Search_Engines_Discouraged_Watcher');
        $instance->register_integration('Yoast\\WP\\SEO\\Integrations\\XMLRPC');
        $instance->register_route('Yoast\\WP\\SEO\\Routes\\Alert_Dismissal_Route');
        $instance->register_route('Yoast\\WP\\SEO\\Routes\\First_Time_Configuration_Route');
        $instance->register_route('Yoast\\WP\\SEO\\Routes\\Importing_Route');
        $instance->register_route('Yoast\\WP\\SEO\\Routes\\Indexables_Head_Route');
        $instance->register_route('Yoast\\WP\\SEO\\Routes\\Indexing_Route');
        $instance->register_route('Yoast\\WP\\SEO\\Routes\\Integrations_Route');
        $instance->register_route('Yoast\\WP\\SEO\\Routes\\Meta_Search_Route');
        $instance->register_route('Yoast\\WP\\SEO\\Routes\\SEMrush_Route');
        $instance->register_route('Yoast\\WP\\SEO\\Routes\\Settings_Introduction_Route');
        $instance->register_route('Yoast\\WP\\SEO\\Routes\\Supported_Features_Route');
        $instance->register_route('Yoast\\WP\\SEO\\Routes\\Wincher_Route');
        $instance->register_route('Yoast\\WP\\SEO\\Routes\\Workouts_Route');
        $instance->register_route('Yoast\\WP\\SEO\\Routes\\Yoast_Head_REST_Field');

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Loggers\Logger' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Loggers\Logger
     */
    protected function getLoggerService()
    {
        return $this->services['Yoast\\WP\\SEO\\Loggers\\Logger'] = new \Yoast\WP\SEO\Loggers\Logger();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Memoizers\Meta_Tags_Context_Memoizer' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Memoizers\Meta_Tags_Context_Memoizer
     */
    protected function getMetaTagsContextMemoizerService()
    {
        return $this->services['Yoast\\WP\\SEO\\Memoizers\\Meta_Tags_Context_Memoizer'] = new \Yoast\WP\SEO\Memoizers\Meta_Tags_Context_Memoizer(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Blocks_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Blocks_Helper'] : $this->getBlocksHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Context\\Meta_Tags_Context']) ? $this->services['Yoast\\WP\\SEO\\Context\\Meta_Tags_Context'] : $this->getMetaTagsContextService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Memoizers\\Presentation_Memoizer']) ? $this->services['Yoast\\WP\\SEO\\Memoizers\\Presentation_Memoizer'] : ($this->services['Yoast\\WP\\SEO\\Memoizers\\Presentation_Memoizer'] = new \Yoast\WP\SEO\Memoizers\Presentation_Memoizer($this))) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Memoizers\Presentation_Memoizer' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Memoizers\Presentation_Memoizer
     */
    protected function getPresentationMemoizerService()
    {
        return $this->services['Yoast\\WP\\SEO\\Memoizers\\Presentation_Memoizer'] = new \Yoast\WP\SEO\Memoizers\Presentation_Memoizer($this);
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Presentations\Abstract_Presentation' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Presentations\Abstract_Presentation
     */
    protected function getAbstractPresentationService()
    {
        return $this->services['Yoast\\WP\\SEO\\Presentations\\Abstract_Presentation'] = new \Yoast\WP\SEO\Presentations\Abstract_Presentation();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Presentations\Indexable_Author_Archive_Presentation' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Presentations\Indexable_Author_Archive_Presentation
     */
    protected function getIndexableAuthorArchivePresentationService()
    {
        $this->services['Yoast\\WP\\SEO\\Presentations\\Indexable_Author_Archive_Presentation'] = $instance = new \Yoast\WP\SEO\Presentations\Indexable_Author_Archive_Presentation(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Author_Archive_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Author_Archive_Helper'] : $this->getAuthorArchiveHelperService()) && false ?: '_'});

        $instance->set_generators(${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator'] : $this->getSchemaGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] : ($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] = new \Yoast\WP\SEO\Generators\Open_Graph_Locale_Generator())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator'] : $this->getOpenGraphImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator'] : $this->getTwitterImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator'] : $this->getBreadcrumbsGeneratorService()) && false ?: '_'});
        $instance->set_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] = new \Yoast\WP\SEO\Helpers\User_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] = new \Yoast\WP\SEO\Helpers\Permalink_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] = new \Yoast\WP\SEO\Helpers\Open_Graph\Values_Helper())) && false ?: '_'});
        $instance->set_archive_adjacent_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper'] : $this->getPaginationHelperService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Presentations\Indexable_Date_Archive_Presentation' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Presentations\Indexable_Date_Archive_Presentation
     */
    protected function getIndexableDateArchivePresentationService()
    {
        $this->services['Yoast\\WP\\SEO\\Presentations\\Indexable_Date_Archive_Presentation'] = $instance = new \Yoast\WP\SEO\Presentations\Indexable_Date_Archive_Presentation(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper'] : $this->getPaginationHelperService()) && false ?: '_'});

        $instance->set_generators(${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator'] : $this->getSchemaGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] : ($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] = new \Yoast\WP\SEO\Generators\Open_Graph_Locale_Generator())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator'] : $this->getOpenGraphImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator'] : $this->getTwitterImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator'] : $this->getBreadcrumbsGeneratorService()) && false ?: '_'});
        $instance->set_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] = new \Yoast\WP\SEO\Helpers\User_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] = new \Yoast\WP\SEO\Helpers\Permalink_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] = new \Yoast\WP\SEO\Helpers\Open_Graph\Values_Helper())) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Presentations\Indexable_Error_Page_Presentation' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Presentations\Indexable_Error_Page_Presentation
     */
    protected function getIndexableErrorPagePresentationService()
    {
        $this->services['Yoast\\WP\\SEO\\Presentations\\Indexable_Error_Page_Presentation'] = $instance = new \Yoast\WP\SEO\Presentations\Indexable_Error_Page_Presentation();

        $instance->set_generators(${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator'] : $this->getSchemaGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] : ($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] = new \Yoast\WP\SEO\Generators\Open_Graph_Locale_Generator())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator'] : $this->getOpenGraphImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator'] : $this->getTwitterImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator'] : $this->getBreadcrumbsGeneratorService()) && false ?: '_'});
        $instance->set_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] = new \Yoast\WP\SEO\Helpers\User_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] = new \Yoast\WP\SEO\Helpers\Permalink_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] = new \Yoast\WP\SEO\Helpers\Open_Graph\Values_Helper())) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Presentations\Indexable_Home_Page_Presentation' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Presentations\Indexable_Home_Page_Presentation
     */
    protected function getIndexableHomePagePresentationService()
    {
        $this->services['Yoast\\WP\\SEO\\Presentations\\Indexable_Home_Page_Presentation'] = $instance = new \Yoast\WP\SEO\Presentations\Indexable_Home_Page_Presentation();

        $instance->set_generators(${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator'] : $this->getSchemaGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] : ($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] = new \Yoast\WP\SEO\Generators\Open_Graph_Locale_Generator())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator'] : $this->getOpenGraphImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator'] : $this->getTwitterImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator'] : $this->getBreadcrumbsGeneratorService()) && false ?: '_'});
        $instance->set_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] = new \Yoast\WP\SEO\Helpers\User_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] = new \Yoast\WP\SEO\Helpers\Permalink_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] = new \Yoast\WP\SEO\Helpers\Open_Graph\Values_Helper())) && false ?: '_'});
        $instance->set_archive_adjacent_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper'] : $this->getPaginationHelperService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Presentations\Indexable_Post_Type_Archive_Presentation' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Presentations\Indexable_Post_Type_Archive_Presentation
     */
    protected function getIndexablePostTypeArchivePresentationService()
    {
        $this->services['Yoast\\WP\\SEO\\Presentations\\Indexable_Post_Type_Archive_Presentation'] = $instance = new \Yoast\WP\SEO\Presentations\Indexable_Post_Type_Archive_Presentation();

        $instance->set_generators(${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator'] : $this->getSchemaGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] : ($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] = new \Yoast\WP\SEO\Generators\Open_Graph_Locale_Generator())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator'] : $this->getOpenGraphImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator'] : $this->getTwitterImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator'] : $this->getBreadcrumbsGeneratorService()) && false ?: '_'});
        $instance->set_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] = new \Yoast\WP\SEO\Helpers\User_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] = new \Yoast\WP\SEO\Helpers\Permalink_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] = new \Yoast\WP\SEO\Helpers\Open_Graph\Values_Helper())) && false ?: '_'});
        $instance->set_archive_adjacent_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper'] : $this->getPaginationHelperService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Presentations\Indexable_Post_Type_Presentation' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Presentations\Indexable_Post_Type_Presentation
     */
    protected function getIndexablePostTypePresentationService()
    {
        $this->services['Yoast\\WP\\SEO\\Presentations\\Indexable_Post_Type_Presentation'] = $instance = new \Yoast\WP\SEO\Presentations\Indexable_Post_Type_Presentation(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper'] = new \Yoast\WP\SEO\Helpers\Date_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper'] : $this->getPaginationHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper'] : $this->getPostHelperService()) && false ?: '_'});

        $instance->set_generators(${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator'] : $this->getSchemaGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] : ($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] = new \Yoast\WP\SEO\Generators\Open_Graph_Locale_Generator())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator'] : $this->getOpenGraphImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator'] : $this->getTwitterImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator'] : $this->getBreadcrumbsGeneratorService()) && false ?: '_'});
        $instance->set_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] = new \Yoast\WP\SEO\Helpers\User_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] = new \Yoast\WP\SEO\Helpers\Permalink_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] = new \Yoast\WP\SEO\Helpers\Open_Graph\Values_Helper())) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Presentations\Indexable_Presentation' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Presentations\Indexable_Presentation
     */
    protected function getIndexablePresentationService()
    {
        $this->services['Yoast\\WP\\SEO\\Presentations\\Indexable_Presentation'] = $instance = new \Yoast\WP\SEO\Presentations\Indexable_Presentation();

        $instance->set_generators(${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator'] : $this->getSchemaGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] : ($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] = new \Yoast\WP\SEO\Generators\Open_Graph_Locale_Generator())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator'] : $this->getOpenGraphImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator'] : $this->getTwitterImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator'] : $this->getBreadcrumbsGeneratorService()) && false ?: '_'});
        $instance->set_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] = new \Yoast\WP\SEO\Helpers\User_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] = new \Yoast\WP\SEO\Helpers\Permalink_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] = new \Yoast\WP\SEO\Helpers\Open_Graph\Values_Helper())) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Presentations\Indexable_Search_Result_Page_Presentation' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Presentations\Indexable_Search_Result_Page_Presentation
     */
    protected function getIndexableSearchResultPagePresentationService()
    {
        $this->services['Yoast\\WP\\SEO\\Presentations\\Indexable_Search_Result_Page_Presentation'] = $instance = new \Yoast\WP\SEO\Presentations\Indexable_Search_Result_Page_Presentation();

        $instance->set_generators(${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator'] : $this->getSchemaGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] : ($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] = new \Yoast\WP\SEO\Generators\Open_Graph_Locale_Generator())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator'] : $this->getOpenGraphImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator'] : $this->getTwitterImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator'] : $this->getBreadcrumbsGeneratorService()) && false ?: '_'});
        $instance->set_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] = new \Yoast\WP\SEO\Helpers\User_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] = new \Yoast\WP\SEO\Helpers\Permalink_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] = new \Yoast\WP\SEO\Helpers\Open_Graph\Values_Helper())) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Presentations\Indexable_Static_Home_Page_Presentation' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Presentations\Indexable_Static_Home_Page_Presentation
     */
    protected function getIndexableStaticHomePagePresentationService()
    {
        $this->services['Yoast\\WP\\SEO\\Presentations\\Indexable_Static_Home_Page_Presentation'] = $instance = new \Yoast\WP\SEO\Presentations\Indexable_Static_Home_Page_Presentation(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper'] = new \Yoast\WP\SEO\Helpers\Date_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper'] : $this->getPaginationHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper'] : $this->getPostHelperService()) && false ?: '_'});

        $instance->set_generators(${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator'] : $this->getSchemaGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] : ($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] = new \Yoast\WP\SEO\Generators\Open_Graph_Locale_Generator())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator'] : $this->getOpenGraphImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator'] : $this->getTwitterImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator'] : $this->getBreadcrumbsGeneratorService()) && false ?: '_'});
        $instance->set_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] = new \Yoast\WP\SEO\Helpers\User_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] = new \Yoast\WP\SEO\Helpers\Permalink_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] = new \Yoast\WP\SEO\Helpers\Open_Graph\Values_Helper())) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Presentations\Indexable_Static_Posts_Page_Presentation' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Presentations\Indexable_Static_Posts_Page_Presentation
     */
    protected function getIndexableStaticPostsPagePresentationService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper'] : $this->getPaginationHelperService()) && false ?: '_'};

        $this->services['Yoast\\WP\\SEO\\Presentations\\Indexable_Static_Posts_Page_Presentation'] = $instance = new \Yoast\WP\SEO\Presentations\Indexable_Static_Posts_Page_Presentation(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Date_Helper'] = new \Yoast\WP\SEO\Helpers\Date_Helper())) && false ?: '_'}, $a, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper'] : $this->getPostHelperService()) && false ?: '_'});

        $instance->set_generators(${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator'] : $this->getSchemaGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] : ($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] = new \Yoast\WP\SEO\Generators\Open_Graph_Locale_Generator())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator'] : $this->getOpenGraphImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator'] : $this->getTwitterImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator'] : $this->getBreadcrumbsGeneratorService()) && false ?: '_'});
        $instance->set_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] = new \Yoast\WP\SEO\Helpers\User_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] = new \Yoast\WP\SEO\Helpers\Permalink_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] = new \Yoast\WP\SEO\Helpers\Open_Graph\Values_Helper())) && false ?: '_'});
        $instance->set_archive_adjacent_helpers($a);

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Presentations\Indexable_Term_Archive_Presentation' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Presentations\Indexable_Term_Archive_Presentation
     */
    protected function getIndexableTermArchivePresentationService()
    {
        $this->services['Yoast\\WP\\SEO\\Presentations\\Indexable_Term_Archive_Presentation'] = $instance = new \Yoast\WP\SEO\Presentations\Indexable_Term_Archive_Presentation(${($_ = isset($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper']) ? $this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper'] : ($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper'] = new \Yoast\WP\SEO\Wrappers\WP_Query_Wrapper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper'] : $this->getTaxonomyHelperService()) && false ?: '_'});

        $instance->set_generators(${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Schema_Generator'] : $this->getSchemaGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] : ($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Locale_Generator'] = new \Yoast\WP\SEO\Generators\Open_Graph_Locale_Generator())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Open_Graph_Image_Generator'] : $this->getOpenGraphImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Twitter_Image_Generator'] : $this->getTwitterImageGeneratorService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator']) ? $this->services['Yoast\\WP\\SEO\\Generators\\Breadcrumbs_Generator'] : $this->getBreadcrumbsGeneratorService()) && false ?: '_'});
        $instance->set_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\User_Helper'] = new \Yoast\WP\SEO\Helpers\User_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Permalink_Helper'] = new \Yoast\WP\SEO\Helpers\Permalink_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Values_Helper'] = new \Yoast\WP\SEO\Helpers\Open_Graph\Values_Helper())) && false ?: '_'});
        $instance->set_archive_adjacent_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Pagination_Helper'] : $this->getPaginationHelperService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Repositories\Indexable_Hierarchy_Repository' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Repositories\Indexable_Hierarchy_Repository
     */
    protected function getIndexableHierarchyRepositoryService()
    {
        $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Hierarchy_Repository'] = $instance = new \Yoast\WP\SEO\Repositories\Indexable_Hierarchy_Repository();

        $instance->set_builder(${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Hierarchy_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Hierarchy_Builder'] : $this->getIndexableHierarchyBuilderService()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Repositories\Indexable_Repository' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Repositories\Indexable_Repository
     */
    protected function getIndexableRepositoryService()
    {
        $a = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder']) ? $this->services['Yoast\\WP\\SEO\\Builders\\Indexable_Builder'] : $this->getIndexableBuilderService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'])) {
            return $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'];
        }
        $b = ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Hierarchy_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Hierarchy_Repository'] : $this->getIndexableHierarchyRepositoryService()) && false ?: '_'};

        if (isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'])) {
            return $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'];
        }

        return $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] = new \Yoast\WP\SEO\Repositories\Indexable_Repository($a, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Current_Page_Helper'] : $this->getCurrentPageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Loggers\\Logger']) ? $this->services['Yoast\\WP\\SEO\\Loggers\\Logger'] : ($this->services['Yoast\\WP\\SEO\\Loggers\\Logger'] = new \Yoast\WP\SEO\Loggers\Logger())) && false ?: '_'}, $b, ${($_ = isset($this->services['wpdb']) ? $this->services['wpdb'] : $this->getWpdbService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Indexables\\Indexable_Version_Manager']) ? $this->services['Yoast\\WP\\SEO\\Services\\Indexables\\Indexable_Version_Manager'] : $this->getIndexableVersionManagerService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Repositories\Primary_Term_Repository' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Repositories\Primary_Term_Repository
     */
    protected function getPrimaryTermRepositoryService()
    {
        return $this->services['Yoast\\WP\\SEO\\Repositories\\Primary_Term_Repository'] = new \Yoast\WP\SEO\Repositories\Primary_Term_Repository();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Repositories\SEO_Links_Repository' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Repositories\SEO_Links_Repository
     */
    protected function getSEOLinksRepositoryService()
    {
        return $this->services['Yoast\\WP\\SEO\\Repositories\\SEO_Links_Repository'] = new \Yoast\WP\SEO\Repositories\SEO_Links_Repository();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Routes\Alert_Dismissal_Route' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Routes\Alert_Dismissal_Route
     */
    protected function getAlertDismissalRouteService()
    {
        return $this->services['Yoast\\WP\\SEO\\Routes\\Alert_Dismissal_Route'] = new \Yoast\WP\SEO\Routes\Alert_Dismissal_Route(${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Alert_Dismissal_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Alert_Dismissal_Action'] : $this->getAlertDismissalActionService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Routes\First_Time_Configuration_Route' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Routes\First_Time_Configuration_Route
     */
    protected function getFirstTimeConfigurationRouteService()
    {
        return $this->services['Yoast\\WP\\SEO\\Routes\\First_Time_Configuration_Route'] = new \Yoast\WP\SEO\Routes\First_Time_Configuration_Route(${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Configuration\\First_Time_Configuration_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Configuration\\First_Time_Configuration_Action'] : $this->getFirstTimeConfigurationActionService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Routes\Importing_Route' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Routes\Importing_Route
     */
    protected function getImportingRouteService()
    {
        return $this->services['Yoast\\WP\\SEO\\Routes\\Importing_Route'] = new \Yoast\WP\SEO\Routes\Importing_Route(${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Importable_Detector_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Importable_Detector_Service'] : $this->getImportableDetectorServiceService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Cleanup_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Cleanup_Action'] : $this->getAioseoCleanupActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Custom_Archive_Settings_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Custom_Archive_Settings_Importing_Action'] : $this->getAioseoCustomArchiveSettingsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Default_Archive_Settings_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Default_Archive_Settings_Importing_Action'] : $this->getAioseoDefaultArchiveSettingsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_General_Settings_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_General_Settings_Importing_Action'] : $this->getAioseoGeneralSettingsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posts_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posts_Importing_Action'] : $this->getAioseoPostsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posttype_Defaults_Settings_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posttype_Defaults_Settings_Importing_Action'] : $this->getAioseoPosttypeDefaultsSettingsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Taxonomy_Settings_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Taxonomy_Settings_Importing_Action'] : $this->getAioseoTaxonomySettingsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Validate_Data_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Validate_Data_Action'] : $this->getAioseoValidateDataActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Deactivate_Conflicting_Plugins_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Deactivate_Conflicting_Plugins_Action'] : $this->getDeactivateConflictingPluginsActionService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Routes\Indexables_Head_Route' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Routes\Indexables_Head_Route
     */
    protected function getIndexablesHeadRouteService()
    {
        return $this->services['Yoast\\WP\\SEO\\Routes\\Indexables_Head_Route'] = new \Yoast\WP\SEO\Routes\Indexables_Head_Route(${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexables\\Indexable_Head_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexables\\Indexable_Head_Action'] : $this->getIndexableHeadActionService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Routes\Indexables_Page_Route' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Routes\Indexables_Page_Route
     *
     * @deprecated Yoast\WP\SEO\Routes\Indexables_Page_Route is deprecated since version 20.4!
     */
    protected function getIndexablesPageRouteService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Routes\\Indexables_Page_Route is deprecated since version 20.4!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Routes\\Indexables_Page_Route'] = new \Yoast\WP\SEO\Routes\Indexables_Page_Route(${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexables_Page_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexables_Page_Action'] : $this->getIndexablesPageActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexables_Page_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexables_Page_Helper'] : $this->getIndexablesPageHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Routes\Indexing_Route' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Routes\Indexing_Route
     */
    protected function getIndexingRouteService()
    {
        return $this->services['Yoast\\WP\\SEO\\Routes\\Indexing_Route'] = new \Yoast\WP\SEO\Routes\Indexing_Route(${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Indexation_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Indexation_Action'] : $this->getIndexablePostIndexationActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Term_Indexation_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Term_Indexation_Action'] : $this->getIndexableTermIndexationActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Type_Archive_Indexation_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Post_Type_Archive_Indexation_Action'] : $this->getIndexablePostTypeArchiveIndexationActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_General_Indexation_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_General_Indexation_Action'] : $this->getIndexableGeneralIndexationActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Indexing_Complete_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexable_Indexing_Complete_Action'] : $this->getIndexableIndexingCompleteActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexing_Complete_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexing_Complete_Action'] : $this->getIndexingCompleteActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexing_Prepare_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Indexing_Prepare_Action'] : $this->getIndexingPrepareActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Post_Link_Indexing_Action'] : $this->getPostLinkIndexingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Term_Link_Indexing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexing\\Term_Link_Indexing_Action'] : $this->getTermLinkIndexingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexing_Helper'] : $this->getIndexingHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Routes\Integrations_Route' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Routes\Integrations_Route
     */
    protected function getIntegrationsRouteService()
    {
        return $this->services['Yoast\\WP\\SEO\\Routes\\Integrations_Route'] = new \Yoast\WP\SEO\Routes\Integrations_Route(${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Integrations_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Integrations_Action'] : $this->getIntegrationsActionService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Routes\Meta_Search_Route' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Routes\Meta_Search_Route
     */
    protected function getMetaSearchRouteService()
    {
        return $this->services['Yoast\\WP\\SEO\\Routes\\Meta_Search_Route'] = new \Yoast\WP\SEO\Routes\Meta_Search_Route();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Routes\SEMrush_Route' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Routes\SEMrush_Route
     */
    protected function getSEMrushRouteService()
    {
        return $this->services['Yoast\\WP\\SEO\\Routes\\SEMrush_Route'] = new \Yoast\WP\SEO\Routes\SEMrush_Route(${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\SEMrush\\SEMrush_Login_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\SEMrush\\SEMrush_Login_Action'] : $this->getSEMrushLoginActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\SEMrush\\SEMrush_Options_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\SEMrush\\SEMrush_Options_Action'] : $this->getSEMrushOptionsActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\SEMrush\\SEMrush_Phrases_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\SEMrush\\SEMrush_Phrases_Action'] : $this->getSEMrushPhrasesActionService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Routes\Settings_Introduction_Route' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Routes\Settings_Introduction_Route
     */
    protected function getSettingsIntroductionRouteService()
    {
        return $this->services['Yoast\\WP\\SEO\\Routes\\Settings_Introduction_Route'] = new \Yoast\WP\SEO\Routes\Settings_Introduction_Route(${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Settings_Introduction_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Settings_Introduction_Action'] : $this->getSettingsIntroductionActionService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Routes\Supported_Features_Route' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Routes\Supported_Features_Route
     */
    protected function getSupportedFeaturesRouteService()
    {
        return $this->services['Yoast\\WP\\SEO\\Routes\\Supported_Features_Route'] = new \Yoast\WP\SEO\Routes\Supported_Features_Route();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Routes\Wincher_Route' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Routes\Wincher_Route
     */
    protected function getWincherRouteService()
    {
        return $this->services['Yoast\\WP\\SEO\\Routes\\Wincher_Route'] = new \Yoast\WP\SEO\Routes\Wincher_Route(${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Login_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Login_Action'] : $this->getWincherLoginActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Account_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Account_Action'] : $this->getWincherAccountActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Keyphrases_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Wincher\\Wincher_Keyphrases_Action'] : $this->getWincherKeyphrasesActionService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Routes\Workouts_Route' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Routes\Workouts_Route
     */
    protected function getWorkoutsRouteService()
    {
        return $this->services['Yoast\\WP\\SEO\\Routes\\Workouts_Route'] = new \Yoast\WP\SEO\Routes\Workouts_Route(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Routes\Yoast_Head_REST_Field' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Routes\Yoast_Head_REST_Field
     */
    protected function getYoastHeadRESTFieldService()
    {
        return $this->services['Yoast\\WP\\SEO\\Routes\\Yoast_Head_REST_Field'] = new \Yoast\WP\SEO\Routes\Yoast_Head_REST_Field(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Type_Helper'] : $this->getPostTypeHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Taxonomy_Helper'] : $this->getTaxonomyHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Post_Helper'] : $this->getPostHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Indexables\\Indexable_Head_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Indexables\\Indexable_Head_Action'] : $this->getIndexableHeadActionService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Schema_Templates\Assets\Icons' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Schema_Templates\Assets\Icons
     *
     * @deprecated Yoast\WP\SEO\Schema_Templates\Assets\Icons is deprecated since version 20.5!
     */
    protected function getIconsService()
    {
        @trigger_error('Yoast\\WP\\SEO\\Schema_Templates\\Assets\\Icons is deprecated since version 20.5!', E_USER_DEPRECATED);

        return $this->services['Yoast\\WP\\SEO\\Schema_Templates\\Assets\\Icons'] = new \Yoast\WP\SEO\Schema_Templates\Assets\Icons();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Health_Check\Default_Tagline_Check' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Health_Check\Default_Tagline_Check
     */
    protected function getDefaultTaglineCheckService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Default_Tagline_Check'] = new \Yoast\WP\SEO\Services\Health_Check\Default_Tagline_Check(${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Default_Tagline_Runner']) ? $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Default_Tagline_Runner'] : ($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Default_Tagline_Runner'] = new \Yoast\WP\SEO\Services\Health_Check\Default_Tagline_Runner())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Default_Tagline_Reports']) ? $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Default_Tagline_Reports'] : $this->getDefaultTaglineReportsService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Health_Check\Default_Tagline_Reports' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Health_Check\Default_Tagline_Reports
     */
    protected function getDefaultTaglineReportsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Default_Tagline_Reports'] = new \Yoast\WP\SEO\Services\Health_Check\Default_Tagline_Reports(${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder_Factory']) ? $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder_Factory'] : ($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder_Factory'] = new \Yoast\WP\SEO\Services\Health_Check\Report_Builder_Factory())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Health_Check\Default_Tagline_Runner' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Health_Check\Default_Tagline_Runner
     */
    protected function getDefaultTaglineRunnerService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Default_Tagline_Runner'] = new \Yoast\WP\SEO\Services\Health_Check\Default_Tagline_Runner();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Health_Check\Links_Table_Check' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Health_Check\Links_Table_Check
     */
    protected function getLinksTableCheckService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Links_Table_Check'] = new \Yoast\WP\SEO\Services\Health_Check\Links_Table_Check(${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Links_Table_Runner']) ? $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Links_Table_Runner'] : $this->getLinksTableRunnerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Links_Table_Reports']) ? $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Links_Table_Reports'] : $this->getLinksTableReportsService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Health_Check\Links_Table_Reports' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Health_Check\Links_Table_Reports
     */
    protected function getLinksTableReportsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Links_Table_Reports'] = new \Yoast\WP\SEO\Services\Health_Check\Links_Table_Reports(${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder_Factory']) ? $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder_Factory'] : ($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder_Factory'] = new \Yoast\WP\SEO\Services\Health_Check\Report_Builder_Factory())) && false ?: '_'}, ${($_ = isset($this->services['WPSEO_Shortlinker']) ? $this->services['WPSEO_Shortlinker'] : $this->getWPSEOShortlinkerService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Health_Check\Links_Table_Runner' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Health_Check\Links_Table_Runner
     */
    protected function getLinksTableRunnerService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Links_Table_Runner'] = new \Yoast\WP\SEO\Services\Health_Check\Links_Table_Runner(${($_ = isset($this->services['Yoast\\WP\\SEO\\Config\\Migration_Status']) ? $this->services['Yoast\\WP\\SEO\\Config\\Migration_Status'] : ($this->services['Yoast\\WP\\SEO\\Config\\Migration_Status'] = new \Yoast\WP\SEO\Config\Migration_Status())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Options_Helper'] = new \Yoast\WP\SEO\Helpers\Options_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Health_Check\MyYoast_Api_Request_Factory' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Health_Check\MyYoast_Api_Request_Factory
     */
    protected function getMyYoastApiRequestFactoryService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\MyYoast_Api_Request_Factory'] = new \Yoast\WP\SEO\Services\Health_Check\MyYoast_Api_Request_Factory();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Health_Check\Page_Comments_Check' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Health_Check\Page_Comments_Check
     */
    protected function getPageCommentsCheckService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Page_Comments_Check'] = new \Yoast\WP\SEO\Services\Health_Check\Page_Comments_Check(${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Page_Comments_Runner']) ? $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Page_Comments_Runner'] : ($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Page_Comments_Runner'] = new \Yoast\WP\SEO\Services\Health_Check\Page_Comments_Runner())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Page_Comments_Reports']) ? $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Page_Comments_Reports'] : $this->getPageCommentsReportsService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Health_Check\Page_Comments_Reports' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Health_Check\Page_Comments_Reports
     */
    protected function getPageCommentsReportsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Page_Comments_Reports'] = new \Yoast\WP\SEO\Services\Health_Check\Page_Comments_Reports(${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder_Factory']) ? $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder_Factory'] : ($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder_Factory'] = new \Yoast\WP\SEO\Services\Health_Check\Report_Builder_Factory())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Health_Check\Page_Comments_Runner' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Health_Check\Page_Comments_Runner
     */
    protected function getPageCommentsRunnerService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Page_Comments_Runner'] = new \Yoast\WP\SEO\Services\Health_Check\Page_Comments_Runner();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Health_Check\Postname_Permalink_Check' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Health_Check\Postname_Permalink_Check
     */
    protected function getPostnamePermalinkCheckService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Postname_Permalink_Check'] = new \Yoast\WP\SEO\Services\Health_Check\Postname_Permalink_Check(${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Postname_Permalink_Runner']) ? $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Postname_Permalink_Runner'] : ($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Postname_Permalink_Runner'] = new \Yoast\WP\SEO\Services\Health_Check\Postname_Permalink_Runner())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Postname_Permalink_Reports']) ? $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Postname_Permalink_Reports'] : $this->getPostnamePermalinkReportsService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Health_Check\Postname_Permalink_Reports' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Health_Check\Postname_Permalink_Reports
     */
    protected function getPostnamePermalinkReportsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Postname_Permalink_Reports'] = new \Yoast\WP\SEO\Services\Health_Check\Postname_Permalink_Reports(${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder_Factory']) ? $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder_Factory'] : ($this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder_Factory'] = new \Yoast\WP\SEO\Services\Health_Check\Report_Builder_Factory())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Health_Check\Postname_Permalink_Runner' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Health_Check\Postname_Permalink_Runner
     */
    protected function getPostnamePermalinkRunnerService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Postname_Permalink_Runner'] = new \Yoast\WP\SEO\Services\Health_Check\Postname_Permalink_Runner();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Health_Check\Report_Builder' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Health_Check\Report_Builder
     */
    protected function getReportBuilderService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder'] = new \Yoast\WP\SEO\Services\Health_Check\Report_Builder();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Health_Check\Report_Builder_Factory' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Health_Check\Report_Builder_Factory
     */
    protected function getReportBuilderFactoryService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Health_Check\\Report_Builder_Factory'] = new \Yoast\WP\SEO\Services\Health_Check\Report_Builder_Factory();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Replacevar_Service' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Replacevar_Service
     */
    protected function getAioseoReplacevarServiceService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Replacevar_Service'] = new \Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Replacevar_Service();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Robots_Provider_Service' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Robots_Provider_Service
     */
    protected function getAioseoRobotsProviderServiceService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service'] = new \Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Robots_Provider_Service(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper'] : $this->getAioseoHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Robots_Transformer_Service' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Robots_Transformer_Service
     */
    protected function getAioseoRobotsTransformerServiceService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Transformer_Service'] = new \Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Robots_Transformer_Service(${($_ = isset($this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service']) ? $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Robots_Provider_Service'] : $this->getAioseoRobotsProviderServiceService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Social_Images_Provider_Service' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Social_Images_Provider_Service
     */
    protected function getAioseoSocialImagesProviderServiceService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Aioseo\\Aioseo_Social_Images_Provider_Service'] = new \Yoast\WP\SEO\Services\Importing\Aioseo\Aioseo_Social_Images_Provider_Service(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Aioseo_Helper'] : $this->getAioseoHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Importing\Conflicting_Plugins_Service' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Importing\Conflicting_Plugins_Service
     */
    protected function getConflictingPluginsServiceService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Conflicting_Plugins_Service'] = new \Yoast\WP\SEO\Services\Importing\Conflicting_Plugins_Service();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Importing\Importable_Detector_Service' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Importing\Importable_Detector_Service
     */
    protected function getImportableDetectorServiceService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Importing\\Importable_Detector_Service'] = new \Yoast\WP\SEO\Services\Importing\Importable_Detector_Service(${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Cleanup_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Cleanup_Action'] : $this->getAioseoCleanupActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Custom_Archive_Settings_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Custom_Archive_Settings_Importing_Action'] : $this->getAioseoCustomArchiveSettingsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Default_Archive_Settings_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Default_Archive_Settings_Importing_Action'] : $this->getAioseoDefaultArchiveSettingsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_General_Settings_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_General_Settings_Importing_Action'] : $this->getAioseoGeneralSettingsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posts_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posts_Importing_Action'] : $this->getAioseoPostsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posttype_Defaults_Settings_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Posttype_Defaults_Settings_Importing_Action'] : $this->getAioseoPosttypeDefaultsSettingsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Taxonomy_Settings_Importing_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Taxonomy_Settings_Importing_Action'] : $this->getAioseoTaxonomySettingsImportingActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Validate_Data_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Aioseo\\Aioseo_Validate_Data_Action'] : $this->getAioseoValidateDataActionService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Deactivate_Conflicting_Plugins_Action']) ? $this->services['Yoast\\WP\\SEO\\Actions\\Importing\\Deactivate_Conflicting_Plugins_Action'] : $this->getDeactivateConflictingPluginsActionService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Services\Indexables\Indexable_Version_Manager' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Services\Indexables\Indexable_Version_Manager
     */
    protected function getIndexableVersionManagerService()
    {
        return $this->services['Yoast\\WP\\SEO\\Services\\Indexables\\Indexable_Version_Manager'] = new \Yoast\WP\SEO\Services\Indexables\Indexable_Version_Manager(${($_ = isset($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions']) ? $this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] : ($this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] = new \Yoast\WP\SEO\Values\Indexables\Indexable_Builder_Versions())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Surfaces\Classes_Surface' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Surfaces\Classes_Surface
     */
    protected function getClassesSurfaceService()
    {
        return $this->services['Yoast\\WP\\SEO\\Surfaces\\Classes_Surface'] = new \Yoast\WP\SEO\Surfaces\Classes_Surface($this);
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Surfaces\Helpers_Surface' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Surfaces\Helpers_Surface
     */
    protected function getHelpersSurfaceService()
    {
        return $this->services['Yoast\\WP\\SEO\\Surfaces\\Helpers_Surface'] = new \Yoast\WP\SEO\Surfaces\Helpers_Surface($this, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Surfaces\\Open_Graph_Helpers_Surface']) ? $this->services['Yoast\\WP\\SEO\\Surfaces\\Open_Graph_Helpers_Surface'] : ($this->services['Yoast\\WP\\SEO\\Surfaces\\Open_Graph_Helpers_Surface'] = new \Yoast\WP\SEO\Surfaces\Open_Graph_Helpers_Surface($this))) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Surfaces\\Schema_Helpers_Surface']) ? $this->services['Yoast\\WP\\SEO\\Surfaces\\Schema_Helpers_Surface'] : ($this->services['Yoast\\WP\\SEO\\Surfaces\\Schema_Helpers_Surface'] = new \Yoast\WP\SEO\Surfaces\Schema_Helpers_Surface($this))) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Surfaces\\Twitter_Helpers_Surface']) ? $this->services['Yoast\\WP\\SEO\\Surfaces\\Twitter_Helpers_Surface'] : ($this->services['Yoast\\WP\\SEO\\Surfaces\\Twitter_Helpers_Surface'] = new \Yoast\WP\SEO\Surfaces\Twitter_Helpers_Surface($this))) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Surfaces\Meta_Surface' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Surfaces\Meta_Surface
     */
    protected function getMetaSurfaceService()
    {
        return $this->services['Yoast\\WP\\SEO\\Surfaces\\Meta_Surface'] = new \Yoast\WP\SEO\Surfaces\Meta_Surface($this, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Memoizers\\Meta_Tags_Context_Memoizer']) ? $this->services['Yoast\\WP\\SEO\\Memoizers\\Meta_Tags_Context_Memoizer'] : $this->getMetaTagsContextMemoizerService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository']) ? $this->services['Yoast\\WP\\SEO\\Repositories\\Indexable_Repository'] : $this->getIndexableRepositoryService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Rewrite_Wrapper']) ? $this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Rewrite_Wrapper'] : ($this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Rewrite_Wrapper'] = new \Yoast\WP\SEO\Wrappers\WP_Rewrite_Wrapper())) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Indexable_Helper'] : $this->getIndexableHelperService()) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Surfaces\Open_Graph_Helpers_Surface' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Surfaces\Open_Graph_Helpers_Surface
     */
    protected function getOpenGraphHelpersSurfaceService()
    {
        return $this->services['Yoast\\WP\\SEO\\Surfaces\\Open_Graph_Helpers_Surface'] = new \Yoast\WP\SEO\Surfaces\Open_Graph_Helpers_Surface($this);
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Surfaces\Schema_Helpers_Surface' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Surfaces\Schema_Helpers_Surface
     */
    protected function getSchemaHelpersSurfaceService()
    {
        return $this->services['Yoast\\WP\\SEO\\Surfaces\\Schema_Helpers_Surface'] = new \Yoast\WP\SEO\Surfaces\Schema_Helpers_Surface($this);
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Surfaces\Twitter_Helpers_Surface' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Surfaces\Twitter_Helpers_Surface
     */
    protected function getTwitterHelpersSurfaceService()
    {
        return $this->services['Yoast\\WP\\SEO\\Surfaces\\Twitter_Helpers_Surface'] = new \Yoast\WP\SEO\Surfaces\Twitter_Helpers_Surface($this);
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Values\Images' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Values\Images
     */
    protected function getImagesService()
    {
        return $this->services['Yoast\\WP\\SEO\\Values\\Images'] = new \Yoast\WP\SEO\Values\Images(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'});
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Values\Indexables\Indexable_Builder_Versions' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Values\Indexables\Indexable_Builder_Versions
     */
    protected function getIndexableBuilderVersionsService()
    {
        return $this->services['Yoast\\WP\\SEO\\Values\\Indexables\\Indexable_Builder_Versions'] = new \Yoast\WP\SEO\Values\Indexables\Indexable_Builder_Versions();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Values\Open_Graph\Images' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Values\Open_Graph\Images
     */
    protected function getImages2Service()
    {
        $this->services['Yoast\\WP\\SEO\\Values\\Open_Graph\\Images'] = $instance = new \Yoast\WP\SEO\Values\Open_Graph\Images(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Image_Helper'] : $this->getImageHelperService()) && false ?: '_'}, ${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] : ($this->services['Yoast\\WP\\SEO\\Helpers\\Url_Helper'] = new \Yoast\WP\SEO\Helpers\Url_Helper())) && false ?: '_'});

        $instance->set_helpers(${($_ = isset($this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper']) ? $this->services['Yoast\\WP\\SEO\\Helpers\\Open_Graph\\Image_Helper'] : $this->getImageHelper2Service()) && false ?: '_'});

        return $instance;
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Wrappers\WP_Query_Wrapper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Wrappers\WP_Query_Wrapper
     */
    protected function getWPQueryWrapperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Query_Wrapper'] = new \Yoast\WP\SEO\Wrappers\WP_Query_Wrapper();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Wrappers\WP_Remote_Handler' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Wrappers\WP_Remote_Handler
     */
    protected function getWPRemoteHandlerService()
    {
        return $this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Remote_Handler'] = new \Yoast\WP\SEO\Wrappers\WP_Remote_Handler();
    }

    /**
     * Gets the public 'Yoast\WP\SEO\Wrappers\WP_Rewrite_Wrapper' shared autowired service.
     *
     * @return \Yoast\WP\SEO\Wrappers\WP_Rewrite_Wrapper
     */
    protected function getWPRewriteWrapperService()
    {
        return $this->services['Yoast\\WP\\SEO\\Wrappers\\WP_Rewrite_Wrapper'] = new \Yoast\WP\SEO\Wrappers\WP_Rewrite_Wrapper();
    }

    /**
     * Gets the public 'Yoast_Notification_Center' shared service.
     *
     * @return \Yoast_Notification_Center
     */
    protected function getYoastNotificationCenterService()
    {
        return $this->services['Yoast_Notification_Center'] = \Yoast_Notification_Center::get();
    }

    /**
     * Gets the private 'wpdb' shared service.
     *
     * @return \wpdb
     */
    protected function getWpdbService()
    {
        return $this->services['wpdb'] = \Yoast\WP\SEO\WordPress\Wrapper::get_wpdb();
    }
}
