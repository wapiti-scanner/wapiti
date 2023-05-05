<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * The mega-class.
 *
 * This contains too much, so please think twice before adding more.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Assets\Logo as Jetpack_Logo;
use Automattic\Jetpack\Config;
use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Connection\Initial_State as Connection_Initial_State;
use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Connection\Nonce_Handler;
use Automattic\Jetpack\Connection\Rest_Authentication as Connection_Rest_Authentication;
use Automattic\Jetpack\Connection\Secrets;
use Automattic\Jetpack\Connection\Tokens;
use Automattic\Jetpack\Connection\Utils as Connection_Utils;
use Automattic\Jetpack\Constants;
use Automattic\Jetpack\CookieState;
use Automattic\Jetpack\Device_Detection\User_Agent_Info;
use Automattic\Jetpack\Errors;
use Automattic\Jetpack\Files;
use Automattic\Jetpack\Identity_Crisis;
use Automattic\Jetpack\Licensing;
use Automattic\Jetpack\Modules;
use Automattic\Jetpack\My_Jetpack\Initializer as My_Jetpack_Initializer;
use Automattic\Jetpack\Partner;
use Automattic\Jetpack\Paths;
use Automattic\Jetpack\Plugin\Tracking as Plugin_Tracking;
use Automattic\Jetpack\Redirect;
use Automattic\Jetpack\Status;
use Automattic\Jetpack\Status\Host;
use Automattic\Jetpack\Status\Visitor;
use Automattic\Jetpack\Sync\Actions as Sync_Actions;
use Automattic\Jetpack\Sync\Health;
use Automattic\Jetpack\Sync\Sender;
use Automattic\Jetpack\Terms_Of_Service;
use Automattic\Jetpack\Tracking;

/*
Options:
jetpack_options (array)
	An array of options.
	@see Jetpack_Options::get_option_names()

jetpack_register (string)
	Temporary verification secrets.

jetpack_activated (int)
	1: the plugin was activated normally
	2: the plugin was activated on this site because of a network-wide activation
	3: the plugin was auto-installed
	4: the plugin was manually disconnected (but is still installed)

jetpack_active_modules (array)
	Array of active module slugs.

jetpack_do_activate (bool)
	Flag for "activating" the plugin on sites where the activation hook never fired (auto-installs)
*/

require_once JETPACK__PLUGIN_DIR . '_inc/lib/class.media.php';

/**
 * The Jetpack class.
 */
class Jetpack {
	/**
	 * XMLRPC server instance.
	 *
	 * @var null|Jetpack_XMLRPC_Server XMLRPC server used by Jetpack.
	 */
	public $xmlrpc_server = null;

	/**
	 * The handles of styles that are concatenated into jetpack.css.
	 *
	 * When making changes to that list, you must also update concat_list in tools/webpack.config.css.js.
	 *
	 * @var array The handles of styles that are concatenated into jetpack.css.
	 */
	public $concatenated_style_handles = array(
		'jetpack-carousel-swiper-css',
		'jetpack-carousel',
		'grunion.css',
		'the-neverending-homepage',
		'jetpack_likes',
		'jetpack_related-posts',
		'sharedaddy',
		'jetpack-slideshow',
		'presentations',
		'quiz',
		'jetpack-subscriptions',
		'jetpack-responsive-videos-style',
		'jetpack-social-menu',
		'tiled-gallery',
		'jetpack_display_posts_widget',
		'gravatar-profile-widget',
		'goodreads-widget',
		'jetpack_social_media_icons_widget',
		'jetpack-top-posts-widget',
		'jetpack_image_widget',
		'jetpack-my-community-widget',
		'jetpack-authors-widget',
		'wordads',
		'eu-cookie-law-style',
		'flickr-widget-style',
		'jetpack-search-widget',
		'jetpack-simple-payments-widget-style',
		'jetpack-widget-social-icons-styles',
		'wpcom_instagram_widget',
		'milestone-widget',
	);

	/**
	 * Contains all assets that have had their URL rewritten to minified versions.
	 *
	 * @var array
	 */
	public static $min_assets = array();

	/**
	 * Plugins to deactivate.
	 *
	 * @var array Plugins to deactivate by module.
	 */
	public $plugins_to_deactivate = array(
		'contact-form'        => array(
			array( 'grunion-contact-form/grunion-contact-form.php', 'Grunion Contact Form' ),
			array( 'mullet/mullet-contact-form.php', 'Mullet Contact Form' ),
		),
		'custom-css'          => array(
			array( 'safecss/safecss.php', 'WordPress.com Custom CSS' ),
		),
		'gravatar-hovercards' => array(
			array( 'jetpack-gravatar-hovercards/gravatar-hovercards.php', 'Jetpack Gravatar Hovercards' ),
		),
		'latex'               => array(
			array( 'wp-latex/wp-latex.php', 'WP LaTeX' ),
		),
		'random-redirect'     => array(
			array( 'random-redirect/random-redirect.php', 'Random Redirect' ),
		),
		'sharedaddy'          => array(
			array( 'sharedaddy/sharedaddy.php', 'Sharedaddy' ),
			array( 'jetpack-sharing/sharedaddy.php', 'Jetpack Sharing' ),
		),
		'shortlinks'          => array(
			array( 'stats/stats.php', 'WordPress.com Stats' ),
		),
		'stats'               => array(
			array( 'stats/stats.php', 'WordPress.com Stats' ),
		),
		'twitter-widget'      => array(
			array( 'wickett-twitter-widget/wickett-twitter-widget.php', 'Wickett Twitter Widget' ),
		),
		'videopress'          => array(
			array( 'video/video.php', 'VideoPress' ),
		),
		'widget-visibility'   => array(
			array( 'jetpack-widget-visibility/widget-visibility.php', 'Jetpack Widget Visibility' ),
			array( 'widget-visibility-without-jetpack/widget-visibility-without-jetpack.php', 'Widget Visibility Without Jetpack' ),
		),
	);

	/**
	 * Map of roles we care about, and their corresponding minimum capabilities.
	 *
	 * @deprecated 7.6 Use Automattic\Jetpack\Roles::$capability_translations instead.
	 *
	 * @access public
	 * @static
	 *
	 * @var array
	 */
	public static $capability_translations = array(
		'administrator' => 'manage_options',
		'editor'        => 'edit_others_posts',
		'author'        => 'publish_posts',
		'contributor'   => 'edit_posts',
		'subscriber'    => 'read',
	);

	/**
	 * Map of modules that have conflicts with plugins and should not be auto-activated
	 * if the plugins are active.  Used by filter_default_modules
	 *
	 * Plugin Authors: If you'd like to prevent a single module from auto-activating,
	 * change `module-slug` and add this to your plugin:
	 *
	 * add_filter( 'jetpack_get_default_modules', 'my_jetpack_get_default_modules' );
	 * function my_jetpack_get_default_modules( $modules ) {
	 *     return array_diff( $modules, array( 'module-slug' ) );
	 * }
	 *
	 * @var array
	 */
	private $conflicting_plugins = array(
		'comments'           => array(
			'Intense Debate'                 => 'intensedebate/intensedebate.php',
			'Disqus'                         => 'disqus-comment-system/disqus.php',
			'Livefyre'                       => 'livefyre-comments/livefyre.php',
			'Comments Evolved for WordPress' => 'gplus-comments/comments-evolved.php',
			'Google+ Comments'               => 'google-plus-comments/google-plus-comments.php',
			'WP-SpamShield Anti-Spam'        => 'wp-spamshield/wp-spamshield.php',
		),
		'comment-likes'      => array(
			'Epoch' => 'epoch/plugincore.php',
		),
		'latex'              => array(
			'LaTeX for WordPress'     => 'latex/latex.php',
			'Youngwhans Simple Latex' => 'youngwhans-simple-latex/yw-latex.php',
			'Easy WP LaTeX'           => 'easy-wp-latex-lite/easy-wp-latex-lite.php',
			'MathJax-LaTeX'           => 'mathjax-latex/mathjax-latex.php',
			'Enable Latex'            => 'enable-latex/enable-latex.php',
			'WP QuickLaTeX'           => 'wp-quicklatex/wp-quicklatex.php',
		),
		'protect'            => array(
			'Limit Login Attempts'              => 'limit-login-attempts/limit-login-attempts.php',
			'Captcha'                           => 'captcha/captcha.php',
			'Brute Force Login Protection'      => 'brute-force-login-protection/brute-force-login-protection.php',
			'Login Security Solution'           => 'login-security-solution/login-security-solution.php',
			'WPSecureOps Brute Force Protect'   => 'wpsecureops-bruteforce-protect/wpsecureops-bruteforce-protect.php',
			'BulletProof Security'              => 'bulletproof-security/bulletproof-security.php',
			'SiteGuard WP Plugin'               => 'siteguard/siteguard.php',
			'Security-protection'               => 'security-protection/security-protection.php',
			'Login Security'                    => 'login-security/login-security.php',
			'Botnet Attack Blocker'             => 'botnet-attack-blocker/botnet-attack-blocker.php',
			'Wordfence Security'                => 'wordfence/wordfence.php',
			'All In One WP Security & Firewall' => 'all-in-one-wp-security-and-firewall/wp-security.php',
			'iThemes Security'                  => 'better-wp-security/better-wp-security.php',
		),
		'random-redirect'    => array(
			'Random Redirect 2' => 'random-redirect-2/random-redirect.php',
		),
		'related-posts'      => array(
			'YARPP'                       => 'yet-another-related-posts-plugin/yarpp.php',
			'WordPress Related Posts'     => 'wordpress-23-related-posts-plugin/wp_related_posts.php',
			'nrelate Related Content'     => 'nrelate-related-content/nrelate-related.php',
			'Contextual Related Posts'    => 'contextual-related-posts/contextual-related-posts.php',
			'Related Posts for WordPress' => 'microkids-related-posts/microkids-related-posts.php',
			'outbrain'                    => 'outbrain/outbrain.php',
			'Shareaholic'                 => 'shareaholic/shareaholic.php',
			'Sexybookmarks'               => 'sexybookmarks/shareaholic.php',
		),
		'sharedaddy'         => array(
			'AddThis'     => 'addthis/addthis_social_widget.php',
			'Add To Any'  => 'add-to-any/add-to-any.php',
			'ShareThis'   => 'share-this/sharethis.php',
			'Shareaholic' => 'shareaholic/shareaholic.php',
		),
		'seo-tools'          => array(
			'WordPress SEO by Yoast'         => 'wordpress-seo/wp-seo.php',
			'WordPress SEO Premium by Yoast' => 'wordpress-seo-premium/wp-seo-premium.php',
			'All in One SEO Pack'            => 'all-in-one-seo-pack/all_in_one_seo_pack.php',
			'All in One SEO Pack Pro'        => 'all-in-one-seo-pack-pro/all_in_one_seo_pack.php',
			'The SEO Framework'              => 'autodescription/autodescription.php',
			'Rank Math'                      => 'seo-by-rank-math/rank-math.php',
			'Slim SEO'                       => 'slim-seo/slim-seo.php',
			'SEOKEY'                         => 'seo-key/seo-key.php',
			'SEOKEY Pro'                     => 'seo-key-pro/seo-key.php',
			'SEOPress'                       => 'wp-seopress/seopress.php',
			'SEOPress Pro'                   => 'wp-seopress-pro/seopress-pro.php',
		),
		'verification-tools' => array(
			'WordPress SEO by Yoast'         => 'wordpress-seo/wp-seo.php',
			'WordPress SEO Premium by Yoast' => 'wordpress-seo-premium/wp-seo-premium.php',
			'All in One SEO Pack'            => 'all-in-one-seo-pack/all_in_one_seo_pack.php',
			'All in One SEO Pack Pro'        => 'all-in-one-seo-pack-pro/all_in_one_seo_pack.php',
			'The SEO Framework'              => 'autodescription/autodescription.php',
			'Rank Math'                      => 'seo-by-rank-math/rank-math.php',
			'Slim SEO'                       => 'slim-seo/slim-seo.php',
		),
		'widget-visibility'  => array(
			'Widget Logic'    => 'widget-logic/widget_logic.php',
			'Dynamic Widgets' => 'dynamic-widgets/dynamic-widgets.php',
		),
		'sitemaps'           => array(
			'Google XML Sitemaps'                  => 'google-sitemap-generator/sitemap.php',
			'Better WordPress Google XML Sitemaps' => 'bwp-google-xml-sitemaps/bwp-simple-gxs.php',
			'Google XML Sitemaps for qTranslate'   => 'google-xml-sitemaps-v3-for-qtranslate/sitemap.php',
			'XML Sitemap & Google News feeds'      => 'xml-sitemap-feed/xml-sitemap.php',
			'Google Sitemap by BestWebSoft'        => 'google-sitemap-plugin/google-sitemap-plugin.php',
			'WordPress SEO by Yoast'               => 'wordpress-seo/wp-seo.php',
			'WordPress SEO Premium by Yoast'       => 'wordpress-seo-premium/wp-seo-premium.php',
			'All in One SEO Pack'                  => 'all-in-one-seo-pack/all_in_one_seo_pack.php',
			'All in One SEO Pack Pro'              => 'all-in-one-seo-pack-pro/all_in_one_seo_pack.php',
			'The SEO Framework'                    => 'autodescription/autodescription.php',
			'Sitemap'                              => 'sitemap/sitemap.php',
			'Simple Wp Sitemap'                    => 'simple-wp-sitemap/simple-wp-sitemap.php',
			'Simple Sitemap'                       => 'simple-sitemap/simple-sitemap.php',
			'XML Sitemaps'                         => 'xml-sitemaps/xml-sitemaps.php',
			'MSM Sitemaps'                         => 'msm-sitemap/msm-sitemap.php',
			'Rank Math'                            => 'seo-by-rank-math/rank-math.php',
			'Slim SEO'                             => 'slim-seo/slim-seo.php',
		),
		'lazy-images'        => array(
			'Lazy Load'              => 'lazy-load/lazy-load.php',
			'BJ Lazy Load'           => 'bj-lazy-load/bj-lazy-load.php',
			'Lazy Load by WP Rocket' => 'rocket-lazy-load/rocket-lazy-load.php',
		),
	);

	/**
	 * Plugins for which we turn off our Facebook OG Tags implementation.
	 *
	 * Note: the following plugins automatically deactivate Jetpack's Open
	 * Graph tags via filter when their Social Meta modules are active:
	 *
	 * - All in One SEO Pack, All in one SEO Pack Pro
	 * - WordPress SEO by Yoast, WordPress SEO Premium by Yoast
	 * - SEOPress, SEOPress Pro
	 *
	 * Plugin authors: If you'd like to prevent Jetpack's Open Graph tag generation in your plugin, you can do so via this filter:
	 * add_filter( 'jetpack_enable_open_graph', '__return_false' );
	 *
	 * @var array Array of plugin slugs.
	 */
	private $open_graph_conflicting_plugins = array(
		'2-click-socialmedia-buttons/2-click-socialmedia-buttons.php', // 2 Click Social Media Buttons.
		'add-link-to-facebook/add-link-to-facebook.php',         // Add Link to Facebook.
		'add-meta-tags/add-meta-tags.php',                       // Add Meta Tags.
		'complete-open-graph/complete-open-graph.php',           // Complete Open Graph.
		'easy-facebook-share-thumbnails/esft.php',               // Easy Facebook Share Thumbnail.
		'heateor-open-graph-meta-tags/heateor-open-graph-meta-tags.php', // Open Graph Meta Tags by Heateor.
		'facebook/facebook.php',                                 // Facebook (official plugin).
		'facebook-awd/AWD_facebook.php',                         // Facebook AWD All in one.
		'facebook-featured-image-and-open-graph-meta-tags/fb-featured-image.php', // Facebook Featured Image & OG Meta Tags.
		'facebook-meta-tags/facebook-metatags.php',              // Facebook Meta Tags.
		'wonderm00ns-simple-facebook-open-graph-tags/wonderm00n-open-graph.php', // Facebook Open Graph Meta Tags for WordPress.
		'facebook-revised-open-graph-meta-tag/index.php',        // Facebook Revised Open Graph Meta Tag.
		'facebook-thumb-fixer/_facebook-thumb-fixer.php',        // Facebook Thumb Fixer.
		'facebook-and-digg-thumbnail-generator/facebook-and-digg-thumbnail-generator.php', // Fedmich's Facebook Open Graph Meta.
		'network-publisher/networkpub.php',                      // Network Publisher.
		'nextgen-facebook/nextgen-facebook.php',                 // NextGEN Facebook OG.
		'social-networks-auto-poster-facebook-twitter-g/NextScripts_SNAP.php', // NextScripts SNAP.
		'og-tags/og-tags.php',                                   // OG Tags.
		'opengraph/opengraph.php',                               // Open Graph.
		'open-graph-protocol-framework/open-graph-protocol-framework.php', // Open Graph Protocol Framework.
		'seo-facebook-comments/seofacebook.php',                 // SEO Facebook Comments.
		'seo-ultimate/seo-ultimate.php',                         // SEO Ultimate.
		'sexybookmarks/sexy-bookmarks.php',                      // Shareaholic.
		'shareaholic/sexy-bookmarks.php',                        // Shareaholic.
		'sharepress/sharepress.php',                             // SharePress.
		'simple-facebook-connect/sfc.php',                       // Simple Facebook Connect.
		'social-discussions/social-discussions.php',             // Social Discussions.
		'social-sharing-toolkit/social_sharing_toolkit.php',     // Social Sharing Toolkit.
		'socialize/socialize.php',                               // Socialize.
		'squirrly-seo/squirrly.php',                             // SEO by SQUIRRLY™.
		'only-tweet-like-share-and-google-1/tweet-like-plusone.php', // Tweet, Like, Google +1 and Share.
		'wordbooker/wordbooker.php',                             // Wordbooker.
		'wpsso/wpsso.php',                                       // WordPress Social Sharing Optimization.
		'wp-caregiver/wp-caregiver.php',                         // WP Caregiver.
		'wp-facebook-like-send-open-graph-meta/wp-facebook-like-send-open-graph-meta.php', // WP Facebook Like Send & Open Graph Meta.
		'wp-facebook-open-graph-protocol/wp-facebook-ogp.php',   // WP Facebook Open Graph protocol.
		'wp-ogp/wp-ogp.php',                                     // WP-OGP.
		'zoltonorg-social-plugin/zosp.php',                      // Zolton.org Social Plugin.
		'wp-fb-share-like-button/wp_fb_share-like_widget.php',   // WP Facebook Like Button.
		'open-graph-metabox/open-graph-metabox.php',              // Open Graph Metabox.
		'seo-by-rank-math/rank-math.php',                        // Rank Math.
		'slim-seo/slim-seo.php',                                 // Slim SEO.
	);

	/**
	 * Plugins for which we turn off our Twitter Cards Tags implementation.
	 *
	 * @var array Plugins that conflict with Twitter cards.
	 */
	private $twitter_cards_conflicting_plugins = array(
		// phpcs:ignore Squiz.PHP.CommentedOutCode.Found
		// 'twitter/twitter.php',                       // The official one handles this on its own.
		// https://github.com/twitter/wordpress/blob/master/src/Twitter/WordPress/Cards/Compatibility.php
			'eewee-twitter-card/index.php',              // Eewee Twitter Card.
		'ig-twitter-cards/ig-twitter-cards.php',     // IG:Twitter Cards.
		'jm-twitter-cards/jm-twitter-cards.php',     // JM Twitter Cards.
		'kevinjohn-gallagher-pure-web-brilliants-social-graph-twitter-cards-extention/kevinjohn_gallagher___social_graph_twitter_output.php',  // Pure Web Brilliant's Social Graph Twitter Cards Extension.
		'twitter-cards/twitter-cards.php',           // Twitter Cards.
		'twitter-cards-meta/twitter-cards-meta.php', // Twitter Cards Meta.
		'wp-to-twitter/wp-to-twitter.php',           // WP to Twitter.
		'wp-twitter-cards/twitter_cards.php',        // WP Twitter Cards.
		'seo-by-rank-math/rank-math.php',            // Rank Math.
		'slim-seo/slim-seo.php',                     // Slim SEO.
	);

	/**
	 * Message to display in admin_notice
	 *
	 * @var string
	 */
	public $message = '';

	/**
	 * Error to display in admin_notice
	 *
	 * @var string
	 */
	public $error = '';

	/**
	 * Modules that need more privacy description.
	 *
	 * @var string
	 */
	public $privacy_checks = '';

	/**
	 * Stats to record once the page loads
	 *
	 * @var array
	 */
	public $stats = array();

	/**
	 * Jetpack_Sync object
	 *
	 * @todo This is also seemingly unused.
	 *
	 * @var object
	 */
	public $sync;

	/**
	 * Verified data for JSON authorization request
	 *
	 * @var array
	 */
	public $json_api_authorization_request = array();

	/**
	 * Connection manager.
	 *
	 * @var Automattic\Jetpack\Connection\Manager
	 */
	protected $connection_manager;

	/**
	 * Plugin lock key.
	 *
	 * @var string Transient key used to prevent multiple simultaneous plugin upgrades
	 */
	public static $plugin_upgrade_lock_key = 'jetpack_upgrade_lock';

	/**
	 * Holds an instance of Automattic\Jetpack\A8c_Mc_Stats
	 *
	 * @var Automattic\Jetpack\A8c_Mc_Stats
	 */
	public $a8c_mc_stats_instance;

	/**
	 * Constant for login redirect key.
	 *
	 * @var string
	 * @since 8.4.0
	 */
	public static $jetpack_redirect_login = 'jetpack_connect_login_redirect';

	/**
	 * Holds the singleton instance of this class
	 *
	 * @since 2.3.3
	 * @var Jetpack
	 */
	public static $instance = false;

	/**
	 * Singleton
	 *
	 * @static
	 */
	public static function init() {
		if ( ! self::$instance ) {
			self::$instance = new Jetpack();
			add_action( 'plugins_loaded', array( self::$instance, 'plugin_upgrade' ) );
			add_action( 'jetpack_idc_disconnect', array( __CLASS__, 'on_idc_disconnect' ) );
		}

		return self::$instance;
	}

	/**
	 * Must never be called statically
	 */
	public function plugin_upgrade() {
		if ( self::is_connection_ready() ) {
			list( $version ) = explode( ':', Jetpack_Options::get_option( 'version' ) );
			if ( JETPACK__VERSION !== $version ) {
				// Prevent multiple upgrades at once - only a single process should trigger
				// an upgrade to avoid stampedes.
				if ( false !== get_transient( self::$plugin_upgrade_lock_key ) ) {
					return;
				}

				// Set a short lock to prevent multiple instances of the upgrade.
				set_transient( self::$plugin_upgrade_lock_key, 1, 10 );

				// check which active modules actually exist and remove others from active_modules list.
				$unfiltered_modules = self::get_active_modules();
				$modules            = array_filter( $unfiltered_modules, array( 'Jetpack', 'is_module' ) );
				if ( array_diff( $unfiltered_modules, $modules ) ) {
					self::update_active_modules( $modules );
				}

				add_action( 'init', array( __CLASS__, 'activate_new_modules' ) );

				// Upgrade to 4.3.0.
				if ( Jetpack_Options::get_option( 'identity_crisis_whitelist' ) ) {
					Jetpack_Options::delete_option( 'identity_crisis_whitelist' );
				}

				// Make sure Markdown for posts gets turned back on.
				if ( ! get_option( 'wpcom_publish_posts_with_markdown' ) ) {
					update_option( 'wpcom_publish_posts_with_markdown', true );
				}

				/*
				 * Minileven deprecation. 8.3.0.
				 * Only delete options if not using
				 * the replacement standalone Minileven plugin.
				 */
				if (
					! self::is_plugin_active( 'minileven-master/minileven.php' )
					&& ! self::is_plugin_active( 'minileven/minileven.php' )
				) {
					if ( get_option( 'wp_mobile_custom_css' ) ) {
						delete_option( 'wp_mobile_custom_css' );
					}
					if ( get_option( 'wp_mobile_excerpt' ) ) {
						delete_option( 'wp_mobile_excerpt' );
					}
					if ( get_option( 'wp_mobile_featured_images' ) ) {
						delete_option( 'wp_mobile_featured_images' );
					}
					if ( get_option( 'wp_mobile_app_promos' ) ) {
						delete_option( 'wp_mobile_app_promos' );
					}
				}

				// Upgrade to 8.4.0.
				if ( Jetpack_Options::get_option( 'ab_connect_banner_green_bar' ) ) {
					Jetpack_Options::delete_option( 'ab_connect_banner_green_bar' );
				}

				// Update to 8.8.x (WordPress 5.5 Compatibility).
				if ( Jetpack_Options::get_option( 'autoupdate_plugins' ) ) {
					$updated = update_site_option(
						'auto_update_plugins',
						array_unique(
							array_merge(
								(array) Jetpack_Options::get_option( 'autoupdate_plugins', array() ),
								(array) get_site_option( 'auto_update_plugins', array() )
							)
						)
					);

					if ( $updated ) {
						Jetpack_Options::delete_option( 'autoupdate_plugins' );
					} // Should we have some type of fallback if something fails here?
				}

				if ( did_action( 'wp_loaded' ) ) {
					self::upgrade_on_load();
				} else {
					add_action(
						'wp_loaded',
						array( __CLASS__, 'upgrade_on_load' )
					);
				}
			}
		}
	}

	/**
	 * Runs upgrade routines that need to have modules loaded.
	 */
	public static function upgrade_on_load() {

		// Not attempting any upgrades if jetpack_modules_loaded did not fire.
		// This can happen in case Jetpack has been just upgraded and is
		// being initialized late during the page load. In this case we wait
		// until the next proper admin page load with Jetpack active.
		if ( ! did_action( 'jetpack_modules_loaded' ) ) {
			delete_transient( self::$plugin_upgrade_lock_key );

			return;
		}

		self::maybe_set_version_option();

		if ( method_exists( 'Jetpack_Widget_Conditions', 'migrate_post_type_rules' ) ) {
			Jetpack_Widget_Conditions::migrate_post_type_rules();
		}

		if (
			class_exists( 'Jetpack_Sitemap_Manager' )
			&& version_compare( JETPACK__VERSION, '5.3', '>=' )
		) {
			do_action( 'jetpack_sitemaps_purge_data' );
		}

		// Delete old stats cache.
		delete_option( 'jetpack_restapi_stats_cache' );

		delete_transient( self::$plugin_upgrade_lock_key );
	}

	/**
	 * Saves all the currently active modules to options.
	 * Also fires Action hooks for each newly activated and deactivated module.
	 *
	 * @param array $modules Array of active modules to be saved in options.
	 *
	 * @return $success bool true for success, false for failure.
	 */
	public static function update_active_modules( $modules ) {
		return ( new Modules() )->update_active( $modules );
	}

	/**
	 * Remove all active modules.
	 *
	 * @return void
	 */
	public static function delete_active_modules() {
		self::update_active_modules( array() );
	}

	/**
	 * Adds a hook to plugins_loaded at a priority that's currently the earliest
	 * available.
	 */
	public function add_configure_hook() {
		global $wp_filter;

		$current_priority = has_filter( 'plugins_loaded', array( $this, 'configure' ) );
		if ( false !== $current_priority ) {
			remove_action( 'plugins_loaded', array( $this, 'configure' ), $current_priority );
		}

		$taken_priorities = array_map( 'intval', array_keys( $wp_filter['plugins_loaded']->callbacks ) );
		sort( $taken_priorities );

		$first_priority = array_shift( $taken_priorities );

		if ( defined( 'PHP_INT_MAX' ) && $first_priority <= - PHP_INT_MAX ) {
			$new_priority = - PHP_INT_MAX;
		} else {
			$new_priority = $first_priority - 1;
		}

		add_action( 'plugins_loaded', array( $this, 'configure' ), $new_priority );
	}

	/**
	 * Constructor.  Initializes WordPress hooks
	 */
	private function __construct() {
		/*
		 * Check for and alert any deprecated hooks
		 */
		add_action( 'init', array( $this, 'deprecated_hooks' ) );

		// Note how this runs at an earlier plugin_loaded hook intentionally to accomodate for other plugins.
		add_action( 'plugin_loaded', array( $this, 'add_configure_hook' ), 90 );
		add_action( 'network_plugin_loaded', array( $this, 'add_configure_hook' ), 90 );
		add_action( 'mu_plugin_loaded', array( $this, 'add_configure_hook' ), 90 );
		add_action( 'plugins_loaded', array( $this, 'late_initialization' ), 90 );

		add_action( 'jetpack_verify_signature_error', array( $this, 'track_xmlrpc_error' ) );

		add_filter(
			'jetpack_signature_check_token',
			array( __CLASS__, 'verify_onboarding_token' ),
			10,
			3
		);

		/**
		 * Prepare Gutenberg Editor functionality
		 */
		require_once JETPACK__PLUGIN_DIR . 'class.jetpack-gutenberg.php';
		add_action( 'plugins_loaded', array( 'Jetpack_Gutenberg', 'init' ) );
		add_action( 'plugins_loaded', array( 'Jetpack_Gutenberg', 'load_independent_blocks' ) );
		add_action( 'plugins_loaded', array( 'Jetpack_Gutenberg', 'load_block_editor_extensions' ), 9 );
		add_action( 'enqueue_block_editor_assets', array( 'Jetpack_Gutenberg', 'enqueue_block_editor_assets' ) );

		add_action( 'set_user_role', array( $this, 'maybe_clear_other_linked_admins_transient' ), 10, 3 );

		// Unlink user before deleting the user from WP.com.
		add_action( 'deleted_user', array( $this, 'disconnect_user' ), 10, 1 );
		add_action( 'remove_user_from_blog', array( $this, 'disconnect_user' ), 10, 1 );

		add_action( 'jetpack_event_log', array( 'Jetpack', 'log' ), 10, 2 );

		add_filter( 'login_url', array( $this, 'login_url' ), 10, 2 );
		add_action( 'login_init', array( $this, 'login_init' ) );

		// Set up the REST authentication hooks.
		Connection_Rest_Authentication::init();

		add_action( 'admin_init', array( $this, 'admin_init' ) );
		add_action( 'admin_init', array( $this, 'dismiss_jetpack_notice' ) );

		add_filter( 'admin_body_class', array( $this, 'admin_body_class' ), 20 );

		// Filter the dashboard meta box order to swap the new one in in place of the old one.
		add_filter( 'get_user_option_meta-box-order_dashboard', array( $this, 'get_user_option_meta_box_order_dashboard' ) );

		// WordPress dashboard widget.
		require_once JETPACK__PLUGIN_DIR . 'class-jetpack-stats-dashboard-widget.php';
		add_action( 'wp_dashboard_setup', array( new Jetpack_Stats_Dashboard_Widget(), 'init' ) );

		// Returns HTTPS support status.
		add_action( 'wp_ajax_jetpack-recheck-ssl', array( $this, 'ajax_recheck_ssl' ) );

		add_action( 'wp_ajax_jetpack_connection_banner', array( $this, 'jetpack_connection_banner_callback' ) );

		add_action( 'wp_ajax_jetpack_recommendations_banner', array( 'Jetpack_Recommendations_Banner', 'ajax_callback' ) );

		add_action( 'wp_loaded', array( $this, 'register_assets' ) );

		/**
		 * These actions run checks to load additional files.
		 * They check for external files or plugins, so they need to run as late as possible.
		 */
		add_action( 'wp_head', array( $this, 'check_open_graph' ), 1 );
		add_action( 'web_stories_story_head', array( $this, 'check_open_graph' ), 1 );
		add_action( 'plugins_loaded', array( $this, 'check_twitter_tags' ), 999 );
		add_action( 'plugins_loaded', array( $this, 'check_rest_api_compat' ), 1000 );

		add_filter( 'plugins_url', array( 'Jetpack', 'maybe_min_asset' ), 1, 3 );
		add_action( 'style_loader_src', array( 'Jetpack', 'set_suffix_on_min' ), 10, 2 );

		add_filter( 'profile_update', array( 'Jetpack', 'user_meta_cleanup' ) );

		add_filter( 'jetpack_get_default_modules', array( $this, 'filter_default_modules' ) );
		add_filter( 'jetpack_get_default_modules', array( $this, 'handle_deprecated_modules' ), 99 );

		require_once JETPACK__PLUGIN_DIR . 'class-jetpack-pre-connection-jitms.php';
		$jetpack_jitm_messages = ( new Jetpack_Pre_Connection_JITMs() );
		add_filter( 'jetpack_pre_connection_jitms', array( $jetpack_jitm_messages, 'add_pre_connection_jitms' ) );

		/*
		 * If enabled, point edit post, page, and comment links to Calypso instead of WP-Admin.
		 * We should make sure to only do this for front end links.
		 */
		if ( self::get_option( 'edit_links_calypso_redirect' ) && ! is_admin() ) {
			add_filter( 'get_edit_post_link', array( $this, 'point_edit_post_links_to_calypso' ), 1, 2 );
			add_filter( 'get_edit_comment_link', array( $this, 'point_edit_comment_links_to_calypso' ), 1 );

			/*
			 * We'll shortcircuit wp_notify_postauthor and wp_notify_moderator pluggable functions
			 * so they point moderation links on emails to Calypso.
			 */
			require_once JETPACK__PLUGIN_DIR . '_inc/lib/functions.wp-notify.php';
			add_filter( 'comment_notification_recipients', 'jetpack_notify_postauthor', 1, 2 );
			add_filter( 'notify_moderator', 'jetpack_notify_moderator', 1, 2 );
		}

		add_action(
			'plugins_loaded',
			function () {
				if ( User_Agent_Info::is_mobile_app() ) {
					add_filter( 'get_edit_post_link', '__return_empty_string' );
				}
			}
		);

		// Update the site's Jetpack plan and products from API on heartbeats.
		add_action( 'jetpack_heartbeat', array( 'Jetpack_Plan', 'refresh_from_wpcom' ) );

		/**
		 * This is the hack to concatenate all css files into one.
		 * For description and reasoning see the implode_frontend_css method.
		 *
		 * Super late priority so we catch all the registered styles.
		 */
		if ( ! is_admin() ) {
			add_action( 'wp_print_styles', array( $this, 'implode_frontend_css' ), -1 ); // Run first.
			add_action( 'wp_print_footer_scripts', array( $this, 'implode_frontend_css' ), -1 ); // Run first to trigger before `print_late_styles`.
		}

		// Actually push the stats on shutdown.
		if ( ! has_action( 'shutdown', array( $this, 'push_stats' ) ) ) {
			add_action( 'shutdown', array( $this, 'push_stats' ) );
		}

		// After a successful connection.
		add_action( 'jetpack_site_registered', array( $this, 'activate_default_modules_on_site_register' ) );
		add_action( 'jetpack_site_registered', array( $this, 'handle_unique_registrations_stats' ) );

		// Actions for Manager::authorize().
		add_action( 'jetpack_authorize_starting', array( $this, 'authorize_starting' ) );
		add_action( 'jetpack_authorize_ending_linked', array( $this, 'authorize_ending_linked' ) );
		add_action( 'jetpack_authorize_ending_authorized', array( $this, 'authorize_ending_authorized' ) );

		add_action( 'jetpack_client_authorize_error', array( Jetpack_Client_Server::class, 'client_authorize_error' ) );
		add_filter( 'jetpack_client_authorize_already_authorized_url', array( Jetpack_Client_Server::class, 'client_authorize_already_authorized_url' ) );
		add_action( 'jetpack_client_authorize_processing', array( Jetpack_Client_Server::class, 'client_authorize_processing' ) );
		add_filter( 'jetpack_client_authorize_fallback_url', array( Jetpack_Client_Server::class, 'client_authorize_fallback_url' ) );

		// Filters for the Manager::get_token() urls and request body.
		add_filter( 'jetpack_token_redirect_url', array( __CLASS__, 'filter_connect_redirect_url' ) );
		add_filter( 'jetpack_token_request_body', array( __CLASS__, 'filter_token_request_body' ) );

		// Filter for the `jetpack/v4/connection/data` API response.
		add_filter( 'jetpack_current_user_connection_data', array( __CLASS__, 'filter_jetpack_current_user_connection_data' ) );

		// Actions for successful reconnect.
		add_action( 'jetpack_reconnection_completed', array( $this, 'reconnection_completed' ) );

		// Actions for successful disconnect.
		add_action( 'jetpack_site_disconnected', array( $this, 'jetpack_site_disconnected' ) );

		// Actions for licensing.
		Licensing::instance()->initialize();

		// Filters for Sync Callables.
		add_filter( 'jetpack_sync_callable_whitelist', array( $this, 'filter_sync_callable_whitelist' ), 10, 1 );
		add_filter( 'jetpack_sync_multisite_callable_whitelist', array( $this, 'filter_sync_multisite_callable_whitelist' ), 10, 1 );

		// Make resources use static domain when possible.
		add_filter( 'jetpack_static_url', array( 'Automattic\\Jetpack\\Assets', 'staticize_subdomain' ) );

		// Validate the domain names in Jetpack development versions.
		add_action( 'jetpack_pre_register', array( get_called_class(), 'registration_check_domains' ) );

		// Register product descriptions for partner coupon usage.
		add_filter( 'jetpack_partner_coupon_products', array( $this, 'get_partner_coupon_product_descriptions' ) );

		// Actions for conditional recommendations.
		add_action( 'plugins_loaded', array( 'Jetpack_Recommendations', 'init_conditional_recommendation_actions' ) );
	}

	/**
	 * Before everything else starts getting initalized, we need to initialize Jetpack using the
	 * Config object.
	 */
	public function configure() {
		$config = new Config();

		foreach (
			array(
				'blaze',
				'jitm',
				'sync',
				'waf',
				'videopress',
				'stats',
				'stats_admin',
				'import',
			)
			as $feature
		) {
			$config->ensure( $feature );
		}

		$config->ensure(
			'connection',
			array(
				'slug' => 'jetpack',
				'name' => 'Jetpack',
			)
		);

		// Identity crisis package.
		$config->ensure(
			'identity_crisis',
			array(
				'slug'       => 'jetpack',
				'admin_page' => '/wp-admin/admin.php?page=jetpack',
			)
		);

		$config->ensure( 'search' );

		if ( defined( 'ENABLE_WORDADS_SHARED_UI' ) && ENABLE_WORDADS_SHARED_UI ) {
			$config->ensure( 'wordads' );
		}

		if ( ! $this->connection_manager ) {
			$this->connection_manager = new Connection_Manager( 'jetpack' );
		}

		$modules = new Automattic\Jetpack\Modules();
		if ( $modules->is_active( 'publicize' ) && $this->connection_manager->has_connected_user() ) {
			$config->ensure( 'publicize' );
		}

		/*
		 * Load things that should only be in Network Admin.
		 *
		 * For now blow away everything else until a more full
		 * understanding of what is needed at the network level is
		 * available
		 */
		if ( is_multisite() ) {
			$network = Jetpack_Network::init();
			$network->set_connection( $this->connection_manager );
		}

		$is_connection_ready = self::is_connection_ready();

		if ( $is_connection_ready ) {
			add_action( 'login_form_jetpack_json_api_authorization', array( $this, 'login_form_json_api_authorization' ) );

			Jetpack_Heartbeat::init();
			if ( self::is_module_active( 'stats' ) && self::is_module_active( 'search' ) ) {
				require_once JETPACK__PLUGIN_DIR . '_inc/lib/class.jetpack-search-performance-logger.php';
				Jetpack_Search_Performance_Logger::init();
			}
		}

		// Initialize remote file upload request handlers.
		$this->add_remote_request_handlers();

		/*
		 * Enable enhanced handling of previewing sites in Calypso
		 */
		if ( $is_connection_ready ) {
			require_once JETPACK__PLUGIN_DIR . '_inc/lib/class.jetpack-iframe-embed.php';
			add_action( 'init', array( 'Jetpack_Iframe_Embed', 'init' ), 9, 0 );
			require_once JETPACK__PLUGIN_DIR . '_inc/lib/class.jetpack-keyring-service-helper.php';
			add_action( 'init', array( 'Jetpack_Keyring_Service_Helper', 'init' ), 9, 0 );
		}

		if ( ( new Tracking( 'jetpack', $this->connection_manager ) )->should_enable_tracking( new Terms_Of_Service(), new Status() ) ) {
			add_action( 'init', array( new Plugin_Tracking(), 'init' ) );
		} else {
			/**
			 * Initialize tracking right after the user agrees to the terms of service.
			 */
			add_action( 'jetpack_agreed_to_terms_of_service', array( new Plugin_Tracking(), 'init' ) );
		}
	}

	/**
	 * Runs on plugins_loaded. Use this to add code that needs to be executed later than other
	 * initialization code.
	 *
	 * @action plugins_loaded
	 */
	public function late_initialization() {
		add_action( 'plugins_loaded', array( 'Jetpack', 'load_modules' ), 100 );

		Partner::init();
		My_Jetpack_Initializer::init();

		/**
		 * Fires when Jetpack is fully loaded and ready. This is the point where it's safe
		 * to instantiate classes from packages and namespaces that are managed by the Jetpack Autoloader.
		 *
		 * @since 8.1.0
		 *
		 * @param Jetpack $jetpack the main plugin class object.
		 */
		do_action( 'jetpack_loaded', $this );

		add_filter( 'map_meta_cap', array( $this, 'jetpack_custom_caps' ), 1, 2 );
	}

	/**
	 * This is ported over from the manage module, which has been deprecated and baked in here.
	 */
	public function add_wpcom_to_allowed_redirect_hosts() {
		add_filter( 'allowed_redirect_hosts', array( $this, 'allow_wpcom_domain' ) );
	}

	/**
	 * Return $domains, with 'wordpress.com' appended.
	 * This is ported over from the manage module, which has been deprecated and baked in here.
	 *
	 * @param array $domains Array of domains allowed for redirect.
	 *
	 * @return array
	 */
	public function allow_wpcom_domain( $domains ) {
		if ( empty( $domains ) ) {
			$domains = array();
		}
		$domains[] = 'wordpress.com';
		return array_unique( $domains );
	}

	/**
	 * Redirect edit post links to Calypso.
	 *
	 * @param string $default_url Post edit URL.
	 * @param int    $post_id Post ID.
	 *
	 * @return string
	 */
	public function point_edit_post_links_to_calypso( $default_url, $post_id ) {
		$post = get_post( $post_id );

		if ( empty( $post ) ) {
			return $default_url;
		}

		$post_type = $post->post_type;

		// Mapping the allowed CPTs on WordPress.com to corresponding paths in Calypso.
		// https://en.support.wordpress.com/custom-post-types/.
		$allowed_post_types = array(
			'post',
			'page',
			'jetpack-portfolio',
			'jetpack-testimonial',
		);

		if ( ! in_array( $post_type, $allowed_post_types, true ) ) {
			return $default_url;
		}

		return Redirect::get_url(
			'calypso-edit-' . $post_type,
			array(
				'path' => $post_id,
			)
		);
	}

	/**
	 * Redirect edit comment links to Calypso.
	 *
	 * @param string $url Comment edit URL.
	 *
	 * @return string
	 */
	public function point_edit_comment_links_to_calypso( $url ) {
		// Take the `query` key value from the URL, and parse its parts to the $query_args. `amp;c` matches the comment ID.
		$query_args = null;
		wp_parse_str( wp_parse_url( $url, PHP_URL_QUERY ), $query_args );

		return Redirect::get_url(
			'calypso-edit-comment',
			array(
				'path' => $query_args['amp;c'],
			)
		);
	}

	/**
	 * Extend Sync callables with Jetpack Plugin functions.
	 *
	 * @param array $callables list of callables.
	 *
	 * @return array list of callables.
	 */
	public function filter_sync_callable_whitelist( $callables ) {

		// Jetpack Functions.
		$jetpack_callables = array(
			'single_user_site'         => array( 'Jetpack', 'is_single_user_site' ),
			'updates'                  => array( 'Jetpack', 'get_updates' ),
			'available_jetpack_blocks' => array( 'Jetpack_Gutenberg', 'get_availability' ), // Includes both Gutenberg blocks *and* plugins.
		);
		$callables         = array_merge( $callables, $jetpack_callables );

		// Jetpack_SSO_Helpers.
		if ( include_once JETPACK__PLUGIN_DIR . 'modules/sso/class.jetpack-sso-helpers.php' ) {
			$sso_helpers = array(
				'sso_is_two_step_required'      => array( 'Jetpack_SSO_Helpers', 'is_two_step_required' ),
				'sso_should_hide_login_form'    => array( 'Jetpack_SSO_Helpers', 'should_hide_login_form' ),
				'sso_match_by_email'            => array( 'Jetpack_SSO_Helpers', 'match_by_email' ),
				'sso_new_user_override'         => array( 'Jetpack_SSO_Helpers', 'new_user_override' ),
				'sso_bypass_default_login_form' => array( 'Jetpack_SSO_Helpers', 'bypass_login_forward_wpcom' ),
			);
			$callables   = array_merge( $callables, $sso_helpers );
		}

		return $callables;
	}

	/**
	 * Extend Sync multisite callables with Jetpack Plugin functions.
	 *
	 * @param array $callables list of callables.
	 *
	 * @return array list of callables.
	 */
	public function filter_sync_multisite_callable_whitelist( $callables ) {

		// Jetpack Funtions.
		$jetpack_multisite_callables = array(
			'network_name'                        => array( 'Jetpack', 'network_name' ),
			'network_allow_new_registrations'     => array( 'Jetpack', 'network_allow_new_registrations' ),
			'network_add_new_users'               => array( 'Jetpack', 'network_add_new_users' ),
			'network_site_upload_space'           => array( 'Jetpack', 'network_site_upload_space' ),
			'network_upload_file_types'           => array( 'Jetpack', 'network_upload_file_types' ),
			'network_enable_administration_menus' => array( 'Jetpack', 'network_enable_administration_menus' ),
		);
		$callables                   = array_merge( $callables, $jetpack_multisite_callables );

		return $callables;
	}

	/**
	 * Deprecated
	 * Please use Automattic\Jetpack\JITMS\JITM::jetpack_track_last_sync_callback instead.
	 *
	 * @param array $params The action parameters.
	 *
	 * @deprecated since 9.8.
	 */
	public function jetpack_track_last_sync_callback( $params ) {
		_deprecated_function( __METHOD__, 'jetpack-9.8', '\Automattic\Jetpack\JITMS\JITM->jetpack_track_last_sync_callback' );
		return Automattic\Jetpack\JITMS\JITM::get_instance()->jetpack_track_last_sync_callback( $params );
	}

	/**
	 * Jetpack Connection banner callback function.
	 *
	 * @return void
	 */
	public function jetpack_connection_banner_callback() {
		check_ajax_referer( 'jp-connection-banner-nonce', 'nonce' );

		// Disable the banner dismiss functionality if the pre-connection prompt helpers filter is set.
		if (
			isset( $_REQUEST['dismissBanner'] ) &&
			! Jetpack_Connection_Banner::force_display()
		) {
			Jetpack_Options::update_option( 'dismissed_connection_banner', 1 );
			wp_send_json_success();
		}

		wp_die();
	}

	/**
	 * If there are any stats that need to be pushed, but haven't been, push them now.
	 */
	public function push_stats() {
		if ( ! empty( $this->stats ) ) {
			$this->do_stats( 'server_side' );
		}
	}

	/**
	 * Sets the Jetpack custom capabilities.
	 *
	 * @param string[] $caps    Array of the user's capabilities.
	 * @param string   $cap     Capability name.
	 */
	public function jetpack_custom_caps( $caps, $cap ) {
		switch ( $cap ) {
			case 'jetpack_manage_modules':
			case 'jetpack_activate_modules':
			case 'jetpack_deactivate_modules':
				$caps = array( 'manage_options' );
				break;
			case 'jetpack_configure_modules':
				$caps = array( 'manage_options' );
				break;
			case 'jetpack_manage_autoupdates':
				$caps = array(
					'manage_options',
					'update_plugins',
				);
				break;
			case 'jetpack_network_admin_page':
			case 'jetpack_network_settings_page':
				$caps = array( 'manage_network_plugins' );
				break;
			case 'jetpack_network_sites_page':
				$caps = array( 'manage_sites' );
				break;
			case 'jetpack_admin_page':
				$is_offline_mode = ( new Status() )->is_offline_mode();
				if ( $is_offline_mode ) {
					$caps = array( 'manage_options' );
					break;
				} else {
					$caps = array( 'read' );
				}
				break;
		}
		return $caps;
	}

	/**
	 * Register assets for use in various modules and the Jetpack admin page.
	 *
	 * @uses wp_script_is, wp_register_script, plugins_url
	 * @action wp_loaded
	 * @return void
	 */
	public function register_assets() {
		if ( ! wp_script_is( 'jetpack-gallery-settings', 'registered' ) ) {
			wp_register_script(
				'jetpack-gallery-settings',
				Assets::get_file_url_for_environment( '_inc/build/gallery-settings.min.js', '_inc/gallery-settings.js' ),
				array( 'media-views' ),
				'20121225',
				true
			);
		}

		if ( ! wp_script_is( 'jetpack-twitter-timeline', 'registered' ) ) {
			wp_register_script(
				'jetpack-twitter-timeline',
				Assets::get_file_url_for_environment( '_inc/build/twitter-timeline.min.js', '_inc/twitter-timeline.js' ),
				array(),
				'4.0.0',
				true
			);
		}

		if ( ! wp_script_is( 'jetpack-facebook-embed', 'registered' ) ) {
			wp_register_script(
				'jetpack-facebook-embed',
				Assets::get_file_url_for_environment( '_inc/build/facebook-embed.min.js', '_inc/facebook-embed.js' ),
				array(),
				JETPACK__VERSION,
				true
			);

			/** This filter is documented in modules/sharedaddy/sharing-sources.php */
			$fb_app_id = apply_filters( 'jetpack_sharing_facebook_app_id', '249643311490' );
			if ( ! is_numeric( $fb_app_id ) ) {
				$fb_app_id = '';
			}
			wp_localize_script(
				'jetpack-facebook-embed',
				'jpfbembed',
				array(
					'appid'  => $fb_app_id,
					'locale' => $this->get_locale(),
				)
			);
		}

		/**
		 * As jetpack_register_genericons is by default fired off a hook,
		 * the hook may have already fired by this point.
		 * So, let's just trigger it manually.
		 */
		require_once JETPACK__PLUGIN_DIR . '_inc/genericons.php';
		jetpack_register_genericons();

		/**
		 * Register the social logos
		 */
		require_once JETPACK__PLUGIN_DIR . '_inc/social-logos.php';
		jetpack_register_social_logos();
	}

	/**
	 * Guess locale from language code.
	 *
	 * @param string $lang Language code.
	 * @return string|bool
	 */
	public function guess_locale_from_lang( $lang ) {
		if ( 'en' === $lang || 'en_US' === $lang || ! $lang ) {
			return 'en_US';
		}

		if ( ! class_exists( 'GP_Locales' ) ) {
			if ( ! defined( 'JETPACK__GLOTPRESS_LOCALES_PATH' ) || ! file_exists( JETPACK__GLOTPRESS_LOCALES_PATH ) ) {
				return false;
			}

			require JETPACK__GLOTPRESS_LOCALES_PATH;
		}

		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			// WP.com: get_locale() returns 'it'.
			$locale = GP_Locales::by_slug( $lang );
		} else {
			// Jetpack: get_locale() returns 'it_IT';.
			$locale = GP_Locales::by_field( 'facebook_locale', $lang );
		}

		if ( ! $locale ) {
			return false;
		}

		if ( empty( $locale->facebook_locale ) ) {
			if ( empty( $locale->wp_locale ) ) {
				return false;
			} else {
				// Facebook SDK is smart enough to fall back to en_US if a
				// locale isn't supported. Since supported Facebook locales
				// can fall out of sync, we'll attempt to use the known
				// wp_locale value and rely on said fallback.
				return $locale->wp_locale;
			}
		}

		return $locale->facebook_locale;
	}

	/**
	 * Get the locale.
	 *
	 * @return string|bool
	 */
	public function get_locale() {
		$locale = $this->guess_locale_from_lang( get_locale() );

		if ( ! $locale ) {
			$locale = 'en_US';
		}

		return $locale;
	}

	/**
	 * Return the network_site_url so that .com knows what network this site is a part of.
	 *
	 * @return string
	 */
	public function jetpack_main_network_site_option() {
		return network_site_url();
	}
	/**
	 * Network Name.
	 */
	public static function network_name() {
		global $current_site;
		return $current_site->site_name;
	}
	/**
	 * Does the network allow new user and site registrations.
	 *
	 * @return string
	 */
	public static function network_allow_new_registrations() {
		return ( in_array( get_site_option( 'registration' ), array( 'none', 'user', 'blog', 'all' ), true ) ? get_site_option( 'registration' ) : 'none' );
	}
	/**
	 * Does the network allow admins to add new users.
	 *
	 * @return boolian
	 */
	public static function network_add_new_users() {
		return (bool) get_site_option( 'add_new_users' );
	}
	/**
	 * File upload psace left per site in MB.
	 *  -1 means NO LIMIT.
	 *
	 * @return number
	 */
	public static function network_site_upload_space() {
		// value in MB.
		return ( get_site_option( 'upload_space_check_disabled' ) ? -1 : get_space_allowed() );
	}

	/**
	 * Network allowed file types.
	 *
	 * @return string
	 */
	public static function network_upload_file_types() {
		return get_site_option( 'upload_filetypes', 'jpg jpeg png gif' );
	}

	/**
	 * Maximum file upload size set by the network.
	 *
	 * @return number
	 */
	public static function network_max_upload_file_size() {
		// value in KB.
		return get_site_option( 'fileupload_maxk', 300 );
	}

	/**
	 * Lets us know if a site allows admins to manage the network.
	 *
	 * @return array
	 */
	public static function network_enable_administration_menus() {
		return get_site_option( 'menu_items' );
	}

	/**
	 * If a user has been promoted to or demoted from admin, we need to clear the
	 * jetpack_other_linked_admins transient.
	 *
	 * @since 4.3.2
	 * @since 4.4.0  $old_roles is null by default and if it's not passed, the transient is cleared.
	 *
	 * @param int    $user_id   The user ID whose role changed.
	 * @param string $role      The new role.
	 * @param array  $old_roles An array of the user's previous roles.
	 */
	public function maybe_clear_other_linked_admins_transient( $user_id, $role, $old_roles = null ) {
		if ( 'administrator' === $role
			|| ( is_array( $old_roles ) && in_array( 'administrator', $old_roles, true ) )
			|| $old_roles === null
		) {
			delete_transient( 'jetpack_other_linked_admins' );
		}
	}

	/**
	 * Checks to see if there are any other users available to become primary
	 * Users must both:
	 * - Be linked to wpcom
	 * - Be an admin
	 *
	 * @return mixed False if no other users are linked, Int if there are.
	 */
	public static function get_other_linked_admins() {
		$other_linked_users = get_transient( 'jetpack_other_linked_admins' );

		if ( false === $other_linked_users ) {
			$admins = get_users( array( 'role' => 'administrator' ) );
			if ( count( $admins ) > 1 ) {
				$available = array();
				foreach ( $admins as $admin ) {
					if ( self::connection()->is_user_connected( $admin->ID ) ) {
						$available[] = $admin->ID;
					}
				}

				$count_connected_admins = count( $available );
				if ( count( $available ) > 1 ) {
					$other_linked_users = $count_connected_admins;
				} else {
					$other_linked_users = 0;
				}
			} else {
				$other_linked_users = 0;
			}

			set_transient( 'jetpack_other_linked_admins', $other_linked_users, HOUR_IN_SECONDS );
		}

		return ( 0 === $other_linked_users ) ? false : $other_linked_users;
	}

	/**
	 * Return whether we are dealing with a multi network setup or not.
	 * The reason we are type casting this is because we want to avoid the situation where
	 * the result is false since when is_main_network_option return false it cases
	 * the rest the get_option( 'jetpack_is_multi_network' ); to return the value that is set in the
	 * database which could be set to anything as opposed to what this function returns.
	 *
	 * @return boolean
	 */
	public function is_main_network_option() {
		// returns either an '1' or an empty string.
		return (string) (bool) self::is_multi_network();
	}

	/**
	 * Return true if we are with multi-site or multi-network false if we are dealing with single site.
	 *
	 * @return string
	 */
	public function is_multisite() {
		return (string) (bool) is_multisite();
	}

	/**
	 * Implemented since there is no core is multi network function
	 * Right now there is no way to tell if we which network is the dominant network on the system
	 *
	 * @since  3.3
	 * @return boolean
	 */
	public static function is_multi_network() {
		global  $wpdb;

		// if we don't have a multi site setup no need to do any more.
		if ( ! is_multisite() ) {
			return false;
		}

		$num_sites = $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->site}" );
		if ( $num_sites > 1 ) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Get back if the current site is single user site.
	 *
	 * @return bool
	 */
	public static function is_single_user_site() {
		global $wpdb;

		$some_users = get_transient( 'jetpack_is_single_user' );
		if ( false === $some_users ) {
			$some_users = $wpdb->get_var( "SELECT COUNT(*) FROM (SELECT user_id FROM $wpdb->usermeta WHERE meta_key = '{$wpdb->prefix}capabilities' LIMIT 2) AS someusers" );
			set_transient( 'jetpack_is_single_user', (int) $some_users, 12 * HOUR_IN_SECONDS );
		}
		return 1 === (int) $some_users;
	}

	/**
	 * Returns true if the site has file write access false otherwise.
	 *
	 * @return string ( '1' | '0' )
	 **/
	public static function file_system_write_access() {
		if ( ! function_exists( 'get_filesystem_method' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		require_once ABSPATH . 'wp-admin/includes/template.php';

		$filesystem_method = get_filesystem_method();
		if ( 'direct' === $filesystem_method ) {
			return 1;
		}

		ob_start();
		$filesystem_credentials_are_stored = request_filesystem_credentials( self_admin_url() );
		ob_end_clean();
		if ( $filesystem_credentials_are_stored ) {
			return 1;
		}
		return 0;
	}

// phpcs:disable WordPress.WP.CapitalPDangit.Misspelled
	/**
	 * Gets updates and stores in jetpack_updates.
	 *
	 * The jetpack_updates option is saved in the following schema:
	 *
	 * array (
	 *      'plugins'                       => (int) Number of plugin updates available.
	 *      'themes'                        => (int) Number of theme updates available.
	 *      'wordpress'                     => (int) Number of WordPress core updates available.
	 *      'translations'                  => (int) Number of translation updates available.
	 *      'total'                         => (int) Total of all available updates.
	 *      'wp_update_version'             => (string) The latest available version of WordPress, only present if a WordPress update is needed.
	 * )
	 *
	 * @return array
	 */
	public static function get_updates() {
		$update_data = wp_get_update_data();

		// Stores the individual update counts as well as the total count.
		if ( isset( $update_data['counts'] ) ) {
			$updates = $update_data['counts'];
		}

		// If we need to update WordPress core, let's find the latest version number.
		if ( ! empty( $updates['wordpress'] ) ) {
			$cur = get_preferred_from_update_core();
			if ( isset( $cur->response ) && 'upgrade' === $cur->response ) {
				$updates['wp_update_version'] = $cur->current;
			}
		}
		return isset( $updates ) ? $updates : array();
	}
	// phpcs:enable

	/**
	 * Get update details for core, plugins, and themes.
	 *
	 * @return array
	 */
	public static function get_update_details() {
		$update_details = array(
			'update_core'    => get_site_transient( 'update_core' ),
			'update_plugins' => get_site_transient( 'update_plugins' ),
			'update_themes'  => get_site_transient( 'update_themes' ),
		);
		return $update_details;
	}

	/**
	 * Is Jetpack active?
	 * The method only checks if there's an existing token for the master user. It doesn't validate the token.
	 *
	 * This method is deprecated since 9.6.0. Please use one of the methods provided by the Manager class in the Connection package,
	 * or Jetpack::is_connection_ready if you want to know when the Jetpack plugin starts considering the connection ready to be used.
	 *
	 * Since this method has a wide spread use, we decided not to throw any deprecation warnings for now.
	 *
	 * @deprecated 9.6.0
	 *
	 * @return bool
	 */
	public static function is_active() {
		return self::connection()->has_connected_owner();
	}

	/**
	 * Returns true if the current site is connected to WordPress.com and has the minimum requirements to enable Jetpack UI
	 *
	 * This method was introduced just before the release of the possibility to use Jetpack without a user connection, while
	 * it was available only when no_user_testing_mode was enabled. In the near future, this will return is_connected for all
	 * users and this option will be available by default for everybody.
	 *
	 * @since 9.6.0
	 * @since 9.7.0 returns is_connected in all cases and adds filter to the returned value
	 *
	 * @return bool is the site connection ready to be used?
	 */
	public static function is_connection_ready() {
		/**
		 * Allows filtering whether the connection is ready to be used. If true, this will enable the Jetpack UI and modules
		 *
		 * Modules will be enabled depending on the connection status and if the module requires a connection or user connection.
		 *
		 * @since 9.7.0
		 *
		 * @param bool                                  $is_connection_ready Is the connection ready?
		 * @param Automattic\Jetpack\Connection\Manager $connection_manager Instance of the Manager class, can be used to check the connection status.
		 */
		return apply_filters( 'jetpack_is_connection_ready', self::connection()->is_connected(), self::connection() );
	}

	/**
	 * Deprecated: Is Jetpack in development (offline) mode?
	 *
	 * This static method is being left here intentionally without the use of _deprecated_function(), as other plugins
	 * and themes still use it, and we do not want to flood them with notices.
	 *
	 * Please use Automattic\Jetpack\Status()->is_offline_mode() instead.
	 *
	 * @deprecated since 8.0.
	 */
	public static function is_development_mode() {
		_deprecated_function( __METHOD__, 'jetpack-8.0', '\Automattic\Jetpack\Status->is_offline_mode' );
		return ( new Status() )->is_offline_mode();
	}

	/**
	 * Whether the site is currently onboarding or not.
	 * A site is considered as being onboarded if it currently has an onboarding token.
	 *
	 * @since 5.8
	 * @deprecated Use \Automattic\Jetpack\Status()->is_onboarding()
	 *
	 * @access public
	 * @static
	 *
	 * @return bool True if the site is currently onboarding, false otherwise
	 */
	public static function is_onboarding() {
		_deprecated_function( __METHOD__, 'jetpack-10.9', 'Automattic\\Jetpack\\Status\\is_onboarding' );

		if ( ! method_exists( 'Automattic\Jetpack\Status', 'is_onboarding' ) ) {
			return Jetpack_Options::get_option( 'onboarding' ) !== false;
		}
		return ( new Status() )->is_onboarding();
	}

	/**
	 * Determines reason for Jetpack offline mode.
	 */
	public static function development_mode_trigger_text() {
		$status = new Status();

		if ( ! $status->is_offline_mode() ) {
			return __( 'Jetpack is not in Offline Mode.', 'jetpack' );
		}

		if ( defined( 'JETPACK_DEV_DEBUG' ) && JETPACK_DEV_DEBUG ) {
			$notice = __( 'The JETPACK_DEV_DEBUG constant is defined in wp-config.php or elsewhere.', 'jetpack' );
		} elseif ( defined( 'WP_LOCAL_DEV' ) && WP_LOCAL_DEV ) {
			$notice = __( 'The WP_LOCAL_DEV constant is defined in wp-config.php or elsewhere.', 'jetpack' );
		} elseif ( $status->is_local_site() ) {
			$notice = __( 'The site URL is a known local development environment URL (e.g. http://localhost).', 'jetpack' );
			/** This filter is documented in packages/status/src/class-status.php */
		} elseif ( has_filter( 'jetpack_development_mode' ) && apply_filters( 'jetpack_development_mode', false ) ) { // This is a deprecated filter name.
			$notice = __( 'The jetpack_development_mode filter is set to true.', 'jetpack' );
		} else {
			$notice = __( 'The jetpack_offline_mode filter is set to true.', 'jetpack' );
		}

		return $notice;
	}
	/**
	 * Get Jetpack offline mode notice text and notice class.
	 *
	 * Mirrors the checks made in Automattic\Jetpack\Status->is_offline_mode
	 */
	public static function show_development_mode_notice() {
		if ( ( new Status() )->is_offline_mode() ) {
			$notice = sprintf(
				/* translators: %s is a URL */
				__( 'In <a href="%s" target="_blank">Offline Mode</a>:', 'jetpack' ),
				Redirect::get_url( 'jetpack-support-development-mode' )
			);

			$notice .= ' ' . self::development_mode_trigger_text();

			echo '<div class="updated" style="border-color: #f0821e;"><p>' . $notice . '</p></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- All provided text.
		}

		// Throw up a notice if using a development version and as for feedback.
		if ( self::is_development_version() ) {
			/* translators: %s is a URL */
			$notice = sprintf( __( 'You are currently running a development version of Jetpack. <a href="%s" target="_blank">Submit your feedback</a>', 'jetpack' ), Redirect::get_url( 'jetpack-contact-support-beta-group' ) );

			echo '<div class="updated" style="border-color: #f0821e;"><p>' . $notice . '</p></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- All provided text.
		}
		// Throw up a notice if using staging mode.
		if ( ( new Status() )->is_staging_site() ) {
			/* translators: %s is a URL */
			$notice = sprintf( __( 'You are running Jetpack on a <a href="%s" target="_blank">staging server</a>.', 'jetpack' ), Redirect::get_url( 'jetpack-support-staging-sites' ) );

			echo '<div class="updated" style="border-color: #f0821e;"><p>' . $notice . '</p></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- All provided text.
		}
	}

	/**
	 * Whether Jetpack's version maps to a public release, or a development version.
	 */
	public static function is_development_version() {
		/**
		 * Allows filtering whether this is a development version of Jetpack.
		 *
		 * This filter is especially useful for tests.
		 *
		 * @since 4.3.0
		 *
		 * @param bool $development_version Is this a develoment version of Jetpack?
		 */
		return (bool) apply_filters(
			'jetpack_development_version',
			! preg_match( '/^\d+(\.\d+)+$/', Constants::get_constant( 'JETPACK__VERSION' ) )
		);
	}

	/**
	 * Is a given user (or the current user if none is specified) linked to a WordPress.com user?
	 *
	 * @param int $user_id User ID or will use get_current_user_id if false/not provided.
	 */
	public static function is_user_connected( $user_id = false ) {
		_deprecated_function( __METHOD__, 'jetpack-9.5', 'Automattic\\Jetpack\\Connection\\Manager\\is_user_connected' );
		return self::connection()->is_user_connected( $user_id );
	}

	/**
	 * Get the wpcom user data of the current|specified connected user.
	 *
	 * @param null|int $user_id User ID or will use get_current_user_id if null.
	 */
	public static function get_connected_user_data( $user_id = null ) {
		_deprecated_function( __METHOD__, 'jetpack-9.5', 'Automattic\\Jetpack\\Connection\\Manager\\get_connected_user_data' );
		return self::connection()->get_connected_user_data( $user_id );
	}

	/**
	 * Get the wpcom email of the current|specified connected user.
	 *
	 * @param null|int $user_id User ID or will use get_current_user_id if null.
	 */
	public static function get_connected_user_email( $user_id = null ) {
		if ( ! $user_id ) {
			$user_id = get_current_user_id();
		}

		$xml = new Jetpack_IXR_Client(
			array(
				'user_id' => $user_id,
			)
		);
		$xml->query( 'wpcom.getUserEmail' );
		if ( ! $xml->isError() ) {
			return $xml->getResponse();
		}
		return false;
	}

	/**
	 * Get the wpcom email of the master user.
	 */
	public static function get_master_user_email() {
		$master_user_id = Jetpack_Options::get_option( 'master_user' );
		if ( $master_user_id ) {
			return self::get_connected_user_email( $master_user_id );
		}
		return '';
	}

	/**
	 * Gets current user IP address.
	 *
	 * @param  bool $check_all_headers Check all headers? Default is `false`.
	 *
	 * @deprecated Jetpack 10.6
	 *
	 * @return string                  Current user IP address.
	 */
	public static function current_user_ip( $check_all_headers = false ) {
		_deprecated_function( __METHOD__, 'jetpack-10.6', 'Automattic\\Jetpack\\Status\\Visitor::get_ip' );

		return ( new Visitor() )->get_ip( $check_all_headers );
	}

	/**
	 * Loads the currently active modules.
	 */
	public static function load_modules() {
		$status = new Status();

		if ( method_exists( $status, 'is_onboarding' ) ) {
			$is_onboarding = $status->is_onboarding();
		} else {
			$is_onboarding = self::is_onboarding();
		}

		if (
			! self::is_connection_ready()
			&& ! $status->is_offline_mode()
			&& ! $is_onboarding
			&& (
				! is_multisite()
				|| ! get_site_option( 'jetpack_protect_active' )
			)
		) {
			return;
		}

		$version = Jetpack_Options::get_option( 'version' );
		if ( ! $version ) {
			$version     = JETPACK__VERSION . ':' . time();
			$old_version = $version;
			/** This action is documented in class.jetpack.php */
			do_action( 'updating_jetpack_version', $version, false );
			Jetpack_Options::update_options( compact( 'version', 'old_version' ) );
		}
		list( $version ) = explode( ':', $version );

		$modules = array_filter( self::get_active_modules(), array( 'Jetpack', 'is_module' ) );

		$modules_data = array();

		// Don't load modules that have had "Major" changes since the stored version until they have been deactivated/reactivated through the lint check.
		if ( version_compare( $version, JETPACK__VERSION, '<' ) ) {
			$updated_modules = array();
			foreach ( $modules as $module ) {
				$modules_data[ $module ] = self::get_module( $module );
				if ( ! isset( $modules_data[ $module ]['changed'] ) ) {
					continue;
				}

				if ( version_compare( $modules_data[ $module ]['changed'], $version, '<=' ) ) {
					continue;
				}

				$updated_modules[] = $module;
			}

			$modules = array_diff( $modules, $updated_modules );
		}

		$is_site_connection = false;

		if ( method_exists( self::connection(), 'is_site_connection' ) ) {
			$is_site_connection = self::connection()->is_site_connection();
		}

		foreach ( $modules as $index => $module ) {
			// If we're in offline/site-connection mode, disable modules requiring a connection/user connection.
			if ( $status->is_offline_mode() || $is_site_connection ) {
				// Prime the pump if we need to.
				if ( empty( $modules_data[ $module ] ) ) {
					$modules_data[ $module ] = self::get_module( $module );
				}
				// If the module requires a connection, but we're in local mode, don't include it.
				if ( $status->is_offline_mode() && $modules_data[ $module ]['requires_connection'] ) {
					continue;
				}

				if ( $is_site_connection && $modules_data[ $module ]['requires_user_connection'] ) {
					continue;
				}
			}

			if ( did_action( 'jetpack_module_loaded_' . $module ) ) {
				continue;
			}

			if ( ! include_once self::get_module_path( $module ) ) { // phpcs:ignore WordPressVIPMinimum.Files.IncludingFile.NotAbsolutePath
				unset( $modules[ $index ] );
				self::update_active_modules( array_values( $modules ) );
				continue;
			}

			/**
			 * Fires when a specific module is loaded.
			 * The dynamic part of the hook, $module, is the module slug.
			 *
			 * @since 1.1.0
			 */
			do_action( 'jetpack_module_loaded_' . $module );
		}

		/**
		 * Fires when all the modules are loaded.
		 *
		 * @since 1.1.0
		 */
		do_action( 'jetpack_modules_loaded' );

		// Load module-specific code that is needed even when a module isn't active. Loaded here because code contained therein may need actions such as setup_theme.
		require_once JETPACK__PLUGIN_DIR . 'modules/module-extras.php';
	}

	/**
	 * Check if Jetpack's REST API compat file should be included
	 *
	 * @action plugins_loaded
	 * @return void
	 */
	public function check_rest_api_compat() {
		/**
		 * Filters the list of REST API compat files to be included.
		 *
		 * @since 2.2.5
		 *
		 * @param array $args Array of REST API compat files to include.
		 */
		$_jetpack_rest_api_compat_includes = apply_filters( 'jetpack_rest_api_compat', array() );

		foreach ( $_jetpack_rest_api_compat_includes as $_jetpack_rest_api_compat_include ) {
			require_once $_jetpack_rest_api_compat_include;
		}
	}

	/**
	 * Gets all plugins currently active in values, regardless of whether they're
	 * traditionally activated or network activated.
	 *
	 * @todo Store the result in core's object cache maybe?
	 */
	public static function get_active_plugins() {
		$active_plugins = (array) get_option( 'active_plugins', array() );

		if ( is_multisite() ) {
			// Due to legacy code, active_sitewide_plugins stores them in the keys,
			// whereas active_plugins stores them in the values.
			$network_plugins = array_keys( get_site_option( 'active_sitewide_plugins', array() ) );
			if ( $network_plugins ) {
				$active_plugins = array_merge( $active_plugins, $network_plugins );
			}
		}

		sort( $active_plugins );

		return array_unique( $active_plugins );
	}

	/**
	 * Gets and parses additional plugin data to send with the heartbeat data
	 *
	 * @since 3.8.1
	 *
	 * @return array Array of plugin data
	 */
	public static function get_parsed_plugin_data() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		/** This filter is documented in wp-admin/includes/class-wp-plugins-list-table.php */
		$all_plugins    = apply_filters( 'all_plugins', get_plugins() );
		$active_plugins = self::get_active_plugins();

		$plugins = array();
		foreach ( $all_plugins as $path => $plugin_data ) {
			$plugins[ $path ] = array(
				'is_active' => in_array( $path, $active_plugins, true ),
				'file'      => $path,
				'name'      => $plugin_data['Name'],
				'version'   => $plugin_data['Version'],
				'author'    => $plugin_data['Author'],
			);
		}

		return $plugins;
	}

	/**
	 * Gets and parses theme data to send with the heartbeat data
	 *
	 * @since 3.8.1
	 *
	 * @return array Array of theme data
	 */
	public static function get_parsed_theme_data() {
		$all_themes  = wp_get_themes( array( 'allowed' => true ) );
		$header_keys = array( 'Name', 'Author', 'Version', 'ThemeURI', 'AuthorURI', 'Status', 'Tags' );

		$themes = array();
		foreach ( $all_themes as $slug => $theme_data ) {
			$theme_headers = array();
			foreach ( $header_keys as $header_key ) {
				$theme_headers[ $header_key ] = $theme_data->get( $header_key );
			}

			$themes[ $slug ] = array(
				'is_active_theme' => wp_get_theme()->get_template() === $slug,
				'slug'            => $slug,
				'theme_root'      => $theme_data->get_theme_root_uri(),
				'parent'          => $theme_data->parent(),
				'headers'         => $theme_headers,
			);
		}

		return $themes;
	}

	/**
	 * Checks whether a specific plugin is active.
	 *
	 * We don't want to store these in a static variable, in case
	 * there are switch_to_blog() calls involved.
	 *
	 * @param string $plugin Plugin to check in 'folder/file.php` format.
	 */
	public static function is_plugin_active( $plugin = 'jetpack/jetpack.php' ) {
		return in_array( $plugin, self::get_active_plugins(), true );
	}

	/**
	 * Check if Jetpack's Open Graph tags should be used.
	 * If certain plugins are active, Jetpack's og tags are suppressed.
	 *
	 * @uses Jetpack::get_active_modules, add_filter, get_option, apply_filters
	 * @action plugins_loaded
	 * @return void
	 */
	public function check_open_graph() {
		if ( in_array( 'publicize', self::get_active_modules(), true ) || in_array( 'sharedaddy', self::get_active_modules(), true ) ) {
			include_once JETPACK__PLUGIN_DIR . 'enhanced-open-graph.php';
			add_filter( 'jetpack_enable_open_graph', '__return_true', 0 );
		}

		$active_plugins = self::get_active_plugins();

		if ( ! empty( $active_plugins ) ) {
			foreach ( $this->open_graph_conflicting_plugins as $plugin ) {
				if ( in_array( $plugin, $active_plugins, true ) ) {
					add_filter( 'jetpack_enable_open_graph', '__return_false', 99 );
					break;
				}
			}
		}

		/**
		 * Allow the addition of Open Graph Meta Tags to all pages.
		 *
		 * @since 2.0.3
		 *
		 * @param bool false Should Open Graph Meta tags be added. Default to false.
		 */
		if ( apply_filters( 'jetpack_enable_open_graph', false ) ) {
			require_once JETPACK__PLUGIN_DIR . 'functions.opengraph.php';
		}
	}

	/**
	 * Check if Jetpack's Twitter tags should be used.
	 * If certain plugins are active, Jetpack's twitter tags are suppressed.
	 *
	 * @uses Jetpack::get_active_modules, add_filter, get_option, apply_filters
	 * @action plugins_loaded
	 * @return void
	 */
	public function check_twitter_tags() {

		$active_plugins = self::get_active_plugins();

		if ( ! empty( $active_plugins ) ) {
			foreach ( $this->twitter_cards_conflicting_plugins as $plugin ) {
				if ( in_array( $plugin, $active_plugins, true ) ) {
					add_filter( 'jetpack_disable_twitter_cards', '__return_true', 99 );
					break;
				}
			}
		}

		/**
		 * Allow Twitter Card Meta tags to be disabled.
		 *
		 * @since 2.6.0
		 *
		 * @param bool true Should Twitter Card Meta tags be disabled. Default to true.
		 */
		if ( ! apply_filters( 'jetpack_disable_twitter_cards', false ) ) {
			require_once JETPACK__PLUGIN_DIR . 'class.jetpack-twitter-cards.php';
		}
	}

	/* Jetpack Options API */

	/**
	 * Gets the option names from Jetpack_Options.
	 *
	 * @param string $type Jetpack option type.
	 *
	 * @return array
	 */
	public static function get_option_names( $type = 'compact' ) {
		return Jetpack_Options::get_option_names( $type );
	}

	/**
	 * Returns the requested option.
	 *
	 * Looks in jetpack_options or jetpack_$name as appropriate.
	 *
	 * @param string $name    Option name.
	 * @param mixed  $default Default value.
	 */
	public static function get_option( $name, $default = false ) {
		return Jetpack_Options::get_option( $name, $default );
	}

	/**
	 * Returns an array of all PHP files in the specified absolute path.
	 * Equivalent to glob( "$absolute_path/*.php" ).
	 *
	 * @param string $absolute_path The absolute path of the directory to search.
	 * @return array Array of absolute paths to the PHP files.
	 */
	public static function glob_php( $absolute_path ) {
		return ( new Files() )->glob_php( $absolute_path );
	}

	/**
	 * Activate new modules.
	 *
	 * @param bool $redirect Should this function redirect after activation.
	 *
	 * @return void
	 */
	public static function activate_new_modules( $redirect = false ) {
		if ( ! self::is_connection_ready() && ! ( new Status() )->is_offline_mode() ) {
			return;
		}

		$jetpack_old_version = Jetpack_Options::get_option( 'version' );
		if ( ! $jetpack_old_version ) {
			$old_version         = '1.1:' . time();
			$version             = $old_version;
			$jetpack_old_version = $version;
			/** This action is documented in class.jetpack.php */
			do_action( 'updating_jetpack_version', $version, false );
			Jetpack_Options::update_options( compact( 'version', 'old_version' ) );
		}

		list( $jetpack_version ) = explode( ':', $jetpack_old_version );

		if ( version_compare( JETPACK__VERSION, $jetpack_version, '<=' ) ) {
			return;
		}

		$active_modules     = self::get_active_modules();
		$reactivate_modules = array();
		foreach ( $active_modules as $active_module ) {
			$module = self::get_module( $active_module );
			if ( ! isset( $module['changed'] ) ) {
				continue;
			}

			if ( version_compare( $module['changed'], $jetpack_version, '<=' ) ) {
				continue;
			}

			$reactivate_modules[] = $active_module;
			self::deactivate_module( $active_module );
		}

		$new_version = JETPACK__VERSION . ':' . time();
		/** This action is documented in class.jetpack.php */
		do_action( 'updating_jetpack_version', $new_version, $jetpack_old_version );
		Jetpack_Options::update_options(
			array(
				'version'     => $new_version,
				'old_version' => $jetpack_old_version,
			)
		);

		self::state( 'message', 'modules_activated' );

		self::activate_default_modules( $jetpack_version, JETPACK__VERSION, $reactivate_modules, $redirect );

		if ( $redirect ) {
			$page = 'jetpack'; // make sure we redirect to either settings or the jetpack page.
			if ( isset( $_GET['page'] ) && in_array( $_GET['page'], array( 'jetpack', 'jetpack_modules' ), true ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- we're not changing the site.
				$page = sanitize_text_field( wp_unslash( $_GET['page'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- we're not changing the site.
			}
			wp_safe_redirect( self::admin_url( 'page=' . rawurlencode( $page ) ) );
			exit;
		}
	}

	/**
	 * List available Jetpack modules. Simply lists .php files in /modules/.
	 * Make sure to tuck away module "library" files in a sub-directory.
	 *
	 * @param bool|string $min_version Only return modules introduced in this version or later. Default is false, do not filter.
	 * @param bool|string $max_version Only return modules introduced before this version. Default is false, do not filter.
	 * @param bool|null   $requires_connection Pass a boolean value to only return modules that require (or do not require) a connection.
	 * @param bool|null   $requires_user_connection Pass a boolean value to only return modules that require (or do not require) a user connection.
	 *
	 * @return array $modules Array of module slugs
	 */
	public static function get_available_modules( $min_version = false, $max_version = false, $requires_connection = null, $requires_user_connection = null ) {
		return ( new Modules() )->get_available( $min_version, $max_version, $requires_connection, $requires_user_connection );
	}

	/**
	 * Get default modules loaded on activation.
	 *
	 * @param bool|string $min_version Only return modules introduced in this version or later. Default is false, do not filter.
	 * @param bool|string $max_version Only return modules introduced before this version. Default is false, do not filter.
	 * @param bool|null   $requires_connection Pass a boolean value to only return modules that require (or do not require) a connection.
	 * @param bool|null   $requires_user_connection Pass a boolean value to only return modules that require (or do not require) a user connection.
	 *
	 * @return array $modules Array of module slugs
	 */
	public static function get_default_modules( $min_version = false, $max_version = false, $requires_connection = null, $requires_user_connection = null ) {
		$return = array();

		foreach ( self::get_available_modules( $min_version, $max_version, $requires_connection, $requires_user_connection ) as $module ) {
			$module_data = self::get_module( $module );

			switch ( strtolower( $module_data['auto_activate'] ) ) {
				case 'yes':
					$return[] = $module;
					break;
				case 'public':
					if ( Jetpack_Options::get_option( 'public' ) ) {
						$return[] = $module;
					}
					break;
				case 'no':
				default:
					break;
			}
		}
		/**
		 * Filters the array of default modules.
		 *
		 * @since 2.5.0
		 *
		 * @param array $return Array of default modules.
		 * @param string $min_version Minimum version number required to use modules.
		 * @param string $max_version Maximum version number required to use modules.
		 * @param bool|null $requires_connection Value of the Requires Connection filter.
		 * @param bool|null $requires_user_connection Value of the Requires User Connection filter.
		 */
		return apply_filters( 'jetpack_get_default_modules', $return, $min_version, $max_version, $requires_connection, $requires_user_connection );
	}

	/**
	 * Checks activated modules during auto-activation to determine
	 * if any of those modules are being deprecated.  If so, close
	 * them out, and add any replacement modules.
	 *
	 * Runs at priority 99 by default.
	 *
	 * This is run late, so that it can still activate a module if
	 * the new module is a replacement for another that the user
	 * currently has active, even if something at the normal priority
	 * would kibosh everything.
	 *
	 * @since 2.6
	 * @uses jetpack_get_default_modules filter
	 * @param array $modules Array of Jetpack modules.
	 * @return array
	 */
	public function handle_deprecated_modules( $modules ) {
		$deprecated_modules = array(
			'debug'            => null,  // Closed out and moved to the debugger library.
			'wpcc'             => 'sso', // Closed out in 2.6 -- SSO provides the same functionality.
			'gplus-authorship' => null,  // Closed out in 3.2 -- Google dropped support.
			'minileven'        => null,  // Closed out in 8.3 -- Responsive themes are common now, and so is AMP.
		);

		// Don't activate SSO if they never completed activating WPCC.
		if ( self::is_module_active( 'wpcc' ) ) {
			$wpcc_options = Jetpack_Options::get_option( 'wpcc_options' );
			if ( empty( $wpcc_options ) || empty( $wpcc_options['client_id'] ) || empty( $wpcc_options['client_id'] ) ) {
				$deprecated_modules['wpcc'] = null;
			}
		}

		foreach ( $deprecated_modules as $module => $replacement ) {
			if ( self::is_module_active( $module ) ) {
				self::deactivate_module( $module );
				if ( $replacement ) {
					$modules[] = $replacement;
				}
			}
		}

		return array_unique( $modules );
	}

	/**
	 * Checks activated plugins during auto-activation to determine
	 * if any of those plugins are in the list with a corresponding module
	 * that is not compatible with the plugin. The module will not be allowed
	 * to auto-activate.
	 *
	 * @since 2.6
	 * @uses jetpack_get_default_modules filter
	 * @param array $modules Array of Jetpack modules.
	 * @return array
	 */
	public function filter_default_modules( $modules ) {

		$active_plugins = self::get_active_plugins();

		if ( ! empty( $active_plugins ) ) {

			// For each module we'd like to auto-activate...
			foreach ( $modules as $key => $module ) {
				// If there are potential conflicts for it...
				if ( ! empty( $this->conflicting_plugins[ $module ] ) ) {
					// For each potential conflict...
					foreach ( $this->conflicting_plugins[ $module ] as $plugin ) {
						// If that conflicting plugin is active...
						if ( in_array( $plugin, $active_plugins, true ) ) {
							// Remove that item from being auto-activated.
							unset( $modules[ $key ] );
						}
					}
				}
			}
		}

		return $modules;
	}

	/**
	 * Extract a module's slug from its full path.
	 *
	 * @param string $file Full path to a file.
	 *
	 * @return string Module slug.
	 */
	public static function get_module_slug( $file ) {
		return ( new Modules() )->get_slug( $file );
	}

	/**
	 * Generate a module's path from its slug.
	 *
	 * @param string $slug Module slug.
	 */
	public static function get_module_path( $slug ) {
		return ( new Modules() )->get_path( $slug );
	}

	/**
	 * Load module data from module file. Headers differ from WordPress
	 * plugin headers to avoid them being identified as standalone
	 * plugins on the WordPress plugins page.
	 *
	 * @param string $module The module slug.
	 */
	public static function get_module( $module ) {
		return ( new Modules() )->get( $module );
	}

	/**
	 * Like core's get_file_data implementation, but caches the result.
	 *
	 * @param string $file Absolute path to the file.
	 * @param array  $headers List of headers, in the format array( 'HeaderKey' => 'Header Name' ).
	 */
	public static function get_file_data( $file, $headers ) {
		return ( new Modules() )->get_file_data( $file, $headers );
	}

	/**
	 * Return translated module tag.
	 *
	 * @param string $tag Tag as it appears in each module heading.
	 *
	 * @return mixed
	 */
	public static function translate_module_tag( $tag ) {
		return jetpack_get_module_i18n_tag( $tag );
	}

	/**
	 * Return module name translation. Uses matching string created in modules/module-headings.php.
	 *
	 * @since 3.9.2
	 *
	 * @param array $modules Array of Jetpack modules.
	 *
	 * @return string|void
	 */
	public static function get_translated_modules( $modules ) {
		foreach ( $modules as $index => $module ) {
			$i18n_module = jetpack_get_module_i18n( $module['module'] );
			if ( isset( $module['name'] ) ) {
				$modules[ $index ]['name'] = $i18n_module['name'];
			}
			if ( isset( $module['description'] ) ) {
				$modules[ $index ]['description']       = $i18n_module['description'];
				$modules[ $index ]['short_description'] = $i18n_module['description'];
			}
			if ( isset( $module['module_tags'] ) ) {
				$modules[ $index ]['module_tags'] = array_map( 'jetpack_get_module_i18n_tag', $module['module_tags'] );
			}
		}
		return $modules;
	}

	/**
	 * Get a list of activated modules as an array of module slugs.
	 */
	public static function get_active_modules() {
		return ( new Modules() )->get_active();
	}

	/**
	 * Check whether or not a Jetpack module is active.
	 *
	 * @param string $module The slug of a Jetpack module.
	 * @return bool
	 *
	 * @static
	 */
	public static function is_module_active( $module ) {
		return ( new Modules() )->is_active( $module );
	}

	/**
	 * Is slug a valid module.
	 *
	 * @param string $module Module slug.
	 *
	 * @return bool
	 */
	public static function is_module( $module ) {
		return ( new Modules() )->is_module( $module );
	}

	/**
	 * Catches PHP errors.  Must be used in conjunction with output buffering.
	 *
	 * @param bool $catch True to start catching, False to stop.
	 *
	 * @static
	 */
	public static function catch_errors( $catch ) {
		return ( new Errors() )->catch_errors( $catch );
	}

	/**
	 * Saves any generated PHP errors in ::state( 'php_errors', {errors} )
	 */
	public static function catch_errors_on_shutdown() {
		self::state( 'php_errors', self::alias_directories( ob_get_clean() ) );
	}

	/**
	 * Rewrite any string to make paths easier to read.
	 *
	 * Rewrites ABSPATH (eg `/home/jetpack/wordpress/`) to ABSPATH, and if WP_CONTENT_DIR
	 * is located outside of ABSPATH, rewrites that to WP_CONTENT_DIR.
	 *
	 * @param string $string String to attempt rewrite.
	 * @return mixed
	 */
	public static function alias_directories( $string ) {
		// ABSPATH has a trailing slash.
		$string = str_replace( ABSPATH, 'ABSPATH/', $string );
		// WP_CONTENT_DIR does not have a trailing slash.
		$string = str_replace( WP_CONTENT_DIR, 'WP_CONTENT_DIR', $string );

		return $string;
	}

	/**
	 * Activates default Jetpack modules.
	 *
	 * @param null|string $min_version Only return modules introduced in this version or later. Default is false, do not filter.
	 * @param null|string $max_version Only return modules introduced before this version. Default is false, do not filter.
	 * @param array       $other_modules Other modules to activate.
	 * @param null|bool   $redirect Should there be a redirection after activation.
	 * @param bool        $send_state_messages If a state message should be sent.
	 * @param bool|null   $requires_connection Pass a boolean value to only return modules that require (or do not require) a connection.
	 * @param bool|null   $requires_user_connection Pass a boolean value to only return modules that require (or do not require) a user connection.
	 *
	 * @return void
	 */
	public static function activate_default_modules(
		$min_version = false,
		$max_version = false,
		$other_modules = array(),
		$redirect = null,
		$send_state_messages = null,
		$requires_connection = null,
		$requires_user_connection = null
	) {
		$jetpack = self::init();

		if ( $redirect === null ) {
			if (
				( defined( 'REST_REQUEST' ) && REST_REQUEST )
			||
				( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST )
			||
				( defined( 'WP_CLI' ) && WP_CLI )
			||
				( defined( 'DOING_CRON' ) && DOING_CRON )
			||
				( defined( 'DOING_AJAX' ) && DOING_AJAX )
			) {
				$redirect = false;
			} elseif ( is_admin() ) {
				$redirect = true;
			} else {
				$redirect = false;
			}
		}

		if ( $send_state_messages === null ) {
			$send_state_messages = current_user_can( 'jetpack_activate_modules' );
		}

		$modules = self::get_default_modules( $min_version, $max_version, $requires_connection, $requires_user_connection );
		$modules = array_merge( $other_modules, $modules );

		// Look for standalone plugins and disable if active.

		$to_deactivate = array();
		foreach ( $modules as $module ) {
			if ( isset( $jetpack->plugins_to_deactivate[ $module ] ) ) {
				$to_deactivate[ $module ] = $jetpack->plugins_to_deactivate[ $module ];
			}
		}

		$deactivated = array();
		foreach ( $to_deactivate as $module => $deactivate_us ) {
			foreach ( $deactivate_us as $i => $deactivate_me ) {
				list( $probable_file, $probable_title ) = $deactivate_me;
				if ( Jetpack_Client_Server::deactivate_plugin( $probable_file, $probable_title ) ) {
					$deactivated[] = "$module:$i";
				}
			}
		}

		if ( $deactivated ) {
			if ( $send_state_messages ) {
				self::state( 'deactivated_plugins', join( ',', $deactivated ) );
			}

			if ( $redirect ) {
				$url = add_query_arg(
					array(
						'action'   => 'activate_default_modules',
						'_wpnonce' => wp_create_nonce( 'activate_default_modules' ),
					),
					add_query_arg( compact( 'min_version', 'max_version', 'other_modules' ), self::admin_url( 'page=jetpack' ) )
				);
				wp_safe_redirect( $url );
				exit;
			}
		}

		/**
		 * Fires before default modules are activated.
		 *
		 * @since 1.9.0
		 *
		 * @param string    $min_version Minimum version number required to use modules.
		 * @param string    $max_version Maximum version number required to use modules.
		 * @param array     $other_modules Array of other modules to activate alongside the default modules.
		 * @param bool|null $requires_connection Value of the Requires Connection filter.
		 * @param bool|null $requires_user_connection Value of the Requires User Connection filter.
		 */
		do_action( 'jetpack_before_activate_default_modules', $min_version, $max_version, $other_modules, $requires_connection, $requires_user_connection );

		// Check each module for fatal errors, a la wp-admin/plugins.php::activate before activating.
		if ( $send_state_messages ) {
			self::restate();
			self::catch_errors( true );
		}

		$active = self::get_active_modules();

		foreach ( $modules as $module ) {
			if ( did_action( "jetpack_module_loaded_$module" ) ) {
				$active[] = $module;
				self::update_active_modules( $active );
				continue;
			}

			if ( $send_state_messages && in_array( $module, $active, true ) ) {
				$module_info = self::get_module( $module );
				if ( ! $module_info['deactivate'] ) {
					$state        = in_array( $module, $other_modules, true ) ? 'reactivated_modules' : 'activated_modules';
					$active_state = self::state( $state );
					if ( $active_state ) {
						$active_state = explode( ',', $active_state );
					} else {
						$active_state = array();
					}
					$active_state[] = $module;
					self::state( $state, implode( ',', $active_state ) );
				}
				continue;
			}

			$file = self::get_module_path( $module );
			if ( ! file_exists( $file ) ) {
				continue;
			}

			// we'll override this later if the plugin can be included without fatal error.
			if ( $redirect ) {
				wp_safe_redirect( self::admin_url( 'page=jetpack' ) );
			}

			if ( $send_state_messages ) {
				self::state( 'error', 'module_activation_failed' );
				self::state( 'module', $module );
			}

			ob_start();
			require_once $file;

			$active[] = $module;

			if ( $send_state_messages ) {

				$state        = in_array( $module, $other_modules, true ) ? 'reactivated_modules' : 'activated_modules';
				$active_state = self::state( $state );
				if ( $active_state ) {
					$active_state = explode( ',', $active_state );
				} else {
					$active_state = array();
				}
				$active_state[] = $module;
				self::state( $state, implode( ',', $active_state ) );
			}

			self::update_active_modules( $active );

			ob_end_clean();
		}

		if ( $send_state_messages ) {
			self::state( 'error', false );
			self::state( 'module', false );
		}

		self::catch_errors( false );
		/**
		 * Fires when default modules are activated.
		 *
		 * @since 1.9.0
		 *
		 * @param string    $min_version Minimum version number required to use modules.
		 * @param string    $max_version Maximum version number required to use modules.
		 * @param array     $other_modules Array of other modules to activate alongside the default modules.
		 * @param bool|null $requires_connection Value of the Requires Connection filter.
		 * @param bool|null $requires_user_connection Value of the Requires User Connection filter.
		 */
		do_action( 'jetpack_activate_default_modules', $min_version, $max_version, $other_modules, $requires_connection, $requires_user_connection );
	}

	/**
	 * Activate a module.
	 *
	 * @param string $module Module slug.
	 * @param bool   $exit Should exit be called after deactivation.
	 * @param bool   $redirect Should there be a redirection after activation.
	 *
	 * @return bool|void
	 */
	public static function activate_module( $module, $exit = true, $redirect = true ) {
		return ( new Modules() )->activate( $module, $exit, $redirect );
	}

	/**
	 * Deactivate module.
	 *
	 * @param string $module Module slug.
	 *
	 * @return bool
	 */
	public static function deactivate_module( $module ) {
		return ( new Modules() )->deactivate( $module );
	}

	/**
	 * Enable a configuable module.
	 *
	 * @param string $module Module slug.
	 *
	 * @return void
	 */
	public static function enable_module_configurable( $module ) {
		$module = self::get_module_slug( $module );
		add_filter( 'jetpack_module_configurable_' . $module, '__return_true' );
	}

	/**
	 * Composes a module configure URL. It uses Jetpack settings search as default value
	 * It is possible to redefine resulting URL by using "jetpack_module_configuration_url_$module" filter
	 *
	 * @param string $module Module slug.
	 * @return string $url module configuration URL.
	 */
	public static function module_configuration_url( $module ) {
		$module      = self::get_module_slug( $module );
		$default_url = self::admin_url() . "#/settings?term=$module";
		/**
		 * Allows to modify configure_url of specific module to be able to redirect to some custom location.
		 *
		 * @since 6.9.0
		 *
		 * @param string $default_url Default url, which redirects to jetpack settings page.
		 */
		$url = apply_filters( 'jetpack_module_configuration_url_' . $module, $default_url );

		return $url;
	}

	/* Installation */
	/**
	 * Bail on activation if there is an issue.
	 *
	 * @param string $message Error message.
	 * @param bool   $deactivate Deactivate Jetpack or not.
	 *
	 * @return void
	 */
	public static function bail_on_activation( $message, $deactivate = true ) {
		?>
<!doctype html>
<html>
<head>
<meta charset="<?php bloginfo( 'charset' ); ?>">
<style>
* {
	text-align: center;
	margin: 0;
	padding: 0;
	font-family: "Lucida Grande",Verdana,Arial,"Bitstream Vera Sans",sans-serif;
}
p {
	margin-top: 1em;
	font-size: 18px;
}
</style>
<body>
<p><?php echo esc_html( $message ); ?></p>
</body>
</html>
		<?php
		if ( $deactivate ) {
			$plugins = get_option( 'active_plugins' );
			$jetpack = plugin_basename( JETPACK__PLUGIN_DIR . 'jetpack.php' );
			$update  = false;
			foreach ( $plugins as $i => $plugin ) {
				if ( $plugin === $jetpack ) {
					$plugins[ $i ] = false;
					$update        = true;
				}
			}

			if ( $update ) {
				update_option( 'active_plugins', array_filter( $plugins ) );
			}
		}
		exit;
	}

	/**
	 * Attached to activate_{ plugin_basename( __FILES__ ) } by register_activation_hook()
	 *
	 * @param bool $network_wide Network-wide activation.
	 */
	public static function plugin_activation( $network_wide ) {
		Jetpack_Options::update_option( 'activated', 1 );

		if ( version_compare( $GLOBALS['wp_version'], JETPACK__MINIMUM_WP_VERSION, '<' ) ) {
			/* translators: Jetpack version number. */
			self::bail_on_activation( sprintf( __( 'Jetpack requires WordPress version %s or later.', 'jetpack' ), JETPACK__MINIMUM_WP_VERSION ) );
		}

		if ( $network_wide ) {
			self::state( 'network_nag', true );
		}

		// For firing one-off events (notices) immediately after activation.
		set_transient( 'activated_jetpack', true, 0.1 * MINUTE_IN_SECONDS );

		update_option( 'jetpack_activation_source', self::get_activation_source( wp_get_referer() ) );

		Health::on_jetpack_activated();

		if ( self::is_connection_ready() && method_exists( 'Automattic\Jetpack\Sync\Actions', 'do_only_first_initial_sync' ) ) {
			Sync_Actions::do_only_first_initial_sync();
		}

		self::plugin_initialize();
	}

	/**
	 * Returns the activation source.
	 *
	 * @param string $referer_url URL.
	 *
	 * @return array source_type, source_query.
	 */
	public static function get_activation_source( $referer_url ) {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return array( 'wp-cli', null );
		}

		$referer = wp_parse_url( $referer_url );

		$source_type  = 'unknown';
		$source_query = null;

		if ( ! is_array( $referer ) || ! isset( $referer['path'] ) ) {
			return array( $source_type, $source_query );
		}

		$plugins_path         = wp_parse_url( admin_url( 'plugins.php' ), PHP_URL_PATH );
		$plugins_install_path = wp_parse_url( admin_url( 'plugin-install.php' ), PHP_URL_PATH );// /wp-admin/plugin-install.php

		if ( isset( $referer['query'] ) ) {
			parse_str( $referer['query'], $query_parts );
		} else {
			$query_parts = array();
		}

		if ( $plugins_path === $referer['path'] ) {
			$source_type = 'list';
		} elseif ( $plugins_install_path === $referer['path'] ) {
			$tab = isset( $query_parts['tab'] ) ? $query_parts['tab'] : 'featured';
			switch ( $tab ) {
				case 'popular':
					$source_type = 'popular';
					break;
				case 'recommended':
					$source_type = 'recommended';
					break;
				case 'favorites':
					$source_type = 'favorites';
					break;
				case 'search':
					$source_type  = 'search-' . ( isset( $query_parts['type'] ) ? $query_parts['type'] : 'term' );
					$source_query = isset( $query_parts['s'] ) ? $query_parts['s'] : null;
					break;
				default:
					$source_type = 'featured';
			}
		}

		return array( $source_type, $source_query );
	}

	/**
	 * Runs before bumping version numbers up to a new version
	 *
	 * @param string $version    Version:timestamp.
	 * @param string $old_version Old Version:timestamp or false if not set yet.
	 */
	public static function do_version_bump( $version, $old_version ) {
		if ( $old_version ) { // For existing Jetpack installations.
			add_action( 'admin_enqueue_scripts', __CLASS__ . '::enqueue_block_style' );

			// If a front end page is visited after the update, the 'wp' action will fire.
			add_action( 'wp', 'Jetpack::set_update_modal_display' );

			// If an admin page is visited after the update, the 'current_screen' action will fire.
			add_action( 'current_screen', 'Jetpack::set_update_modal_display' );
		}
	}

	/**
	 * Sets the display_update_modal state.
	 */
	public static function set_update_modal_display() {
		self::state( 'display_update_modal', true );
	}

	/**
	 * Enqueues the block library styles.
	 *
	 * @param string $hook The current admin page.
	 */
	public static function enqueue_block_style( $hook ) {
		if ( 'toplevel_page_jetpack' === $hook ) {
			wp_enqueue_style( 'wp-block-library' );
		}
	}

	/**
	 * Sets the internal version number and activation state.
	 *
	 * @static
	 */
	public static function plugin_initialize() {
		if ( ! Jetpack_Options::get_option( 'activated' ) ) {
			Jetpack_Options::update_option( 'activated', 2 );
		}

		if ( ! Jetpack_Options::get_option( 'version' ) ) {
			$old_version = JETPACK__VERSION . ':' . time();
			$version     = $old_version;
			/** This action is documented in class.jetpack.php */
			do_action( 'updating_jetpack_version', $version, false );
			Jetpack_Options::update_options( compact( 'version', 'old_version' ) );
		}

		if ( self::is_connection_ready() ) {
			self::handle_default_module_activation( true );
		}

		self::load_modules();

		Jetpack_Options::delete_option( 'do_activate' );
		Jetpack_Options::delete_option( 'dismissed_connection_banner' );
	}

	/**
	 * Handles the activation of the default modules depending on the current state of the site:
	 *  - If the site already has the jetpack_active_modules option, activate those.
	 *  - If the site has a site-only connection, only activate the default modules that require only a site connection.
	 *  - If the site has a user connection, activate the default modules that require a user connection.
	 *
	 * @param bool $should_activate_user_modules Whether the status of the user connection should be checked and the default modules that
	 *                                           require a user connection activated.
	 */
	private static function handle_default_module_activation( $should_activate_user_modules ) {
		$active_modules = Jetpack_Options::get_option( 'active_modules' );
		if ( $active_modules ) {
			self::delete_active_modules();

			/**
			 * Previously active modules could mean two things. First, it could mean
			 * that Jetpack was previously active on the site. In this case we would like
			 * to only activate the modules that were set to active.
			 * Another case could be that the module option was set by a standalone
			 * plugin. In that case the `active_modules_initalized` option will not
			 * be set, so we need to enable default Jetpack modules as well.
			 */
			if ( ! Jetpack_Options::get_option( 'active_modules_initialized' ) ) {
				$default_modules = self::get_default_modules();
				$active_modules  = array_merge( $active_modules, $default_modules );
				Jetpack_Options::update_option( 'active_modules_initialized', true );
			}

			self::activate_default_modules(
				999, // This version trick basically excludes every default module.
				1,
				$active_modules,
				false
			);
		} elseif ( $should_activate_user_modules && ( new Connection_Manager() )->get_connection_owner_id() ) { // Check for a user connection.
			self::activate_default_modules( false, false, array(), false, null, null, null );
			Jetpack_Options::update_option( 'active_modules_initialized', true );
		} else {
			self::activate_default_modules( false, false, array(), false, null, null, false );
		}
	}

	/**
	 * Removes all connection options
	 *
	 * @static
	 */
	public static function plugin_deactivation() {
		require_once ABSPATH . '/wp-admin/includes/plugin.php';
		$tracking = new Tracking();
		$tracking->record_user_event( 'deactivate_plugin', array() );
		if ( is_plugin_active_for_network( 'jetpack/jetpack.php' ) ) {
			Jetpack_Network::init()->deactivate();
		} else {
			add_filter( 'jetpack_update_activated_state_on_disconnect', '__return_false' );
			self::disconnect();
			Jetpack_Options::delete_option( 'version' );
		}
	}

	/**
	 * Set activated option to 4 on jetpack_idc_disconnect action.
	 */
	public static function on_idc_disconnect() {
		\Jetpack_Options::update_option( 'activated', 4 );
	}

	/**
	 * Disconnects from the Jetpack servers.
	 * Forgets all connection details and tells the Jetpack servers to do the same.
	 *
	 * Will not disconnect if there are other plugins using the connection.
	 *
	 * @since 11.0 Do not disconnect if other plugins are using the connection.
	 *
	 * @static
	 */
	public static function disconnect() {

		$connection = self::connection();

		// If the site is in an IDC because sync is not allowed,
		// let's make sure to not disconnect the production site.
		$connection->remove_connection( ! Identity_Crisis::validate_sync_error_idc_option() );
	}

	/**
	 * Happens after a successfull disconnection.
	 *
	 * @static
	 */
	public static function jetpack_site_disconnected() {
		Identity_Crisis::clear_all_idc_options();

		// Delete all the sync related data. Since it could be taking up space.
		Sender::get_instance()->uninstall();

		/**
		 * Filters whether the Jetpack activated state should be updated after disconnecting.
		 *
		 * @since 10.0.0
		 *
		 * @param bool $update_activated_state Whether activated state should be updated after disconnecting, defaults to true.
		 */
		$update_activated_state = apply_filters( 'jetpack_update_activated_state_on_disconnect', true );

		if ( $update_activated_state ) {
			Jetpack_Options::update_option( 'activated', 4 );
		}
	}

	/**
	 * Disconnects the user
	 *
	 * @param int $user_id The user ID to disconnect.
	 */
	public function disconnect_user( $user_id ) {
		$this->connection_manager->disconnect_user( $user_id );
	}

	/**
	 * Attempts Jetpack registration.  If it fail, a state flag is set: @see ::admin_page_load()
	 *
	 * @deprecated since Jetpack 9.7.0
	 * @see Automattic\Jetpack\Connection\Manager::try_registration()
	 *
	 * @return bool|WP_Error
	 */
	public static function try_registration() {
		_deprecated_function( __METHOD__, 'jetpack-9.7', 'Automattic\\Jetpack\\Connection\\Manager::try_registration' );
		return static::connection()->try_registration();
	}

	/**
	 * Checking the domain names in beta versions.
	 * If this is a development version, before attempting to connect, let's make sure that the domains are viable.
	 *
	 * @param null|\WP_Error $error The domain validation error, or `null` if everything's fine.
	 *
	 * @return null|\WP_Error The domain validation error, or `null` if everything's fine.
	 */
	public static function registration_check_domains( $error ) {
		if ( static::is_development_version() && defined( 'PHP_URL_HOST' ) ) {
			$domains_to_check = array_unique(
				array(
					'siteurl' => wp_parse_url( get_site_url(), PHP_URL_HOST ),
					'homeurl' => wp_parse_url( get_home_url(), PHP_URL_HOST ),
				)
			);
			foreach ( $domains_to_check as $domain ) {
				$result = static::connection()->is_usable_domain( $domain );
				if ( is_wp_error( $result ) ) {
					return $result;
				}
			}
		}

		return $error;
	}

	/**
	 * Tracking an internal event log. Try not to put too much chaff in here.
	 *
	 * [Everyone Loves a Log!](https://www.youtube.com/watch?v=2C7mNr5WMjA)
	 *
	 * @param mixed $code Error code to log.
	 * @param mixed $data Data to log.
	 */
	public static function log( $code, $data = null ) {
		// only grab the latest 200 entries.
		$log = array_slice( Jetpack_Options::get_option( 'log', array() ), -199, 199 );

		// Append our event to the log.
		$log_entry = array(
			'time'    => time(),
			'user_id' => get_current_user_id(),
			'blog_id' => Jetpack_Options::get_option( 'id' ),
			'code'    => $code,
		);
		// Don't bother storing it unless we've got some.
		if ( $data !== null ) {
			$log_entry['data'] = $data;
		}
		$log[] = $log_entry;

		// Try add_option first, to make sure it's not autoloaded.
		// @todo: Add an add_option method to Jetpack_Options.
		if ( ! add_option( 'jetpack_log', $log, '', 'no' ) ) {
			Jetpack_Options::update_option( 'log', $log );
		}

		/**
		 * Fires when Jetpack logs an internal event.
		 *
		 * @since 3.0.0
		 *
		 * @param array $log_entry {
		 *  Array of details about the log entry.
		 *
		 *  @param string time Time of the event.
		 *  @param int user_id ID of the user who trigerred the event.
		 *  @param int blog_id Jetpack Blog ID.
		 *  @param string code Unique name for the event.
		 *  @param string data Data about the event.
		 * }
		 */
		do_action( 'jetpack_log_entry', $log_entry );
	}

	/**
	 * Get the internal event log.
	 *
	 * @param string $event only return the specific log events.
	 * @param int    $num - get specific number of latest results, limited to 200.
	 *
	 * @return array of log events || WP_Error for invalid params
	 */
	public static function get_log( $event = false, $num = false ) {
		if ( $event && ! is_string( $event ) ) {
			return new WP_Error( __( 'First param must be string or empty', 'jetpack' ) );
		}

		if ( $num && ! is_numeric( $num ) ) {
			return new WP_Error( __( 'Second param must be numeric or empty', 'jetpack' ) );
		}

		$entire_log = Jetpack_Options::get_option( 'log', array() );

		// If nothing set - act as it did before, otherwise let's start customizing the output.
		if ( ! $num && ! $event ) {
			return $entire_log;
		} else {
			$entire_log = array_reverse( $entire_log );
		}

		$custom_log_output = array();

		if ( $event ) {
			foreach ( $entire_log as $log_event ) {
				if ( $event === $log_event['code'] ) {
					$custom_log_output[] = $log_event;
				}
			}
		} else {
			$custom_log_output = $entire_log;
		}

		if ( $num ) {
			$custom_log_output = array_slice( $custom_log_output, 0, $num );
		}

		return $custom_log_output;
	}

	/**
	 * Log modification of important settings.
	 *
	 * @param string $option Option name.
	 * @param string $old_value Old value of option.
	 * @param string $value New value of option.
	 */
	public static function log_settings_change( $option, $old_value, $value ) {
		switch ( $option ) {
			case 'jetpack_sync_non_public_post_stati':
				self::log( $option, $value );
				break;
		}
	}

	/**
	 * Return stat data for WPCOM sync.
	 *
	 * @param bool $encode JSON encode the result.
	 * @param bool $extended Adds additional stats data.
	 *
	 * @return array|string Stats data. Array if $encode is false. JSON-encoded string is $encode is true.
	 */
	public static function get_stat_data( $encode = true, $extended = true ) {
		$data = Jetpack_Heartbeat::generate_stats_array();

		if ( $extended ) {
			$additional_data = self::get_additional_stat_data();
			$data            = array_merge( $data, $additional_data );
		}

		if ( $encode ) {
			return wp_json_encode( $data );
		}

		return $data;
	}

	/**
	 * Get additional stat data to sync to WPCOM
	 *
	 * @param string $prefix Stats prefix.
	 *
	 * @return array stats values.
	 */
	public static function get_additional_stat_data( $prefix = '' ) {
		$return                             = array();
		$return[ "{$prefix}themes" ]        = self::get_parsed_theme_data();
		$return[ "{$prefix}plugins-extra" ] = self::get_parsed_plugin_data();
		$return[ "{$prefix}users" ]         = (int) self::get_site_user_count();
		$return[ "{$prefix}site-count" ]    = 0;

		if ( function_exists( 'get_blog_count' ) ) {
			$return[ "{$prefix}site-count" ] = get_blog_count();
		}
		return $return;
	}

	/**
	 * Get current site's user count.
	 *
	 * @return int|string|null Number of users on the site. -1 for a large network.
	 */
	private static function get_site_user_count() {
		global $wpdb;

		if ( function_exists( 'wp_is_large_network' ) ) {
			if ( wp_is_large_network( 'users' ) ) {
				return -1; // Not a real value but should tell us that we are dealing with a large network.
			}
		}
		$user_count = get_transient( 'jetpack_site_user_count' );
		if ( false === ( $user_count ) ) {
			// It wasn't there, so regenerate the data and save the transient.
			$user_count = $wpdb->get_var( "SELECT COUNT(*) FROM $wpdb->usermeta WHERE meta_key = '{$wpdb->prefix}capabilities'" );
			set_transient( 'jetpack_site_user_count', $user_count, DAY_IN_SECONDS );
		}
		return $user_count;
	}

	/* Admin Pages */

	/**
	 * Admin init function.
	 *
	 * Runs on admin_init hook.
	 *
	 * @return void
	 */
	public function admin_init() {
		// If the plugin is not connected, display a connect message.
		if (
			// the plugin was auto-activated and needs its candy.
			Jetpack_Options::get_option_and_ensure_autoload( 'do_activate', '0' )
		||
			// the plugin is active, but was never activated.  Probably came from a site-wide network activation.
			! Jetpack_Options::get_option( 'activated' )
		) {
			self::plugin_initialize();
		}

		$is_offline_mode              = ( new Status() )->is_offline_mode();
		$fallback_no_verify_ssl_certs = Jetpack_Options::get_option( 'fallback_no_verify_ssl_certs' );
		/** Already documented in automattic/jetpack-connection::src/class-client.php */
		$client_verify_ssl_certs = apply_filters( 'jetpack_client_verify_ssl_certs', false );

		if ( ! $is_offline_mode ) {
			Jetpack_Connection_Banner::init();
			Jetpack_Connection_Widget::init();
		}

		if ( ( self::is_connection_ready() || $is_offline_mode ) && false === $fallback_no_verify_ssl_certs && ! $client_verify_ssl_certs ) {
			// Upgrade: 1.1 -> 1.1.1
			// Check and see if host can verify the Jetpack servers' SSL certificate.
			$args = array();
			Client::_wp_remote_request( self::connection()->api_url( 'test' ), $args, true );
		}

		Jetpack_Recommendations_Banner::init();

		if ( current_user_can( 'manage_options' ) && ! self::permit_ssl() ) {
			add_action( 'jetpack_notices', array( $this, 'alert_auto_ssl_fail' ) );
		}

		add_action( 'load-plugins.php', array( $this, 'intercept_plugin_error_scrape_init' ) );
		add_action( 'load-plugins.php', array( $this, 'plugins_page_init_jetpack_state' ) );

		if ( ! ( is_multisite() && is_plugin_active_for_network( 'jetpack/jetpack.php' ) && ! is_network_admin() ) ) {
			add_action( 'admin_enqueue_scripts', array( $this, 'deactivate_dialog' ) );
		}

		if ( isset( $_COOKIE['jetpackState']['display_update_modal'] ) ) {
			add_action( 'admin_enqueue_scripts', __CLASS__ . '::enqueue_block_style' );
		}

		add_filter( 'plugin_action_links_' . plugin_basename( JETPACK__PLUGIN_DIR . 'jetpack.php' ), array( $this, 'plugin_action_links' ) );

		if ( self::is_connection_ready() || $is_offline_mode ) {
			// Artificially throw errors in certain specific cases during plugin activation.
			add_action( 'activate_plugin', array( $this, 'throw_error_on_activate_plugin' ) );
		}

		// Add custom column in wp-admin/users.php to show whether user is linked.
		add_filter( 'manage_users_columns', array( $this, 'jetpack_icon_user_connected' ) );
		add_action( 'manage_users_custom_column', array( $this, 'jetpack_show_user_connected_icon' ), 10, 3 );
		add_action( 'admin_print_styles', array( $this, 'jetpack_user_col_style' ) );
	}

	/**
	 * Adds body classes.
	 *
	 * @param string $admin_body_class Body classes.
	 *
	 * @return string
	 */
	public function admin_body_class( $admin_body_class = '' ) {
		$classes = explode( ' ', trim( $admin_body_class ) );

		$classes[] = self::is_connection_ready() ? 'jetpack-connected' : 'jetpack-disconnected';

		$admin_body_class = implode( ' ', array_unique( $classes ) );
		return " $admin_body_class ";
	}

	/**
	 * Adds Jetpack Page styles by appending class to the admin body class.
	 *
	 * @param string $admin_body_class Existing admin body class string.
	 *
	 * @return string
	 */
	public static function add_jetpack_pagestyles( $admin_body_class = '' ) {
		return $admin_body_class . ' jetpack-pagestyles ';
	}

	/**
	 * Sometimes a plugin can activate without causing errors, but it will cause errors on the next page load.
	 * This function artificially throws errors for such cases (per a specific list).
	 *
	 * @param string $plugin The activated plugin.
	 */
	public function throw_error_on_activate_plugin( $plugin ) {
		$active_modules = self::get_active_modules();

		// The Shortlinks module and the Stats plugin conflict, but won't cause errors on activation because of some function_exists() checks.
		if ( function_exists( 'stats_get_api_key' ) && in_array( 'shortlinks', $active_modules, true ) ) {
			$throw = false;

			// Try and make sure it really was the stats plugin.
			if ( ! class_exists( 'ReflectionFunction' ) ) {
				if ( 'stats.php' === basename( $plugin ) ) {
					$throw = true;
				}
			} else {
				$reflection = new ReflectionFunction( 'stats_get_api_key' );
				if ( basename( $plugin ) === basename( $reflection->getFileName() ) ) {
					$throw = true;
				}
			}

			if ( $throw ) {
				/* translators: Plugin name to deactivate. */
				trigger_error( sprintf( esc_html__( 'Jetpack contains the most recent version of the old &#8220;%1$s&#8221; plugin.', 'jetpack' ), 'WordPress.com Stats' ), E_USER_ERROR ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error
			}
		}
	}

	/**
	 * Call to Jetpack::state on the load-plugins.php hook.
	 * In case the jetpackState cookie is populated, this call will read and re-set the cookie before HTTP headers are sent.
	 */
	public function plugins_page_init_jetpack_state() {
		self::state( 'message' );
	}

	/**
	 * Adds the intercept action to the check_admin_referer hook.
	 *
	 * @return void
	 */
	public function intercept_plugin_error_scrape_init() {
		add_action( 'check_admin_referer', array( $this, 'intercept_plugin_error_scrape' ), 10, 2 );
	}

	/**
	 * Detect if conflicting plugin is being deactivated.
	 *
	 * @param string   $action The nonce action.
	 * @param bool|int $result False if the nonce is invalid, 1 if the nonce is valid and generated between 0-12 hours ago, 2 if the nonce is valid and generated between 12-24 hours ago.
	 *
	 * @return void
	 */
	public function intercept_plugin_error_scrape( $action, $result ) {
		if ( ! $result ) {
			return;
		}

		foreach ( $this->plugins_to_deactivate as $deactivate_us ) {
			foreach ( $deactivate_us as $deactivate_me ) {
				if ( "plugin-activation-error_{$deactivate_me[0]}" === $action ) {
					/* translators: Plugin name to deactivate. */
					self::bail_on_activation( sprintf( __( 'Jetpack contains the most recent version of the old &#8220;%1$s&#8221; plugin.', 'jetpack' ), $deactivate_me[1] ), false );
				}
			}
		}
	}

	/**
	 * Register the remote file upload request handlers, if needed.
	 *
	 * @access public
	 */
	public function add_remote_request_handlers() {
		// Remote file uploads are allowed only via AJAX requests.
		if ( ! is_admin() || ! Constants::get_constant( 'DOING_AJAX' ) ) {
			return;
		}

		// Remote file uploads are allowed only for a set of specific AJAX actions.
		$remote_request_actions = array(
			'jetpack_upload_file',
			'jetpack_update_file',
		);

		// phpcs:ignore WordPress.Security.NonceVerification
		if ( ! isset( $_POST['action'] ) || ! in_array( $_POST['action'], $remote_request_actions, true ) ) {
			return;
		}

		// Require Jetpack authentication for the remote file upload AJAX requests.
		if ( ! $this->connection_manager ) {
			$this->connection_manager = new Connection_Manager();
		}

		$this->connection_manager->require_jetpack_authentication();

		// Register the remote file upload AJAX handlers.
		foreach ( $remote_request_actions as $action ) {
			add_action( "wp_ajax_nopriv_{$action}", array( $this, 'remote_request_handlers' ) );
		}
	}

	/**
	 * Handler for Jetpack remote file uploads.
	 *
	 * @access public
	 */
	public function remote_request_handlers() {
		switch ( current_filter() ) {
			case 'wp_ajax_nopriv_jetpack_upload_file':
				$response = $this->upload_handler();
				break;

			case 'wp_ajax_nopriv_jetpack_update_file':
				$response = $this->upload_handler( true );
				break;
			default:
				$response = new WP_Error( 'unknown_handler', 'Unknown Handler', 400 );
				break;
		}

		if ( ! $response ) {
			$response = new WP_Error( 'unknown_error', 'Unknown Error', 400 );
		}

		if ( is_wp_error( $response ) ) {
			$status_code       = $response->get_error_data();
			$error             = $response->get_error_code();
			$error_description = $response->get_error_message();

			if ( ! is_int( $status_code ) ) {
				$status_code = 400;
			}

			status_header( $status_code );
			die( wp_json_encode( (object) compact( 'error', 'error_description' ) ) );
		}

		status_header( 200 );
		if ( true === $response ) {
			exit;
		}

		die( wp_json_encode( (object) $response ) );
	}

	/**
	 * Uploads a file gotten from the global $_FILES.
	 * If `$update_media_item` is true and `post_id` is defined
	 * the attachment file of the media item (gotten through of the post_id)
	 * will be updated instead of add a new one.
	 *
	 * @param  boolean $update_media_item - update media attachment.
	 * @return array - An array describing the uploadind files process.
	 */
	public function upload_handler( $update_media_item = false ) {
		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'POST' !== strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) ) {
			return new WP_Error( 405, get_status_header_desc( 405 ), 405 );
		}

		$user = wp_authenticate( '', '' );
		if ( ! $user || is_wp_error( $user ) ) {
			return new WP_Error( 403, get_status_header_desc( 403 ), 403 );
		}

		wp_set_current_user( $user->ID );

		if ( ! current_user_can( 'upload_files' ) ) {
			return new WP_Error( 'cannot_upload_files', 'User does not have permission to upload files', 403 );
		}

		if ( empty( $_FILES ) ) {
			return new WP_Error( 'no_files_uploaded', 'No files were uploaded: nothing to process', 400 );
		}

		foreach ( array_keys( $_FILES ) as $files_key ) {
			if ( ! isset( $_POST[ "_jetpack_file_hmac_{$files_key}" ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- no site changes here.
				return new WP_Error( 'missing_hmac', 'An HMAC for one or more files is missing', 400 );
			}
		}

		$media_keys = isset( $_FILES['media'] ) ? array_keys( $_FILES['media'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Unslash is not needed for `$_FILES`, the sniff is wrong. Sanitization should happen below.

		$token = ( new Tokens() )->get_access_token( get_current_user_id() );
		if ( ! $token || is_wp_error( $token ) ) {
			return new WP_Error( 'unknown_token', 'Unknown Jetpack token', 403 );
		}

		/**
		 * Optionally block uploads processed through Jetpack's upload_handler().
		 * The filter may return false or WP_Error to block this particular upload.
		 *
		 * @since 10.8
		 *
		 * @param bool|WP_Error $allowed If false or WP_Error, block the upload. If true, allow the upload.
		 * @param mixed $_FILES The $_FILES attempting to be uploaded.
		 */
		$can_upload = apply_filters( 'jetpack_upload_handler_can_upload', true, $_FILES );
		if ( ! $can_upload || is_wp_error( $can_upload ) ) {
			if ( is_wp_error( $can_upload ) ) {
				return $can_upload;
			}
			return new WP_Error( 'handler_cannot_upload', __( 'The upload handler cannot upload files', 'jetpack' ), 400 );
		}

		$uploaded_files = array();
		$global_post    = isset( $GLOBALS['post'] ) ? $GLOBALS['post'] : null;
		unset( $GLOBALS['post'] );
		if ( empty( $_FILES['media']['name'] ) ) {
			// Nothing to process, just return.
			return $uploaded_files;
		}
		foreach ( $_FILES['media']['name'] as $index => $name ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- As above, unslash sniff is wrong. Validation should happen below.
			$file = array();
			foreach ( $media_keys as $media_key ) {
				$file[ $media_key ] = isset( $_FILES['media'][ $media_key ][ $index ] ) ? $_FILES['media'][ $media_key ][ $index ] : null; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- As above, the unslash sniff is wrong.
			}

			list( $hmac_provided, $salt ) = isset( $_POST['_jetpack_file_hmac_media'][ $index ] ) ? explode( ':', filter_var( wp_unslash( $_POST['_jetpack_file_hmac_media'][ $index ] ) ) ) : array( 'no', '' ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce should have been checked by the caller.

			$hmac_file = hash_hmac_file( 'sha1', $file['tmp_name'], $salt . $token->secret );
			if ( $hmac_provided !== $hmac_file ) {
				$uploaded_files[ $index ] = (object) array(
					'error'             => 'invalid_hmac',
					'error_description' => 'The corresponding HMAC for this file does not match',
				);
				continue;
			}

			$_FILES['.jetpack.upload.'] = $file;
			$post_id                    = isset( $_POST['post_id'][ $index ] ) ? absint( $_POST['post_id'][ $index ] ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- caller should have checked a nonce.
			if ( ! current_user_can( 'edit_post', $post_id ) ) {
				$post_id = 0;
			}

			if ( $update_media_item ) {
				if ( ! isset( $post_id ) || 0 === $post_id ) {
					return new WP_Error( 'invalid_input', 'Media ID must be defined.', 400 );
				}

				$media_array = $_FILES['media']; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

				$file_array             = array();
				$file_array['name']     = $media_array['name'][0];
				$file_array['type']     = $media_array['type'][0];
				$file_array['tmp_name'] = $media_array['tmp_name'][0];
				$file_array['error']    = $media_array['error'][0];
				$file_array['size']     = $media_array['size'][0];

				$edited_media_item = Jetpack_Media::edit_media_file( $post_id, $file_array );

				if ( is_wp_error( $edited_media_item ) ) {
					return $edited_media_item;
				}

				$response = (object) array(
					'id'   => (string) $post_id,
					'file' => (string) $edited_media_item->post_title,
					'url'  => (string) wp_get_attachment_url( $post_id ),
					'type' => (string) $edited_media_item->post_mime_type,
					'meta' => (array) wp_get_attachment_metadata( $post_id ),
				);

				return (array) array( $response );
			}

			$attachment_id = media_handle_upload(
				'.jetpack.upload.',
				$post_id,
				array(),
				array(
					'action' => 'jetpack_upload_file',
				)
			);

			if ( ! $attachment_id ) {
				$uploaded_files[ $index ] = (object) array(
					'error'             => 'unknown',
					'error_description' => 'An unknown problem occurred processing the upload on the Jetpack site',
				);
			} elseif ( is_wp_error( $attachment_id ) ) {
				$uploaded_files[ $index ] = (object) array(
					'error'             => 'attachment_' . $attachment_id->get_error_code(),
					'error_description' => $attachment_id->get_error_message(),
				);
			} else {
				$attachment               = get_post( $attachment_id );
				$uploaded_files[ $index ] = (object) array(
					'id'   => (string) $attachment_id,
					'file' => $attachment->post_title,
					'url'  => wp_get_attachment_url( $attachment_id ),
					'type' => $attachment->post_mime_type,
					'meta' => wp_get_attachment_metadata( $attachment_id ),
				);
			}
		}
		if ( $global_post !== null ) {
			$GLOBALS['post'] = $global_post; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		}

		return $uploaded_files;
	}

	/**
	 * Add help to the Jetpack page
	 *
	 * @since Jetpack (1.2.3)
	 * @return void
	 */
	public function admin_help() {
		$current_screen = get_current_screen();

		// Overview.
		$current_screen->add_help_tab(
			array(
				'id'      => 'home',
				'title'   => __( 'Home', 'jetpack' ),
				'content' =>
					'<p><strong>' . __( 'Jetpack', 'jetpack' ) . '</strong></p>' .
					'<p>' . __( 'Jetpack supercharges your self-hosted WordPress site with the awesome cloud power of WordPress.com.', 'jetpack' ) . '</p>' .
					'<p>' . __( 'On this page, you are able to view the modules available within Jetpack, learn more about them, and activate or deactivate them as needed.', 'jetpack' ) . '</p>',
			)
		);

		// Screen Content.
		if ( current_user_can( 'manage_options' ) ) {
			$current_screen->add_help_tab(
				array(
					'id'      => 'settings',
					'title'   => __( 'Settings', 'jetpack' ),
					'content' =>
						'<p><strong>' . __( 'Jetpack', 'jetpack' ) . '</strong></p>' .
						'<p>' . __( 'You can activate or deactivate individual Jetpack modules to suit your needs.', 'jetpack' ) . '</p>' .
						'<ol>' .
							'<li>' . __( 'Each module has an Activate or Deactivate link so you can toggle one individually.', 'jetpack' ) . '</li>' .
							'<li>' . __( 'Using the checkboxes next to each module, you can select multiple modules to toggle via the Bulk Actions menu at the top of the list.', 'jetpack' ) . '</li>' .
						'</ol>' .
						'<p>' . __( 'Using the tools on the right, you can search for specific modules, filter by module categories or which are active, or change the sorting order.', 'jetpack' ) . '</p>',
				)
			);
		}

		// Help Sidebar.
		$support_url = Redirect::get_url( 'jetpack-support' );
		$faq_url     = Redirect::get_url( 'jetpack-faq' );
		$current_screen->set_help_sidebar(
			'<p><strong>' . __( 'For more information:', 'jetpack' ) . '</strong></p>' .
			'<p><a href="' . $faq_url . '" rel="noopener noreferrer" target="_blank">' . __( 'Jetpack FAQ', 'jetpack' ) . '</a></p>' .
			'<p><a href="' . $support_url . '" rel="noopener noreferrer" target="_blank">' . __( 'Jetpack Support', 'jetpack' ) . '</a></p>' .
			'<p><a href="' . self::admin_url( array( 'page' => 'jetpack-debugger' ) ) . '">' . __( 'Jetpack Debugging Center', 'jetpack' ) . '</a></p>'
		);
	}

	/**
	 * Enqueues the jetpack-icons style.
	 *
	 * @return void
	 */
	public function admin_menu_css() {
		wp_enqueue_style( 'jetpack-icons' );
	}

	/**
	 * Add action links for the Jetpack plugin.
	 *
	 * @param array $actions Plugin actions.
	 *
	 * @return array
	 */
	public function plugin_action_links( $actions ) {
		$support_link = ( new Host() )->is_woa_site() ? 'https://wordpress.com/help/contact/' : self::admin_url( 'page=jetpack-debugger' );

		if ( current_user_can( 'jetpack_manage_modules' ) && ( self::is_connection_ready() || ( new Status() )->is_offline_mode() ) ) {
			return array_merge(
				array( 'settings' => sprintf( '<a href="%s">%s</a>', self::admin_url( 'page=jetpack#/settings' ), __( 'Settings', 'jetpack' ) ) ),
				array( 'support' => sprintf( '<a href="%s">%s</a>', $support_link, __( 'Support', 'jetpack' ) ) ),
				$actions
			);
		}

		return $actions;
	}

	/**
	 * Add an activation modal to the plugins page and the main dashboard.
	 *
	 * @param string $hook The current admin page.
	 *
	 * @return void
	 */
	public function activate_dialog( $hook ) {
		/*
		 * We do not need it on other plugin pages,
		 * or when Jetpack is already connected.
		 */
		if (
			! in_array( $hook, array( 'plugins.php', 'index.php' ), true )
			|| self::is_connection_ready()
		) {
			return;
		}

		// add an activation script that will pick up deactivation actions for the Jetpack plugin.
		Assets::register_script(
			'jetpack-full-activation-modal-js',
			'_inc/build/activation-modal.js',
			JETPACK__PLUGIN_FILE,
			array(
				'enqueue'      => true,
				'in_footer'    => true,
				'textdomain'   => 'jetpack',
				'dependencies' => array(
					'wp-polyfill',
					'wp-components',
				),
			)
		);

		// Add objects to be passed to the initial state of the app.
		// Use wp_add_inline_script instead of wp_localize_script, see https://core.trac.wordpress.org/ticket/25280.
		wp_add_inline_script( 'jetpack-full-activation-modal-js', 'var Initial_State=JSON.parse(decodeURIComponent("' . rawurlencode( wp_json_encode( Jetpack_Redux_State_Helper::get_minimal_state() ) ) . '"));', 'before' );

		// Adds Connection package initial state.
		wp_add_inline_script( 'jetpack-full-activation-modal-js', Connection_Initial_State::render(), 'before' );

		add_action( 'admin_notices', array( $this, 'jetpack_plugin_portal_containers' ) );
	}

	/**
	 * Adds the deactivation warning modal for Jetpack.
	 *
	 * @param string $hook The current admin page.
	 *
	 * @return void
	 */
	public function deactivate_dialog( $hook ) {
		if (
			'plugins.php' === $hook
			&& self::is_connection_ready()
		) {

			// Register jp-tracks-functions dependency.
			Tracking::register_tracks_functions_scripts( true );

			// add a deactivation script that will pick up deactivation actions for the Jetpack plugin.
			Assets::register_script(
				'jetpack-plugins-page-js',
				'_inc/build/plugins-page.js',
				JETPACK__PLUGIN_FILE,
				array(
					'in_footer'    => true,
					'textdomain'   => 'jetpack',
					'dependencies' => array(
						'wp-polyfill',
						'wp-components',
					),
				)
			);
			Assets::enqueue_script( 'jetpack-plugins-page-js' );

			// Add objects to be passed to the initial state of the app.
			// Use wp_add_inline_script instead of wp_localize_script, see https://core.trac.wordpress.org/ticket/25280.
			wp_add_inline_script( 'jetpack-plugins-page-js', 'var Initial_State=JSON.parse(decodeURIComponent("' . rawurlencode( wp_json_encode( Jetpack_Redux_State_Helper::get_minimal_state() ) ) . '"));', 'before' );

			add_action( 'admin_footer', array( $this, 'jetpack_plugin_portal_containers' ) );
		}
	}

	/**
	 * Outputs the wrapper for the plugin modal
	 * Contents are loaded by React script
	 *
	 * @return void
	 */
	public function jetpack_plugin_portal_containers() {
		$this->load_view( 'admin/jetpack-plugin-portal-containers.php' );
	}

	/**
	 * Filters the login URL to include the registration flow in case the user isn't logged in.
	 *
	 * @param string $login_url The wp-login URL.
	 * @param string $redirect  URL to redirect users after logging in.
	 * @since Jetpack 8.4
	 * @return string
	 */
	public function login_url( $login_url, $redirect ) {
		parse_str( (string) wp_parse_url( $redirect, PHP_URL_QUERY ), $redirect_parts );
		if ( ! empty( $redirect_parts[ self::$jetpack_redirect_login ] ) ) {
			$login_url = add_query_arg( self::$jetpack_redirect_login, 'true', $login_url );
		}
		return $login_url;
	}

	/**
	 * Redirects non-authenticated users to authenticate with Calypso if redirect flag is set.
	 *
	 * @since Jetpack 8.4
	 */
	public function login_init() {
		// phpcs:ignore WordPress.Security.NonceVerification
		if ( ! empty( $_GET[ self::$jetpack_redirect_login ] ) ) {
			add_filter( 'allowed_redirect_hosts', array( Host::class, 'allow_wpcom_environments' ) );
			wp_safe_redirect(
				add_query_arg(
					array(
						'forceInstall' => 1,
						'url'          => rawurlencode( get_site_url() ),
					),
					// @todo provide way to go to specific calypso env.
					self::get_calypso_host() . 'jetpack/connect'
				)
			);
			exit;
		}
	}

	/*
	 * Registration flow:
	 * 1 - ::admin_page_load() action=register
	 * 2 - ::try_registration()
	 * 3 - ::register()
	 *     - Creates jetpack_register option containing two secrets and a timestamp
	 *     - Calls https://jetpack.wordpress.com/jetpack.register/1/ with
	 *       siteurl, home, gmt_offset, timezone_string, site_name, secret_1, secret_2, site_lang, timeout, stats_id
	 *     - That request to jetpack.wordpress.com does not immediately respond.  It first makes a request BACK to this site's
	 *       xmlrpc.php?for=jetpack: RPC method: jetpack.verifyRegistration, Parameters: secret_1
	 *     - The XML-RPC request verifies secret_1, deletes both secrets and responds with: secret_2
	 *     - https://jetpack.wordpress.com/jetpack.register/1/ verifies that XML-RPC response (secret_2) then finally responds itself with
	 *       jetpack_id, jetpack_secret, jetpack_public
	 *     - ::register() then stores jetpack_options: id => jetpack_id, blog_token => jetpack_secret
	 * 4 - redirect to https://wordpress.com/start/jetpack-connect
	 * 5 - user logs in with WP.com account
	 * 6 - remote request to this site's xmlrpc.php with action remoteAuthorize, Jetpack_XMLRPC_Server->remote_authorize
	 *      - Manager::authorize()
	 *      - Manager::get_token()
	 *      - GET https://jetpack.wordpress.com/jetpack.token/1/ with
	 *        client_id, client_secret, grant_type, code, redirect_uri:action=authorize, state, scope, user_email, user_login
	 *          - which responds with access_token, token_type, scope
	 *      - Manager::authorize() stores jetpack_options: user_token => access_token.$user_id
	 *      - Jetpack::activate_default_modules()
	 *          - Deactivates deprecated plugins
	 *          - Activates all default modules
	 *      - Responds with either error, or 'connected' for new connection, or 'linked' for additional linked users
	 * 7 - For a new connection, user selects a Jetpack plan on wordpress.com
	 * 8 - User is redirected back to wp-admin/index.php?page=jetpack with state:message=authorized
	 *     Done!
	 */

	/**
	 * Handles the page load events for the Jetpack admin page
	 */
	public function admin_page_load() {
		$error = false;

		// Make sure we have the right body class to hook stylings for subpages off of.
		add_filter( 'admin_body_class', array( __CLASS__, 'add_jetpack_pagestyles' ), 20 );

		if ( ! empty( $_GET['jetpack_restate'] ) ) {
			// Should only be used in intermediate redirects to preserve state across redirects.
			self::restate();
		}

		if ( isset( $_GET['action'] ) ) {
			switch ( $_GET['action'] ) {
				/**
				 * Cases authorize and authorize_redirect are now handled by Connection package Webhooks
				 */
				case 'authorize_redirect':
				case 'authorize':
					break;
				case 'register':
					if ( ! current_user_can( 'jetpack_connect' ) ) {
						$error = 'cheatin';
						break;
					}
					check_admin_referer( 'jetpack-register' );
					self::log( 'register' );
					self::maybe_set_version_option();
					$from = isset( $_GET['from'] ) ? sanitize_text_field( wp_unslash( $_GET['from'] ) ) : false;
					if ( $from ) {
						static::connection()->add_register_request_param( 'from', (string) $from );
					}
					$registered = static::connection()->try_registration();
					if ( is_wp_error( $registered ) ) {
						$error = $registered->get_error_code();
						self::state( 'error', $error );
						self::state( 'error', $registered->get_error_message() );

						/**
						 * Jetpack registration Error.
						 *
						 * @since 7.5.0
						 *
						 * @param string|int $error The error code.
						 * @param \WP_Error $registered The error object.
						 */
						do_action( 'jetpack_connection_register_fail', $error, $registered );
						break;
					}

					$redirect = isset( $_GET['redirect'] ) ? wp_unslash( $_GET['redirect'] ) : false; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

					/**
					 * Jetpack registration Success.
					 *
					 * @since 7.5.0
					 *
					 * @param string $from 'from' GET parameter;
					 */
					do_action( 'jetpack_connection_register_success', $from );

					$url = $this->build_connect_url( true, $redirect, $from );

					if ( ! empty( $_GET['onboarding'] ) ) {
						$url = add_query_arg( 'onboarding', rawurlencode_deep( wp_unslash( $_GET['onboarding'] ) ), $url ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
					}

					if ( ! empty( $_GET['auth_approved'] ) && 'true' === $_GET['auth_approved'] ) {
						$url = add_query_arg( 'auth_approved', 'true', $url );
					}

					add_filter( 'allowed_redirect_hosts', array( Host::class, 'allow_wpcom_environments' ) );
					wp_safe_redirect( $url );
					exit;
				case 'activate':
					if ( ! current_user_can( 'jetpack_activate_modules' ) ) {
						$error = 'cheatin';
						break;
					}

					$module = isset( $_GET['module'] ) ? sanitize_text_field( wp_unslash( $_GET['module'] ) ) : '';
					check_admin_referer( "jetpack_activate-$module" );
					self::log( 'activate', $module );
					if ( ! self::activate_module( $module ) ) {
						/* translators: module/feature name */
						self::state( 'error', sprintf( __( 'Could not activate %s', 'jetpack' ), $module ) );
					}
					// The following two lines will rarely happen, as Jetpack::activate_module normally exits at the end.
					wp_safe_redirect( self::admin_url( 'page=jetpack' ) );
					exit;
				case 'activate_default_modules':
					check_admin_referer( 'activate_default_modules' );
					self::log( 'activate_default_modules' );
					self::restate();
					$min_version   = isset( $_GET['min_version'] ) ? sanitize_text_field( wp_unslash( $_GET['min_version'] ) ) : false;
					$max_version   = isset( $_GET['max_version'] ) ? sanitize_text_field( wp_unslash( $_GET['max_version'] ) ) : false;
					$other_modules = isset( $_GET['other_modules'] ) && is_array( $_GET['other_modules'] ) ? array_map( 'sanitize_text_field', wp_unslash( $_GET['other_modules'] ) ) : array();
					self::activate_default_modules( $min_version, $max_version, $other_modules );
					wp_safe_redirect( self::admin_url( 'page=jetpack' ) );
					exit;
				case 'disconnect':
					if ( ! current_user_can( 'jetpack_disconnect' ) ) {
						$error = 'cheatin';
						break;
					}

					check_admin_referer( 'jetpack-disconnect' );
					self::log( 'disconnect' );
					self::disconnect();
					wp_safe_redirect( self::admin_url( 'disconnected=true' ) );
					exit;
				case 'reconnect':
					if ( ! current_user_can( 'jetpack_reconnect' ) ) {
						$error = 'cheatin';
						break;
					}

					check_admin_referer( 'jetpack-reconnect' );
					self::log( 'reconnect' );
					self::disconnect();

					add_filter( 'allowed_redirect_hosts', array( Host::class, 'allow_wpcom_environments' ) );
					wp_safe_redirect( $this->build_connect_url( true, false, 'reconnect' ) );
					exit;
				case 'deactivate':
					if ( ! current_user_can( 'jetpack_deactivate_modules' ) ) {
						$error = 'cheatin';
						break;
					}

					$modules = sanitize_text_field( wp_unslash( $_GET['module'] ) );
					check_admin_referer( "jetpack_deactivate-$modules" );
					foreach ( explode( ',', $modules ) as $module ) {
						self::log( 'deactivate', $module );
						self::deactivate_module( $module );
						self::state( 'message', 'module_deactivated' );
					}
					self::state( 'module', $modules );
					wp_safe_redirect( self::admin_url( 'page=jetpack' ) );
					exit;
				case 'unlink':
					$redirect = isset( $_GET['redirect'] ) ? sanitize_text_field( wp_unslash( $_GET['redirect'] ) ) : '';
					check_admin_referer( 'jetpack-unlink' );
					self::log( 'unlink' );
					$this->connection_manager->disconnect_user();
					self::state( 'message', 'unlinked' );
					if ( 'sub-unlink' === $redirect ) {
						wp_safe_redirect( admin_url() );
					} else {
						wp_safe_redirect( self::admin_url( array( 'page' => rawurlencode( $redirect ) ) ) );
					}
					exit;
				case 'onboard':
					if ( ! current_user_can( 'manage_options' ) ) {
						wp_safe_redirect( self::admin_url( 'page=jetpack' ) );
					} else {
						self::create_onboarding_token();
						$url = $this->build_connect_url( true );

						$token = Jetpack_Options::get_option( 'onboarding' );

						if ( false !== ( $token ) ) {
							$url = add_query_arg( 'onboarding', $token, $url );
						}

						$calypso_env = $this->get_calypso_env();
						if ( ! empty( $calypso_env ) ) {
							$url = add_query_arg( 'calypso_env', $calypso_env, $url );
						}

						add_filter( 'allowed_redirect_hosts', array( Host::class, 'allow_wpcom_environments' ) );
						wp_safe_redirect( $url );
						exit;
					}
					exit;
				default:
					/**
					 * Fires when a Jetpack admin page is loaded with an unrecognized parameter.
					 *
					 * @since 2.6.0
					 *
					 * @param string sanitize_key( $_GET['action'] ) Unrecognized URL parameter.
					 */
					do_action( 'jetpack_unrecognized_action', sanitize_key( $_GET['action'] ) );
			}
		}

		$error = $error ? $error : self::state( 'error' );
		if ( ! $error ) {
			self::activate_new_modules( true );
		}

		$message_code = self::state( 'message' );
		if ( self::state( 'optin-manage' ) ) {
			$activated_manage = $message_code;
			$message_code     = 'jetpack-manage';
		}

		switch ( $message_code ) {
			case 'jetpack-manage':
				$sites_url = esc_url( Redirect::get_url( 'calypso-sites' ) );
				// translators: %s is the URL to the "Sites" panel on wordpress.com.
				$this->message = '<strong>' . sprintf( __( 'You are all set! Your site can now be managed from <a href="%s" target="_blank">wordpress.com/sites</a>.', 'jetpack' ), $sites_url ) . '</strong>';
				if ( $activated_manage ) {
					$this->message .= '<br /><strong>' . __( 'Manage has been activated for you!', 'jetpack' ) . '</strong>';
				}
				break;

		}

		$deactivated_plugins = self::state( 'deactivated_plugins' );

		if ( ! empty( $deactivated_plugins ) ) {
			$deactivated_plugins = explode( ',', $deactivated_plugins );
			$deactivated_titles  = array();
			foreach ( $deactivated_plugins as $deactivated_plugin ) {
				list( $module, $idx ) = explode( ':', $deactivated_plugin );
				if ( ! isset( $this->plugins_to_deactivate[ $module ][ $idx ] ) ) {
					continue;
				}

				$deactivated_titles[] = '<strong>' . str_replace( ' ', '&nbsp;', $this->plugins_to_deactivate[ $module ][ $idx ][1] ) . '</strong>';
			}

			if ( $deactivated_titles ) {
				if ( $this->message ) {
					$this->message .= "<br /><br />\n";
				}

				$this->message .= wp_sprintf(
					_n(
						'Jetpack contains the most recent version of the old %l plugin.',
						'Jetpack contains the most recent versions of the old %l plugins.',
						count( $deactivated_titles ),
						'jetpack'
					),
					$deactivated_titles
				);

				$this->message .= "<br />\n";

				$this->message .= _n(
					'The old version has been deactivated and can be removed from your site.',
					'The old versions have been deactivated and can be removed from your site.',
					count( $deactivated_titles ),
					'jetpack'
				);
			}
		}

		$this->privacy_checks = self::state( 'privacy_checks' );

		if ( $this->message || $this->error || $this->privacy_checks ) {
			add_action( 'jetpack_notices', array( $this, 'admin_notices' ) );
		}

		add_filter( 'jetpack_short_module_description', 'wptexturize' );
	}

	/**
	 * Display admin notice upon error.
	 *
	 * @return void
	 */
	public function admin_notices() {

		if ( $this->error ) {
			?>
<div id="message" class="jetpack-message jetpack-err">
	<div class="squeezer">
		<h2>
			<?php
			echo wp_kses(
				$this->error,
				array(
					'a'      => array( 'href' => array() ),
					'small'  => true,
					'code'   => true,
					'strong' => true,
					'br'     => true,
					'b'      => true,
				)
			);
			?>
			</h2>
			<?php
			$desc = self::state( 'error_description' );
			if ( $desc ) :
				?>
		<p><?php echo esc_html( stripslashes( $desc ) ); ?></p>
<?php	endif; ?>
	</div>
</div>
			<?php
		}

		if ( $this->message ) {
			?>
<div id="message" class="jetpack-message">
	<div class="squeezer">
		<h2>
			<?php
			echo wp_kses(
				$this->message,
				array(
					'strong' => array(),
					'a'      => array( 'href' => true ),
					'br'     => true,
				)
			);
			?>
			</h2>
	</div>
</div>
			<?php
		}

		if ( $this->privacy_checks ) :
			$module_names = array();
			$module_slugs = array();

			$privacy_checks = explode( ',', $this->privacy_checks );
			$privacy_checks = array_filter( $privacy_checks, array( 'Jetpack', 'is_module' ) );
			foreach ( $privacy_checks as $module_slug ) {
				$module = self::get_module( $module_slug );
				if ( ! $module ) {
					continue;
				}

				$module_slugs[] = $module_slug;
				$module_names[] = "<strong>{$module['name']}</strong>";
			}

			$module_slugs = join( ',', $module_slugs );
			?>
<div id="message" class="jetpack-message jetpack-err">
	<div class="squeezer">
		<h2><strong><?php esc_html_e( 'Is this site private?', 'jetpack' ); ?></strong></h2><br />
		<p>
			<?php
			echo wp_kses(
				wptexturize(
					wp_sprintf(
						_nx(
							"Like your site's RSS feeds, %l allows access to your posts and other content to third parties.",
							"Like your site's RSS feeds, %l allow access to your posts and other content to third parties.",
							count( $privacy_checks ),
							'%l = list of Jetpack module/feature names',
							'jetpack'
						),
						$module_names
					)
				),
				array( 'strong' => true )
			);

			echo "\n<br />\n";

			echo wp_kses(
				sprintf(
						/* translators: URL to deactivate Jetpack features. */
					_nx(
						'If your site is not publicly accessible, consider <a href="%1$s" title="%2$s">deactivating this feature</a>.',
						'If your site is not publicly accessible, consider <a href="%1$s" title="%2$s">deactivating these features</a>.',
						count( $privacy_checks ),
						'%1$s = deactivation URL, %2$s = "Deactivate {list of Jetpack module/feature names}',
						'jetpack'
					),
					wp_nonce_url(
						self::admin_url(
							array(
								'page'   => 'jetpack',
								'action' => 'deactivate',
								'module' => rawurlencode( $module_slugs ),
							)
						),
						"jetpack_deactivate-$module_slugs"
					),
					esc_attr( wp_kses( wp_sprintf( _x( 'Deactivate %l', '%l = list of Jetpack module/feature names', 'jetpack' ), $module_names ), array() ) )
				),
				array(
					'a' => array(
						'href'  => true,
						'title' => true,
					),
				)
			);
			?>
		</p>
	</div>
</div>
			<?php
endif;
	}

	/**
	 * We can't always respond to a signed XML-RPC request with a
	 * helpful error message. In some circumstances, doing so could
	 * leak information.
	 *
	 * Instead, track that the error occurred via a Jetpack_Option,
	 * and send that data back in the heartbeat.
	 * All this does is increment a number, but it's enough to find
	 * trends.
	 *
	 * @param WP_Error $xmlrpc_error The error produced during
	 *                               signature validation.
	 */
	public function track_xmlrpc_error( $xmlrpc_error ) {
		$code = is_wp_error( $xmlrpc_error )
			? $xmlrpc_error->get_error_code()
			: 'should-not-happen';

		$xmlrpc_errors = Jetpack_Options::get_option( 'xmlrpc_errors', array() );
		if ( isset( $xmlrpc_errors[ $code ] ) && $xmlrpc_errors[ $code ] ) {
			// No need to update the option if we already have
			// this code stored.
			return;
		}
		$xmlrpc_errors[ $code ] = true;

		Jetpack_Options::update_option( 'xmlrpc_errors', $xmlrpc_errors, false );
	}

	/**
	 * Initialize the jetpack stats instance only when needed
	 *
	 * @return void
	 */
	private function initialize_stats() {
		if ( $this->a8c_mc_stats_instance === null ) {
			$this->a8c_mc_stats_instance = new Automattic\Jetpack\A8c_Mc_Stats();
		}
	}

	/**
	 * Record a stat for later output.  This will only currently output in the admin_footer.
	 *
	 * @param string $group Stats group.
	 * @param string $detail Stats detail.
	 */
	public function stat( $group, $detail ) {
		$this->initialize_stats();
		$this->a8c_mc_stats_instance->add( $group, $detail );

		// Keep a local copy for backward compatibility (there are some direct checks on this).
		$this->stats = $this->a8c_mc_stats_instance->get_current_stats();
	}

	/**
	 * Load stats pixels. $group is auto-prefixed with "x_jetpack-"
	 *
	 * @param string $method Used to check if method is "server-side".
	 */
	public function do_stats( $method = '' ) {
		$this->initialize_stats();
		if ( 'server_side' === $method ) {
			$this->a8c_mc_stats_instance->do_server_side_stats();
		} else {
			$this->a8c_mc_stats_instance->do_stats();
		}

		// Keep a local copy for backward compatibility (there are some direct checks on this).
		$this->stats = array();
	}

	/**
	 * Runs stats code for a one-off, server-side.
	 *
	 * @param array|string $args The arguments to append to the URL. Should include `x_jetpack-{$group}={$stats}` or whatever we want to store.
	 *
	 * @return bool If it worked.
	 */
	public static function do_server_side_stat( $args ) {
		$url                   = self::build_stats_url( $args );
		$a8c_mc_stats_instance = new Automattic\Jetpack\A8c_Mc_Stats();
		return $a8c_mc_stats_instance->do_server_side_stat( $url );
	}

	/**
	 * Builds the stats url.
	 *
	 * @param array|string $args The arguments to append to the URL.
	 *
	 * @return string The URL to be pinged.
	 */
	public static function build_stats_url( $args ) {

		$a8c_mc_stats_instance = new Automattic\Jetpack\A8c_Mc_Stats();
		return $a8c_mc_stats_instance->build_stats_url( $args );
	}

	/**
	 * Builds a URL to the Jetpack connection auth page
	 *
	 * @since 3.9.5
	 *
	 * @param bool        $raw If true, URL will not be escaped.
	 * @param bool|string $redirect If true, will redirect back to Jetpack wp-admin landing page after connection.
	 *                              If string, will be a custom redirect.
	 * @param bool|string $from If not false, adds 'from=$from' param to the connect URL.
	 * @param bool        $register If true, will generate a register URL regardless of the existing token, since 4.9.0.
	 *
	 * @return string Connect URL
	 */
	public function build_connect_url( $raw = false, $redirect = false, $from = false, $register = false ) {
		$site_id    = Jetpack_Options::get_option( 'id' );
		$blog_token = ( new Tokens() )->get_access_token();

		if ( $register || ! $blog_token || ! $site_id ) {
			$url = self::nonce_url_no_esc( self::admin_url( 'action=register' ), 'jetpack-register' );

			if ( ! empty( $redirect ) ) {
				$url = add_query_arg(
					'redirect',
					rawurlencode( wp_validate_redirect( esc_url_raw( $redirect ) ) ),
					$url
				);
			}

			if ( is_network_admin() ) {
				$url = add_query_arg( 'is_multisite', network_admin_url( 'admin.php?page=jetpack-settings' ), $url );
			}

			$calypso_env = self::get_calypso_env();

			if ( ! empty( $calypso_env ) ) {
				$url = add_query_arg( 'calypso_env', $calypso_env, $url );
			}
		} else {

			// Let's check the existing blog token to see if we need to re-register. We only check once per minute
			// because otherwise this logic can get us in to a loop.
			$last_connect_url_check = (int) Jetpack_Options::get_raw_option( 'jetpack_last_connect_url_check' );
			if ( ! $last_connect_url_check || ( time() - $last_connect_url_check ) > MINUTE_IN_SECONDS ) {
				Jetpack_Options::update_raw_option( 'jetpack_last_connect_url_check', time() );

				$response = Client::wpcom_json_api_request_as_blog(
					sprintf( '/sites/%d', $site_id ) . '?force=wpcom',
					'1.1'
				);

				if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {

					// Generating a register URL instead to refresh the existing token.
					return $this->build_connect_url( $raw, $redirect, $from, true );
				}
			}

			$url = $this->build_authorize_url( $redirect );
		}

		if ( $from ) {
			$url = add_query_arg( 'from', $from, $url );
		}

		$url = $raw ? esc_url_raw( $url ) : esc_url( $url );
		/**
		 * Filter the URL used when connecting a user to a WordPress.com account.
		 *
		 * @since 8.1.0
		 *
		 * @param string $url Connection URL.
		 * @param bool   $raw If true, URL will not be escaped.
		 */
		return apply_filters( 'jetpack_build_connection_url', $url, $raw );
	}

	/**
	 * Create the Jetpack authorization URL.
	 *
	 * @param bool|string $redirect URL to redirect to.
	 * @param null        $deprecated Deprecated since Jetpack 10.9.
	 *
	 * @todo Update default value for redirect since the called function expects a string.
	 *
	 * @return mixed|void
	 */
	public static function build_authorize_url( $redirect = false, $deprecated = null ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable

		add_filter( 'jetpack_connect_request_body', array( __CLASS__, 'filter_connect_request_body' ) );
		add_filter( 'jetpack_connect_redirect_url', array( __CLASS__, 'filter_connect_redirect_url' ) );

		$c8n = self::connection();
		$url = $c8n->get_authorization_url( wp_get_current_user(), $redirect );

		remove_filter( 'jetpack_connect_request_body', array( __CLASS__, 'filter_connect_request_body' ) );
		remove_filter( 'jetpack_connect_redirect_url', array( __CLASS__, 'filter_connect_redirect_url' ) );

		/**
		 * Filter the URL used when authorizing a user to a WordPress.com account.
		 *
		 * @since 8.9.0
		 *
		 * @param string $url Connection URL.
		 */
		return apply_filters( 'jetpack_build_authorize_url', $url );
	}

	/**
	 * Filters the connection URL parameter array.
	 *
	 * @param array $args default URL parameters used by the package.
	 * @return array the modified URL arguments array.
	 */
	public static function filter_connect_request_body( $args ) {
		if (
			Constants::is_defined( 'JETPACK__GLOTPRESS_LOCALES_PATH' )
			&& include_once Constants::get_constant( 'JETPACK__GLOTPRESS_LOCALES_PATH' )
		) {
			$gp_locale      = GP_Locales::by_field( 'wp_locale', get_locale() );
			$args['locale'] = isset( $gp_locale ) && isset( $gp_locale->slug )
				? $gp_locale->slug
				: '';
		}

		$tracking        = new Tracking();
		$tracks_identity = $tracking->tracks_get_identity( $args['state'] );

		$args = array_merge(
			$args,
			array(
				'_ui' => $tracks_identity['_ui'],
				'_ut' => $tracks_identity['_ut'],
			)
		);

		$calypso_env = self::get_calypso_env();

		if ( ! empty( $calypso_env ) ) {
			$args['calypso_env'] = $calypso_env;
		}

		return $args;
	}

	/**
	 * Filters the `jetpack/v4/connection/data` API response of the Connection package in order to
	 * add Jetpack-the-plugin related permissions.
	 *
	 * @since 10.0
	 *
	 * @param array $current_user_connection_data An array containing the current user connection data.
	 * @return array
	 */
	public static function filter_jetpack_current_user_connection_data( $current_user_connection_data ) {
		$jetpack_permissions = array(
			'admin_page'         => current_user_can( 'jetpack_admin_page' ),
			'manage_modules'     => current_user_can( 'jetpack_manage_modules' ),
			'network_admin'      => current_user_can( 'jetpack_network_admin_page' ),
			'network_sites_page' => current_user_can( 'jetpack_network_sites_page' ),
			'edit_posts'         => current_user_can( 'edit_posts' ),
			'publish_posts'      => current_user_can( 'publish_posts' ),
			'manage_options'     => current_user_can( 'manage_options' ),
			'view_stats'         => current_user_can( 'view_stats' ),
			'manage_plugins'     => current_user_can( 'install_plugins' )
									&& current_user_can( 'activate_plugins' )
									&& current_user_can( 'update_plugins' )
									&& current_user_can( 'delete_plugins' ),
		);

		if ( isset( $current_user_connection_data['permissions'] ) &&
			is_array( $current_user_connection_data['permissions'] ) ) {
				$current_user_connection_data['permissions'] = array_merge( $current_user_connection_data['permissions'], $jetpack_permissions );
		} else {
			$current_user_connection_data['permissions'] = $jetpack_permissions;
		}

		return $current_user_connection_data;
	}

	/**
	 * Filters the URL that will process the connection data. It can be different from the URL
	 * that we send the user to after everything is done.
	 *
	 * @param String $processing_url the default redirect URL used by the package.
	 * @return String the modified URL.
	 *
	 * @deprecated since Jetpack 9.5.0
	 */
	public static function filter_connect_processing_url( $processing_url ) {
		_deprecated_function( __METHOD__, 'jetpack-9.5' );

		$processing_url = admin_url( 'admin.php?page=jetpack' ); // Making PHPCS happy.
		return $processing_url;
	}

	/**
	 * Filters the redirection URL that is used for connect requests. The redirect
	 * URL should return the user back to the Jetpack console.
	 *
	 * @param String $redirect the default redirect URL used by the package.
	 * @return String the modified URL.
	 */
	public static function filter_connect_redirect_url( $redirect ) {
		$jetpack_admin_page = esc_url_raw( admin_url( 'admin.php?page=jetpack' ) );
		$redirect           = $redirect
			? wp_validate_redirect( esc_url_raw( $redirect ), $jetpack_admin_page )
			: $jetpack_admin_page;

		if ( isset( $_REQUEST['is_multisite'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- not making a site change here.
			$redirect = Jetpack_Network::init()->get_url( 'network_admin_page' );
		}

		return $redirect;
	}

	/**
	 * This action fires at the beginning of the Manager::authorize method.
	 */
	public static function authorize_starting() {
		$jetpack_unique_connection = Jetpack_Options::get_option( 'unique_connection' );
		// Checking if site has been active/connected previously before recording unique connection.
		if ( ! $jetpack_unique_connection ) {
			// jetpack_unique_connection option has never been set.
			$jetpack_unique_connection = array(
				'connected'    => 0,
				'disconnected' => 0,
				'version'      => '3.6.1',
			);

			update_option( 'jetpack_unique_connection', $jetpack_unique_connection );

			// Track unique connection.
			$jetpack = self::init();

			$jetpack->stat( 'connections', 'unique-connection' );
			$jetpack->do_stats( 'server_side' );
		}

		// Increment number of times connected.
		$jetpack_unique_connection['connected'] += 1;
		Jetpack_Options::update_option( 'unique_connection', $jetpack_unique_connection );
	}

	/**
	 * This action fires when the site is registered (connected at a site level).
	 */
	public function handle_unique_registrations_stats() {
		$jetpack_unique_registrations = Jetpack_Options::get_option( 'unique_registrations' );
		// Checking if site has been registered previously before recording unique connection.
		if ( ! $jetpack_unique_registrations ) {

			$jetpack_unique_registrations = 0;

			$this->stat( 'connections', 'unique-registrations' );
			$this->do_stats( 'server_side' );
		}

		// Increment number of times connected.
		++$jetpack_unique_registrations;
		Jetpack_Options::update_option( 'unique_registrations', $jetpack_unique_registrations );
	}

	/**
	 * This action fires at the end of the Manager::authorize method when a secondary user is
	 * linked.
	 */
	public static function authorize_ending_linked() {
		// Don't activate anything since we are just connecting a user.
		self::state( 'message', 'linked' );
	}

	/**
	 * This action fires at the end of the Manager::authorize method when the master user is
	 * authorized.
	 *
	 * @param array $data The request data.
	 */
	public static function authorize_ending_authorized( $data ) {
		// If this site has been through the Jetpack Onboarding flow, delete the onboarding token.
		self::invalidate_onboarding_token();

		// If redirect_uri is SSO, ensure SSO module is enabled.
		parse_str( wp_parse_url( $data['redirect_uri'], PHP_URL_QUERY ), $redirect_options );

		/** This filter is documented in class.jetpack-cli.php */
		$jetpack_start_enable_sso = apply_filters( 'jetpack_start_enable_sso', true );

		$activate_sso = (
			isset( $redirect_options['action'] ) &&
			'jetpack-sso' === $redirect_options['action'] &&
			$jetpack_start_enable_sso
		);

		$do_redirect_on_error = ( 'client' === $data['auth_type'] );

		self::handle_post_authorization_actions( $activate_sso, $do_redirect_on_error );
	}

	/**
	 * Fires on the jetpack_site_registered hook and acitvates default modules
	 */
	public static function activate_default_modules_on_site_register() {
		self::handle_default_module_activation( false );

		// Since this is a fresh connection, be sure to clear out IDC options.
		Identity_Crisis::clear_all_idc_options();
	}

	/**
	 * This action fires at the end of the REST_Connector connection_reconnect method when the
	 * reconnect process is completed.
	 * Note that this currently only happens when we don't need the user to re-authorize
	 * their WP.com account, eg in cases where we are restoring a connection with
	 * unhealthy blog token.
	 */
	public static function reconnection_completed() {
		self::state( 'message', 'reconnection_completed' );
	}

	/**
	 * Apply activation source to a query string array.
	 *
	 * @param array $args Args used for a query string.
	 *
	 * @return void
	 */
	public static function apply_activation_source_to_args( &$args ) {
		list( $activation_source_name, $activation_source_keyword ) = get_option( 'jetpack_activation_source' );

		if ( $activation_source_name ) {
			$args['_as'] = rawurlencode( $activation_source_name );
		}

		if ( $activation_source_keyword ) {
			$args['_ak'] = rawurlencode( $activation_source_keyword );
		}
	}

	/**
	 * Returns the reconnection URL.
	 *
	 * @param bool $raw True to return an unescaped URL. False returns value after `esc_url`.
	 *
	 * @return string|null
	 */
	public function build_reconnect_url( $raw = false ) {
		$url = wp_nonce_url( self::admin_url( 'action=reconnect' ), 'jetpack-reconnect' );
		return $raw ? $url : esc_url( $url );
	}

	/**
	 * Jetpack Admin URL.
	 *
	 * @param array $args Query string args.
	 *
	 * @return string Jetpack admin URL.
	 */
	public static function admin_url( $args = null ) {
		return ( new Paths() )->admin_url( $args );
	}

	/**
	 * Creates a nonce from an URL.
	 *
	 * @param string $actionurl URL for action.
	 * @param string $action Nonce action.
	 * @param string $name Query arg name.
	 *
	 * @return string
	 */
	public static function nonce_url_no_esc( $actionurl, $action = -1, $name = '_wpnonce' ) {
		$actionurl = str_replace( '&amp;', '&', $actionurl );
		return add_query_arg( $name, wp_create_nonce( $action ), $actionurl );
	}

	/**
	 * Dismiss Jetpack notices.
	 *
	 * @return void
	 */
	public function dismiss_jetpack_notice() {
		if ( ! isset( $_GET['jetpack-notice'] ) ) {
			return;
		}

		switch ( $_GET['jetpack-notice'] ) {
			case 'dismiss':
				if ( check_admin_referer( 'jetpack-deactivate' ) && ! is_plugin_active_for_network( plugin_basename( JETPACK__PLUGIN_DIR . 'jetpack.php' ) ) ) {

					require_once ABSPATH . 'wp-admin/includes/plugin.php';
					deactivate_plugins( JETPACK__PLUGIN_DIR . 'jetpack.php', false, false );
					wp_safe_redirect( admin_url() . 'plugins.php?deactivate=true&plugin_status=all&paged=1&s=' );
				}
				break;
		}
	}

	/**
	 * Determines which module has a higher sort order.
	 *
	 * @param array $a Modules array.
	 * @param array $b Modules array.
	 *
	 * @return int 0 if the same sort or (+/-) to indicate which is greater.
	 */
	public static function sort_modules( $a, $b ) {
		if ( $a['sort'] === $b['sort'] ) {
			return 0;
		}

		return ( $a['sort'] < $b['sort'] ) ? -1 : 1;
	}

	/**
	 * Recheck SSL status for use via an AJAX call.
	 *
	 * Sends data back via `wp_send_json`.
	 *
	 * @return void
	 */
	public function ajax_recheck_ssl() {
		check_ajax_referer( 'recheck-ssl', 'ajax-nonce' );
		$result = self::permit_ssl( true );
		wp_send_json(
			array(
				'enabled' => $result,
				'message' => get_transient( 'jetpack_https_test_message' ),
			)
		);
	}

	/* Client API */

	/**
	 * Verify the onboarding token.
	 *
	 * @param array  $token_data Token data.
	 * @param string $token Token value.
	 * @param string $request_data JSON-encoded request data.
	 *
	 * @return mixed
	 */
	public static function verify_onboarding_token( $token_data, $token, $request_data ) {
		// Default to a blog token.
		$token_type = 'blog';

		// Let's see if this is onboarding. In such case, use user token type and the provided user id.
		if ( isset( $request_data ) || ! empty( $_GET['onboarding'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no site changes, if caller is changing the site the nonce should be verified there.
			if ( ! empty( $_GET['onboarding'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no site changes.
				$jpo = $_GET; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no site changes.
			} else {
				$jpo = json_decode( $request_data, true );
			}

			$jpo_token = ! empty( $jpo['onboarding']['token'] ) ? $jpo['onboarding']['token'] : null;
			$jpo_user  = ! empty( $jpo['onboarding']['jpUser'] ) ? $jpo['onboarding']['jpUser'] : null;

			if (
				isset( $jpo_user )
				&& isset( $jpo_token )
				&& is_email( $jpo_user )
				&& ctype_alnum( $jpo_token )
				&& isset( $_GET['rest_route'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- no site changes.
				&& self::validate_onboarding_token_action(
					$jpo_token,
					wp_unslash( $_GET['rest_route'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- no site changes.
				)
			) {
				$jp_user = get_user_by( 'email', $jpo_user );
				if ( is_a( $jp_user, 'WP_User' ) ) {
					wp_set_current_user( $jp_user->ID );
					$user_can = is_multisite()
						? current_user_can_for_blog( get_current_blog_id(), 'manage_options' )
						: current_user_can( 'manage_options' );
					if ( $user_can ) {
						$token_type              = 'user';
						$token->external_user_id = $jp_user->ID;
					}
				}
			}

			$token_data['type']    = $token_type;
			$token_data['user_id'] = $token->external_user_id;
		}

		return $token_data;
	}

	/**
	 * Create a random secret for validating onboarding payload
	 *
	 * @return string Secret token
	 */
	public static function create_onboarding_token() {
		$token = Jetpack_Options::get_option( 'onboarding' );
		if ( false === ( $token ) ) {
			$token = wp_generate_password( 32, false );
			Jetpack_Options::update_option( 'onboarding', $token );
		}

		return $token;
	}

	/**
	 * Remove the onboarding token
	 *
	 * @return bool True on success, false on failure
	 */
	public static function invalidate_onboarding_token() {
		return Jetpack_Options::delete_option( 'onboarding' );
	}

	/**
	 * Validate an onboarding token for a specific action
	 *
	 * @param string $token Onboarding token.
	 * @param string $action Action name.
	 *
	 * @return boolean True if token/action pair is accepted, false if not
	 */
	public static function validate_onboarding_token_action( $token, $action ) {
		// Compare tokens, bail if tokens do not match.
		if ( ! hash_equals( $token, Jetpack_Options::get_option( 'onboarding' ) ) ) {
			return false;
		}

		// List of valid actions we can take.
		$valid_actions = array(
			'/jetpack/v4/settings',
		);

		// Only allow valid actions.
		if ( ! in_array( $action, $valid_actions, true ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Checks to see if the URL is using SSL to connect with Jetpack
	 *
	 * @param bool $force_recheck Force SSL recheck.
	 *
	 * @return boolean
	 * @since 2.3.3
	 */
	public static function permit_ssl( $force_recheck = false ) {
		// Do some fancy tests to see if ssl is being supported.
		if ( ! $force_recheck ) {
			$ssl = get_transient( 'jetpack_https_test' );
		}

		if ( $force_recheck || false === $ssl ) {
			$message = '';
			if ( 'https' !== substr( JETPACK__API_BASE, 0, 5 ) ) {
				$ssl = 0;
			} else {
				$ssl = 1;

				if ( ! wp_http_supports( array( 'ssl' => true ) ) ) {
					$ssl     = 0;
					$message = __( 'WordPress reports no SSL support', 'jetpack' );
				} else {
					$response = wp_remote_get( JETPACK__API_BASE . 'test/1/' );
					if ( is_wp_error( $response ) ) {
						$ssl     = 0;
						$message = __( 'WordPress reports no SSL support', 'jetpack' );
					} elseif ( 'OK' !== wp_remote_retrieve_body( $response ) ) {
						$ssl     = 0;
						$message = __( 'Response was not OK: ', 'jetpack' ) . wp_remote_retrieve_body( $response );
					}
				}
			}
			set_transient( 'jetpack_https_test', $ssl, DAY_IN_SECONDS );
			set_transient( 'jetpack_https_test_message', $message, DAY_IN_SECONDS );
		}

		return (bool) $ssl;
	}

	/**
	 * Displays an admin_notice, alerting the user that outbound SSL isn't working.
	 */
	public function alert_auto_ssl_fail() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$ajax_nonce = wp_create_nonce( 'recheck-ssl' );
		?>

		<div id="jetpack-ssl-warning" class="error jp-identity-crisis">
			<div class="jp-banner__content">
				<h2><?php esc_html_e( 'Outbound HTTPS not working', 'jetpack' ); ?></h2>
				<p><?php esc_html_e( 'Your site could not connect to WordPress.com via HTTPS. This could be due to any number of reasons, including faulty SSL certificates, misconfigured or missing SSL libraries, or network issues.', 'jetpack' ); ?></p>
				<p>
					<?php esc_html_e( 'Jetpack will re-test for HTTPS support once a day, but you can click here to try again immediately: ', 'jetpack' ); ?>
					<a href="#" id="jetpack-recheck-ssl-button"><?php esc_html_e( 'Try again', 'jetpack' ); ?></a>
					<span id="jetpack-recheck-ssl-output"><?php echo esc_html( get_transient( 'jetpack_https_test_message' ) ); ?></span>
				</p>
				<p>
					<?php
					printf(
							/* translators: Both are URLs. First for the connection debug tool and the second for a support page. */
						__( 'For more help, try our <a href="%1$s">connection debugger</a> or <a href="%2$s" target="_blank">troubleshooting tips</a>.', 'jetpack' ), // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- we're building known HTML.
						esc_url( self::admin_url( array( 'page' => 'jetpack-debugger' ) ) ),
						esc_url( Redirect::get_url( 'jetpack-support-getting-started-troubleshooting-tips' ) )
					);
					?>
				</p>
			</div>
		</div>
		<style>
			#jetpack-recheck-ssl-output { margin-left: 5px; color: red; }
		</style>
		<script type="text/javascript">
			jQuery( document ).ready( function( $ ) {
				$( '#jetpack-recheck-ssl-button' ).click( function( e ) {
					var $this = $( this );
					$this.html( <?php echo wp_json_encode( __( 'Checking', 'jetpack' ) ); ?> );
					$( '#jetpack-recheck-ssl-output' ).html( '' );
					e.preventDefault();
					var data = { action: 'jetpack-recheck-ssl', 'ajax-nonce': <?php echo wp_json_encode( $ajax_nonce ); ?> };
					$.post( ajaxurl, data )
					.done( function( response ) {
						if ( response.enabled ) {
							$( '#jetpack-ssl-warning' ).hide();
						} else {
							this.html( <?php echo wp_json_encode( __( 'Try again', 'jetpack' ) ); ?> );
							$( '#jetpack-recheck-ssl-output' ).html( 'SSL Failed: ' + response.message );
						}
					}.bind( $this ) );
				} );
			} );
		</script>

		<?php
	}

	/**
	 * Returns the connection manager object.
	 *
	 * @return Automattic\Jetpack\Connection\Manager
	 */
	public static function connection() {
		$jetpack = static::init();

		// If the connection manager hasn't been instantiated, do that now.
		if ( ! $jetpack->connection_manager ) {
			$jetpack->connection_manager = new Connection_Manager( 'jetpack' );
		}

		return $jetpack->connection_manager;
	}

	/**
	 * Creates two secret tokens and the end of life timestamp for them.
	 *
	 * Note these tokens are unique per call, NOT static per site for connecting.
	 *
	 * @deprecated 9.5 Use Automattic\Jetpack\Connection\Secrets->generate() instead.
	 *
	 * @since 2.6
	 * @param String  $action  The action name.
	 * @param Integer $user_id The user identifier.
	 * @param Integer $exp     Expiration time in seconds.
	 * @return array
	 */
	public static function generate_secrets( $action, $user_id = false, $exp = 600 ) {
		_deprecated_function( __METHOD__, 'jetpack-9.5', 'Automattic\\Jetpack\\Connection\\Secrets->generate' );
		return self::connection()->generate_secrets( $action, $user_id, $exp );
	}

	/**
	 * Get verification secrets.
	 *
	 * @param string $action Action name.
	 * @param int    $user_id User ID.
	 *
	 * @return array|string|WP_Error
	 */
	public static function get_secrets( $action, $user_id ) {
		$secrets = ( new Secrets() )->get( $action, $user_id );

		if ( Secrets::SECRETS_MISSING === $secrets ) {
			return new WP_Error( 'verify_secrets_missing', 'Verification secrets not found' );
		}

		if ( Secrets::SECRETS_EXPIRED === $secrets ) {
			return new WP_Error( 'verify_secrets_expired', 'Verification took too long' );
		}

		return $secrets;
	}

	/**
	 * Register a connection.
	 *
	 * @deprecated Jetpack 9.7.0
	 * @see Automattic\Jetpack\Connection\Manager::try_registration()
	 *
	 * @return bool|WP_Error
	 */
	public static function register() {
		_deprecated_function( __METHOD__, 'jetpack-9.7', 'Automattic\\Jetpack\\Connection\\Manager::try_registration' );
		return static::connection()->try_registration( false );
	}

	/**
	 * Filters the registration request body to include tracking properties.
	 *
	 * @deprecated Jetpack 9.7.0
	 * @see Automattic\Jetpack\Connection\Utils::filter_register_request_body()
	 *
	 * @param array $properties Token request properties.
	 * @return array amended properties.
	 */
	public static function filter_register_request_body( $properties ) {
		_deprecated_function( __METHOD__, 'jetpack-9.7', 'Automattic\\Jetpack\\Connection\\Utils::filter_register_request_body' );
		return Connection_Utils::filter_register_request_body( $properties );
	}

	/**
	 * Filters the token request body to include tracking properties.
	 *
	 * @param array $properties Token request properties.
	 *
	 * @return array amended properties.
	 */
	public static function filter_token_request_body( $properties ) {
		$tracking        = new Tracking();
		$tracks_identity = $tracking->tracks_get_identity( get_current_user_id() );

		return array_merge(
			$properties,
			array(
				'_ui' => $tracks_identity['_ui'],
				'_ut' => $tracks_identity['_ut'],
			)
		);
	}

	/**
	 * If the db version is showing something other that what we've got now, bump it to current.
	 *
	 * @return bool: True if the option was incorrect and updated, false if nothing happened.
	 */
	public static function maybe_set_version_option() {
		list( $version ) = explode( ':', Jetpack_Options::get_option( 'version' ) );
		if ( JETPACK__VERSION !== $version ) {
			Jetpack_Options::update_option( 'version', JETPACK__VERSION . ':' . time() );

			if ( version_compare( JETPACK__VERSION, $version, '>' ) ) {
				/** This action is documented in class.jetpack.php */
				do_action( 'updating_jetpack_version', JETPACK__VERSION, $version );
			}

			return true;
		}
		return false;
	}

	/* Client Server API */

	/**
	 * Loads the Jetpack XML-RPC client.
	 * No longer necessary, as the XML-RPC client will be automagically loaded.
	 *
	 * Note: we cannot remove this function yet as it is used in this plugin:
	 * https://wordpress.org/plugins/jetpack-subscription-form/
	 *
	 * @deprecated since 7.7.0
	 */
	public static function load_xml_rpc_client() {
		_deprecated_function( __METHOD__, 'jetpack-7.7' );
	}

	/**
	 * State is passed via cookies from one request to the next, but never to subsequent requests.
	 * SET: state( $key, $value );
	 * GET: $value = state( $key );
	 *
	 * @param string $key State key.
	 * @param string $value Value.
	 * @param bool   $restate Reset the cookie (private).
	 */
	public static function state( $key = null, $value = null, $restate = false ) {
		return ( new CookieState() )->state( $key, $value, $restate );
	}

	/**
	 * Set an empty state.
	 *
	 * @return void
	 */
	public static function restate() {
		self::state( null, null, true );
	}

	/**
	 * Determines whether the jetpackState[$key] value should be added to the
	 * cookie.
	 *
	 * @param string $key The state key.
	 *
	 * @return boolean Whether the value should be added to the cookie.
	 */
	public static function should_set_cookie( $key ) {
		return ( new CookieState() )->should_set_cookie( $key );
	}

	/**
	 * Check if site is publicly accessible.
	 *
	 * @param string $file Module file.
	 *
	 * @return void
	 */
	public static function check_privacy( $file ) {
		static $is_site_publicly_accessible = null;

		if ( $is_site_publicly_accessible === null ) {
			$is_site_publicly_accessible = false;

			$rpc = new Jetpack_IXR_Client();

			$success = $rpc->query( 'jetpack.isSitePubliclyAccessible', home_url() );
			if ( $success ) {
				$response = $rpc->getResponse();
				if ( $response ) {
					$is_site_publicly_accessible = true;
				}
			}

			Jetpack_Options::update_option( 'public', (int) $is_site_publicly_accessible );
		}

		if ( $is_site_publicly_accessible ) {
			return;
		}

		$module_slug = self::get_module_slug( $file );

		$privacy_checks = self::state( 'privacy_checks' );
		if ( ! $privacy_checks ) {
			$privacy_checks = $module_slug;
		} else {
			$privacy_checks .= ",$module_slug";
		}

		self::state( 'privacy_checks', $privacy_checks );
	}

	/**
	 * Serve a WordPress.com static resource via a randomized wp.com subdomain.
	 *
	 * @deprecated 9.3.0 Use Assets::staticize_subdomain.
	 *
	 * @param string $url WordPress.com static resource URL.
	 */
	public static function staticize_subdomain( $url ) {
		_deprecated_function( __METHOD__, 'jetpack-9.3.0', 'Automattic\Jetpack\Assets::staticize_subdomain' );
		return Assets::staticize_subdomain( $url );
	}

	/* JSON API Authorization */

	/**
	 * Handles the login action for Authorizing the JSON API
	 */
	public function login_form_json_api_authorization() {
		$this->verify_json_api_authorization_request();

		add_action( 'wp_login', array( $this, 'store_json_api_authorization_token' ), 10, 2 );

		add_action( 'login_message', array( $this, 'login_message_json_api_authorization' ) );
		add_action( 'login_form', array( $this, 'preserve_action_in_login_form_for_json_api_authorization' ) );
		add_filter( 'site_url', array( $this, 'post_login_form_to_signed_url' ), 10, 3 );
	}

	/**
	 * Make sure the login form is POSTed to the signed URL so we can reverify the request.
	 *
	 * @param string $url Redirect URL.
	 * @param string $path Path.
	 * @param string $scheme URL Scheme.
	 */
	public function post_login_form_to_signed_url( $url, $path, $scheme ) {
		if ( 'wp-login.php' !== $path || ( 'login_post' !== $scheme && 'login' !== $scheme ) ) {
			return $url;
		}
		$query_string = isset( $_SERVER['QUERY_STRING'] ) ? wp_unslash( $_SERVER['QUERY_STRING'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$parsed_url   = wp_parse_url( $url );
		$url          = strtok( $url, '?' );
		$url          = "$url?{$query_string}";
		if ( ! empty( $parsed_url['query'] ) ) {
			$url .= "&{$parsed_url['query']}";
		}

		return $url;
	}

	/**
	 * Make sure the POSTed request is handled by the same action.
	 */
	public function preserve_action_in_login_form_for_json_api_authorization() {
		$http_host   = isset( $_SERVER['HTTP_HOST'] ) ? wp_unslash( $_SERVER['HTTP_HOST'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- escaped with esc_url below.
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- escaped with esc_url below.
		echo "<input type='hidden' name='action' value='jetpack_json_api_authorization' />\n";
		echo "<input type='hidden' name='jetpack_json_api_original_query' value='" . esc_url( set_url_scheme( $http_host . $request_uri ) ) . "' />\n";
	}

	/**
	 * If someone logs in to approve API access, store the Access Code in usermeta.
	 *
	 * @param string  $user_login Unused.
	 * @param WP_User $user User logged in.
	 */
	public function store_json_api_authorization_token( $user_login, $user ) {
		add_filter( 'login_redirect', array( $this, 'add_token_to_login_redirect_json_api_authorization' ), 10, 3 );
		add_filter( 'allowed_redirect_hosts', array( $this, 'allow_wpcom_public_api_domain' ) );
		$token = wp_generate_password( 32, false );
		update_user_meta( $user->ID, 'jetpack_json_api_' . $this->json_api_authorization_request['client_id'], $token );
	}

	/**
	 * Add public-api.wordpress.com to the safe redirect allowed list - only added when someone allows API access.
	 *
	 * To be used with a filter of allowed domains for a redirect.
	 *
	 * @param array $domains Allowed WP.com Environments.
	 */
	public function allow_wpcom_public_api_domain( $domains ) {
		$domains[] = 'public-api.wordpress.com';
		return $domains;
	}

	/**
	 * Check if the redirect is encoded.
	 *
	 * @param string $redirect_url Redirect URL.
	 *
	 * @return bool If redirect has been encoded.
	 */
	public static function is_redirect_encoded( $redirect_url ) {
		return preg_match( '/https?%3A%2F%2F/i', $redirect_url ) > 0;
	}

	/**
	 * Add all wordpress.com environments to the safe redirect allowed list.
	 *
	 * To be used with a filter of allowed domains for a redirect.
	 *
	 * @param array $domains Allowed WP.com Environments.
	 *
	 * @deprecated since 11.1
	 */
	public function allow_wpcom_environments( $domains ) {
		return Host::allow_wpcom_environments( $domains );
	}

	/**
	 * Add the Access Code details to the public-api.wordpress.com redirect.
	 *
	 * @param string  $redirect_to URL.
	 * @param string  $original_redirect_to URL.
	 * @param WP_User $user WP_User for the redirect.
	 *
	 * @return string
	 */
	public function add_token_to_login_redirect_json_api_authorization( $redirect_to, $original_redirect_to, $user ) {
		return add_query_arg(
			urlencode_deep(
				array(
					'jetpack-code'    => get_user_meta( $user->ID, 'jetpack_json_api_' . $this->json_api_authorization_request['client_id'], true ),
					'jetpack-user-id' => (int) $user->ID,
					'jetpack-state'   => $this->json_api_authorization_request['state'],
				)
			),
			$redirect_to
		);
	}

	/**
	 * Verifies the request by checking the signature
	 *
	 * @since 4.6.0 Method was updated to use `$_REQUEST` instead of `$_GET` and `$_POST`. Method also updated to allow
	 * passing in an `$environment` argument that overrides `$_REQUEST`. This was useful for integrating with SSO.
	 *
	 * @param null|array $environment Value to override $_REQUEST.
	 */
	public function verify_json_api_authorization_request( $environment = null ) {
		$environment = $environment === null
			? $_REQUEST // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- nonce verification handled later in function.
			: $environment;

		list( $env_token,, $env_user_id ) = explode( ':', $environment['token'] );
		$token                            = ( new Tokens() )->get_access_token( $env_user_id, $env_token );
		if ( ! $token || empty( $token->secret ) ) {
			wp_die( esc_html__( 'You must connect your Jetpack plugin to WordPress.com to use this feature.', 'jetpack' ) );
		}

		$die_error = __( 'Someone may be trying to trick you into giving them access to your site. Or it could be you just encountered a bug :).  Either way, please close this window.', 'jetpack' );

		// Host has encoded the request URL, probably as a result of a bad http => https redirect.
		if ( self::is_redirect_encoded( esc_url_raw( wp_unslash( $_GET['redirect_to'] ) ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- no site changes, we're erroring out.
			/**
			 * Jetpack authorisation request Error.
			 *
			 * @since 7.5.0
			 */
			do_action( 'jetpack_verify_api_authorization_request_error_double_encode' );
			$die_error = sprintf(
				/* translators: %s is a URL */
				__( 'Your site is incorrectly double-encoding redirects from http to https. This is preventing Jetpack from authenticating your connection. Please visit our <a href="%s">support page</a> for details about how to resolve this.', 'jetpack' ),
				Redirect::get_url( 'jetpack-support-double-encoding' )
			);
		}

		$jetpack_signature = new Jetpack_Signature( $token->secret, (int) Jetpack_Options::get_option( 'time_diff' ) );

		if ( isset( $environment['jetpack_json_api_original_query'] ) ) {
			$signature = $jetpack_signature->sign_request(
				$environment['token'],
				$environment['timestamp'],
				$environment['nonce'],
				'',
				'GET',
				$environment['jetpack_json_api_original_query'],
				null,
				true
			);
		} else {
			$signature = $jetpack_signature->sign_current_request(
				array(
					'body'   => null,
					'method' => 'GET',
				)
			);
		}

		if ( ! $signature ) {
			wp_die(
				wp_kses(
					$die_error,
					array(
						'a' => array(
							'href' => array(),
						),
					)
				)
			);
		} elseif ( is_wp_error( $signature ) ) {
			wp_die(
				wp_kses(
					$die_error,
					array(
						'a' => array(
							'href' => array(),
						),
					)
				)
			);
		} elseif ( ! hash_equals( $signature, $environment['signature'] ) ) {
			if ( is_ssl() ) {
				// If we signed an HTTP request on the Jetpack Servers, but got redirected to HTTPS by the local blog, check the HTTP signature as well.
				$signature = $jetpack_signature->sign_current_request(
					array(
						'scheme' => 'http',
						'body'   => null,
						'method' => 'GET',
					)
				);
				if ( ! $signature || is_wp_error( $signature ) || ! hash_equals( $signature, $environment['signature'] ) ) {
					wp_die(
						wp_kses(
							$die_error,
							array(
								'a' => array(
									'href' => array(),
								),
							)
						)
					);
				}
			} else {
				wp_die(
					wp_kses(
						$die_error,
						array(
							'a' => array(
								'href' => array(),
							),
						)
					)
				);
			}
		}

		$timestamp = (int) $environment['timestamp'];
		$nonce     = stripslashes( (string) $environment['nonce'] );

		if ( ! $this->connection_manager ) {
			$this->connection_manager = new Connection_Manager();
		}

		if ( ! ( new Nonce_Handler() )->add( $timestamp, $nonce ) ) {
			// De-nonce the nonce, at least for 5 minutes.
			// We have to reuse this nonce at least once (used the first time when the initial request is made, used a second time when the login form is POSTed).
			$old_nonce_time = get_option( "jetpack_nonce_{$timestamp}_{$nonce}" );
			if ( $old_nonce_time < time() - 300 ) {
				wp_die( esc_html__( 'The authorization process expired. Please go back and try again.', 'jetpack' ) );
			}
		}

		$data         = json_decode( base64_decode( stripslashes( $environment['data'] ) ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		$data_filters = array(
			'state'        => 'opaque',
			'client_id'    => 'int',
			'client_title' => 'string',
			'client_image' => 'url',
		);

		foreach ( $data_filters as $key => $sanitation ) {
			if ( ! isset( $data->$key ) ) {
				wp_die(
					wp_kses(
						$die_error,
						array(
							'a' => array(
								'href' => array(),
							),
						)
					)
				);
			}

			switch ( $sanitation ) {
				case 'int':
					$this->json_api_authorization_request[ $key ] = (int) $data->$key;
					break;
				case 'opaque':
					$this->json_api_authorization_request[ $key ] = (string) $data->$key;
					break;
				case 'string':
					$this->json_api_authorization_request[ $key ] = wp_kses( (string) $data->$key, array() );
					break;
				case 'url':
					$this->json_api_authorization_request[ $key ] = esc_url_raw( (string) $data->$key );
					break;
			}
		}

		if ( empty( $this->json_api_authorization_request['client_id'] ) ) {
			wp_die(
				wp_kses(
					$die_error,
					array(
						'a' => array(
							'href' => array(),
						),
					)
				)
			);
		}
	}

	/**
	 * HTML for the JSON API authorization notice.
	 *
	 * @return string
	 */
	public function login_message_json_api_authorization() {
		return '<p class="message">' . sprintf(
			/* translators: Name/image of the client requesting authorization */
			esc_html__( '%s wants to access your site’s data. Log in to authorize that access.', 'jetpack' ),
			'<strong>' . esc_html( $this->json_api_authorization_request['client_title'] ) . '</strong>'
		) . '<img src="' . esc_url( $this->json_api_authorization_request['client_image'] ) . '" /></p>';
	}

	/**
	 * Get $content_width, but with a <s>twist</s> filter.
	 */
	public static function get_content_width() {
		$content_width = ( isset( $GLOBALS['content_width'] ) && is_numeric( $GLOBALS['content_width'] ) )
			? $GLOBALS['content_width']
			: false;
		/**
		 * Filter the Content Width value.
		 *
		 * @since 2.2.3
		 *
		 * @param string $content_width Content Width value.
		 */
		return apply_filters( 'jetpack_content_width', $content_width );
	}

	/**
	 * Pings the WordPress.com Mirror Site for the specified options.
	 *
	 * @param string|array $option_names The option names to request from the WordPress.com Mirror Site.
	 *
	 * @return array An associative array of the option values as stored in the WordPress.com Mirror Site
	 */
	public function get_cloud_site_options( $option_names ) {
		$option_names = array_filter( (array) $option_names, 'is_string' );

		$xml = new Jetpack_IXR_Client();
		$xml->query( 'jetpack.fetchSiteOptions', $option_names );
		if ( $xml->isError() ) {
			return array(
				'error_code' => $xml->getErrorCode(),
				'error_msg'  => $xml->getErrorMessage(),
			);
		}
		$cloud_site_options = $xml->getResponse();

		return $cloud_site_options;
	}

	/**
	 * Checks if the site is currently in an identity crisis.
	 *
	 * @return array|bool Array of options that are in a crisis, or false if everything is OK.
	 */
	public static function check_identity_crisis() {
		if ( ! self::is_connection_ready() || ( new Status() )->is_offline_mode() || ! Identity_Crisis::validate_sync_error_idc_option() ) {
			return false;
		}

		return Jetpack_Options::get_option( 'sync_error_idc' );
	}

	/**
	 * Checks whether the sync_error_idc option is valid or not, and if not, will do cleanup.
	 *
	 * @since 4.4.0
	 * @since 5.4.0 Do not call get_sync_error_idc_option() unless site is in IDC
	 *
	 * @return bool
	 */
	public static function validate_sync_error_idc_option() {
		_deprecated_function( __METHOD__, 'jetpack-9.8', '\\Automattic\\Jetpack\\Identity_Crisis::validate_sync_error_idc_option' );
		return Identity_Crisis::validate_sync_error_idc_option();
	}

	/**
	 * Normalizes a url by doing three things:
	 *  - Strips protocol
	 *  - Strips www
	 *  - Adds a trailing slash
	 *
	 * @since 4.4.0
	 * @param string $url URL.
	 * @return WP_Error|string
	 */
	public static function normalize_url_protocol_agnostic( $url ) {
		$parsed_url = wp_parse_url( trailingslashit( esc_url_raw( $url ) ) );
		if ( ! $parsed_url || empty( $parsed_url['host'] ) || empty( $parsed_url['path'] ) ) {
			/* translators: URL string */
			return new WP_Error( 'cannot_parse_url', sprintf( esc_html__( 'Cannot parse URL %s', 'jetpack' ), $url ) );
		}

		// Strip www and protocols.
		$url = preg_replace( '/^www\./i', '', $parsed_url['host'] . $parsed_url['path'] );
		return $url;
	}

	/**
	 * Gets the value that is to be saved in the jetpack_sync_error_idc option.
	 *
	 * @since 4.4.0
	 * @since 5.4.0 Add transient since home/siteurl retrieved directly from DB
	 * @deprecated 9.8.0 Use \\Automattic\\Jetpack\\Identity_Crisis::get_sync_error_idc_option
	 *
	 * @param array $response HTTP response.
	 * @return array Array of the local urls, wpcom urls, and error code
	 */
	public static function get_sync_error_idc_option( $response = array() ) {
		_deprecated_function( __METHOD__, 'jetpack-9.8', '\\Automattic\\Jetpack\\Identity_Crisis::get_sync_error_idc_option' );
		return Identity_Crisis::get_sync_error_idc_option( $response );
	}

	/**
	 * Returns the value of the jetpack_sync_idc_optin filter, or constant.
	 * If set to true, the site will be put into staging mode.
	 *
	 * @since 4.3.2
	 * @return bool
	 */
	public static function sync_idc_optin() {
		_deprecated_function( __METHOD__, 'jetpack-9.8', '\\Automattic\\Jetpack\\Identity_Crisis::sync_idc_optin' );
		return Identity_Crisis::sync_idc_optin();
	}

	/**
	 * Maybe Use a .min.css stylesheet, maybe not.
	 *
	 * Hooks onto `plugins_url` filter at priority 1, and accepts all 3 args.
	 *
	 * @param string $url URL.
	 * @param string $path File path.
	 * @param string $plugin Plugin.
	 *
	 * @return mixed
	 */
	public static function maybe_min_asset( $url, $path, $plugin ) {
		// Short out on things trying to find actual paths.
		if ( ! $path || empty( $plugin ) ) {
			return $url;
		}

		$path = ltrim( $path, '/' );

		// Strip out the abspath.
		$base = dirname( plugin_basename( $plugin ) );

		// Short out on non-Jetpack assets.
		if ( 'jetpack/' !== substr( $base, 0, 8 ) ) {
			return $url;
		}

		// File name parsing.
		$file              = "{$base}/{$path}";
		$full_path         = JETPACK__PLUGIN_DIR . substr( $file, 8 );
		$file_name         = substr( $full_path, strrpos( $full_path, '/' ) + 1 );
		$file_name_parts_r = array_reverse( explode( '.', $file_name ) );
		$extension         = array_shift( $file_name_parts_r );

		if ( in_array( strtolower( $extension ), array( 'css', 'js' ), true ) ) {
			// Already pointing at the minified version.
			if ( 'min' === $file_name_parts_r[0] ) {
				return $url;
			}

			$min_full_path = preg_replace( "#\.{$extension}$#", ".min.{$extension}", $full_path );
			if ( file_exists( $min_full_path ) ) {
				$url = preg_replace( "#\.{$extension}$#", ".min.{$extension}", $url );
				// If it's a CSS file, stash it so we can set the .min suffix for rtl-ing.
				if ( 'css' === $extension ) {
					$key                      = str_replace( JETPACK__PLUGIN_DIR, 'jetpack/', $min_full_path );
					self::$min_assets[ $key ] = $path;
				}
			}
		}

		return $url;
	}

	/**
	 * If the asset is minified, let's flag .min as the suffix.
	 *
	 * Attached to `style_loader_src` filter.
	 *
	 * @param string $src source file.
	 * @param string $handle The registered handle of the script in question.
	 *
	 * @return mixed
	 */
	public static function set_suffix_on_min( $src, $handle ) {
		if ( false === strpos( $src, '.min.css' ) ) {
			return $src;
		}

		if ( ! empty( self::$min_assets ) ) {
			foreach ( self::$min_assets as $file => $path ) {
				if ( false !== strpos( $src, $file ) ) {
					wp_style_add_data( $handle, 'suffix', '.min' );
					return $src;
				}
			}
		}

		return $src;
	}

	/**
	 * Maybe inlines a stylesheet.
	 *
	 * @deprecated since 11.7.
	 *
	 * @param string $tag The tag that would link to the external asset.
	 * @param string $handle The registered handle of the script in question.
	 *
	 * @return string
	 */
	public static function maybe_inline_style( $tag, $handle ) { //phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		_deprecated_function( __METHOD__, '11.7', 'wp_maybe_inline_styles' );

		return $tag;
	}

	/**
	 * Loads a view file from the views
	 *
	 * Data passed in with the $data parameter will be available in the
	 * template file as $data['value']
	 *
	 * @param string $template - Template file to load.
	 * @param array  $data - Any data to pass along to the template.
	 * @return boolean - If template file was found.
	 **/
	public function load_view( $template, $data = array() ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable -- This is used via the required files.
		$views_dir = JETPACK__PLUGIN_DIR . 'views/';

		if ( file_exists( $views_dir . $template ) ) {
			require_once $views_dir . $template;
			return true;
		}

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			trigger_error( sprintf( 'Jetpack: Unable to find view file: %s', esc_html( $views_dir . $template ) ), E_USER_WARNING ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_trigger_error
		}
		return false;
	}

	/**
	 * Throws warnings for deprecated hooks to be removed from Jetpack that cannot remain in the original place in the code.
	 */
	public function deprecated_hooks() {
		$filter_deprecated_list = array(
			'jetpack_bail_on_shortcode'                    => array(
				'replacement' => 'jetpack_shortcodes_to_include',
				'version'     => 'jetpack-3.1.0',
			),
			'wpl_sharing_2014_1'                           => array(
				'replacement' => null,
				'version'     => 'jetpack-3.6.0',
			),
			'jetpack-tools-to-include'                     => array(
				'replacement' => 'jetpack_tools_to_include',
				'version'     => 'jetpack-3.9.0',
			),
			'jetpack_identity_crisis_options_to_check'     => array(
				'replacement' => null,
				'version'     => 'jetpack-4.0.0',
			),
			'update_option_jetpack_single_user_site'       => array(
				'replacement' => null,
				'version'     => 'jetpack-4.3.0',
			),
			'audio_player_default_colors'                  => array(
				'replacement' => null,
				'version'     => 'jetpack-4.3.0',
			),
			'add_option_jetpack_featured_images_enabled'   => array(
				'replacement' => null,
				'version'     => 'jetpack-4.3.0',
			),
			'add_option_jetpack_update_details'            => array(
				'replacement' => null,
				'version'     => 'jetpack-4.3.0',
			),
			'add_option_jetpack_updates'                   => array(
				'replacement' => null,
				'version'     => 'jetpack-4.3.0',
			),
			'add_option_jetpack_network_name'              => array(
				'replacement' => null,
				'version'     => 'jetpack-4.3.0',
			),
			'add_option_jetpack_network_allow_new_registrations' => array(
				'replacement' => null,
				'version'     => 'jetpack-4.3.0',
			),
			'add_option_jetpack_network_add_new_users'     => array(
				'replacement' => null,
				'version'     => 'jetpack-4.3.0',
			),
			'add_option_jetpack_network_site_upload_space' => array(
				'replacement' => null,
				'version'     => 'jetpack-4.3.0',
			),
			'add_option_jetpack_network_upload_file_types' => array(
				'replacement' => null,
				'version'     => 'jetpack-4.3.0',
			),
			'add_option_jetpack_network_enable_administration_menus' => array(
				'replacement' => null,
				'version'     => 'jetpack-4.3.0',
			),
			'add_option_jetpack_is_multi_site'             => array(
				'replacement' => null,
				'version'     => 'jetpack-4.3.0',
			),
			'add_option_jetpack_is_main_network'           => array(
				'replacement' => null,
				'version'     => 'jetpack-4.3.0',
			),
			'add_option_jetpack_main_network_site'         => array(
				'replacement' => null,
				'version'     => 'jetpack-4.3.0',
			),
			'jetpack_sync_all_registered_options'          => array(
				'replacement' => null,
				'version'     => 'jetpack-4.3.0',
			),
			'jetpack_has_identity_crisis'                  => array(
				'replacement' => 'jetpack_sync_error_idc_validation',
				'version'     => 'jetpack-4.4.0',
			),
			'jetpack_is_post_mailable'                     => array(
				'replacement' => null,
				'version'     => 'jetpack-4.4.0',
			),
			'jetpack_seo_site_host'                        => array(
				'replacement' => null,
				'version'     => 'jetpack-5.1.0',
			),
			'jetpack_installed_plugin'                     => array(
				'replacement' => 'jetpack_plugin_installed',
				'version'     => 'jetpack-6.0.0',
			),
			'jetpack_holiday_snow_option_name'             => array(
				'replacement' => null,
				'version'     => 'jetpack-6.0.0',
			),
			'jetpack_holiday_chance_of_snow'               => array(
				'replacement' => null,
				'version'     => 'jetpack-6.0.0',
			),
			'jetpack_holiday_snow_js_url'                  => array(
				'replacement' => null,
				'version'     => 'jetpack-6.0.0',
			),
			'jetpack_is_holiday_snow_season'               => array(
				'replacement' => null,
				'version'     => 'jetpack-6.0.0',
			),
			'jetpack_holiday_snow_option_updated'          => array(
				'replacement' => null,
				'version'     => 'jetpack-6.0.0',
			),
			'jetpack_holiday_snowing'                      => array(
				'replacement' => null,
				'version'     => 'jetpack-6.0.0',
			),
			'jetpack_sso_auth_cookie_expirtation'          => array(
				'replacement' => 'jetpack_sso_auth_cookie_expiration',
				'version'     => 'jetpack-6.1.0',
			),
			'jetpack_cache_plans'                          => array(
				'replacement' => null,
				'version'     => 'jetpack-6.1.0',
			),

			'jetpack_lazy_images_skip_image_with_atttributes' => array(
				'replacement' => 'jetpack_lazy_images_skip_image_with_attributes',
				'version'     => 'jetpack-6.5.0',
			),
			'jetpack_enable_site_verification'             => array(
				'replacement' => null,
				'version'     => 'jetpack-6.5.0',
			),
			'can_display_jetpack_manage_notice'            => array(
				'replacement' => null,
				'version'     => 'jetpack-7.3.0',
			),
			'atd_http_post_timeout'                        => array(
				'replacement' => null,
				'version'     => 'jetpack-7.3.0',
			),
			'atd_service_domain'                           => array(
				'replacement' => null,
				'version'     => 'jetpack-7.3.0',
			),
			'atd_load_scripts'                             => array(
				'replacement' => null,
				'version'     => 'jetpack-7.3.0',
			),
			'jetpack_widget_authors_exclude'               => array(
				'replacement' => 'jetpack_widget_authors_params',
				'version'     => 'jetpack-7.7.0',
			),
			// Removed in Jetpack 7.9.0.
			'jetpack_pwa_manifest'                         => array(
				'replacement' => null,
				'version'     => 'jetpack-7.9.0',
			),
			'jetpack_pwa_background_color'                 => array(
				'replacement' => null,
				'version'     => 'jetpack-7.9.0',
			),
			'jetpack_check_mobile'                         => array(
				'replacement' => null,
				'version'     => 'jetpack-8.3.0',
			),
			'jetpack_mobile_stylesheet'                    => array(
				'replacement' => null,
				'version'     => 'jetpack-8.3.0',
			),
			'jetpack_mobile_template'                      => array(
				'replacement' => null,
				'version'     => 'jetpack-8.3.0',
			),
			'jetpack_mobile_theme_menu'                    => array(
				'replacement' => null,
				'version'     => 'jetpack-8.3.0',
			),
			'minileven_show_featured_images'               => array(
				'replacement' => null,
				'version'     => 'jetpack-8.3.0',
			),
			'minileven_attachment_size'                    => array(
				'replacement' => null,
				'version'     => 'jetpack-8.3.0',
			),
			'instagram_cache_oembed_api_response_body'     => array(
				'replacement' => null,
				'version'     => 'jetpack-9.1.0',
			),
			'jetpack_can_make_outbound_https'              => array(
				'replacement' => null,
				'version'     => 'jetpack-9.1.0',
			),
			'sharing_email_can_send'                       => array(
				'replacement' => null,
				'version'     => 'jetpack-11.0.0',
			),
			'sharing_email_check'                          => array(
				'replacement' => null,
				'version'     => 'jetpack-11.0.0',
			),
			'sharing_services_email'                       => array(
				'replacement' => null,
				'version'     => 'jetpack-11.0.0',
			),
			'jetpack_dsp_promote_posts_enabled'            => array(
				'replacement' => null,
				'version'     => 'jetpack-11.8.0',
			),
			'jetpack_are_blogging_prompts_enabled'         => array(
				'replacement' => null,
				'version'     => 'jetpack-11.8.0',
			),
		);

		foreach ( $filter_deprecated_list as $tag => $args ) {
			if ( has_filter( $tag ) ) {
				apply_filters_deprecated( $tag, array( null ), $args['version'], $args['replacement'] );
			}
		}

		$action_deprecated_list = array(
			'jetpack_updated_theme'        => array(
				'replacement' => 'jetpack_updated_themes',
				'version'     => 'jetpack-6.2.0',
			),
			'atd_http_post_error'          => array(
				'replacement' => null,
				'version'     => 'jetpack-7.3.0',
			),
			'mobile_reject_mobile'         => array(
				'replacement' => null,
				'version'     => 'jetpack-8.3.0',
			),
			'mobile_force_mobile'          => array(
				'replacement' => null,
				'version'     => 'jetpack-8.3.0',
			),
			'mobile_app_promo_download'    => array(
				'replacement' => null,
				'version'     => 'jetpack-8.3.0',
			),
			'mobile_setup'                 => array(
				'replacement' => null,
				'version'     => 'jetpack-8.3.0',
			),
			'jetpack_mobile_footer_before' => array(
				'replacement' => null,
				'version'     => 'jetpack-8.3.0',
			),
			'wp_mobile_theme_footer'       => array(
				'replacement' => null,
				'version'     => 'jetpack-8.3.0',
			),
			'minileven_credits'            => array(
				'replacement' => null,
				'version'     => 'jetpack-8.3.0',
			),
			'jetpack_mobile_header_before' => array(
				'replacement' => null,
				'version'     => 'jetpack-8.3.0',
			),
			'jetpack_mobile_header_after'  => array(
				'replacement' => null,
				'version'     => 'jetpack-8.3.0',
			),
			'sharing_email_dialog'         => array(
				'replacement' => null,
				'version'     => 'jetpack-11.0.0',
			),
			'sharing_email_send_post'      => array(
				'replacement' => null,
				'version'     => 'jetpack-11.0.0',
			),
		);

		foreach ( $action_deprecated_list as $tag => $args ) {
			if ( has_action( $tag ) ) {
				do_action_deprecated( $tag, array(), $args['version'], $args['replacement'] );
			}
		}
	}

	/**
	 * Converts any url in a stylesheet, to the correct absolute url.
	 *
	 * Considerations:
	 *  - Normal, relative URLs     `feh.png`
	 *  - Data URLs                 `data:image/gif;base64,eh129ehiuehjdhsa==`
	 *  - Schema-agnostic URLs      `//domain.com/feh.png`
	 *  - Absolute URLs             `http://domain.com/feh.png`
	 *  - Domain root relative URLs `/feh.png`
	 *
	 * @param string $css The raw CSS -- should be read in directly from the file.
	 * @param string $css_file_url The URL that the file can be accessed at, for calculating paths from.
	 *
	 * @return mixed|string
	 */
	public static function absolutize_css_urls( $css, $css_file_url ) {
		$pattern = '#url\((?P<path>[^)]*)\)#i';
		$css_dir = dirname( $css_file_url );
		$p       = wp_parse_url( $css_dir );
		$domain  = sprintf(
			'%1$s//%2$s%3$s%4$s',
			isset( $p['scheme'] ) ? "{$p['scheme']}:" : '',
			isset( $p['user'], $p['pass'] ) ? "{$p['user']}:{$p['pass']}@" : '',
			$p['host'],
			isset( $p['port'] ) ? ":{$p['port']}" : ''
		);

		if ( preg_match_all( $pattern, $css, $matches, PREG_SET_ORDER ) ) {
			$replace = array();
			$find    = array();
			foreach ( $matches as $match ) {
				$url = trim( $match['path'], "'\" \t" );

				// If this is a data url, we don't want to mess with it.
				if ( 'data:' === substr( $url, 0, 5 ) ) {
					continue;
				}

				// If this is an absolute or protocol-agnostic url,
				// we don't want to mess with it.
				if ( preg_match( '#^(https?:)?//#i', $url ) ) {
					continue;
				}

				switch ( substr( $url, 0, 1 ) ) {
					case '/':
						$absolute = $domain . $url;
						break;
					default:
						$absolute = $css_dir . '/' . $url;
				}

				$find[]    = $match[0];
				$replace[] = sprintf( 'url("%s")', $absolute );
			}
			$css = str_replace( $find, $replace, $css );
		}

		return $css;
	}

	/**
	 * This methods removes all of the registered css files on the front end
	 * from Jetpack in favor of using a single file. In effect "imploding"
	 * all the files into one file.
	 *
	 * Pros:
	 * - Uses only ONE css asset connection instead of 15
	 * - Saves a minimum of 56k
	 * - Reduces server load
	 * - Reduces time to first painted byte
	 *
	 * Cons:
	 * - Loads css for ALL modules. However all selectors are prefixed so it
	 *      should not cause any issues with themes.
	 * - Plugins/themes dequeuing styles no longer do anything. See
	 *      jetpack_implode_frontend_css filter for a workaround
	 *
	 * For some situations developers may wish to disable css imploding and
	 * instead operate in legacy mode where each file loads seperately and
	 * can be edited individually or dequeued. This can be accomplished with
	 * the following line:
	 *
	 * add_filter( 'jetpack_implode_frontend_css', '__return_false' );
	 *
	 * @param bool $travis_test Is this a test run.
	 *
	 * @since 3.2
	 */
	public function implode_frontend_css( $travis_test = false ) {
		$do_implode = true;
		if ( defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG ) {
			$do_implode = false;
		}

		// Do not implode CSS when the page loads via the AMP plugin.
		if ( class_exists( Jetpack_AMP_Support::class ) && Jetpack_AMP_Support::is_amp_request() ) {
			$do_implode = false;
		}

		/**
		 * Allow CSS to be concatenated into a single jetpack.css file.
		 *
		 * @since 3.2.0
		 *
		 * @param bool $do_implode Should CSS be concatenated? Default to true.
		 */
		$do_implode = apply_filters( 'jetpack_implode_frontend_css', $do_implode );

		// Do not use the imploded file when default behavior was altered through the filter.
		if ( ! $do_implode ) {
			return;
		}

		// We do not want to use the imploded file in dev mode, or if not connected.
		if ( ( new Status() )->is_offline_mode() || ! self::is_connection_ready() ) {
			if ( ! $travis_test ) {
				return;
			}
		}

		// Do not use the imploded file if sharing css was dequeued via the sharing settings screen.
		if ( get_option( 'sharedaddy_disable_resources' ) ) {
			return;
		}

		/*
		 * Now we assume Jetpack is connected and able to serve the single
		 * file.
		 *
		 * In the future there will be a check here to serve the file locally
		 * or potentially from the Jetpack CDN
		 *
		 * For now:
		 * - Enqueue a single imploded css file
		 * - Zero out the style_loader_tag for the bundled ones
		 * - Be happy, drink scotch
		 */

		add_filter( 'style_loader_tag', array( $this, 'concat_remove_style_loader_tag' ), 10, 2 );

		$version = self::is_development_version() ? filemtime( JETPACK__PLUGIN_DIR . 'css/jetpack.css' ) : JETPACK__VERSION;

		wp_enqueue_style( 'jetpack_css', plugins_url( 'css/jetpack.css', __FILE__ ), array(), $version );
		wp_style_add_data( 'jetpack_css', 'rtl', 'replace' );
	}

	/**
	 * Removes styles that are part of concatenated group.
	 *
	 * @param string $tag Style tag.
	 * @param string $handle Style handle.
	 *
	 * @return string
	 */
	public function concat_remove_style_loader_tag( $tag, $handle ) {
		if ( in_array( $handle, $this->concatenated_style_handles, true ) ) {
			$tag = '';
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				$tag = '<!-- `' . esc_html( $handle ) . "` is included in the concatenated jetpack.css -->\r\n";
			}
		}

		return $tag;
	}

	/**
	 * Check the heartbeat data
	 *
	 * Organizes the heartbeat data by severity.  For example, if the site
	 * is in an ID crisis, it will be in the $filtered_data['bad'] array.
	 *
	 * Data will be added to "caution" array, if it either:
	 *  - Out of date Jetpack version
	 *  - Out of date WP version
	 *  - Out of date PHP version
	 *
	 * $return array $filtered_data
	 */
	public static function jetpack_check_heartbeat_data() {
		$raw_data = Jetpack_Heartbeat::generate_stats_array();

		$good    = array();
		$caution = array();
		$bad     = array();

		foreach ( $raw_data as $stat => $value ) {

			// Check jetpack version.
			if ( 'version' === $stat ) {
				if ( version_compare( $value, JETPACK__VERSION, '<' ) ) {
					$caution[ $stat ] = $value . ' - min supported is ' . JETPACK__VERSION;
					continue;
				}
			}

			// Check WP version.
			if ( 'wp-version' === $stat ) {
				if ( version_compare( $value, JETPACK__MINIMUM_WP_VERSION, '<' ) ) {
					$caution[ $stat ] = $value . ' - min supported is ' . JETPACK__MINIMUM_WP_VERSION;
					continue;
				}
			}

			// Check PHP version.
			if ( 'php-version' === $stat ) {
				if ( version_compare( PHP_VERSION, JETPACK__MINIMUM_PHP_VERSION, '<' ) ) {
					$caution[ $stat ] = $value . ' - min supported is ' . JETPACK__MINIMUM_PHP_VERSION;
					continue;
				}
			}

			// Check ID crisis.
			if ( 'identitycrisis' === $stat ) {
				if ( 'yes' === $value ) {
					$bad[ $stat ] = $value;
					continue;
				}
			}

			// The rest are good :).
			$good[ $stat ] = $value;
		}

		$filtered_data = array(
			'good'    => $good,
			'caution' => $caution,
			'bad'     => $bad,
		);

		return $filtered_data;
	}

	/**
	 * This method is used to organize all options that can be reset
	 * without disconnecting Jetpack.
	 *
	 * It is used in class.jetpack-cli.php to reset options
	 *
	 * @since 5.4.0 Logic moved to Jetpack_Options class. Method left in Jetpack class for backwards compat.
	 *
	 * @return array of options to delete.
	 */
	public static function get_jetpack_options_for_reset() {
		return Jetpack_Options::get_options_for_reset();
	}

	/**
	 * Strip http:// or https:// from a url, replaces forward slash with ::,
	 * so we can bring them directly to their site in calypso.
	 *
	 * @deprecated 9.2.0 Use Automattic\Jetpack\Status::get_site_suffix
	 *
	 * @param string $url URL.
	 * @return string url without the guff.
	 */
	public static function build_raw_urls( $url ) {
		_deprecated_function( __METHOD__, 'jetpack-9.2.0', 'Automattic\Jetpack\Status::get_site_suffix' );

		return ( new Status() )->get_site_suffix( $url );
	}

	/**
	 * Get the user's meta box order.
	 *
	 * @param array $sorted Value for the user's option.
	 * @return mixed
	 */
	public function get_user_option_meta_box_order_dashboard( $sorted ) {
		if ( ! is_array( $sorted ) ) {
			return $sorted;
		}

		foreach ( $sorted as $box_context => $ids ) {
			if ( false === strpos( $ids, 'dashboard_stats' ) ) {
				// If the old id isn't anywhere in the ids, don't bother exploding and fail out.
				continue;
			}

			$ids_array = explode( ',', $ids );
			$key       = array_search( 'dashboard_stats', $ids_array, true );

			if ( false !== $key ) {
				// If we've found that exact value in the option (and not `google_dashboard_stats` for example).
				$ids_array[ $key ]      = 'jetpack_summary_widget';
				$sorted[ $box_context ] = implode( ',', $ids_array );
				// We've found it, stop searching, and just return.
				break;
			}
		}

		return $sorted;
	}

	/**
	 * Adds a "blank" column in the user admin table to display indication of user connection.
	 *
	 * @param array $columns User list table columns.
	 *
	 * @return array
	 */
	public function jetpack_icon_user_connected( $columns ) {
		$columns['user_jetpack'] = '';
		return $columns;
	}

	/**
	 * Show Jetpack icon if the user is linked.
	 *
	 * @param string $val HTML for the icon.
	 * @param string $col User list table column.
	 * @param int    $user_id User ID.
	 *
	 * @return string
	 */
	public function jetpack_show_user_connected_icon( $val, $col, $user_id ) {
		if ( 'user_jetpack' === $col && self::connection()->is_user_connected( $user_id ) ) {
			$jetpack_logo = new Jetpack_Logo();
			$emblem_html  = sprintf(
				'<a title="%1$s" class="jp-emblem-user-admin">%2$s</a>',
				esc_attr__( 'This user is linked and ready to fly with Jetpack.', 'jetpack' ),
				$jetpack_logo->get_jp_emblem()
			);
			return $emblem_html;
		}

		return $val;
	}

	/**
	 * Style the Jetpack user column
	 */
	public function jetpack_user_col_style() {
		global $current_screen;
		if ( ! empty( $current_screen->base ) && 'users' === $current_screen->base ) {
			?>
			<style>
				.fixed .column-user_jetpack {
					width: 21px;
				}
				.jp-emblem-user-admin svg {
					width: 20px;
					height: 20px;
				}
				.jp-emblem-user-admin path {
					fill: #069e08;
				}
			</style>
			<?php
		}
	}

	/**
	 * Checks if Akismet is active and working.
	 *
	 * We dropped support for Akismet 3.0 with Jetpack 6.1.1 while introducing a check for an Akismet valid key
	 * that implied usage of methods present since more recent version.
	 * See https://github.com/Automattic/jetpack/pull/9585
	 *
	 * @since  5.1.0
	 *
	 * @return bool True = Akismet available. False = Aksimet not available.
	 */
	public static function is_akismet_active() {
		static $status = null;

		if ( $status !== null ) {
			return $status;
		}

		// Check if a modern version of Akismet is active.
		if ( ! method_exists( 'Akismet', 'http_post' ) ) {
			$status = false;
			return $status;
		}

		// Make sure there is a key known to Akismet at all before verifying key.
		$akismet_key = Akismet::get_api_key();
		if ( ! $akismet_key ) {
			$status = false;
			return $status;
		}

		// Possible values: valid, invalid, failure via Akismet. false if no status is cached.
		$akismet_key_state = get_transient( 'jetpack_akismet_key_is_valid' );

		// Do not used the cache result in wp-admin or REST API requests if the key isn't valid, in case someone is actively renewing, etc.
		$recheck = ( is_admin() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) && 'valid' !== $akismet_key_state;
		// We cache the result of the Akismet key verification for ten minutes.
		if ( ! $akismet_key_state || $recheck ) {
			$akismet_key_state = Akismet::verify_key( $akismet_key );
			set_transient( 'jetpack_akismet_key_is_valid', $akismet_key_state, 10 * MINUTE_IN_SECONDS );
		}

		$status = 'valid' === $akismet_key_state;

		return $status;
	}

	/**
	 * Given a minified path, and a non-minified path, will return
	 * a minified or non-minified file URL based on whether SCRIPT_DEBUG is set and truthy.
	 *
	 * Both `$min_base` and `$non_min_base` are expected to be relative to the
	 * root Jetpack directory.
	 *
	 * @since 5.6.0
	 *
	 * @param string $min_path Minimized path.
	 * @param string $non_min_path Non-minimized path.
	 * @return string The URL to the file
	 */
	public static function get_file_url_for_environment( $min_path, $non_min_path ) {
		return Assets::get_file_url_for_environment( $min_path, $non_min_path );
	}

	/**
	 * Checks for whether Jetpack Backup is enabled.
	 * Will return true if the state of Backup is anything except "unavailable".
	 *
	 * @return bool|int|mixed
	 */
	public static function is_rewind_enabled() {
		// Rewind is a paid feature, therefore requires a user-level connection.
		if ( ! static::connection()->has_connected_owner() ) {
			return false;
		}
		$rewind_enabled = get_transient( 'jetpack_rewind_enabled' );
		$recheck        = ( is_admin() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) && '0' === $rewind_enabled;
		if ( false === $rewind_enabled || $recheck ) {
			require_once JETPACK__PLUGIN_DIR . '_inc/lib/class.core-rest-api-endpoints.php';
			$rewind_data    = (array) Jetpack_Core_Json_Api_Endpoints::rewind_data();
			$rewind_enabled = ( ! is_wp_error( $rewind_data )
				&& ! empty( $rewind_data['state'] )
				&& 'active' === $rewind_data['state'] )
				? 1
				: 0;
			set_transient( 'jetpack_rewind_enabled', $rewind_enabled, 10 * MINUTE_IN_SECONDS );
		}
		return $rewind_enabled;
	}

	/**
	 * Return Calypso environment value; used for developing Jetpack and pairing
	 * it with different Calypso enrionments, such as localhost.
	 *
	 * @since 7.4.0
	 *
	 * @return string Calypso environment
	 */
	public static function get_calypso_env() {
		if ( isset( $_GET['calypso_env'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce is not required; only used for changing environments.
			return sanitize_key( $_GET['calypso_env'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce is not required; only used for changing environments.
		}

		if ( getenv( 'CALYPSO_ENV' ) ) {
			return sanitize_key( getenv( 'CALYPSO_ENV' ) );
		}

		if ( defined( 'CALYPSO_ENV' ) && CALYPSO_ENV ) {
			return sanitize_key( CALYPSO_ENV );
		}

		return '';
	}

	/**
	 * Returns the hostname with protocol for Calypso.
	 * Used for developing Jetpack with Calypso.
	 *
	 * @since 8.4.0
	 *
	 * @return string Calypso host.
	 */
	public static function get_calypso_host() {
		$calypso_env = self::get_calypso_env();
		switch ( $calypso_env ) {
			case 'development':
				return 'http://calypso.localhost:3000/';
			case 'wpcalypso':
				return 'https://wpcalypso.wordpress.com/';
			case 'horizon':
				return 'https://horizon.wordpress.com/';
			default:
				return 'https://wordpress.com/';
		}
	}

	/**
	 * Handles activating default modules as well general cleanup for the new connection.
	 *
	 * @param boolean $activate_sso                 Whether to activate the SSO module when activating default modules.
	 * @param boolean $redirect_on_activation_error Whether to redirect on activation error.
	 * @param boolean $send_state_messages          Whether to send state messages.
	 * @return void
	 */
	public static function handle_post_authorization_actions(
		$activate_sso = false,
		$redirect_on_activation_error = false,
		$send_state_messages = true
	) {
		$other_modules = $activate_sso
			? array( 'sso' )
			: array();

		if ( Jetpack_Options::get_option( 'active_modules_initialized' ) ) {
			$active_modules = self::get_active_modules();
			self::delete_active_modules();

			self::activate_default_modules( 999, 1, array_merge( $active_modules, $other_modules ), $redirect_on_activation_error, $send_state_messages );
		} else {
			// Default modules that don't require a user were already activated on site_register.
			// This time let's activate only those that require a user, this assures we don't reactivate manually deactivated modules while the site was connected only at a site level.
			self::activate_default_modules( false, false, $other_modules, $redirect_on_activation_error, $send_state_messages, null, true );
			Jetpack_Options::update_option( 'active_modules_initialized', true );
		}

		// Since this is a fresh connection, be sure to clear out IDC options.
		Identity_Crisis::clear_all_idc_options();

		if ( $send_state_messages ) {
			self::state( 'message', 'authorized' );
		}
	}

	/**
	 * Returns a boolean for whether backups UI should be displayed or not.
	 *
	 * @return bool Should backups UI be displayed?
	 */
	public static function show_backups_ui() {
		/**
		 * Whether UI for backups should be displayed.
		 *
		 * @since 6.5.0
		 *
		 * @param bool $show_backups Should UI for backups be displayed? True by default.
		 */
		return self::is_plugin_active( 'vaultpress/vaultpress.php' ) || apply_filters( 'jetpack_show_backups', true );
	}

	/**
	 * Clean leftoveruser meta.
	 *
	 * Delete Jetpack-related user meta when it is no longer needed.
	 *
	 * @since 7.3.0
	 *
	 * @param int $user_id User ID being updated.
	 */
	public static function user_meta_cleanup( $user_id ) {
		$meta_keys = array(
			// AtD removed from Jetpack 7.3.
			'AtD_options',
			'AtD_check_when',
			'AtD_guess_lang',
			'AtD_ignored_phrases',
		);

		foreach ( $meta_keys as $meta_key ) {
			if ( get_user_meta( $user_id, $meta_key ) ) {
				delete_user_meta( $user_id, $meta_key );
			}
		}
	}

	/**
	 * Checks if a Jetpack site is both active and not in offline mode.
	 *
	 * This is a DRY function to avoid repeating `Jetpack::is_connection_ready && ! Automattic\Jetpack\Status->is_offline_mode`.
	 *
	 * @since 8.8.0
	 *
	 * @return bool True if Jetpack is active and not in offline mode.
	 */
	public static function is_active_and_not_offline_mode() {
		if ( ! self::is_connection_ready() || ( new Status() )->is_offline_mode() ) {
			return false;
		}
		return true;
	}

	/**
	 * Returns the list of products that we have available for purchase.
	 *
	 * This method will not take current purchases or upgrades into account
	 * but is instead a static list of products Jetpack offers with some
	 * corresponding sales text/materials.
	 *
	 * @param bool $show_legacy Determine if we should include legacy product/plan details.
	 * @return array
	 */
	public static function get_products_for_purchase( $show_legacy = false ) {
		$products = array();

		$products['backup'] = array(
			'title'             => __( 'Jetpack Backup', 'jetpack' ),
			'slug'              => 'jetpack_backup_t1_yearly',
			'description'       => __( 'Never lose a word, image, page, or time worrying about your site with automated backups & one-click restores.', 'jetpack' ),
			'show_promotion'    => true,
			'discount_percent'  => 50,
			'included_in_plans' => array( 'security' ),
			'features'          => array(
				_x( 'Real-time cloud backups', 'Backup Product Feature', 'jetpack' ),
				_x( '10GB of backup storage', 'Backup Product Feature', 'jetpack' ),
				_x( '30-day archive & activity log*', 'Backup Product Feature', 'jetpack' ),
				_x( 'One-click restores', 'Backup Product Feature', 'jetpack' ),
			),
			'disclaimer'        => array(
				'text'      => __( '* Subject to your usage and storage limit.', 'jetpack' ),
				'link_text' => __( 'Learn more', 'jetpack' ),
				'url'       => Redirect::get_url( 'jetpack-faq-backup-disclaimer' ),
			),
		);

		$products['scan'] = array(
			'title'             => __( 'Jetpack Scan', 'jetpack' ),
			'slug'              => 'jetpack_scan',
			'description'       => __( 'Automatic scanning and one-click fixes keep your site one step ahead of security threats and malware.', 'jetpack' ),
			'show_promotion'    => true,
			'discount_percent'  => 50,
			'included_in_plans' => array( 'security' ),
			'features'          => array(
				_x( 'Automated daily scanning', 'Scan Product Feature', 'jetpack' ),
				_x( 'One-click fixes for most issues', 'Scan Product Feature', 'jetpack' ),
				_x( 'Instant email notifications', 'Scan Product Feature', 'jetpack' ),
				_x( 'Access to latest Firewall rules', 'Scan Product Feature', 'jetpack' ),
			),
		);

		$products['search'] = array(
			'title'             => __( 'Jetpack Site Search', 'jetpack' ),
			'slug'              => 'jetpack_search',
			'description'       => __( 'Help your site visitors find answers instantly so they keep reading and buying. Great for sites with a lot of content.', 'jetpack' ),
			'show_promotion'    => true,
			'discount_percent'  => 50,
			'included_in_plans' => array(),
			'features'          => array(
				_x( 'Instant search and indexing', 'Search Product Feature', 'jetpack' ),
				_x( 'Powerful filtering', 'Search Product Feature', 'jetpack' ),
				_x( 'Supports 38 languages', 'Search Product Feature', 'jetpack' ),
				_x( 'Spelling correction', 'Search Product Feature', 'jetpack' ),
			),
		);

		$products['akismet'] = array(
			'title'             => __( 'Akismet Anti-Spam', 'jetpack' ),
			'slug'              => 'jetpack_anti_spam',
			'description'       => __( 'Save time and get better responses by automatically blocking spam from your comments and forms.', 'jetpack' ),
			'show_promotion'    => true,
			'discount_percent'  => 50,
			'included_in_plans' => array( 'security' ),
			'features'          => array(
				_x( 'Comment and form spam protection', 'Anti-Spam Product Feature', 'jetpack' ),
				_x( 'Block spam without CAPTCHAs', 'Anti-Spam Product Feature', 'jetpack' ),
				_x( 'Advanced stats', 'Anti-Spam Product Feature', 'jetpack' ),
			),
		);

		$products['security'] = array(
			'title'             => _x( 'Security', 'Jetpack product name', 'jetpack' ),
			'slug'              => 'jetpack_security_t1_yearly',
			'description'       => __( 'Comprehensive site security, including Backup, Scan, and Anti-spam.', 'jetpack' ),
			'show_promotion'    => true,
			'discount_percent'  => 50,
			'included_in_plans' => array(),
			'features'          => array(
				_x( 'Real-time cloud backups with 10GB storage', 'Security Tier 1 Feature', 'jetpack' ),
				_x( 'Automated real-time malware scan', 'Security Daily Plan Feature', 'jetpack' ),
				_x( 'One-click fixes for most threats', 'Security Daily Plan Feature', 'jetpack' ),
				_x( 'Comment & form spam protection', 'Security Daily Plan Feature', 'jetpack' ),
			),
		);

		$products['videopress'] = array(
			'title'             => __( 'Jetpack VideoPress', 'jetpack' ),
			'slug'              => 'jetpack_videopress',
			'description'       => __( 'High-quality, ad-free video built specifically for WordPress.', 'jetpack' ),
			'show_promotion'    => true,
			'discount_percent'  => 50,
			'included_in_plans' => array(),
			'features'          => array(
				_x( '1TB of storage', 'VideoPress Product Feature', 'jetpack' ),
				_x( 'Built into WordPress editor', 'VideoPress Product Feature', 'jetpack' ),
				_x( 'Ad-free and customizable player', 'VideoPress Product Feature', 'jetpack' ),
				_x( 'Unlimited users', 'VideoPress Product Feature', 'jetpack' ),
			),
		);

		if ( $show_legacy ) {
			$products['jetpack_backup_daily'] = array(
				'title'             => __( 'Jetpack Backup', 'jetpack' ),
				'slug'              => 'jetpack_backup_daily',
				'description'       => __( 'Never lose a word, image, page, or time worrying about your site with automated backups & one-click restores.', 'jetpack' ),
				'show_promotion'    => false,
				'discount_percent'  => 0,
				'included_in_plans' => array(),
				'features'          => array(
					_x( 'Automated daily backups (off-site)', 'Backup Product Feature', 'jetpack' ),
					_x( 'One-click restores', 'Backup Product Feature', 'jetpack' ),
					_x( 'Unlimited backup storage', 'Backup Product Feature', 'jetpack' ),
				),
			);
		}

		return $products;
	}

	/**
	 * Register product descriptions for partner coupon usage.
	 *
	 * @since 10.4.0
	 *
	 * @param array $products An array of registered products.
	 *
	 * @return array
	 */
	public function get_partner_coupon_product_descriptions( $products ) {
		return array_merge( $products, self::get_products_for_purchase( true ) );
	}

	/**
	 * Determine if the current user is allowed to make Jetpack purchases without
	 * a WordPress.com account
	 *
	 * @return boolean True if the user can make purchases, false if not
	 */
	public static function current_user_can_purchase() {

		// The site must be site-connected to Jetpack (no users connected).
		if ( ! self::connection()->is_site_connection() ) {
			return false;
		}

		// Make sure only administrators can make purchases.
		if ( ! current_user_can( 'manage_options' ) ) {
			return false;
		}

		return true;
	}

}
