<?php
/**
 * Jetpack's Post-Connection JITM class.
 *
 * @package automattic/jetpack-jitm
 */

namespace Automattic\Jetpack\JITMS;

use Automattic\Jetpack\A8c_Mc_Stats;
use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Connection\Manager;
use Automattic\Jetpack\Device_Detection;
use Automattic\Jetpack\Partner;
use Automattic\Jetpack\Redirect;
use Automattic\Jetpack\Tracking;

/**
 * Jetpack just in time messaging through out the admin
 *
 * @since 1.1.0
 *
 * @since-jetpack 5.6.0
 */
class Post_Connection_JITM extends JITM {

	/**
	 * Tracking object.
	 *
	 * @var Automattic\Jetpack\Tracking
	 *
	 * @access private
	 */
	public $tracking;

	/**
	 * JITM constructor.
	 */
	public function __construct() {
		$this->tracking = new Tracking();
	}

	/**
	 * A special filter for WooCommerce, to set a message based on local state.
	 *
	 * @param string $content The current message.
	 *
	 * @return array The new message.
	 */
	public static function jitm_woocommerce_services_msg( $content ) {
		if ( ! function_exists( 'wc_get_base_location' ) ) {
			return $content;
		}

		$base_location = wc_get_base_location();

		switch ( $base_location['country'] ) {
			case 'US':
				$content->message = esc_html__( 'New free service: Show USPS shipping rates on your store! Added bonus: print shipping labels without leaving WooCommerce.', 'jetpack-jitm' );
				break;
			case 'CA':
				$content->message = esc_html__( 'New free service: Show Canada Post shipping rates on your store!', 'jetpack-jitm' );
				break;
			default:
				$content->message = '';
		}

		return $content;
	}

	/**
	 * A special filter for WooCommerce Call To Action button
	 *
	 * @return string The new CTA
	 */
	public static function jitm_jetpack_woo_services_install() {
		return wp_nonce_url(
			add_query_arg(
				array(
					'wc-services-action' => 'install',
				),
				admin_url( 'admin.php?page=wc-settings' )
			),
			'wc-services-install'
		);
	}

	/**
	 * A special filter for WooCommerce Call To Action button.
	 *
	 * @return string The new CTA
	 */
	public static function jitm_jetpack_woo_services_activate() {
		return wp_nonce_url(
			add_query_arg(
				array(
					'wc-services-action' => 'activate',
				),
				admin_url( 'admin.php?page=wc-settings' )
			),
			'wc-services-install'
		);
	}

	/**
	 * A special filter used in the CTA of a JITM offering to install the Creative Mail plugin.
	 *
	 * @return string The new CTA
	 */
	public static function jitm_jetpack_creative_mail_install() {
		return wp_nonce_url(
			add_query_arg(
				array(
					'creative-mail-action' => 'install',
				),
				admin_url( 'edit.php?post_type=feedback' )
			),
			'creative-mail-install'
		);
	}

	/**
	 * A special filter used in the CTA of a JITM offering to activate the Creative Mail plugin.
	 *
	 * @return string The new CTA
	 */
	public static function jitm_jetpack_creative_mail_activate() {
		return wp_nonce_url(
			add_query_arg(
				array(
					'creative-mail-action' => 'activate',
				),
				admin_url( 'edit.php?post_type=feedback' )
			),
			'creative-mail-install'
		);
	}

	/**
	 * A special filter used in the CTA of a JITM offering to install the Jetpack Backup plugin.
	 *
	 * @return string The new CTA
	 */
	public static function jitm_jetpack_backup_install() {
		return wp_nonce_url(
			add_query_arg(
				array(
					'jetpack-backup-action' => 'install',
				),
				admin_url( 'admin.php?page=jetpack' )
			),
			'jetpack-backup-install'
		);
	}

	/**
	 * A special filter used in the CTA of a JITM offering to activate the Jetpack Backup plugin.
	 *
	 * @return string The new CTA
	 */
	public static function jitm_jetpack_backup_activate() {
		return wp_nonce_url(
			add_query_arg(
				array(
					'jetpack-backup-action' => 'activate',
				),
				admin_url( 'admin.php?page=jetpack' )
			),
			'jetpack-backup-install'
		);
	}

	/**
	 * A special filter used in the CTA of a JITM offering to install the Jetpack Boost plugin.
	 *
	 * @return string The new CTA
	 */
	public static function jitm_jetpack_boost_install() {
		return wp_nonce_url(
			add_query_arg(
				array(
					'jetpack-boost-action' => 'install',
				),
				admin_url( 'admin.php?page=jetpack' )
			),
			'jetpack-boost-install'
		);
	}

	/**
	 * A special filter used in the CTA of a JITM offering to activate the Jetpack Boost plugin.
	 *
	 * @return string The new CTA
	 */
	public static function jitm_jetpack_boost_activate() {
		return wp_nonce_url(
			add_query_arg(
				array(
					'jetpack-boost-action' => 'activate',
				),
				admin_url( 'admin.php?page=jetpack' )
			),
			'jetpack-boost-install'
		);
	}

	/**
	 * Dismisses a JITM feature class so that it will no longer be shown.
	 *
	 * @param string $id The id of the JITM that was dismissed.
	 * @param string $feature_class The feature class of the JITM that was dismissed.
	 *
	 * @return bool Always true.
	 */
	public function dismiss( $id, $feature_class ) {
		$this->tracking->record_user_event(
			'jitm_dismiss_client',
			array(
				'jitm_id'       => $id,
				'feature_class' => $feature_class,
			)
		);
		$this->save_dismiss( $feature_class );
		return true;
	}

	/**
	 * Asks the wpcom API for the current message to display keyed on query string and message path
	 *
	 * @param string $message_path The message path to ask for.
	 * @param string $query The query string originally from the front end.
	 * @param bool   $full_jp_logo_exists If there is a full Jetpack logo already on the page.
	 *
	 * @return array The JITM's to show, or an empty array if there is nothing to show
	 */
	public function get_messages( $message_path, $query, $full_jp_logo_exists ) {
		// WooCommerce Services.
		add_filter( 'jitm_woocommerce_services_msg', array( $this, 'jitm_woocommerce_services_msg' ) );
		add_filter( 'jitm_jetpack_woo_services_install', array( $this, 'jitm_jetpack_woo_services_install' ) );
		add_filter( 'jitm_jetpack_woo_services_activate', array( $this, 'jitm_jetpack_woo_services_activate' ) );

		// Creative Mail.
		add_filter( 'jitm_jetpack_creative_mail_install', array( $this, 'jitm_jetpack_creative_mail_install' ) );
		add_filter( 'jitm_jetpack_creative_mail_activate', array( $this, 'jitm_jetpack_creative_mail_activate' ) );

		// Jetpack Backup.
		add_filter( 'jitm_jetpack_backup_install', array( $this, 'jitm_jetpack_backup_install' ) );
		add_filter( 'jitm_jetpack_backup_activate', array( $this, 'jitm_jetpack_backup_activate' ) );

		// Jetpack Boost.
		add_filter( 'jitm_jetpack_boost_install', array( $this, 'jitm_jetpack_boost_install' ) );
		add_filter( 'jitm_jetpack_boost_activate', array( $this, 'jitm_jetpack_boost_activate' ) );

		$user = wp_get_current_user();

		// Unauthenticated or invalid requests just bail.
		if ( ! $user ) {
			return array();
		}

		$user_roles = implode( ',', $user->roles );
		$site_id    = \Jetpack_Options::get_option( 'id' );

		// Build our jitm request.
		$path = add_query_arg(
			array(
				'external_user_id' => urlencode_deep( $user->ID ),
				'user_roles'       => urlencode_deep( $user_roles ),
				'query_string'     => urlencode_deep( $query ),
				'mobile_browser'   => Device_Detection::is_smartphone() ? 1 : 0,
				'_locale'          => get_user_locale(),
			),
			sprintf( '/sites/%d/jitm/%s', $site_id, $message_path )
		);

		// Attempt to get from cache.
		$envelopes = get_transient( 'jetpack_jitm_' . substr( md5( $path ), 0, 31 ) );

		// If something is in the cache and it was put in the cache after the last sync we care about, use it.
		$use_cache = false;

		/**
		 * Filter to turn off jitm caching
		 *
		 * @since 1.1.0
		 * @since-jetpack 5.4.0
		 *
		 * @param bool true Whether to cache just in time messages
		 */
		if ( apply_filters( 'jetpack_just_in_time_msg_cache', true ) ) {
			$use_cache = true;
		}

		if ( $use_cache ) {
			$last_sync  = (int) get_transient( 'jetpack_last_plugin_sync' );
			$from_cache = $envelopes && $last_sync > 0 && $last_sync < $envelopes['last_response_time'];
		} else {
			$from_cache = false;
		}

		// Otherwise, ask again.
		if ( ! $from_cache ) {
			$wpcom_response = Client::wpcom_json_api_request_as_blog(
				$path,
				'2',
				array(
					'user_id'    => $user->ID,
					'user_roles' => implode( ',', $user->roles ),
				),
				null,
				'wpcom'
			);

			// silently fail...might be helpful to track it?
			if ( is_wp_error( $wpcom_response ) ) {
				return array();
			}

			$envelopes = json_decode( $wpcom_response['body'] );

			if ( ! is_array( $envelopes ) ) {
				return array();
			}

			$expiration = isset( $envelopes[0] ) ? $envelopes[0]->ttl : 300;

			// Do not cache if expiration is 0 or we're not using the cache.
			if ( 0 !== $expiration && $use_cache ) {
				$envelopes['last_response_time'] = time();

				set_transient( 'jetpack_jitm_' . substr( md5( $path ), 0, 31 ), $envelopes, $expiration );
			}
		}

		$hidden_jitms = \Jetpack_Options::get_option( 'hide_jitm' );
		unset( $envelopes['last_response_time'] );

		/**
		 * Allow adding your own custom JITMs after a set of JITMs has been received.
		 *
		 * @since 1.1.0
		 * @since-jetpack 6.9.0
		 * @since-jetpack 8.3.0 - Added Message path.
		 *
		 * @param array  $envelopes    array of existing JITMs.
		 * @param string $message_path The message path to ask for.
		 */
		$envelopes = apply_filters( 'jetpack_jitm_received_envelopes', $envelopes, $message_path );

		foreach ( $envelopes as $idx => &$envelope ) {

			$dismissed_feature = isset( $hidden_jitms[ $envelope->feature_class ] ) && is_array( $hidden_jitms[ $envelope->feature_class ] ) ? $hidden_jitms[ $envelope->feature_class ] : null;

			// If the this feature class has been dismissed and the request has not passed the ttl, skip it as it's been dismissed.
			if ( is_array( $dismissed_feature ) && ( time() - $dismissed_feature['last_dismissal'] < $envelope->expires || $dismissed_feature['number'] >= $envelope->max_dismissal ) ) {
				unset( $envelopes[ $idx ] );
				continue;
			}

			$this->tracking->record_user_event(
				'jitm_view_client',
				array(
					'jitm_id' => $envelope->id,
				)
			);

			$url_params = array(
				'u' => $user->ID,
			);

			// Get affiliate code and add it to the array of URL parameters.
			$aff = Partner::init()->get_partner_code( Partner::AFFILIATE_CODE );
			if ( '' !== $aff ) {
				$url_params['aff'] = $aff;
			}

			// Check if the current user has connected their WP.com account
			// and if not add this information to the the array of URL parameters.
			if ( ! ( new Manager() )->is_user_connected( $user->ID ) ) {
				$url_params['query'] = 'unlinked=1';
			}
			$envelope->url = esc_url( Redirect::get_url( "jitm-$envelope->id", $url_params ) );

			$stats = new A8c_Mc_Stats();

			$envelope->jitm_stats_url = $stats->build_stats_url( array( 'x_jetpack-jitm' => $envelope->id ) );

			// phpcs:disable WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
			// $CTA is not valid per PHPCS, but it is part of the return from WordPress.com, so allowing.
			if ( $envelope->CTA->hook ) {
				$envelope->url = apply_filters( 'jitm_' . $envelope->CTA->hook, $envelope->url );
				unset( $envelope->CTA->hook );
			}
			// phpcs:enable

			if ( isset( $envelope->content->hook ) ) {
				$envelope->content = apply_filters( 'jitm_' . $envelope->content->hook, $envelope->content );
				unset( $envelope->content->hook );
			}

			// No point in showing an empty message.
			if ( empty( $envelope->content->message ) ) {
				unset( $envelopes[ $idx ] );
				continue;
			}

			$envelope->content->icon = $this->generate_icon( $envelope->content->icon, $full_jp_logo_exists );

			$stats->add( 'jitm', $envelope->id . '-viewed' );
			$stats->do_server_side_stats();
		}

		return $envelopes;
	}

}
