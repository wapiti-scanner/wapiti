<?php
/**
 * Publicize_Base class.
 *
 * @package automattic/jetpack-publicize
 */

// phpcs:disable WordPress.NamingConventions.ValidVariableName

namespace Automattic\Jetpack\Publicize;

use Automattic\Jetpack\Connection\Client;
use Automattic\Jetpack\Current_Plan;
use Automattic\Jetpack\Redirect;
use Automattic\Jetpack\Status;

/**
 * Base class for Publicize.
 */
abstract class Publicize_Base {

	/**
	 * Services that are currently connected to the given user
	 * through Publicize.
	 *
	 * @var array
	 */
	public $connected_services = array();

	/**
	 * Services that are supported by publicize. They don't
	 * necessarily need to be connected to the current user.
	 *
	 * @var array
	 */
	public $services;

	/**
	 * Post meta key for admin page.
	 *
	 * @var string
	 */
	public $ADMIN_PAGE = 'wpas';

	/**
	 * Post meta key for post message.
	 *
	 * @var string
	 */
	public $POST_MESS = '_wpas_mess';

	/**
	 * Post meta key for flagging when the post is a tweetstorm.
	 *
	 * @var string
	 */
	public $POST_TWEETSTORM = '_wpas_is_tweetstorm';

	/**
	 * Post meta key for the flagging when the post share feature is disabled.
	 *
	 * @var string
	 */
	const POST_PUBLICIZE_FEATURE_ENABLED = '_wpas_feature_enabled';

	/**
	 * Post meta key for Jetpack Social options.
	 *
	 * @var string
	 */
	const POST_JETPACK_SOCIAL_OPTIONS = '_wpas_options';

	/**
	 * Connection ID appended to indicate that a connection should NOT be publicized to.
	 *
	 * @var string
	 */
	public $POST_SKIP = '_wpas_skip_';

	/**
	 * Connection ID appended to indicate a connection has already been publicized to.
	 *
	 * @var string
	 */
	public $POST_DONE = '_wpas_done_';

	/**
	 * Prefix for user authorization (used in publicize-wpcom.php)
	 *
	 * @var string
	 */
	public $USER_AUTH = 'wpas_authorize';

	/**
	 * Prefix for user opt.
	 *
	 * @var string
	 */
	public $USER_OPT = 'wpas_';

	/**
	 * Ready for Publicize to do its thing.
	 *
	 * @var string
	 */
	public $PENDING = '_publicize_pending';

	/**
	 * Array of external IDs where we've Publicized.
	 *
	 * @var string
	 */
	public $POST_SERVICE_DONE = '_publicize_done_external';

	/**
	 * Default pieces of the message used in constructing the
	 * content pushed out to other social networks.
	 */

	/**
	 * Default prefix.
	 *
	 * @var string
	 */
	public $default_prefix = '';

	/**
	 * Default message.
	 *
	 * @var string
	 */
	public $default_message = '%title%';

	/**
	 * Default suffix.
	 *
	 * @var string
	 */
	public $default_suffix = ' ';

	/**
	 * What WP capability is require to create/delete global connections?
	 * All users with this cap can un-globalize all other global connections, and globalize any of their own
	 * Globalized connections cannot be unselected by users without this capability when publishing
	 *
	 * @var string
	 */
	public $GLOBAL_CAP = 'publish_posts';

	/**
	 * Sets up the basics of Publicize.
	 */
	public function __construct() {
		$this->default_message = self::build_sprintf(
			array(
				/**
				 * Filter the default Publicize message.
				 *
				 * @since 0.1.0
				 * @since-jetpack 2.0.0
				 *
				 * @param string $this->default_message Publicize's default message. Default is the post title.
				 */
				apply_filters( 'wpas_default_message', $this->default_message ),
				'title',
				'url',
			)
		);

		$this->default_prefix = self::build_sprintf(
			array(
				/**
				 * Filter the message prepended to the Publicize custom message.
				 *
				 * @since 0.1.0
				 * @since-jetpack 2.0.0
				 *
				 * @param string $this->default_prefix String prepended to the Publicize custom message.
				 */
				apply_filters( 'wpas_default_prefix', $this->default_prefix ),
				'url',
			)
		);

		$this->default_suffix = self::build_sprintf(
			array(
				/**
				 * Filter the message appended to the Publicize custom message.
				 *
				 * @since 0.1.0
				 * @since-jetpack 2.0.0
				 *
				 * @param string $this->default_suffix String appended to the Publicize custom message.
				 */
				apply_filters( 'wpas_default_suffix', $this->default_suffix ),
				'url',
			)
		);

		/**
		 * Filter the capability to change global Publicize connection options.
		 *
		 * All users with this cap can un-globalize all other global connections, and globalize any of their own
		 * Globalized connections cannot be unselected by users without this capability when publishing.
		 *
		 * @since 0.1.0
		 * @since-jetpack 2.2.1
		 *
		 * @param string $this->GLOBAL_CAP default capability in control of global Publicize connection options. Default to edit_others_posts.
		 */
		$this->GLOBAL_CAP = apply_filters( 'jetpack_publicize_global_connections_cap', $this->GLOBAL_CAP );

		// stage 1 and 2 of 3-stage Publicize. Flag for Publicize on creation, save meta,
		// then check meta and publicize based on that. stage 3 implemented on wpcom.
		add_action( 'transition_post_status', array( $this, 'flag_post_for_publicize' ), 10, 3 );
		add_action( 'save_post', array( $this, 'save_meta' ), 20, 2 );

		// Default checkbox state for each Connection.
		add_filter( 'publicize_checkbox_default', array( $this, 'publicize_checkbox_default' ), 10, 2 );
		add_filter( 'jetpack_open_graph_tags', array( $this, 'add_jetpack_social_og_images' ), 12, 1 ); // $priority = 12, to run after Jetpack adds the tags in the Jetpack_Twitter_Cards class.

		// Alter the "Post Publish" admin notice to mention the Connections we Publicized to.
		add_filter( 'post_updated_messages', array( $this, 'update_published_message' ), 20, 1 );

		// Connection test callback.
		add_action( 'wp_ajax_test_publicize_conns', array( $this, 'test_publicize_conns' ) );

		// Custom priority to ensure post type support is added prior to thumbnail support being added to the theme.
		add_action( 'init', array( $this, 'add_post_type_support' ), 8 );
		add_action( 'init', array( $this, 'register_post_meta' ), 20 );

		// The custom priority for this action ensures that any existing code that
		// removes post-thumbnails support during 'init' continues to work.
		add_action( 'init', __NAMESPACE__ . '\add_theme_post_thumbnails_support', 8 );
	}

	/**
	 * Services: Facebook, Twitter, etc.
	 */

	/**
	 * Get services for the given blog and user.
	 *
	 * Can return all available services or just the ones with an active connection.
	 *
	 * @param string    $filter Type of filter.
	 *        'all' (default) - Get all services available for connecting.
	 *        'connected'     - Get all services currently connected.
	 * @param false|int $_blog_id The blog ID. Use false (default) for the current blog.
	 * @param false|int $_user_id The user ID. Use false (default) for the current user.
	 * @return array
	 */
	abstract public function get_services( $filter = 'all', $_blog_id = false, $_user_id = false );

	/**
	 * Does the given user have a connection to the service on the given blog?
	 *
	 * @param string    $service_name 'facebook', 'twitter', etc.
	 * @param false|int $_blog_id The blog ID. Use false (default) for the current blog.
	 * @param false|int $_user_id The user ID. Use false (default) for the current user.
	 * @return bool
	 */
	public function is_enabled( $service_name, $_blog_id = false, $_user_id = false ) {
		if ( ! $_blog_id ) {
			$_blog_id = $this->blog_id();
		}

		if ( ! $_user_id ) {
			$_user_id = $this->user_id();
		}

		$connections = $this->get_connections( $service_name, $_blog_id, $_user_id );
		return ( is_array( $connections ) && count( $connections ) > 0 ? true : false );
	}

	/**
	 * Generates a connection URL.
	 *
	 * This is the URL, which, when visited by the user, starts the authentication
	 * process required to forge a connection.
	 *
	 * @param string $service_name 'facebook', 'twitter', etc.
	 * @return string
	 */
	abstract public function connect_url( $service_name );

	/**
	 * Generates a Connection refresh URL.
	 *
	 * This is the URL, which, when visited by the user, re-authenticates their
	 * connection to the service.
	 *
	 * @param string $service_name 'facebook', 'twitter', etc.
	 * @return string
	 */
	abstract public function refresh_url( $service_name );

	/**
	 * Generates a disconnection URL.
	 *
	 * This is the URL, which, when visited by the user, breaks their connection
	 * with the service.
	 *
	 * @param string $service_name 'facebook', 'twitter', etc.
	 * @param string $connection_id Connection ID.
	 * @return string
	 */
	abstract public function disconnect_url( $service_name, $connection_id );

	/**
	 * Returns a display name for the Service
	 *
	 * @param string $service_name 'facebook', 'twitter', etc.
	 * @return string
	 */
	public static function get_service_label( $service_name ) {
		switch ( $service_name ) {
			case 'linkedin':
				return 'LinkedIn';
			case 'google_drive': // google-drive used to be called google_drive.
			case 'google-drive':
				return 'Google Drive';
			case 'twitter':
			case 'facebook':
			case 'tumblr':
			default:
				return ucfirst( $service_name );
		}
	}

	/**
	 * Connections: For each Service, there can be multiple connections
	 * for a given user. For example, one user could be connected to Twitter
	 * as both @jetpack and as @wordpressdotcom
	 *
	 * For historical reasons, Connections are represented as an object
	 * on WordPress.com and as an array in Jetpack.
	 */

	/**
	 * Get the active Connections of a Service
	 *
	 * @param string    $service_name 'facebook', 'twitter', etc.
	 * @param false|int $_blog_id The blog ID. Use false (default) for the current blog.
	 * @param false|int $_user_id The user ID. Use false (default) for the current user.
	 * @return false|object[]|array[] false if no connections exist
	 */
	abstract public function get_connections( $service_name, $_blog_id = false, $_user_id = false );

	/**
	 * Get a single Connection of a Service
	 *
	 * @param string    $service_name 'facebook', 'twitter', etc.
	 * @param string    $connection_id Connection ID.
	 * @param false|int $_blog_id The blog ID. Use false (default) for the current blog.
	 * @param false|int $_user_id The user ID. Use false (default) for the current user.
	 * @return false|object[]|array[] false if no connections exist
	 */
	abstract public function get_connection( $service_name, $connection_id, $_blog_id = false, $_user_id = false );

	/**
	 * Get the Connection ID.
	 *
	 * Note that this is different than the Connection's uniqueid.
	 *
	 * Via a quirk of history, ID is globally unique and unique_id
	 * is only unique per site.
	 *
	 * @param object|array $connection The Connection object (WordPress.com) or array (Jetpack).
	 * @return string
	 */
	abstract public function get_connection_id( $connection );

	/**
	 * Get the Connection unique_id
	 *
	 * Note that this is different than the Connections ID.
	 *
	 * Via a quirk of history, ID is globally unique and unique_id
	 * is only unique per site.
	 *
	 * @param object|array $connection The Connection object (WordPress.com) or array (Jetpack).
	 * @return string
	 */
	abstract public function get_connection_unique_id( $connection );

	/**
	 * Get the Connection's Meta data
	 *
	 * @param object|array $connection Connection.
	 * @return array Connection Meta
	 */
	abstract public function get_connection_meta( $connection );

	/**
	 * Disconnect a Connection
	 *
	 * @param string    $service_name 'facebook', 'twitter', etc.
	 * @param string    $connection_id Connection ID.
	 * @param false|int $_blog_id The blog ID. Use false (default) for the current blog.
	 * @param false|int $_user_id The user ID. Use false (default) for the current user.
	 * @param bool      $force_delete Whether to skip permissions checks.
	 * @return false|void False on failure. Void on success.
	 */
	abstract public function disconnect( $service_name, $connection_id, $_blog_id = false, $_user_id = false, $force_delete = false );

	/**
	 * Globalizes a Connection
	 *
	 * @param string $connection_id Connection ID.
	 * @return bool Falsey on failure. Truthy on success.
	 */
	abstract public function globalize_connection( $connection_id );

	/**
	 * Unglobalizes a Connection
	 *
	 * @param string $connection_id Connection ID.
	 * @return bool Falsey on failure. Truthy on success.
	 */
	abstract public function unglobalize_connection( $connection_id );

	/**
	 * Returns an external URL to the Connection's profile
	 *
	 * @param string       $service_name 'facebook', 'twitter', etc.
	 * @param object|array $connection The Connection object (WordPress.com) or array (Jetpack).
	 * @return false|string False on failure. URL on success.
	 */
	public function get_profile_link( $service_name, $connection ) {
		$cmeta = $this->get_connection_meta( $connection );

		if ( isset( $cmeta['connection_data']['meta']['link'] ) ) {
			if ( 'facebook' === $service_name && 0 === strpos( wp_parse_url( $cmeta['connection_data']['meta']['link'], PHP_URL_PATH ), '/app_scoped_user_id/' ) ) {
				// App-scoped Facebook user IDs are not usable profile links.
				return false;
			}

			return $cmeta['connection_data']['meta']['link'];
		}

		if ( 'facebook' === $service_name && isset( $cmeta['connection_data']['meta']['facebook_page'] ) ) {
			return 'https://facebook.com/' . $cmeta['connection_data']['meta']['facebook_page'];
		}

		if ( 'tumblr' === $service_name && isset( $cmeta['connection_data']['meta']['tumblr_base_hostname'] ) ) {
			return 'https://' . $cmeta['connection_data']['meta']['tumblr_base_hostname'];
		}

		if ( 'twitter' === $service_name ) {
			return 'https://twitter.com/' . substr( $cmeta['external_display'], 1 ); // Has a leading '@'.
		}

		if ( 'linkedin' === $service_name ) {
			if ( ! isset( $cmeta['connection_data']['meta']['profile_url'] ) ) {
				return false;
			}

			$profile_url_query      = wp_parse_url( $cmeta['connection_data']['meta']['profile_url'], PHP_URL_QUERY );
			$profile_url_query_args = null;
			wp_parse_str( $profile_url_query, $profile_url_query_args );

			$id = null;

			if ( isset( $profile_url_query_args['key'] ) ) {
				$id = $profile_url_query_args['key'];
			} elseif ( isset( $profile_url_query_args['id'] ) ) {
				$id = $profile_url_query_args['id'];
			} else {
				return false;
			}

			return esc_url_raw( add_query_arg( 'id', rawurlencode( $id ), 'https://www.linkedin.com/profile/view' ) );
		}

		return false; // no fallback. we just won't link it.
	}

	/**
	 * Returns a display name for the Connection
	 *
	 * @param string       $service_name 'facebook', 'twitter', etc.
	 * @param object|array $connection The Connection object (WordPress.com) or array (Jetpack).
	 * @return string
	 */
	public function get_display_name( $service_name, $connection ) {
		$cmeta = $this->get_connection_meta( $connection );

		if ( isset( $cmeta['connection_data']['meta']['display_name'] ) ) {
			return $cmeta['connection_data']['meta']['display_name'];
		}

		if ( 'tumblr' === $service_name && isset( $cmeta['connection_data']['meta']['tumblr_base_hostname'] ) ) {
			return $cmeta['connection_data']['meta']['tumblr_base_hostname'];
		}

		if ( 'twitter' === $service_name ) {
			return $cmeta['external_display'];
		}

		$connection_display = $cmeta['external_display'];

		if ( empty( $connection_display ) ) {
			$connection_display = $cmeta['external_name'];
		}

		return $connection_display;
	}

	/**
	 * Returns a profile picture for the Connection
	 *
	 * @param object|array $connection The Connection object (WordPress.com) or array (Jetpack).
	 * @return string
	 */
	private function get_profile_picture( $connection ) {
		$cmeta = $this->get_connection_meta( $connection );

		if ( isset( $cmeta['profile_picture'] ) ) {
			return $cmeta['profile_picture'];
		}

		return '';
	}

	/**
	 * Whether the user needs to select additional options after connecting
	 *
	 * @param string       $service_name 'facebook', 'twitter', etc.
	 * @param object|array $connection The Connection object (WordPress.com) or array (Jetpack).
	 * @return bool
	 */
	public function show_options_popup( $service_name, $connection ) {
		$cmeta = $this->get_connection_meta( $connection );

		// Always show if no selection has been made for Facebook.
		if ( 'facebook' === $service_name && empty( $cmeta['connection_data']['meta']['facebook_profile'] ) && empty( $cmeta['connection_data']['meta']['facebook_page'] ) ) {
			return true;
		}

		// Always show if no selection has been made for Tumblr.
		if ( 'tumblr' === $service_name && empty( $cmeta['connection_data']['meta']['tumblr_base_hostname'] ) ) {
			return true;
		}

		// if we have the specific connection info..
		$id = ! empty( $_GET['id'] ) ? sanitize_text_field( wp_unslash( $_GET['id'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( $id ) {
			if ( $cmeta['connection_data']['id'] === $id ) {
				return true;
			}
		} else {
			// Otherwise, just show if this is the completed step / first load.
			// phpcs:disable WordPress.Security.NonceVerification.Recommended
			$is_completed = ! empty( $_GET['action'] ) && 'completed' === $_GET['action'];
			$service      = ! empty( $_GET['service'] ) ? sanitize_text_field( wp_unslash( $_GET['service'] ) ) : false;
			// phpcs:enable WordPress.Security.NonceVerification.Recommended

			if ( $is_completed && $service_name === $service && ! in_array( $service, array( 'facebook', 'tumblr' ), true ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if a connection is global
	 *
	 * @param array $connection Connection data.
	 * @return bool Whether the connection is global.
	 */
	public function is_global_connection( $connection ) {
		return empty( $connection['connection_data']['user_id'] );
	}

	/**
	 * Whether the Connection is "valid" wrt Facebook's requirements.
	 *
	 * Must be connected to a Page (not a Profile).
	 * (Also returns true if we're in the middle of the connection process)
	 *
	 * @param object|array $connection The Connection object (WordPress.com) or array (Jetpack).
	 * @return bool
	 */
	public function is_valid_facebook_connection( $connection ) {
		if ( $this->is_connecting_connection( $connection ) ) {
			return true;
		}
		$connection_meta = $this->get_connection_meta( $connection );
		$connection_data = $connection_meta['connection_data'];
		return isset( $connection_data['meta']['facebook_page'] );
	}

	/**
	 * LinkedIn needs to be reauthenticated to use v2 of their API.
	 * If it's using LinkedIn old API, it's an 'invalid' connection
	 *
	 * @param object|array $connection The Connection object (WordPress.com) or array (Jetpack).
	 * @return bool
	 */
	public function is_invalid_linkedin_connection( $connection ) {
		// LinkedIn API v1 included the profile link in the connection data.
		$connection_meta = $this->get_connection_meta( $connection );
		return isset( $connection_meta['connection_data']['meta']['profile_url'] );
	}

	/**
	 * Whether the Connection currently being connected
	 *
	 * @param object|array $connection The Connection object (WordPress.com) or array (Jetpack).
	 * @return bool
	 */
	public function is_connecting_connection( $connection ) {
		$connection_meta = $this->get_connection_meta( $connection );
		$connection_data = $connection_meta['connection_data'];
		return isset( $connection_data['meta']['options_responses'] );
	}

	/**
	 * AJAX Handler to run connection tests on all Connections
	 *
	 * @return void
	 */
	public function test_publicize_conns() {
		wp_send_json_success( $this->get_publicize_conns_test_results() );
	}

	/**
	 * Run connection tests on all Connections
	 *
	 * @return array {
	 *     Array of connection test results.
	 *
	 *     @type string 'connectionID'          Connection identifier string that is unique for each connection
	 *     @type string 'serviceName'           Slug of the connection's service (facebook, twitter, ...)
	 *     @type bool   'connectionTestPassed'  Whether the connection test was successful
	 *     @type string 'connectionTestMessage' Test success or error message
	 *     @type bool   'userCanRefresh'        Whether the user can re-authenticate their connection to the service
	 *     @type string 'refreshText'           Message instructing user to re-authenticate their connection to the service
	 *     @type string 'refreshURL'            URL, which, when visited by the user, re-authenticates their connection to the service.
	 *     @type string 'unique_id'             ID string representing connection
	 * }
	 */
	public function get_publicize_conns_test_results() {
		$test_results = array();

		foreach ( (array) $this->get_services( 'connected' ) as $service_name => $connections ) {
			foreach ( $connections as $connection ) {

				$id = $this->get_connection_id( $connection );

				$connection_test_passed  = true;
				$connection_test_message = __( 'This connection is working correctly.', 'jetpack-publicize-pkg' );
				$user_can_refresh        = false;
				$refresh_text            = '';
				$refresh_url             = '';

				$connection_test_result = true;
				if ( method_exists( $this, 'test_connection' ) ) {
					$connection_test_result = $this->test_connection( $service_name, $connection );
				}

				if ( is_wp_error( $connection_test_result ) ) {
					$connection_test_passed  = false;
					$connection_test_message = $connection_test_result->get_error_message();
					$error_data              = $connection_test_result->get_error_data();

					$user_can_refresh = $error_data['user_can_refresh'];
					$refresh_text     = $error_data['refresh_text'];
					$refresh_url      = $error_data['refresh_url'];
				}
				// Mark Facebook profiles as deprecated.
				if ( 'facebook' === $service_name ) {
					if ( ! $this->is_valid_facebook_connection( $connection ) ) {
						$connection_test_passed  = false;
						$user_can_refresh        = false;
						$connection_test_message = __( 'Please select a Facebook Page to publish updates.', 'jetpack-publicize-pkg' );
					}
				}

				// LinkedIn needs reauthentication to be compatible with v2 of their API.
				if ( 'linkedin' === $service_name && $this->is_invalid_linkedin_connection( $connection ) ) {
					$connection_test_passed  = 'must_reauth';
					$user_can_refresh        = false;
					$connection_test_message = esc_html__( 'Your LinkedIn connection needs to be reauthenticated to continue working – head to Sharing to take care of it.', 'jetpack-publicize-pkg' );
				}

				$unique_id = null;

				if ( ! empty( $connection->unique_id ) ) {
					$unique_id = $connection->unique_id;
				} elseif ( ! empty( $connection['connection_data']['token_id'] ) ) {
					$unique_id = $connection['connection_data']['token_id'];
				}

				$test_results[] = array(
					'connectionID'          => $id,
					'serviceName'           => $service_name,
					'connectionTestPassed'  => $connection_test_passed,
					'connectionTestMessage' => esc_attr( $connection_test_message ),
					'userCanRefresh'        => $user_can_refresh,
					'refreshText'           => esc_attr( $refresh_text ),
					'refreshURL'            => $refresh_url,
					'unique_id'             => $unique_id,
				);
			}
		}

		return $test_results;
	}

	/**
	 * Run the connection test for the Connection
	 *
	 * @param string       $service_name $service_name 'facebook', 'twitter', etc.
	 * @param object|array $connection The Connection object (WordPress.com) or array (Jetpack).
	 * @return WP_Error|true WP_Error on failure. True on success
	 */
	abstract public function test_connection( $service_name, $connection );

	/**
	 * Retrieves current list of connections and applies filters.
	 *
	 * Retrieves current available connections and checks if the connections
	 * have already been used to share current post. Finally, the checkbox
	 * form UI fields are calculated. This function exposes connection form
	 * data directly as array so it can be retrieved for static HTML generation
	 * or JSON consumption.
	 *
	 * @since 0.1.0
	 * @since-jetpack 6.7.0
	 *
	 * @param integer $selected_post_id Optional. Post ID to query connection status for.
	 *
	 * @return array {
	 *     Array of UI setup data for connection list form.
	 *
	 *     @type string 'unique_id'        ID string representing connection
	 *     @type string 'service_name'     Slug of the connection's service (facebook, twitter, ...)
	 *     @type string 'service_label'    Service Label (Facebook, Twitter, ...)
	 *     @type string 'display_name'     Connection's human-readable Username: "@jetpack"
	 *     @type string 'profile_picture'  Connection profile picture.
	 *     @type bool   'enabled'          Default value for the connection (e.g., for a checkbox).
	 *     @type bool   'done'             Has this connection already been publicized to?
	 *     @type bool   'toggleable'       Is the user allowed to change the value for the connection?
	 *     @type bool   'global'           Is this connection a global one?
	 * }
	 */
	public function get_filtered_connection_data( $selected_post_id = null ) {
		$connection_list = array();

		$post = get_post( $selected_post_id ); // Defaults to current post if $post_id is null.
		// Handle case where there is no current post.
		if ( ! empty( $post ) ) {
			$post_id = $post->ID;
		} else {
			$post_id = null;
		}

		$services = $this->get_services( 'connected' );
		$all_done = $this->post_is_done_sharing( $post_id );

		// We don't allow Publicizing to the same external id twice, to prevent spam.
		$service_id_done = (array) get_post_meta( $post_id, $this->POST_SERVICE_DONE, true );

		foreach ( $services as $service_name => $connections ) {
			foreach ( $connections as $connection ) {
				$connection_meta = $this->get_connection_meta( $connection );
				$connection_data = $connection_meta['connection_data'];

				$unique_id = $this->get_connection_unique_id( $connection );

				// Was this connection (OR, old-format service) already Publicized to?
				$done = ! empty( $post ) && (
					// New flags.
					1 === (int) get_post_meta( $post->ID, $this->POST_DONE . $unique_id, true )
					||
					// Old flags.
					1 === (int) get_post_meta( $post->ID, $this->POST_DONE . $service_name, true )
				);

				/**
				 * Filter whether a post should be publicized to a given service.
				 *
				 * @since 0.1.0
				 * @since-jetpack 2.0.0
				 *
				 * @param bool true Should the post be publicized to a given service? Default to true.
				 * @param int $post_id Post ID.
				 * @param string $service_name Service name.
				 * @param array $connection_data Array of information about all Publicize details for the site.
				 */
				/* phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores */
				if ( ! apply_filters( 'wpas_submit_post?', true, $post_id, $service_name, $connection_data ) ) {
					continue;
				}

				// Should we be skipping this one?
				$skip = (
					(
						! empty( $post )
						&&
						in_array( $post->post_status, array( 'publish', 'draft', 'future' ), true )
						&&
						(
							// New flags.
							get_post_meta( $post->ID, $this->POST_SKIP . $unique_id, true )
							||
							// Old flags.
							get_post_meta( $post->ID, $this->POST_SKIP . $service_name )
						)
					)
					||
					(
						is_array( $connection )
						&&
						isset( $connection_meta['external_id'] ) && ! empty( $service_id_done[ $service_name ][ $connection_meta['external_id'] ] )
					)
				);

				// If this one has already been publicized to, don't let it happen again.
				$toggleable = ! $done && ! $all_done;

				// Determine the state of the checkbox (on/off) and allow filtering.
				$enabled = $done || ! $skip;
				/**
				 * Filter the checkbox state of each Publicize connection appearing in the post editor.
				 *
				 * @since 0.1.0
				 * @since-jetpack 2.0.1
				 *
				 * @param bool $enabled Should the Publicize checkbox be enabled for a given service.
				 * @param int $post_id Post ID.
				 * @param string $service_name Service name.
				 * @param array $connection Array of connection details.
				 */
				$enabled = apply_filters( 'publicize_checkbox_default', $enabled, $post_id, $service_name, $connection );

				/**
				 * If this is a global connection and this user doesn't have enough permissions to modify
				 * those connections, don't let them change it.
				 */
				if ( ! $done && $this->is_global_connection( $connection_meta ) && ! current_user_can( $this->GLOBAL_CAP ) ) {
					$toggleable = false;

					/**
					 * Filters the checkboxes for global connections with non-prilvedged users.
					 *
					 * @since 0.1.0
					 * @since-jetpack 3.7.0
					 *
					 * @param bool   $enabled Indicates if this connection should be enabled. Default true.
					 * @param int    $post_id ID of the current post
					 * @param string $service_name Name of the connection (Facebook, Twitter, etc)
					 * @param array  $connection Array of data about the connection.
					 */
					$enabled = apply_filters( 'publicize_checkbox_global_default', $enabled, $post_id, $service_name, $connection );
				}

				// Force the checkbox to be checked if the post was DONE, regardless of what the filter does.
				if ( $done ) {
					$enabled = true;
				}

				$connection_list[] = array(
					'unique_id'       => $unique_id,
					'service_name'    => $service_name,
					'service_label'   => $this->get_service_label( $service_name ),
					'display_name'    => $this->get_display_name( $service_name, $connection ),
					'profile_picture' => $this->get_profile_picture( $connection ),
					'enabled'         => $enabled,
					'done'            => $done,
					'toggleable'      => $toggleable,
					'global'          => 0 == $connection_data['user_id'], // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual,WordPress.PHP.StrictComparisons.LooseComparison -- Other types can be used at times.
				);
			}
		}

		return $connection_list;
	}

	/**
	 * Checks if post has already been shared by Publicize in the past.
	 *
	 * @since 0.1.0
	 * @since-jetpack 6.7.0
	 *
	 * @param integer $post_id Optional. Post ID to query connection status for: will use current post if missing.
	 *
	 * @return bool True if post has already been shared by Publicize, false otherwise.
	 */
	abstract public function post_is_done_sharing( $post_id = null );

	/**
	 * Retrieves full list of available Publicize connection services.
	 *
	 * Retrieves current available publicize service connections
	 * with associated labels and URLs.
	 *
	 * @since 0.1.0
	 * @since-jetpack 6.7.0
	 *
	 * @return array {
	 *     Array of UI service connection data for all services
	 *
	 *     @type string 'name'  Name of service.
	 *     @type string 'label' Display label for service.
	 *     @type string 'url'   URL for adding connection to service.
	 * }
	 */
	public function get_available_service_data() {
		$available_services     = $this->get_services( 'all' );
		$available_service_data = array();

		foreach ( $available_services as $service_name => $service ) {
			$available_service_data[] = array(
				'name'  => $service_name,
				'label' => $this->get_service_label( $service_name ),
				'url'   => $this->connect_url( $service_name ),
			);
		}

		return $available_service_data;
	}

	/**
	 * Site Data
	 */

	/**
	 * Get user ID.
	 *
	 * @return int The current user's ID, or 0 if no user is logged in.
	 */
	public function user_id() {
		return get_current_user_id();
	}

	/**
	 * Get site ID.
	 *
	 * @return int Site ID.
	 */
	public function blog_id() {
		return get_current_blog_id();
	}

	/**
	 * Posts
	 */

	/**
	 * Checks old and new status to see if the post should be flagged as
	 * ready to Publicize.
	 *
	 * Attached to the `transition_post_status` filter.
	 *
	 * @param string  $new_status New status.
	 * @param string  $old_status Old status.
	 * @param WP_Post $post Post object.
	 * @return void
	 */
	abstract public function flag_post_for_publicize( $new_status, $old_status, $post );

	/**
	 * Ensures the Post internal post-type supports `publicize`
	 *
	 * This feature support flag is used by the REST API.
	 */
	public function add_post_type_support() {
		add_post_type_support( 'post', 'publicize' );
	}

	/**
	 * Can the current user access Publicize Data.
	 *
	 * @param int $post_id 0 for general access. Post_ID for specific access.
	 * @return bool
	 */
	public function current_user_can_access_publicize_data( $post_id = 0 ) {
		/**
		 * Filter what user capability is required to use the publicize form on the edit post page. Useful if publish post capability has been removed from role.
		 *
		 * @since 0.1.0
		 * @since-jetpack 4.1.0
		 *
		 * @param string $capability User capability needed to use publicize
		 */
		$capability = apply_filters( 'jetpack_publicize_capability', 'publish_posts' );

		if ( 'publish_posts' === $capability && $post_id ) {
			return current_user_can( 'publish_post', $post_id );
		}

		return current_user_can( $capability );
	}

	/**
	 * Auth callback for the protected ->POST_MESS post_meta
	 *
	 * @param int $object_id Post ID.
	 * @return bool
	 */
	public function message_meta_auth_callback( $object_id ) {
		return $this->current_user_can_access_publicize_data( $object_id );
	}

	/**
	 * Registers the post_meta for use in the REST API.
	 *
	 * Registers for each post type that with `publicize` feature support.
	 */
	public function register_post_meta() {
		$message_args = array(
			'type'          => 'string',
			'description'   => __( 'The message to use instead of the title when sharing to Jetpack Social services', 'jetpack-publicize-pkg' ),
			'single'        => true,
			'default'       => '',
			'show_in_rest'  => array(
				'name' => 'jetpack_publicize_message',
			),
			'auth_callback' => array( $this, 'message_meta_auth_callback' ),
		);

		$tweetstorm_args = array(
			'type'          => 'boolean',
			'description'   => __( 'Whether or not the post should be treated as a Twitter thread.', 'jetpack-publicize-pkg' ),
			'single'        => true,
			'default'       => false,
			'show_in_rest'  => array(
				'name' => 'jetpack_is_tweetstorm',
			),
			'auth_callback' => array( $this, 'message_meta_auth_callback' ),
		);

		$publicize_feature_enable_args = array(
			'type'          => 'boolean',
			'description'   => __( 'Whether or not the Share Post feature is enabled.', 'jetpack-publicize-pkg' ),
			'single'        => true,
			'default'       => true,
			'show_in_rest'  => array(
				'name' => 'jetpack_publicize_feature_enabled',
			),
			'auth_callback' => array( $this, 'message_meta_auth_callback' ),
		);

		$already_shared_flag_args = array(
			'type'          => 'boolean',
			'description'   => __( 'Whether or not the post has already been shared.', 'jetpack-publicize-pkg' ),
			'single'        => true,
			'default'       => false,
			'show_in_rest'  => array(
				'name' => 'jetpack_social_post_already_shared',
			),
			'auth_callback' => array( $this, 'message_meta_auth_callback' ),
		);

		$jetpack_social_options_args = array(
			'type'          => 'object',
			'description'   => __( 'Post options related to Jetpack Social.', 'jetpack-publicize-pkg' ),
			'single'        => true,
			'default'       => array(
				'image_generator_settings' => array(
					'template' => ( new Social_Image_Generator\Settings() )->get_default_template(),
					'enabled'  => false,
				),
			),
			'show_in_rest'  => array(
				'name'   => 'jetpack_social_options',
				'schema' => array(
					'type'       => 'object',
					'properties' => array(
						'attached_media'               => array(
							'type'  => 'array',
							'items' => array(
								'type'       => 'object',
								'properties' => array(
									'id'  => array(
										'type' => 'number',
									),
									'url' => array(
										'type' => 'string',
									),
								),
							),
						),
						'should_upload_attached_media' => array(
							'type' => 'boolean',
						),
						'image_generator_settings'     => array(
							'type'       => 'object',
							'properties' => array(
								'enabled'     => array(
									'type' => 'boolean',
								),
								'custom_text' => array(
									'type' => 'string',
								),
								'image_type'  => array(
									'type' => 'string',
								),
								'image_id'    => array(
									'type' => 'number',
								),
								'template'    => array(
									'type' => 'string',
								),
								'token'       => array(
									'type' => 'string',
								),
							),
						),
					),
				),
			),
			'auth_callback' => array( $this, 'message_meta_auth_callback' ),
		);

		foreach ( get_post_types() as $post_type ) {
			if ( ! $this->post_type_is_publicizeable( $post_type ) ) {
				continue;
			}

			$message_args['object_subtype']                  = $post_type;
			$tweetstorm_args['object_subtype']               = $post_type;
			$publicize_feature_enable_args['object_subtype'] = $post_type;
			$already_shared_flag_args['object_subtype']      = $post_type;
			$jetpack_social_options_args['object_subtype']   = $post_type;

			register_meta( 'post', $this->POST_MESS, $message_args );
			register_meta( 'post', $this->POST_TWEETSTORM, $tweetstorm_args );
			register_meta( 'post', self::POST_PUBLICIZE_FEATURE_ENABLED, $publicize_feature_enable_args );
			register_meta( 'post', $this->POST_DONE . 'all', $already_shared_flag_args );
			register_meta( 'post', self::POST_JETPACK_SOCIAL_OPTIONS, $jetpack_social_options_args );
		}
	}

	/**
	 * Helper function to allow us to not publicize posts in certain contexts.
	 *
	 * @param WP_Post $post Post object.
	 */
	public function should_submit_post_pre_checks( $post ) {
		$submit_post = true;

		if ( defined( 'WP_IMPORTING' ) && WP_IMPORTING ) {
			$submit_post = false;
		}

		if (
			defined( 'DOING_AUTOSAVE' )
		&&
			DOING_AUTOSAVE
		) {
			$submit_post = false;
		}

		// To stop quick edits from getting publicized.
		if ( did_action( 'wp_ajax_inline-save' ) ) {
			$submit_post = false;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_GET['bulk_edit'] ) ) {
			$submit_post = false;
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		// - API/XML-RPC Test Posts
		if (
			(
				defined( 'XMLRPC_REQUEST' )
			&&
				XMLRPC_REQUEST
			||
				defined( 'APP_REQUEST' )
			&&
				APP_REQUEST
			)
		&&
			0 === strpos( $post->post_title, 'Temporary Post Used For Theme Detection' )
		) {
			$submit_post = false;
		}

		// Only work with certain statuses (avoids inherits, auto drafts etc).
		if ( ! in_array( $post->post_status, array( 'publish', 'draft', 'future' ), true ) ) {
			$submit_post = false;
		}

		// Don't publish password protected posts.
		if ( '' !== $post->post_password ) {
			$submit_post = false;
		}

		return $submit_post;
	}

	/**
	 * Fires when a post is saved, checks conditions and saves state in postmeta so that it
	 * can be picked up later by @see ::publicize_post() on WordPress.com codebase.
	 *
	 * Attached to the `save_post` action.
	 *
	 * @param int     $post_id Post ID.
	 * @param WP_Post $post Post object.
	 */
	public function save_meta( $post_id, $post ) {
		$cron_user   = null;
		$submit_post = true;

		if ( ! $this->post_type_is_publicizeable( $post->post_type ) ) {
			return;
		}

		$submit_post = $this->should_submit_post_pre_checks( $post );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- We're only checking if a value is set
		$admin_page = isset( $_POST[ $this->ADMIN_PAGE ] ) ? $_POST[ $this->ADMIN_PAGE ] : null;

		// Did this request happen via wp-admin?
		$from_web = isset( $_SERVER['REQUEST_METHOD'] )
			&&
			'post' === strtolower( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) )
			&&
			! empty( $admin_page );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$title = isset( $_POST['wpas_title'] ) ? sanitize_textarea_field( wp_unslash( $_POST['wpas_title'] ) ) : null;

		if ( ( $from_web || defined( 'POST_BY_EMAIL' ) ) && $title ) {
			if ( empty( $title ) ) {
				delete_post_meta( $post_id, $this->POST_MESS );
			} else {
				update_post_meta( $post_id, $this->POST_MESS, trim( stripslashes( $title ) ) );
			}
		}

		// Change current user to provide context for get_services() if we're running during cron.
		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			$cron_user = (int) $GLOBALS['user_ID'];
			wp_set_current_user( $post->post_author );
		}

		/**
		 * In this phase, we mark connections that we want to SKIP. When Publicize is actually triggered,
		 * it will Publicize to everything *except* those marked for skipping.
		 */
		foreach ( (array) $this->get_services( 'connected' ) as $service_name => $connections ) {
			foreach ( $connections as $connection ) {
				$connection_data = '';
				if ( is_object( $connection ) && method_exists( $connection, 'get_meta' ) ) {
					$connection_data = $connection->get_meta( 'connection_data' );
				} elseif ( ! empty( $connection['connection_data'] ) ) {
					$connection_data = $connection['connection_data'];
				}

				/** This action is documented in modules/publicize/ui.php */
				/* phpcs:ignore WordPress.NamingConventions.ValidHookName.UseUnderscores */
				if ( false === apply_filters( 'wpas_submit_post?', $submit_post, $post_id, $service_name, $connection_data ) ) {
					delete_post_meta( $post_id, $this->PENDING );
					continue;
				}

				if ( ! empty( $connection->unique_id ) ) {
					$unique_id = $connection->unique_id;
				} elseif ( ! empty( $connection['connection_data']['token_id'] ) ) {
					$unique_id = $connection['connection_data']['token_id'];
				}

				// This was a wp-admin request, so we need to check the state of checkboxes.
				if ( $from_web ) {
					// Delete stray service-based post meta.
					delete_post_meta( $post_id, $this->POST_SKIP . $service_name );

					// We *unchecked* this stream from the admin page, or it's set to readonly, or it's a new addition.
					if ( empty( $admin_page['submit'][ $unique_id ] ) ) {
						// Also make sure that the service-specific input isn't there.
						// If the user connected to a new service 'in-page' then a hidden field with the service
						// name is added, so we just assume they wanted to Publicize to that service.
						if ( empty( $admin_page['submit'][ $service_name ] ) ) {
							// Nothing seems to be checked, so we're going to mark this one to be skipped.
							update_post_meta( $post_id, $this->POST_SKIP . $unique_id, 1 );
							continue;
						} else {
							// Clean up any stray post meta.
							delete_post_meta( $post_id, $this->POST_SKIP . $unique_id );
						}
					} else {
						// The checkbox for this connection is explicitly checked -- make sure we DON'T skip it.
						delete_post_meta( $post_id, $this->POST_SKIP . $unique_id );
					}
				}

				/**
				 * Fires right before the post is processed for Publicize.
				 * Users may hook in here and do anything else they need to after meta is written,
				 * and before the post is processed for Publicize.
				 *
				 * @since 0.1.0
				 * @since-jetpack 2.1.2
				 *
				 * @param bool $submit_post Should the post be publicized.
				 * @param int $post->ID Post ID.
				 * @param string $service_name Service name.
				 * @param array $connection Array of connection details.
				 */
				do_action( 'publicize_save_meta', $submit_post, $post_id, $service_name, $connection );
			}
		}

		if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
			wp_set_current_user( $cron_user );
		}

		// Next up will be ::publicize_post().
	}

	/**
	 * Alters the "Post Published" message to include information about where the post
	 * was Publicized to.
	 *
	 * Attached to the `post_updated_messages` filter
	 *
	 * @param string[] $messages Array of messages.
	 * @return string[]
	 */
	public function update_published_message( $messages ) {
		global $post_type, $post_type_object, $post;
		if ( ! $this->post_type_is_publicizeable( $post_type ) ) {
			return $messages;
		}

		// Bail early if the post is private.
		if ( 'publish' !== $post->post_status ) {
			return $messages;
		}

		$view_post_link_html = '';
		$viewable            = is_post_type_viewable( $post_type_object );
		if ( $viewable ) {
			/* phpcs:ignore WordPress.WP.I18n.MissingArgDomain, WordPress.Utils.I18nTextDomainFixer.MissingArgDomain */
			$view_text = esc_html__( 'View post' ); // Intentionally omitted domain.

			if ( 'jetpack-portfolio' === $post_type ) {
				$view_text = esc_html__( 'View project', 'jetpack-publicize-pkg' );
			}

			$view_post_link_html = sprintf(
				' <a href="%1$s">%2$s</a>',
				esc_url( get_permalink( $post ) ),
				$view_text
			);
		}

		$services = $this->get_publicizing_services( $post->ID );
		if ( empty( $services ) ) {
			return $messages;
		}

		$labels = array();
		foreach ( $services as $service_name => $display_names ) {
			$labels[] = sprintf(
				/* translators: Service name is %1$s, and account name is %2$s. */
				esc_html__( '%1$s (%2$s)', 'jetpack-publicize-pkg' ),
				esc_html( $service_name ),
				esc_html( is_array( $display_names ) ? implode( ', ', $display_names ) : $display_names )
			);
		}

		$messages['post'][6] = sprintf(
			/* translators: %1$s is a comma-separated list of services and accounts. Ex. Facebook (@jetpack), Twitter (@jetpack) */
			esc_html__( 'Post published and sharing on %1$s.', 'jetpack-publicize-pkg' ),
			implode( ', ', $labels )
		) . $view_post_link_html;

		if ( 'post' === $post_type && class_exists( 'Jetpack_Subscriptions' ) ) {
			$subscription = \Jetpack_Subscriptions::init();
			if ( $subscription->should_email_post_to_subscribers( $post ) ) {
				$messages['post'][6] = sprintf(
					/* translators: %1$s is a comma-separated list of services and accounts. Ex. Facebook (@jetpack), Twitter (@jetpack) */
					esc_html__( 'Post published, sending emails to subscribers and sharing post on %1$s.', 'jetpack-publicize-pkg' ),
					implode( ', ', $labels )
				) . $view_post_link_html;
			}
		}

		$messages['jetpack-portfolio'][6] = sprintf(
			/* translators: %1$s is a comma-separated list of services and accounts. Ex. Facebook (@jetpack), Twitter (@jetpack) */
			esc_html__( 'Project published and sharing project on %1$s.', 'jetpack-publicize-pkg' ),
			implode( ', ', $labels )
		) . $view_post_link_html;

		return $messages;
	}

	/**
	 * Get the Connections the Post was just Publicized to.
	 *
	 * Only reliable just after the Post was published.
	 *
	 * @param int $post_id Post ID.
	 * @return string[] Array of Service display name => Connection display name
	 */
	public function get_publicizing_services( $post_id ) {
		$services = array();

		foreach ( (array) $this->get_services( 'connected' ) as $service_name => $connections ) {
			// services have multiple connections.
			foreach ( $connections as $connection ) {
				$unique_id = '';
				if ( ! empty( $connection->unique_id ) ) {
					$unique_id = $connection->unique_id;
				} elseif ( ! empty( $connection['connection_data']['token_id'] ) ) {
					$unique_id = $connection['connection_data']['token_id'];
				}

				// Did we skip this connection?
				if ( get_post_meta( $post_id, $this->POST_SKIP . $unique_id, true ) ) {
					continue;
				}
				$services[ $this->get_service_label( $service_name ) ][] = $this->get_display_name( $service_name, $connection );
			}
		}

		return $services;
	}

	/**
	 * Is the post Publicize-able?
	 *
	 * Only valid prior to Publicizing a Post.
	 *
	 * @param WP_Post $post Post to check.
	 * @return bool
	 */
	public function post_is_publicizeable( $post ) {
		if ( ! $this->post_type_is_publicizeable( $post->post_type ) ) {
			return false;
		}

		// This is more a precaution. To only publicize posts that are published. (Mostly relevant for Jetpack sites).
		if ( 'publish' !== $post->post_status ) {
			return false;
		}

		// If it's not flagged as ready, then abort. @see ::flag_post_for_publicize().
		if ( ! get_post_meta( $post->ID, $this->PENDING, true ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Is a given post type Publicize-able?
	 *
	 * Not every CPT lends itself to Publicize-ation.  Allow CPTs to register by adding their CPT via
	 * the publicize_post_types array filter.
	 *
	 * @param string $post_type The post type to check.
	 * @return bool True if the post type can be Publicized.
	 */
	public function post_type_is_publicizeable( $post_type ) {
		if ( 'post' === $post_type ) {
			return true;
		}

		return post_type_supports( $post_type, 'publicize' );
	}

	/**
	 * Already-published posts should not be Publicized by default. This filter sets checked to
	 * false if a post has already been published.
	 *
	 * Attached to the `publicize_checkbox_default` filter
	 *
	 * @param bool $checked True if checkbox is checked, false otherwise.
	 * @param int  $post_id Post ID to set checkbox for.
	 * @return bool
	 */
	public function publicize_checkbox_default( $checked, $post_id ) {
		if ( 'publish' === get_post_status( $post_id ) ) {
			return false;
		}

		return $checked;
	}

	/**
	 * Get the attached image for a post.
	 *
	 * @param int $post_id ID of the post to get attached media for.
	 * @return array {
	 *     Array of image data, or empty array if no image is available.
	 *
	 *     @type string $url Image source URL.
	 *     @type int    $width Image width in pixels.
	 *     @type int    $height Image height in pixels.
	 * }
	 */
	public function get_attached_media_image( $post_id ) {
		$options = get_post_meta( $post_id, self::POST_JETPACK_SOCIAL_OPTIONS, true );

		if ( ! is_array( $options ) || empty( $options['attached_media'] ) || empty( $options['attached_media'][0]['id'] ) ) {
			return array();
		}

		$media_id = $options['attached_media'][0]['id'];

		if ( ! wp_attachment_is_image( $media_id ) ) {
			return array();
		}

		$image = wp_get_attachment_image_src( $media_id, array( 1200 ) );

		if ( ! $image ) {
			return array();
		}

		return array(
			'url'    => $image[0],
			'width'  => $image[1],
			'height' => $image[2],
		);
	}

	/**
	 * Get the OpenGraph image for a post.
	 *
	 * @param int $post_id ID of the post to get OpenGraph image for.
	 * @return array {
	 *     Array of image data, or empty array if no image is available.
	 *
	 *     @type string $url Image source URL.
	 *     @type int    $width Image width in pixels.
	 *     @type int    $height Image height in pixels.
	 * }
	 */
	public function get_social_opengraph_image( $post_id ) {
		$generated_image_url = Social_Image_Generator\get_image_url( $post_id );

		if ( ! empty( $generated_image_url ) ) {
			return array(
				'url'    => $generated_image_url,
				'width'  => 1200,
				'height' => 630,
			);
		}

		$attached_media = $this->get_attached_media_image( $post_id );

		if ( $attached_media ) {
			return $attached_media;
		}

		return array();
	}

	/**
	 * Add the Jetpack Social images (attached media, SIG image) to the OpenGraph tags.
	 *
	 * @param array $tags Current tags.
	 */
	public function add_jetpack_social_og_images( $tags ) {
		$opengraph_image = $this->get_social_opengraph_image( get_the_ID() );

		if ( empty( $opengraph_image ) ) {
			return $tags;
		}

		// If this code is running in Jetpack, we need to add Twitter cards.
		// Some active plugins disable Jetpack's Twitter Cards, so we need
		// to check if the class was instantiated before adding the cards.
		$needs_twitter_cards = class_exists( 'Jetpack_Twitter_Cards' );

		return array_merge(
			$tags,
			array(
				'og:image'        => $opengraph_image['url'],
				'og:image:width'  => $opengraph_image['width'],
				'og:image:height' => $opengraph_image['height'],
			),
			$needs_twitter_cards ? array(
				'twitter:image' => $opengraph_image['url'],
				'twitter:card'  => 'summary_large_image',
			) : array()
		);
	}

	/**
	 * Util
	 */

	/**
	 * Converts a Publicize message template string into a sprintf format string
	 *
	 * @param string[] $args Array of arguments.
	 *               0 - The Publicize message template: 'Check out my post: %title% @ %url'
	 *             ... - The template tags 'title', 'url', etc.
	 * @return string
	 */
	protected static function build_sprintf( $args ) {
		$search  = array();
		$replace = array();
		foreach ( $args as $k => $arg ) {
			if ( 0 === $k ) {
				$string = $arg;
				continue;
			}
			$search[]  = "%$arg%";
			$replace[] = "%$k\$s";
		}
		return str_replace( $search, $replace, $string );
	}

	/**
	 * Get Calypso URL for Publicize connections.
	 *
	 * @param string $source The idenfitier of the place the function is called from.
	 * @return string
	 */
	public function publicize_connections_url( $source = 'calypso-marketing-connections' ) {
		$allowed_sources = array( 'jetpack-social-connections-admin-page', 'jetpack-social-connections-classic-editor', 'calypso-marketing-connections' );
		$source          = in_array( $source, $allowed_sources, true ) ? $source : 'calypso-marketing-connections';
		return Redirect::get_url( $source, array( 'site' => ( new Status() )->get_site_suffix() ) );
	}

	/**
	 * Get the Jetpack Social info from the API.
	 *
	 * @param int $blog_id The WPCOM blog_id for the current blog.
	 * @return array
	 */
	public function get_api_data( $blog_id ) {
		static $api_data_response = null;
		$key                      = 'jetpack_social_api_data';

		if ( isset( $api_data_response ) ) {
			return ! is_wp_error( $api_data_response ) ? $api_data_response : array();
		}

		$rest_controller   = new REST_Controller();
		$response          = Client::wpcom_json_api_request_as_blog(
			sprintf( 'sites/%d/jetpack-social', absint( $blog_id ) ),
			'2',
			array(
				'headers' => array( 'content-type' => 'application/json' ),
				'method'  => 'GET',
			),
			null,
			'wpcom'
		);
		$api_data_response = $rest_controller->make_proper_response( $response );

		if ( ! is_wp_error( $api_data_response ) ) {
			set_transient( $key, $api_data_response, DAY_IN_SECONDS );
			return $api_data_response;
		}

		$cached_response = get_transient( $key );
		if ( ! empty( $cached_response ) ) {
			return $cached_response;
		}

		return array();
	}

	/**
	 * Get the Publicize shares info.
	 *
	 * @param string $blog_id The WPCOM blog_id for the current blog.
	 * @return ?array
	 */
	public function get_publicize_shares_info( $blog_id ) {
		$data = $this->get_api_data( $blog_id );

		if ( empty( $data ) ) {
			return null;
		}

		return $data;
	}

	/**
	 * Check if enhanced publishing is enabled.
	 *
	 * @param int $blog_id The blog ID for the current blog.
	 * @return bool
	 */
	public function is_enhanced_publishing_enabled( $blog_id ) {
		$data = $this->get_api_data( $blog_id );

		if ( empty( $data ) ) {
			return false;
		}

		return ! empty( $data['is_enhanced_publishing_enabled'] );
	}

	/**
	 * Check if the social image generator is enabled.
	 *
	 * @deprecated 0.24.2 use Automattic\Jetpack\Publicize\Publicize_Base\has_social_image_generator_feature instead.
	 * @param int $blog_id The blog ID for the current blog.
	 * @return bool
	 */
	public function is_social_image_generator_enabled( $blog_id ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return $this->has_social_image_generator_feature();
	}

	/**
	 * Check if the social image generator is enabled.
	 *
	 * @return bool
	 */
	public function has_social_image_generator_feature() {
		return Current_Plan::supports( 'social-image-generator' );
	}

	/**
	 * Call the WPCOM REST API to calculate the scheduled shares.
	 *
	 * @param string $blog_id The blog_id.
	 */
	public function calculate_scheduled_shares( $blog_id ) {
		$response        = Client::wpcom_json_api_request_as_blog(
			sprintf( 'sites/%d/jetpack-social/count-scheduled-shares', absint( $blog_id ) ),
			'2',
			array(
				'headers' => array( 'content-type' => 'application/json' ),
				'method'  => 'GET',
			),
			null,
			'wpcom'
		);
		$rest_controller = new REST_Controller();
		return $rest_controller->make_proper_response( $response );
	}

	/**
	 * Check if we have a paid Jetpack Social plan.
	 *
	 * @param bool $refresh_from_wpcom Whether to force refresh the plan check.
	 *
	 * @return bool True if we have a paid plan, false otherwise.
	 */
	public function has_paid_plan( $refresh_from_wpcom = false ) {
		static $has_paid_plan = null;
		if ( ! $has_paid_plan ) {
			$has_paid_plan = Current_Plan::supports( 'social-shares-1000', $refresh_from_wpcom );
		}
		return $has_paid_plan;
	}
}

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move these functions to some other file.

/**
 * Get Calypso URL for Publicize connections.
 *
 * @return string
 */
function publicize_calypso_url() {
	_deprecated_function( __METHOD__, '0.2.0', 'Publicize::publicize_connections_url' );
	return Redirect::get_url( 'calypso-marketing-connections', array( 'site' => ( new Status() )->get_site_suffix() ) );
}

/**
 * Adds support for the post-thumbnails feature, regardless of underlying theme support.
 *
 * This ensures the featured image UI appears in the editor, allowing the user to
 * explicitly set an image for their social media post.
 */
function add_theme_post_thumbnails_support() {
	add_theme_support( 'post-thumbnails', get_post_types_by_support( 'publicize' ) );
}
