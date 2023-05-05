<?php
/**
 * The Backup Rest Controller class.
 * Registers the REST routes for Backup.
 *
 * @package automattic/jetpack-backup
 */

namespace Automattic\Jetpack\Backup;

use Automattic\Jetpack\Connection\Rest_Authentication;
use Automattic\Jetpack\Sync\Actions as Sync_Actions;
use WP_Error;
use WP_REST_Request;
use WP_REST_Server;

/**
 * Registers the REST routes for Backup.
 */
class REST_Controller {
	/**
	 * Registers the REST routes for Backup.
	 *
	 * @access public
	 * @static
	 */
	public static function register_rest_routes() {
		// Install a Helper Script to assist Jetpack Backup fetch data.
		register_rest_route(
			'jetpack/v4',
			'/backup-helper-script',
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => __CLASS__ . '::install_backup_helper_script',
				'permission_callback' => __CLASS__ . '::backup_permissions_callback',
				'args'                => array(
					'helper' => array(
						'description' => __( 'base64 encoded Backup Helper Script body.', 'jetpack-backup-pkg' ),
						'type'        => 'string',
						'required'    => true,
					),
				),
			)
		);

		// Delete a Backup Helper Script.
		register_rest_route(
			'jetpack/v4',
			'/backup-helper-script',
			array(
				'methods'             => WP_REST_Server::DELETABLE,
				'callback'            => __CLASS__ . '::delete_backup_helper_script',
				'permission_callback' => __CLASS__ . '::backup_permissions_callback',
				'args'                => array(
					'path' => array(
						'description' => __( 'Path to Backup Helper Script', 'jetpack-backup-pkg' ),
						'type'        => 'string',
						'required'    => true,
					),
				),
			)
		);

		// Fetch a backup of a database object, along with all of its metadata.
		register_rest_route(
			'jetpack/v4',
			'/database-object/backup',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::fetch_database_object_backup',
				'permission_callback' => __CLASS__ . '::backup_permissions_callback',
				'args'                => array(
					'object_type' => array(
						'description'       => __( 'Type of object to fetch from the database', 'jetpack-backup-pkg' ),
						'required'          => true,
						'validate_callback' => function ( $value ) {
							if ( ! is_string( $value ) ) {
								return new WP_Error(
									'rest_invalid_param',
									__( 'The object_type argument must be a non-empty string.', 'jetpack-backup-pkg' ),
									array( 'status' => 400 )
								);
							}

							$allowed_object_types = array_keys( self::get_allowed_object_types() );

							if ( ! in_array( $value, $allowed_object_types, true ) ) {
								return new WP_Error(
									'rest_invalid_param',
									sprintf(
										/* translators: %s: comma-separated list of allowed object types */
										__( 'The object_type argument should be one of %s', 'jetpack-backup-pkg' ),
										implode( ', ', $allowed_object_types )
									),
									array( 'status' => 400 )
								);
							}

							return true;
						},
					),
					'object_id'   => array(
						'description' => __( 'ID of the database object to fetch', 'jetpack-backup-pkg' ),
						'type'        => 'integer',
						'required'    => true,
					),
				),
			)
		);

		// Fetch a backup of an option.
		register_rest_route(
			'jetpack/v4',
			'/options/backup',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::fetch_options_backup',
				'permission_callback' => __CLASS__ . '::backup_permissions_callback',
				'args'                => array(
					'name' => array(
						'description'       => __( 'One or more option names to include in the backup', 'jetpack-backup-pkg' ),
						'validate_callback' => function ( $value ) {
							$is_valid = is_array( $value ) || is_string( $value );
							if ( ! $is_valid ) {
								return new WP_Error( 'rest_invalid_param', __( 'The name argument should be an option name or an array of option names', 'jetpack-backup-pkg' ), array( 'status' => 400 ) );
							}

							return true;
						},
						'required'          => true,
					),
				),
			)
		);

		// Fetch a backup of a comment, along with all of its metadata.
		register_rest_route(
			'jetpack/v4',
			'/comments/(?P<id>\d+)/backup',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::fetch_comment_backup',
				'permission_callback' => __CLASS__ . '::backup_permissions_callback',
			)
		);

		// Fetch a backup of a post, along with all of its metadata.
		register_rest_route(
			'jetpack/v4',
			'/posts/(?P<id>\d+)/backup',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::fetch_post_backup',
				'permission_callback' => __CLASS__ . '::backup_permissions_callback',
			)
		);

		// Fetch a backup of a term, along with all of its metadata.
		register_rest_route(
			'jetpack/v4',
			'/terms/(?P<id>\d+)/backup',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::fetch_term_backup',
				'permission_callback' => __CLASS__ . '::backup_permissions_callback',
			)
		);

		// Fetch a backup of a user, along with all of its metadata.
		register_rest_route(
			'jetpack/v4',
			'/users/(?P<id>\d+)/backup',
			array(
				'methods'             => WP_REST_Server::READABLE,
				'callback'            => __CLASS__ . '::fetch_user_backup',
				'permission_callback' => __CLASS__ . '::backup_permissions_callback',
			)
		);
	}

	/**
	 * The Backup endpoints should only be available via site-level authentication.
	 * This means that the corresponding endpoints can only be accessible from WPCOM.
	 *
	 * @access public
	 * @static
	 *
	 * @return bool|WP_Error True if a blog token was used to sign the request, WP_Error otherwise.
	 */
	public static function backup_permissions_callback() {
		if ( Rest_Authentication::is_signed_with_blog_token() ) {
			return true;
		}

		$error_msg = esc_html__(
			'You are not allowed to perform this action.',
			'jetpack-backup-pkg'
		);

		return new WP_Error( 'rest_forbidden', $error_msg, array( 'status' => rest_authorization_required_code() ) );
	}

	/**
	 * Install the Backup Helper Script.
	 *
	 * @access public
	 * @static
	 *
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 * @return array|WP_Error Returns the result of Helper Script installation. Returns one of:
	 * - WP_Error on failure, or
	 * - An array with installation info on success:
	 *  'path'    (string) The sinstallation path.
	 *  'url'     (string) The access url.
	 *  'abspath' (string) The abspath.
	 */
	public static function install_backup_helper_script( $request ) {
		$helper_script = $request->get_param( 'helper' );

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		$helper_script = base64_decode( $helper_script );
		if ( ! $helper_script ) {
			return new WP_Error( 'invalid_args', __( 'Helper script body must be base64 encoded', 'jetpack-backup-pkg' ), 400 );
		}

		$installation_info = Helper_Script_Manager::install_helper_script( $helper_script );
		Helper_Script_Manager::cleanup_expired_helper_scripts();

		// Include ABSPATH with successful result.
		if ( ! is_wp_error( $installation_info ) ) {
			$installation_info['abspath'] = ABSPATH;
		}

		return rest_ensure_response( $installation_info );
	}

	/**
	 * Delete a Backup Helper Script.
	 *
	 * @access public
	 * @static
	 *
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 * @return array An array with 'success' key indicating the result of the delete operation.
	 */
	public static function delete_backup_helper_script( $request ) {
		$path_to_helper_script = $request->get_param( 'path' );

		$deleted = Helper_Script_Manager::delete_helper_script( $path_to_helper_script );
		Helper_Script_Manager::cleanup_expired_helper_scripts();

		return rest_ensure_response(
			array(
				'success' => $deleted,
			)
		);
	}

	/**
	 * Fetch a backup of a database object, along with all of its metadata.
	 *
	 * @access public
	 * @static
	 *
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 * @return array
	 */
	public static function fetch_database_object_backup( $request ) {
		global $wpdb;

		// Disable Sync as this is a read-only operation and triggered by sync activity.
		Sync_Actions::mark_sync_read_only();

		$allowed_object_types = self::get_allowed_object_types();
		// Safe to do this as we have already validated the object_type key exists in self::get_allowed_object_types().
		$object_type = $allowed_object_types[ $request->get_param( 'object_type' ) ];
		$object_id   = $request->get_param( 'object_id' );
		$table       = $wpdb->prefix . $object_type['table'];
		$id_field    = $object_type['id_field'];

		// Fetch the requested object.
		$object = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM `' . $table . '` WHERE `' . $id_field . '` = %d', // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
				$object_id
			)
		);

		if ( empty( $object ) ) {
			return new WP_Error( 'object_not_found', __( 'Object not found', 'jetpack-backup-pkg' ), array( 'status' => 404 ) );
		}

		$result = array( 'object' => $object );

		// Fetch associated metadata (if this object type has any).
		if ( ! empty( $object_type['meta_type'] ) ) {
			$result['meta'] = get_metadata( $object_type['meta_type'], $object_id );
		}

		// If there is a child linked table (eg: woocommerce_tax_rate_locations), fetch linked records.
		if ( ! empty( $object_type['child_table'] ) ) {
			$child_table    = $wpdb->prefix . $object_type['child_table'];
			$child_id_field = $object_type['child_id_field'];

			$result['children'] = $wpdb->get_results(
				$wpdb->prepare(
					'SELECT * FROM `' . $child_table . '` where `' . $child_id_field . '` = %d', // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
					$object_id
				)
			);
		}

		return $result;
	}

	/**
	 * Fetch a backup of an option.
	 *
	 * @access public
	 * @static
	 *
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 * @return array
	 */
	public static function fetch_options_backup( $request ) {
		// Disable Sync as this is a read-only operation and triggered by sync activity.
		Sync_Actions::mark_sync_read_only();

		$option_names = (array) $request->get_param( 'name' );

		$options = array_map( self::class . '::get_option_row', $option_names );
		return array( 'options' => $options );
	}

	/**
	 * Fetch a backup of a comment, along with all of its metadata.
	 *
	 * @access public
	 * @static
	 *
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 * @return array
	 */
	public static function fetch_comment_backup( $request ) {
		// Disable Sync as this is a read-only operation and triggered by sync activity.
		Sync_Actions::mark_sync_read_only();

		$comment_id = $request['id'];
		$comment    = get_comment( $comment_id );

		if ( empty( $comment ) ) {
			return new WP_Error( 'comment_not_found', __( 'Comment not found', 'jetpack-backup-pkg' ), array( 'status' => 404 ) );
		}

		$allowed_keys = array(
			'comment_ID',
			'comment_post_ID',
			'comment_author',
			'comment_author_email',
			'comment_author_url',
			'comment_author_IP',
			'comment_date',
			'comment_date_gmt',
			'comment_content',
			'comment_karma',
			'comment_approved',
			'comment_agent',
			'comment_type',
			'comment_parent',
			'user_id',
		);

		$comment = array_intersect_key( $comment->to_array(), array_flip( $allowed_keys ) );

		$comment_meta = get_comment_meta( $comment['comment_ID'] );

		return array(
			'comment' => $comment,
			'meta'    => is_array( $comment_meta ) ? $comment_meta : array(),
		);
	}

	/**
	 * Fetch a backup of a post, along with all of its metadata.
	 *
	 * @access public
	 * @static
	 *
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 * @return array
	 */
	public static function fetch_post_backup( $request ) {
		global $wpdb;

		// Disable Sync as this is a read-only operation and triggered by sync activity.
		Sync_Actions::mark_sync_read_only();

		$post_id = $request['id'];
		$post    = get_post( $post_id );

		if ( empty( $post ) ) {
			return new WP_Error( 'post_not_found', __( 'Post not found', 'jetpack-backup-pkg' ), array( 'status' => 404 ) );
		}

		// Fetch terms associated with this post object.
		$terms = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT term_taxonomy_id, term_order FROM {$wpdb->term_relationships} WHERE object_id = %d;",
				$post->ID
			)
		);

		return array(
			'post'  => (array) $post,
			'meta'  => get_post_meta( $post->ID ),
			'terms' => (array) $terms,
		);
	}

	/**
	 * Fetch a backup of a term, along with all of its metadata.
	 *
	 * @access public
	 * @static
	 *
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 * @return array
	 */
	public static function fetch_term_backup( $request ) {
		// Disable Sync as this is a read-only operation and triggered by sync activity.
		Sync_Actions::mark_sync_read_only();

		$term_id = $request['id'];
		$term    = get_term( $term_id );

		if ( empty( $term ) ) {
			return new WP_Error( 'term_not_found', __( 'Term not found', 'jetpack-backup-pkg' ), array( 'status' => 404 ) );
		}

		return array(
			'term' => (array) $term,
			'meta' => get_term_meta( $term_id ),
		);
	}

	/**
	 * Fetch a backup of a user, along with all of its metadata.
	 *
	 * @access public
	 * @static
	 *
	 * @param WP_REST_Request $request The request sent to the WP REST API.
	 * @return array
	 */
	public static function fetch_user_backup( $request ) {
		// Disable Sync as this is a read-only operation and triggered by sync activity.
		Sync_Actions::mark_sync_read_only();

		$user_id = $request['id'];
		$user    = get_user_by( 'id', $user_id );

		if ( empty( $user ) ) {
			return new WP_Error( 'user_not_found', __( 'User not found', 'jetpack-backup-pkg' ), array( 'status' => 404 ) );
		}

		return array(
			'user' => $user->to_array(),
			'meta' => get_user_meta( $user->ID ),
		);
	}

	/**
	 * Get allowed object types for the '/database-object/backup' endpoint.
	 *
	 * @access private
	 * @static
	 *
	 * @return array
	 */
	private static function get_allowed_object_types() {
		return array(
			'woocommerce_attribute'                       => array(
				'table'    => 'woocommerce_attribute_taxonomies',
				'id_field' => 'attribute_id',
			),
			'woocommerce_downloadable_product_permission' => array(
				'table'    => 'woocommerce_downloadable_product_permissions',
				'id_field' => 'permission_id',
			),
			'woocommerce_order_item'                      => array(
				'table'     => 'woocommerce_order_items',
				'id_field'  => 'order_item_id',
				'meta_type' => 'order_item',
			),
			'woocommerce_payment_token'                   => array(
				'table'     => 'woocommerce_payment_tokens',
				'id_field'  => 'token_id',
				'meta_type' => 'payment_token',
			),
			'woocommerce_tax_rate'                        => array(
				'table'          => 'woocommerce_tax_rates',
				'id_field'       => 'tax_rate_id',
				'child_table'    => 'woocommerce_tax_rate_locations',
				'child_id_field' => 'tax_rate_id',
			),
			'woocommerce_webhook'                         => array(
				'table'    => 'wc_webhooks',
				'id_field' => 'webhook_id',
			),
		);
	}

	/**
	 * Fetch option row by option name.
	 *
	 * @access private
	 * @static
	 *
	 * @param string $name The option name.
	 * @return object|null Database query result as object format specified or null on failure.
	 */
	private static function get_option_row( $name ) {
		global $wpdb;
		return $wpdb->get_row( $wpdb->prepare( "select * from `{$wpdb->options}` where option_name = %s", $name ) );
	}
}
