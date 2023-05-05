<?php
/**
 * Users sync module.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync\Modules;

use Automattic\Jetpack\Constants as Jetpack_Constants;
use Automattic\Jetpack\Password_Checker;
use Automattic\Jetpack\Sync\Defaults;

/**
 * Class to handle sync for users.
 */
class Users extends Module {
	/**
	 * Maximum number of users to sync initially.
	 *
	 * @var int
	 */
	const MAX_INITIAL_SYNC_USERS = 100;

	/**
	 * User flags we care about.
	 *
	 * @access protected
	 *
	 * @var array
	 */
	protected $flags = array();

	/**
	 * Mapping between user fields to flags.
	 *
	 * @var array
	 */
	protected $user_fields_to_flags_mapping = array(
		'user_pass'           => 'password_changed',
		'user_email'          => 'email_changed',
		'user_nicename'       => 'nicename_changed',
		'user_url'            => 'url_changed',
		'user_registered'     => 'registration_date_changed',
		'user_activation_key' => 'activation_key_changed',
		'display_name'        => 'display_name_changed',
	);

	/**
	 * Sync module name.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function name() {
		return 'users';
	}

	/**
	 * The table in the database.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function table_name() {
		return 'usermeta';
	}

	/**
	 * The id field in the database.
	 *
	 * @access public
	 *
	 * @return string
	 */
	public function id_field() {
		return 'user_id';
	}

	/**
	 * Retrieve a user by its ID.
	 * This is here to support the backfill API.
	 *
	 * @access public
	 *
	 * @param string $object_type Type of the sync object.
	 * @param int    $id          ID of the sync object.
	 * @return \WP_User|bool Filtered \WP_User object, or false if the object is not a user.
	 */
	public function get_object_by_id( $object_type, $id ) {
		if ( 'user' === $object_type ) {
			$user = get_user_by( 'id', (int) $id );
			if ( $user ) {
				return $this->sanitize_user_and_expand( $user );
			}
		}

		return false;
	}

	/**
	 * Initialize users action listeners.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_listeners( $callable ) {
		// Users.
		add_action( 'user_register', array( $this, 'user_register_handler' ) );
		add_action( 'profile_update', array( $this, 'save_user_handler' ), 10, 2 );

		add_action( 'add_user_to_blog', array( $this, 'add_user_to_blog_handler' ) );
		add_action( 'jetpack_sync_add_user', $callable, 10, 2 );

		add_action( 'jetpack_sync_register_user', $callable, 10, 2 );
		add_action( 'jetpack_sync_save_user', $callable, 10, 2 );

		add_action( 'jetpack_sync_user_locale', $callable, 10, 2 );
		add_action( 'jetpack_sync_user_locale_delete', $callable, 10, 1 );

		add_action( 'deleted_user', array( $this, 'deleted_user_handler' ), 10, 2 );
		add_action( 'jetpack_deleted_user', $callable, 10, 3 );
		add_action( 'remove_user_from_blog', array( $this, 'remove_user_from_blog_handler' ), 10, 2 );
		add_action( 'jetpack_removed_user_from_blog', $callable, 10, 2 );

		// User roles.
		add_action( 'add_user_role', array( $this, 'save_user_role_handler' ), 10, 2 );
		add_action( 'set_user_role', array( $this, 'save_user_role_handler' ), 10, 3 );
		add_action( 'remove_user_role', array( $this, 'save_user_role_handler' ), 10, 2 );

		// User capabilities.
		add_action( 'added_user_meta', array( $this, 'maybe_save_user_meta' ), 10, 4 );
		add_action( 'updated_user_meta', array( $this, 'maybe_save_user_meta' ), 10, 4 );
		add_action( 'deleted_user_meta', array( $this, 'maybe_save_user_meta' ), 10, 4 );

		// User authentication.
		add_filter( 'authenticate', array( $this, 'authenticate_handler' ), 1000, 3 );
		add_action( 'wp_login', array( $this, 'wp_login_handler' ), 10, 2 );

		add_action( 'jetpack_wp_login', $callable, 10, 3 );

		add_action( 'wp_logout', $callable, 10, 0 );
		add_action( 'wp_masterbar_logout', $callable, 10, 1 );

		// Add on init.
		add_filter( 'jetpack_sync_before_enqueue_jetpack_sync_add_user', array( $this, 'expand_action' ) );
		add_filter( 'jetpack_sync_before_enqueue_jetpack_sync_register_user', array( $this, 'expand_action' ) );
		add_filter( 'jetpack_sync_before_enqueue_jetpack_sync_save_user', array( $this, 'expand_action' ) );
	}

	/**
	 * Initialize users action listeners for full sync.
	 *
	 * @access public
	 *
	 * @param callable $callable Action handler callable.
	 */
	public function init_full_sync_listeners( $callable ) {
		add_action( 'jetpack_full_sync_users', $callable );
	}

	/**
	 * Initialize the module in the sender.
	 *
	 * @access public
	 */
	public function init_before_send() {
		add_filter( 'jetpack_sync_before_send_jetpack_wp_login', array( $this, 'expand_login_username' ), 10, 1 );
		add_filter( 'jetpack_sync_before_send_wp_logout', array( $this, 'expand_logout_username' ), 10, 2 );

		// Full sync.
		add_filter( 'jetpack_sync_before_send_jetpack_full_sync_users', array( $this, 'expand_users' ) );
	}

	/**
	 * Retrieve a user by a user ID or object.
	 *
	 * @access private
	 *
	 * @param mixed $user User object or ID.
	 * @return \WP_User User object, or `null` if user invalid/not found.
	 */
	private function get_user( $user ) {
		if ( is_numeric( $user ) ) {
			$user = get_user_by( 'id', $user );
		}
		if ( $user instanceof \WP_User ) {
			return $user;
		}
		return null;
	}

	/**
	 * Sanitize a user object.
	 * Removes the password from the user object because we don't want to sync it.
	 *
	 * @access public
	 *
	 * @todo Refactor `serialize`/`unserialize` to `wp_json_encode`/`wp_json_decode`.
	 *
	 * @param \WP_User $user User object.
	 * @return \WP_User Sanitized user object.
	 */
	public function sanitize_user( $user ) {
		$user = $this->get_user( $user );
		// This creates a new user object and stops the passing of the object by reference.
		// // phpcs:disable WordPress.PHP.DiscouragedPHPFunctions.serialize_serialize, WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize
		$user = unserialize( serialize( $user ) );

		if ( is_object( $user ) && is_object( $user->data ) ) {
			unset( $user->data->user_pass );
		}
		return $user;
	}

	/**
	 * Expand a particular user.
	 *
	 * @access public
	 *
	 * @param \WP_User $user User object.
	 * @return \WP_User Expanded user object.
	 */
	public function expand_user( $user ) {
		if ( ! is_object( $user ) ) {
			return null;
		}
		$user->allowed_mime_types = get_allowed_mime_types( $user );
		$user->allcaps            = $this->get_real_user_capabilities( $user );

		// Only set the user locale if it is different from the site locale.
		if ( get_locale() !== get_user_locale( $user->ID ) ) {
			$user->locale = get_user_locale( $user->ID );
		}

		return $user;
	}

	/**
	 * Retrieve capabilities we care about for a particular user.
	 *
	 * @access public
	 *
	 * @param \WP_User $user User object.
	 * @return array User capabilities.
	 */
	public function get_real_user_capabilities( $user ) {
		$user_capabilities = array();
		if ( is_wp_error( $user ) ) {
			return $user_capabilities;
		}
		foreach ( Defaults::get_capabilities_whitelist() as $capability ) {
			if ( user_can( $user, $capability ) ) {
				$user_capabilities[ $capability ] = true;
			}
		}
		return $user_capabilities;
	}

	/**
	 * Retrieve, expand and sanitize a user.
	 * Can be directly used in the sync user action handlers.
	 *
	 * @access public
	 *
	 * @param mixed $user User ID or user object.
	 * @return \WP_User Expanded and sanitized user object.
	 */
	public function sanitize_user_and_expand( $user ) {
		$user = $this->get_user( $user );
		$user = $this->expand_user( $user );
		return $this->sanitize_user( $user );
	}

	/**
	 * Expand the user within a hook before it is serialized and sent to the server.
	 *
	 * @access public
	 *
	 * @param array $args The hook arguments.
	 * @return array $args The hook arguments.
	 */
	public function expand_action( $args ) {
		// The first argument is always the user.
		list( $user ) = $args;
		if ( $user ) {
			$args[0] = $this->sanitize_user_and_expand( $user );
			return $args;
		}

		return false;
	}

	/**
	 * Expand the user username at login before being sent to the server.
	 *
	 * @access public
	 *
	 * @param array $args The hook arguments.
	 * @return array $args Expanded hook arguments.
	 */
	public function expand_login_username( $args ) {
		list( $login, $user, $flags ) = $args;
		$user                         = $this->sanitize_user( $user );

		return array( $login, $user, $flags );
	}

	/**
	 * Expand the user username at logout before being sent to the server.
	 *
	 * @access public
	 *
	 * @param  array $args The hook arguments.
	 * @param  int   $user_id ID of the user.
	 * @return array $args Expanded hook arguments.
	 */
	public function expand_logout_username( $args, $user_id ) {
		$user = get_userdata( $user_id );
		$user = $this->sanitize_user( $user );

		$login = '';
		if ( is_object( $user ) && is_object( $user->data ) ) {
			$login = $user->data->user_login;
		}

		// If we don't have a user here lets not send anything.
		if ( empty( $login ) ) {
			return false;
		}

		return array( $login, $user );
	}

	/**
	 * Additional processing is needed for wp_login so we introduce this wrapper handler.
	 *
	 * @access public
	 *
	 * @param string   $user_login The user login.
	 * @param \WP_User $user       The user object.
	 */
	public function wp_login_handler( $user_login, $user ) {
		/**
		 * Fires when a user is logged into a site.
		 *
		 * @since 1.6.3
		 * @since-jetpack 7.2.0
		 *
		 * @param int      $user_id The user ID.
		 * @param \WP_User $user    The User Object  of the user that currently logged in.
		 * @param array    $params  Any Flags that have been added during login.
		 */
		do_action( 'jetpack_wp_login', $user->ID, $user, $this->get_flags( $user->ID ) );
		$this->clear_flags( $user->ID );
	}

	/**
	 * A hook for the authenticate event that checks the password strength.
	 *
	 * @access public
	 *
	 * @param \WP_Error|\WP_User $user     The user object, or an error.
	 * @param string             $username The username.
	 * @param string             $password The password used to authenticate.
	 * @return \WP_Error|\WP_User the same object that was passed into the function.
	 */
	public function authenticate_handler( $user, $username, $password ) {
		// In case of cookie authentication we don't do anything here.
		if ( empty( $password ) ) {
			return $user;
		}

		// We are only interested in successful authentication events.
		if ( is_wp_error( $user ) || ! ( $user instanceof \WP_User ) ) {
			return $user;
		}

		$password_checker = new Password_Checker( $user->ID );

		$test_results = $password_checker->test( $password, true );

		// If the password passes tests, we don't do anything.
		if ( empty( $test_results['test_results']['failed'] ) ) {
			return $user;
		}

		$this->add_flags(
			$user->ID,
			array(
				'warning'  => 'The password failed at least one strength test.',
				'failures' => $test_results['test_results']['failed'],
			)
		);

		return $user;
	}

	/**
	 * Handler for after the user is deleted.
	 *
	 * @access public
	 *
	 * @param int $deleted_user_id    ID of the deleted user.
	 * @param int $reassigned_user_id ID of the user the deleted user's posts are reassigned to (if any).
	 */
	public function deleted_user_handler( $deleted_user_id, $reassigned_user_id = '' ) {
		$is_multisite = is_multisite();
		/**
		 * Fires when a user is deleted on a site
		 *
		 * @since 1.6.3
		 * @since-jetpack 5.4.0
		 *
		 * @param int $deleted_user_id - ID of the deleted user.
		 * @param int $reassigned_user_id - ID of the user the deleted user's posts are reassigned to (if any).
		 * @param bool $is_multisite - Whether this site is a multisite installation.
		 */
		do_action( 'jetpack_deleted_user', $deleted_user_id, $reassigned_user_id, $is_multisite );
	}

	/**
	 * Handler for user registration.
	 *
	 * @access public
	 *
	 * @param int $user_id ID of the deleted user.
	 */
	public function user_register_handler( $user_id ) {
		// Ensure we only sync users who are members of the current blog.
		if ( ! is_user_member_of_blog( $user_id, get_current_blog_id() ) ) {
			return;
		}

		if ( Jetpack_Constants::is_true( 'JETPACK_INVITE_ACCEPTED' ) ) {
			$this->add_flags( $user_id, array( 'invitation_accepted' => true ) );
		}
		/**
		 * Fires when a new user is registered on a site
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.9.0
		 *
		 * @param object The WP_User object
		 */
		do_action( 'jetpack_sync_register_user', $user_id, $this->get_flags( $user_id ) );
		$this->clear_flags( $user_id );
	}

	/**
	 * Handler for user addition to the current blog.
	 *
	 * @access public
	 *
	 * @param int $user_id ID of the user.
	 */
	public function add_user_to_blog_handler( $user_id ) {
		// Ensure we only sync users who are members of the current blog.
		if ( ! is_user_member_of_blog( $user_id, get_current_blog_id() ) ) {
			return;
		}

		if ( Jetpack_Constants::is_true( 'JETPACK_INVITE_ACCEPTED' ) ) {
			$this->add_flags( $user_id, array( 'invitation_accepted' => true ) );
		}

		/**
		 * Fires when a user is added on a site
		 *
		 * @since 1.6.3
		 * @since-jetpack 4.9.0
		 *
		 * @param object The WP_User object
		 */
		do_action( 'jetpack_sync_add_user', $user_id, $this->get_flags( $user_id ) );
		$this->clear_flags( $user_id );
	}

	/**
	 * Handler for user save.
	 *
	 * @access public
	 *
	 * @param int      $user_id ID of the user.
	 * @param \WP_User $old_user_data User object before the changes.
	 */
	public function save_user_handler( $user_id, $old_user_data = null ) {
		// Ensure we only sync users who are members of the current blog.
		if ( ! is_user_member_of_blog( $user_id, get_current_blog_id() ) ) {
			return;
		}

		$user = get_user_by( 'id', $user_id );

		// Older versions of WP don't pass the old_user_data in ->data.
		if ( isset( $old_user_data->data ) ) {
			$old_user = $old_user_data->data;
		} else {
			$old_user = $old_user_data;
		}

		if ( ! is_object( $old_user ) ) {
			return;
		}

		$old_user_array = get_object_vars( $old_user );

		foreach ( $old_user_array as $user_field => $field_value ) {
			if ( false === $user->has_prop( $user_field ) ) {
				continue;
			}
			if ( $user->$user_field !== $field_value ) {
				if ( 'user_email' === $user_field ) {
					/**
					 * The '_new_email' user meta is deleted right after the call to wp_update_user
					 * that got us to this point so if it's still set then this was a user confirming
					 * their new email address.
					 */
					if ( 1 === (int) get_user_meta( $user->ID, '_new_email', true ) ) {
						$this->flags[ $user_id ]['email_changed'] = true;
					}
					continue;
				}

				$flag = isset( $this->user_fields_to_flags_mapping[ $user_field ] ) ? $this->user_fields_to_flags_mapping[ $user_field ] : 'unknown_field_changed';

				$this->flags[ $user_id ][ $flag ] = true;
			}
		}

		if ( isset( $this->flags[ $user_id ] ) ) {

			/**
			 * Fires when the client needs to sync an updated user.
			 *
			 * @since 1.6.3
			 * @since-jetpack 4.2.0
			 *
			 * @param \WP_User The WP_User object
			 * @param array    State - New since 5.8.0
			 */
			do_action( 'jetpack_sync_save_user', $user_id, $this->get_flags( $user_id ) );
			$this->clear_flags( $user_id );
		}
	}

	/**
	 * Handler for user role change.
	 *
	 * @access public
	 *
	 * @param int    $user_id   ID of the user.
	 * @param string $role      New user role.
	 * @param array  $old_roles Previous user roles.
	 */
	public function save_user_role_handler( $user_id, $role, $old_roles = null ) {
		$this->add_flags(
			$user_id,
			array(
				'role_changed'  => true,
				'previous_role' => $old_roles,
			)
		);

		// The jetpack_sync_register_user payload is identical to jetpack_sync_save_user, don't send both.
		if ( $this->is_create_user() || $this->is_add_user_to_blog() ) {
			return;
		}
		/**
		 * This action is documented already in this file
		 */
		do_action( 'jetpack_sync_save_user', $user_id, $this->get_flags( $user_id ) );
		$this->clear_flags( $user_id );
	}

	/**
	 * Retrieve current flags for a particular user.
	 *
	 * @access public
	 *
	 * @param int $user_id ID of the user.
	 * @return array Current flags of the user.
	 */
	public function get_flags( $user_id ) {
		if ( isset( $this->flags[ $user_id ] ) ) {
			return $this->flags[ $user_id ];
		}
		return array();
	}

	/**
	 * Clear the flags of a particular user.
	 *
	 * @access public
	 *
	 * @param int $user_id ID of the user.
	 */
	public function clear_flags( $user_id ) {
		if ( isset( $this->flags[ $user_id ] ) ) {
			unset( $this->flags[ $user_id ] );
		}
	}

	/**
	 * Add flags to a particular user.
	 *
	 * @access public
	 *
	 * @param int   $user_id ID of the user.
	 * @param array $flags   New flags to add for the user.
	 */
	public function add_flags( $user_id, $flags ) {
		$this->flags[ $user_id ] = wp_parse_args( $flags, $this->get_flags( $user_id ) );
	}

	/**
	 * Save the user meta, if we're interested in it.
	 * Also uses the time to add flags for the user.
	 *
	 * @access public
	 *
	 * @param int    $meta_id  ID of the meta object.
	 * @param int    $user_id  ID of the user.
	 * @param string $meta_key Meta key.
	 * @param mixed  $value    Meta value.
	 */
	public function maybe_save_user_meta( $meta_id, $user_id, $meta_key, $value ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		if ( 'locale' === $meta_key ) {
			$this->add_flags( $user_id, array( 'locale_changed' => true ) );
		}

		$user = get_user_by( 'id', $user_id );
		if ( isset( $user->cap_key ) && $meta_key === $user->cap_key ) {
			$this->add_flags( $user_id, array( 'capabilities_changed' => true ) );
		}

		if ( $this->is_create_user() || $this->is_add_user_to_blog() || $this->is_delete_user() ) {
			return;
		}

		if ( isset( $this->flags[ $user_id ] ) ) {
			/**
			 * This action is documented already in this file
			 */
			do_action( 'jetpack_sync_save_user', $user_id, $this->get_flags( $user_id ) );
		}
	}

	/**
	 * Enqueue the users actions for full sync.
	 *
	 * @access public
	 *
	 * @param array   $config               Full sync configuration for this sync module.
	 * @param int     $max_items_to_enqueue Maximum number of items to enqueue.
	 * @param boolean $state                True if full sync has finished enqueueing this module, false otherwise.
	 * @return array Number of actions enqueued, and next module state.
	 */
	public function enqueue_full_sync_actions( $config, $max_items_to_enqueue, $state ) {
		global $wpdb;

		return $this->enqueue_all_ids_as_action( 'jetpack_full_sync_users', $wpdb->usermeta, 'user_id', $this->get_where_sql( $config ), $max_items_to_enqueue, $state );
	}

	/**
	 * Retrieve an estimated number of actions that will be enqueued.
	 *
	 * @access public
	 *
	 * @todo Refactor to prepare the SQL query before executing it.
	 *
	 * @param array $config Full sync configuration for this sync module.
	 * @return array Number of items yet to be enqueued.
	 */
	public function estimate_full_sync_actions( $config ) {
		global $wpdb;

		$query = "SELECT count(*) FROM $wpdb->usermeta";

		$where_sql = $this->get_where_sql( $config );
		if ( $where_sql ) {
			$query .= ' WHERE ' . $where_sql;
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$count = $wpdb->get_var( $query );

		return (int) ceil( $count / self::ARRAY_CHUNK_SIZE );
	}

	/**
	 * Retrieve the WHERE SQL clause based on the module config.
	 *
	 * @access public
	 *
	 * @param array $config Full sync configuration for this sync module.
	 * @return string WHERE SQL clause, or `null` if no comments are specified in the module config.
	 */
	public function get_where_sql( $config ) {
		global $wpdb;

		$query = "meta_key = '{$wpdb->prefix}user_level' AND meta_value > 0";

		// The $config variable is a list of user IDs to sync.
		if ( is_array( $config ) ) {
			$query .= ' AND user_id IN (' . implode( ',', array_map( 'intval', $config ) ) . ')';
		}

		return $query;
	}

	/**
	 * Retrieve the actions that will be sent for this module during a full sync.
	 *
	 * @access public
	 *
	 * @return array Full sync actions of this module.
	 */
	public function get_full_sync_actions() {
		return array( 'jetpack_full_sync_users' );
	}

	/**
	 * Retrieve initial sync user config.
	 *
	 * @access public
	 *
	 * @todo Refactor the SQL query to call $wpdb->prepare() before execution.
	 *
	 * @return array|boolean IDs of users to initially sync, or false if tbe number of users exceed the maximum.
	 */
	public function get_initial_sync_user_config() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$user_ids = $wpdb->get_col( "SELECT user_id FROM $wpdb->usermeta WHERE meta_key = '{$wpdb->prefix}user_level' AND meta_value > 0 LIMIT " . ( self::MAX_INITIAL_SYNC_USERS + 1 ) );

		if ( count( $user_ids ) <= self::MAX_INITIAL_SYNC_USERS ) {
			return $user_ids;
		} else {
			return false;
		}
	}

	/**
	 * Expand the users within a hook before they are serialized and sent to the server.
	 *
	 * @access public
	 *
	 * @param array $args The hook arguments.
	 * @return array $args The hook arguments.
	 */
	public function expand_users( $args ) {
		list( $user_ids, $previous_end ) = $args;

		return array(
			'users'        => array_map(
				array( $this, 'sanitize_user_and_expand' ),
				get_users(
					array(
						'include' => $user_ids,
						'orderby' => 'ID',
						'order'   => 'DESC',
					)
				)
			),
			'previous_end' => $previous_end,
		);
	}

	/**
	 * Handler for user removal from a particular blog.
	 *
	 * @access public
	 *
	 * @param int $user_id ID of the user.
	 * @param int $blog_id ID of the blog.
	 */
	public function remove_user_from_blog_handler( $user_id, $blog_id ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		// User is removed on add, see https://github.com/WordPress/WordPress/blob/0401cee8b36df3def8e807dd766adc02b359dfaf/wp-includes/ms-functions.php#L2114.
		if ( $this->is_add_new_user_to_blog() ) {
			return;
		}

		$reassigned_user_id = $this->get_reassigned_network_user_id();

		// Note that we are in the context of the blog the user is removed from, see https://github.com/WordPress/WordPress/blob/473e1ba73bc5c18c72d7f288447503713d518790/wp-includes/ms-functions.php#L233.
		/**
		 * Fires when a user is removed from a blog on a multisite installation
		 *
		 * @since 1.6.3
		 * @since-jetpack 5.4.0
		 *
		 * @param int $user_id - ID of the removed user
		 * @param int $reassigned_user_id - ID of the user the removed user's posts are reassigned to (if any).
		 */
		do_action( 'jetpack_removed_user_from_blog', $user_id, $reassigned_user_id );
	}

	/**
	 * Whether we're adding a new user to a blog in this request.
	 *
	 * @access protected
	 *
	 * @return boolean
	 */
	protected function is_add_new_user_to_blog() {
		return $this->is_function_in_backtrace( 'add_new_user_to_blog' );
	}

	/**
	 * Whether we're adding an existing user to a blog in this request.
	 *
	 * @access protected
	 *
	 * @return boolean
	 */
	protected function is_add_user_to_blog() {
		return $this->is_function_in_backtrace( 'add_user_to_blog' );
	}

	/**
	 * Whether we're removing a user from a blog in this request.
	 *
	 * @access protected
	 *
	 * @return boolean
	 */
	protected function is_delete_user() {
		return $this->is_function_in_backtrace( array( 'wp_delete_user', 'remove_user_from_blog' ) );
	}

	/**
	 * Whether we're creating a user or adding a new user to a blog.
	 *
	 * @access protected
	 *
	 * @return boolean
	 */
	protected function is_create_user() {
		$functions = array(
			'add_new_user_to_blog', // Used to suppress jetpack_sync_save_user in save_user_cap_handler when user registered on multi site.
			'wp_create_user', // Used to suppress jetpack_sync_save_user in save_user_role_handler when user registered on multi site.
			'wp_insert_user', // Used to suppress jetpack_sync_save_user in save_user_cap_handler and save_user_role_handler when user registered on single site.
		);

		return $this->is_function_in_backtrace( $functions );
	}

	/**
	 * Retrieve the ID of the user the removed user's posts are reassigned to (if any).
	 *
	 * @return int ID of the user that got reassigned as the author of the posts.
	 */
	protected function get_reassigned_network_user_id() {
		$backtrace = debug_backtrace( false ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace
		foreach ( $backtrace as $call ) {
			if (
				'remove_user_from_blog' === $call['function'] &&
				3 === count( $call['args'] )
			) {
				return $call['args'][2];
			}
		}

		return false;
	}

	/**
	 * Checks if one or more function names is in debug_backtrace.
	 *
	 * @access protected
	 *
	 * @param array|string $names Mixed string name of function or array of string names of functions.
	 * @return bool
	 */
	protected function is_function_in_backtrace( $names ) {
		$backtrace = debug_backtrace( false ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace
		if ( ! is_array( $names ) ) {
			$names = array( $names );
		}
		$names_as_keys = array_flip( $names );

		// Do check in constant O(1) time for PHP5.5+.
		if ( function_exists( 'array_column' ) ) {
			$backtrace_functions         = array_column( $backtrace, 'function' ); // phpcs:ignore PHPCompatibility.FunctionUse.NewFunctions.array_columnFound
			$backtrace_functions_as_keys = array_flip( $backtrace_functions );
			$intersection                = array_intersect_key( $backtrace_functions_as_keys, $names_as_keys );
			return ! empty( $intersection );
		}

		// Do check in linear O(n) time for < PHP5.5 ( using isset at least prevents O(n^2) ).
		foreach ( $backtrace as $call ) {
			if ( isset( $names_as_keys[ $call['function'] ] ) ) {
				return true;
			}
		}
		return false;
	}
}
