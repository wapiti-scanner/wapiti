<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

use Automattic\Jetpack\Constants;

/**
 * User create endpoint class.
 */
class Jetpack_JSON_API_User_Create_Endpoint extends Jetpack_JSON_API_Endpoint {

	/**
	 * Needed capabilities.
	 *
	 * @var string
	 */
	protected $needed_capabilities = 'create_users';

	/**
	 * User data.
	 *
	 * @var array
	 */
	private $user_data;

	/**
	 * Endpoint callback.
	 *
	 * @return object|false
	 */
	public function result() {
		return $this->create_or_get_user();
	}

	/**
	 * Validate the input.
	 *
	 * @param object $object - the object.
	 *
	 * @return bool|WP_Error
	 */
	public function validate_input( $object ) {
		$this->user_data = $this->input();

		if ( empty( $this->user_data ) ) {
			return new WP_Error( 'input_error', __( 'user_data is required', 'jetpack' ) );
		}
		if ( ! isset( $this->user_data['email'] ) ) {
			return new WP_Error( 'input_error', __( 'user email is required', 'jetpack' ) );
		}
		if ( ! isset( $this->user_data['login'] ) ) {
			return new WP_Error( 'input_error', __( 'user login is required', 'jetpack' ) );
		}
		return parent::validate_input( $object );
	}

	/**
	 * Create or get the user.
	 *
	 * @return object|false
	 */
	public function create_or_get_user() {
		require_once JETPACK__PLUGIN_DIR . 'modules/sso/class.jetpack-sso-helpers.php';
		// Check for an existing user
		$user  = get_user_by( 'email', $this->user_data['email'] );
		$roles = (array) $this->user_data['roles'];
		$role  = array_pop( $roles );

		$query_args = $this->query_args();
		if ( isset( $query_args['invite_accepted'] ) && $query_args['invite_accepted'] ) {
			Constants::set_constant( 'JETPACK_INVITE_ACCEPTED', true );
		}

		if ( ! $user ) {
			// We modify the input here to mimick the same call structure of the update user endpoint.
			$this->user_data               = (object) $this->user_data;
			$this->user_data->role         = $role;
			$this->user_data->url          = isset( $this->user_data->URL ) ? $this->user_data->URL : '';
			$this->user_data->display_name = $this->user_data->name;
			$this->user_data->description  = '';
			$user                          = Jetpack_SSO_Helpers::generate_user( $this->user_data );
		}

		if ( is_multisite() ) {
			add_user_to_blog( get_current_blog_id(), $user->ID, $role );
		}

		if ( ! $user ) {

			return false;
		}

		return $this->get_user( $user->ID );
	}

	/**
	 * Get the user.
	 *
	 * @param int $user_id - the user ID.
	 *
	 * @return object|WP_Error
	 */
	public function get_user( $user_id ) {
		$the_user = $this->get_author( $user_id, true );
		if ( $the_user && ! is_wp_error( $the_user ) ) {
			$userdata        = get_userdata( $user_id );
			$the_user->roles = ! is_wp_error( $userdata ) ? $userdata->roles : array();
		}

		return $the_user;
	}

}
