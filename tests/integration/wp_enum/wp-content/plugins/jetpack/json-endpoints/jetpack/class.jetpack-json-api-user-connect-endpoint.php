<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

use Automattic\Jetpack\Connection\Manager as Connection_Manager;
use Automattic\Jetpack\Connection\Tokens;

/**
 * User connect endpoint class.
 */
class Jetpack_JSON_API_User_Connect_Endpoint extends Jetpack_JSON_API_Endpoint {

	/**
	 * Needed capabilities.
	 *
	 * @var string
	 */
	protected $needed_capabilities = 'create_users';

	/**
	 * The user ID.
	 *
	 * @var int
	 */
	private $user_id;

	/**
	 * The user token.
	 *
	 * @var string
	 */
	private $user_token;

	/**
	 * The endpoint callback.
	 *
	 * @return array
	 */
	public function result() {
		( new Tokens() )->update_user_token( $this->user_id, sprintf( '%s.%d', $this->user_token, $this->user_id ), false );
		return array( 'success' => ( new Connection_Manager( 'jetpack' ) )->is_user_connected( $this->user_id ) );
	}

	/**
	 * Validate input.
	 *
	 * @param int $user_id - the User ID.
	 *
	 * @return bool|WP_Error
	 */
	public function validate_input( $user_id ) {
		$input = $this->input();
		if ( ! isset( $user_id ) ) {
			return new WP_Error( 'input_error', __( 'user_id is required', 'jetpack' ) );
		}
		$this->user_id = $user_id;
		if ( ( new Connection_Manager( 'jetpack' ) )->is_user_connected( $this->user_id ) ) {
			return new WP_Error( 'user_already_connected', __( 'The user is already connected', 'jetpack' ) );
		}
		if ( ! isset( $input['user_token'] ) ) {
			return new WP_Error( 'input_error', __( 'user_token is required', 'jetpack' ) );
		}
		$this->user_token = sanitize_text_field( $input['user_token'] );
		return parent::validate_input( $user_id );
	}
}
