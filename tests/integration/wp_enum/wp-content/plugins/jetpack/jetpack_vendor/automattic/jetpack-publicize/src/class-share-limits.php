<?php
/**
 * Enforce sharing limits for Jetpack Social.
 *
 * @package automattic/jetpack-publicize
 */

namespace Automattic\Jetpack\Publicize;

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Redirect;

/**
 * Enforce sharing limits for Jetpack Social.
 */
class Share_Limits {
	/**
	 * List of all connections.
	 *
	 * @var array
	 */
	public $connections;

	/**
	 * Number of shares remaining.
	 *
	 * @var int
	 */
	public $shares_remaining;

	/**
	 * Whether we're loading the classic editor.
	 *
	 * @var bool
	 */
	public $is_classic_editor;

	/**
	 * Constructor.
	 *
	 * @param array $connections List of Publicize connections.
	 * @param int   $shares_remaining Number of shares remaining for this period.
	 * @param bool  $is_classic_editor Whether we're loading the classic editor.
	 */
	public function __construct( $connections, $shares_remaining, $is_classic_editor ) {
		$this->connections       = $connections;
		$this->shares_remaining  = $shares_remaining;
		$this->is_classic_editor = $is_classic_editor;
	}

	/**
	 * Run functionality required to enforce sharing limits.
	 */
	public function enforce_share_limits() {
		if ( ! $this->has_more_shares_than_connections() ) {
			/**
			 * If the number of connections is greater than the share limit, we set all
			 * connections to disabled by default. This allows the user to pick and
			 * choose which services they want to share to, without going over the limit.
			 */
			add_filter( 'publicize_checkbox_default', '__return_false' );
		}

		if ( ! $this->is_classic_editor ) {
			return;
		}

		add_action( 'publicize_classic_editor_form_after', array( $this, 'render_classic_editor_notice' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_classic_editor_scripts' ) );
	}

	/**
	 * Check if a site has more shares than connections.
	 *
	 * @return bool True if there's more shares than connections left, false otherwise.
	 */
	public function has_more_shares_than_connections() {
		return $this->shares_remaining >= count( $this->connections );
	}

	/**
	 * Get current URL.
	 *
	 * @return string Current URL.
	 */
	public function get_current_url() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$host = ! empty( $_SERVER['HTTP_HOST'] ) ? wp_unslash( $_SERVER['HTTP_HOST'] ) : wp_parse_url( home_url(), PHP_URL_HOST );
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$path = ! empty( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '/';
		return esc_url_raw( ( is_ssl() ? 'https' : 'http' ) . '://' . $host . $path );
	}

	/**
	 * Render a notice with the share count in the classic editor.
	 */
	public function render_classic_editor_notice() {
		$current_url = $this->get_current_url();
		$notice      = sprintf(
			/* translators: %1$d: number of shares remaining, %2$s: link to upgrade the plan. */
			_n(
				'You currently have %1$d share remaining. <a href="%2$s" target="_blank">Upgrade</a> to get more.',
				'You currently have %1$d shares remaining. <a href="%2$s" target="_blank">Upgrade</a> to get more.',
				$this->shares_remaining,
				'jetpack-publicize-pkg'
			),
			$this->shares_remaining,
			Redirect::get_url(
				'jetpack-social-basic-plan-classic-editor',
				array(
					'query' => 'redirect_to=' . rawurlencode( $current_url ),
				)
			)
		);
		$more_link = sprintf(
			/* translators: %s: link to find out more about the plan, and potentially upgrade. */
			__( '<a href="%s" target="_blank">More about Jetpack Social</a>', 'jetpack-publicize-pkg' ),
			Redirect::get_url(
				'jetpack-social-basic-plan-block-editor',
				array(
					'query' => 'redirect_to=' . rawurlencode( $current_url ),
				)
			)
		);

		$kses_allowed_tags = array(
			'a' => array(
				'href'   => array(),
				'target' => array(),
			),
		);

		echo '<p><em>' . wp_kses( $notice, $kses_allowed_tags ) . '<br />' . wp_kses( $more_link, $kses_allowed_tags ) . ' </em></p>';
	}

	/**
	 * Enqueue scripts for the Classic Editor on the post edit screen.
	 */
	public function enqueue_classic_editor_scripts() {
		if ( get_post_status() === 'publish' ) {
			return;
		}

		Assets::register_script(
			'jetpack-social-classic-editor-share-limits',
			'../build/classic-editor-share-limits.js',
			__FILE__,
			array(
				'in_footer'  => true,
				'textdomain' => 'jetpack-publicize-pkg',
			)
		);

		Assets::enqueue_script( 'jetpack-social-classic-editor-share-limits' );
		wp_add_inline_script( 'jetpack-social-classic-editor-share-limits', $this->render_initial_state(), 'before' );
	}

	/**
	 * Get the initial state for the Classic Editor.
	 *
	 * @return string
	 */
	public function render_initial_state() {
		$state = array(
			'sharesRemaining'     => $this->shares_remaining,
			'numberOfConnections' => count( $this->connections ),
		);

		return 'var jetpackSocialClassicEditorInitialState=JSON.parse(decodeURIComponent("' . rawurlencode( wp_json_encode( $state ) ) . '"));';
	}
}
