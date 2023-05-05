<?php
/**
 * Adds a Jetpack Search debug panel to Debug Bar.
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Search as Jetpack_Search;

/**
 * Singleton class instantiated by Jetpack_Searc_Debug_Bar::instance() that handles
 * rendering the Jetpack Search debug bar menu item and panel.
 */
class Jetpack_Search_Debug_Bar extends Debug_Bar_Panel {
	/**
	 * Holds singleton instance
	 *
	 * @var Jetpack_Search_Debug_Bar
	 */
	protected static $instance = null;

	/**
	 * The title to use in the debug bar navigation
	 *
	 * @var string
	 */
	public $title;

	/**
	 * Constructor
	 */
	public function __construct() {
		$this->title( esc_html__( 'Jetpack Search', 'jetpack' ) );
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
		add_action( 'enqueue_embed_scripts', array( $this, 'enqueue_scripts' ) );
	}

	/**
	 * Returns the singleton instance of Jetpack_Search_Debug_Bar
	 *
	 * @return Jetpack_Search_Debug_Bar
	 */
	public static function instance() {
		if ( self::$instance === null ) {
			self::$instance = new Jetpack_Search_Debug_Bar();
		}
		return self::$instance;
	}

	/**
	 * Enqueues styles for our panel in the debug bar
	 *
	 * @return void
	 */
	public function enqueue_scripts() {
		// Do not enqueue scripts if we haven't already enqueued Debug Bar or Query Monitor styles.
		if ( ! wp_style_is( 'debug-bar' ) && ! wp_style_is( 'query-monitor' ) ) {
			return;
		}

		wp_enqueue_style(
			'jetpack-search-debug-bar',
			plugins_url( '3rd-party/debug-bar/debug-bar.css', JETPACK__PLUGIN_FILE ),
			array(),
			JETPACK__VERSION
		);
		wp_enqueue_script(
			'jetpack-search-debug-bar',
			plugins_url( '3rd-party/debug-bar/debug-bar.js', JETPACK__PLUGIN_FILE ),
			array( 'jquery' ),
			JETPACK__VERSION,
			true
		);
	}

	/**
	 * Should the Jetpack Search Debug Bar show?
	 *
	 * Since we've previously done a check for the search module being activated, let's just return true.
	 * Later on, we can update this to only show when `is_search()` is true.
	 *
	 * @return boolean
	 */
	public function is_visible() {
		return true;
	}

	/**
	 * Renders the panel content
	 *
	 * @return void
	 */
	public function render() {
		$jetpack_search = (
			Jetpack_Search\Options::is_instant_enabled() ?
			Jetpack_Search\Instant_Search::instance() :
			Jetpack_Search\Classic_Search::instance()
		);

		// Search hasn't been initialized. Exit early and do not display the debug bar.
		if ( ! method_exists( $jetpack_search, 'get_last_query_info' ) ) {
			return;
		}

		$last_query_info = $jetpack_search->get_last_query_info();

		// If not empty, let's reshuffle the order of some things.
		if ( ! empty( $last_query_info ) ) {
			$args          = $last_query_info['args'];
			$response      = $last_query_info['response'];
			$response_code = $last_query_info['response_code'];

			unset( $last_query_info['args'] );
			unset( $last_query_info['response'] );
			unset( $last_query_info['response_code'] );

			if ( $last_query_info['es_time'] === null ) {
				$last_query_info['es_time'] = esc_html_x(
					'cache hit',
					'displayed in search results when results are cached',
					'jetpack'
				);
			}

			$temp = array_merge(
				array( 'response_code' => $response_code ),
				array( 'args' => $args ),
				$last_query_info,
				array( 'response' => $response )
			);

			$last_query_info = $temp;
		}
		?>
		<div class="jetpack-search-debug-bar">
			<h2><?php esc_html_e( 'Last query information:', 'jetpack' ); ?></h2>
			<?php if ( empty( $last_query_info ) ) : ?>
					<?php echo esc_html_x( 'None', 'Text displayed when there is no information', 'jetpack' ); ?>
				<?php
				else :
					foreach ( $last_query_info as $key => $info ) :
						?>
						<h3><?php echo esc_html( $key ); ?></h3>
						<?php
						if ( 'response' !== $key && 'args' !== $key ) :
							?>
						<pre><?php print_r( esc_html( $info ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions ?></pre>
							<?php
					else :
						$this->render_json_toggle( $info );
					endif;
					?>
						<?php
					endforeach;
			endif;
				?>
		</div><!-- Closes .jetpack-search-debug-bar -->
		<?php
	}

	/**
	 * Responsible for rendering the HTML necessary for the JSON toggle
	 *
	 * @param array $value The resonse from the API as an array.
	 * @return void
	 */
	public function render_json_toggle( $value ) {
		?>
		<div class="json-toggle-wrap">
			<pre class="json">
			<?php
				// esc_html() will not double-encode entities (&amp; -> &amp;amp;).
				// If any entities are part of the JSON blob, we want to re-encoode them
				// (double-encode them) so that they are displayed correctly in the debug
				// bar.
				// Use _wp_specialchars() "manually" to ensure entities are encoded correctly.
				echo _wp_specialchars( // phpcs:ignore WordPress.Security.EscapeOutput
					wp_json_encode( $value ),
					ENT_NOQUOTES, // Don't need to encode quotes (output is for a text node).
					'UTF-8',         // wp_json_encode() outputs UTF-8 (really just ASCII), not the blog's charset.
					true       // Do "double-encode" existing HTML entities.
				);
			?>
			</pre>
			<span class="pretty toggle"><?php echo esc_html_x( 'Pretty', 'label for formatting JSON', 'jetpack' ); ?></span>
			<span class="ugly toggle"><?php echo esc_html_x( 'Minify', 'label for formatting JSON', 'jetpack' ); ?></span>
		</div>
		<?php
	}
}
