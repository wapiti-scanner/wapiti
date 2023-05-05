<?php
/**
 * Adds the Jetpack stats widget to the WordPress admin dashboard.
 *
 * @package jetpack
 */

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Assets\Logo as Jetpack_Logo;
use Automattic\Jetpack\Redirect;
use Automattic\Jetpack\Stats\Options as Stats_Options;
use Automattic\Jetpack\Stats_Admin\WP_Dashboard_Odyssey_Widget as Dashboard_Stats_Widget;
use Automattic\Jetpack\Status;

/**
 * Class that adds the Jetpack stats widget to the WordPress admin dashboard.
 *
 * Note that this widget renders whether or not the stats module is active because it currently
 * displays information about Akismet and Protect.
 */
class Jetpack_Stats_Dashboard_Widget {

	/**
	 * Indicates whether the class initialized or not.
	 *
	 * @var bool
	 */
	private static $initialized = false;

	/**
	 * Initialize the class by calling the setup static function.
	 *
	 * @return void
	 */
	public static function init() {
		if ( ! self::$initialized ) {
			self::$initialized = true;
			self::wp_dashboard_setup();
		}
	}

	/**
	 * Sets up the Jetpack Stats widget in the WordPress admin dashboard.
	 */
	public static function wp_dashboard_setup() {

		/**
		 * Filter whether the Jetpack Stats dashboard widget should be shown to the current user.
		 * By default, the dashboard widget is shown to users who can view_stats.
		 *
		 * @module stats
		 * @since 11.9
		 *
		 * @param bool Whether to show the widget to the current user.
		 */
		if ( ! apply_filters( 'jetpack_stats_dashboard_widget_show_to_user', current_user_can( 'view_stats' ) ) ) {
			return;
		}

		if ( Jetpack::is_connection_ready() ) {
			add_action( 'admin_head', array( static::class, 'admin_head' ) );

			$widget_title = sprintf(
				__( 'Jetpack Stats', 'jetpack' )
			);

			if ( Stats_Options::get_option( 'enable_odyssey_stats' ) ) {
				// New widget implemented in Odyssey Stats.
				$stats_widget = new Dashboard_Stats_Widget();
				wp_add_dashboard_widget(
					'jetpack_summary_widget',
					$widget_title,
					array( $stats_widget, 'render' )
				);
				$stats_widget->load_admin_scripts();
			} else {
				// Legacy widget.
				wp_add_dashboard_widget(
					'jetpack_summary_widget',
					$widget_title,
					array( __CLASS__, 'render_widget' )
				);
				wp_enqueue_style(
					'jetpack-dashboard-widget',
					Assets::get_file_url_for_environment(
						'css/dashboard-widget.min.css',
						'css/dashboard-widget.css'
					),
					array(),
					JETPACK__VERSION
				);
				wp_style_add_data( 'jetpack-dashboard-widget', 'rtl', 'replace' );
			}
		}
	}

	/**
	 * JavaScript and CSS for dashboard widget.
	 *
	 * @access public
	 * @return void
	 */
	public static function admin_head() {
		?>
			<script type="text/javascript">
				/* <![CDATA[ */
				jQuery( function($) {
					var dashStats = jQuery( '#dashboard_stats div.inside' );

					if ( dashStats.find( '.dashboard-widget-control-form' ).length ) {
						return;
					}

					if ( ! dashStats.length ) {
						dashStats = jQuery( '#dashboard_stats div.dashboard-widget-content' );
						var h = parseInt( dashStats.parent().height() ) - parseInt( dashStats.prev().height() );
						var args = 'width=' + dashStats.width() + '&height=' + h.toString();
					} else {
						if ( jQuery('#dashboard_stats' ).hasClass('postbox') ) {
							var args = 'width=' + ( dashStats.prev().width() * 2 ).toString();
						} else {
							var args = 'width=' + ( dashStats.width() * 2 ).toString();
						}
					}

					dashStats
						.not( '.dashboard-widget-control' )
						.load( 'admin.php?page=stats&noheader&dashboard&' + args, function() {
							jQuery( '#dashboard_stats' ).removeClass( 'is-loading' );
							jQuery( '#stat-chart' ).css( 'width', 'auto' );
						} );

					// Widget settings toggle container.
					var toggle = $( '.js-toggle-stats_dashboard_widget_control' );

					// Move the toggle in the widget header.
					toggle.appendTo( '#jetpack_summary_widget .handle-actions' );

					// Toggle settings when clicking on it.
					toggle.show().click( function( e ) {
						e.preventDefault();
						e.stopImmediatePropagation();
						$( this ).parent().toggleClass( 'controlVisible' );
						$( '#stats_dashboard_widget_control' ).slideToggle();
					} );
				} );
				/* ]]> */
			</script>
		<?php
	}

	/**
	 * Renders the widget and fires a dashboard widget action.
	 */
	public static function render_widget() {
		// This function won't exist if the stats module is disabled.
		if ( function_exists( 'stats_jetpack_dashboard_widget' ) ) {
			stats_jetpack_dashboard_widget();
		}

		/**
		 * Fires when the dashboard is loaded, but no longer used anywhere in the Jetpack plugin.
		 * The action is still available for backward compatibility.
		 *
		 * @since 3.4.0
		 */
		do_action( 'jetpack_dashboard_widget' );

		self::render_footer();
	}

	/**
	 * Load the widget footer showing brute force protection and Akismet stats.
	 */
	public static function render_footer() {
		?>
		<footer>
		<div class="blocked-container">
			<div class="protect">
				<h3><?php esc_html_e( 'Brute force attack protection', 'jetpack' ); ?></h3>
				<?php if ( Jetpack::is_module_active( 'protect' ) ) : ?>
					<p class="blocked-count">
						<?php echo esc_html( number_format_i18n( get_site_option( 'jetpack_protect_blocked_attempts', 0 ) ) ); ?>
					</p>
					<p><?php echo esc_html_x( 'Blocked malicious login attempts', '{#} Blocked malicious login attempts -- number is on a prior line, text is a caption.', 'jetpack' ); ?></p>
				<?php elseif ( current_user_can( 'jetpack_activate_modules' ) && ! ( new Status() )->is_offline_mode() ) : ?>
					<a href="
					<?php
					echo esc_url(
						wp_nonce_url(
							Jetpack::admin_url(
								array(
									'action' => 'activate',
									'module' => 'protect',
								)
							),
							'jetpack_activate-protect'
						)
					);
					?>
								" class="button button-primary" title="<?php esc_attr_e( 'Jetpack helps to keep you secure from brute-force login attacks.', 'jetpack' ); ?>">
						<?php esc_html_e( 'Activate', 'jetpack' ); ?>
					</a>
				<?php else : ?>
					<?php esc_html_e( 'Brute force attack protection is inactive.', 'jetpack' ); ?>
				<?php endif; ?>
			</div>

			<div class="akismet">
				<h3><?php esc_html_e( 'Akismet Anti-spam', 'jetpack' ); ?></h3>
				<?php if ( is_plugin_active( 'akismet/akismet.php' ) ) : ?>
					<p class="blocked-count">
						<?php echo esc_html( number_format_i18n( get_option( 'akismet_spam_count', 0 ) ) ); ?>
					</p>
					<p><?php echo esc_html_x( 'Blocked spam comments', '{#} Spam comments blocked by Akismet -- number is on a prior line, text is a caption.', 'jetpack' ); ?></p>
				<?php elseif ( current_user_can( 'activate_plugins' ) && ! is_wp_error( validate_plugin( 'akismet/akismet.php' ) ) ) : ?>
					<a href="
					<?php
					echo esc_url(
						wp_nonce_url(
							add_query_arg(
								array(
									'action' => 'activate',
									'plugin' => 'akismet/akismet.php',
								),
								admin_url( 'plugins.php' )
							),
							'activate-plugin_akismet/akismet.php'
						)
					);
					?>
								" class="button button-primary">
						<?php esc_html_e( 'Activate', 'jetpack' ); ?>
					</a>
				<?php else : ?>
					<p><a href="<?php echo esc_url( 'https://akismet.com/?utm_source=jetpack&utm_medium=link&utm_campaign=Jetpack%20Dashboard%20Widget%20Footer%20Link' ); ?>"><?php esc_html_e( 'Anti-spam can help to keep your blog safe from spam!', 'jetpack' ); ?></a></p>
				<?php endif; ?>
			</div>
		</div>
		<div class="footer-links">
			<a href="<?php echo esc_url( Redirect::get_url( 'jetpack-support-wordpress-com-stats' ) ); ?>" target="_blank">
				<?php
					$jetpack_logo = new Jetpack_Logo();
					echo $jetpack_logo->get_jp_emblem( true );// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				?>
			</a>
		</div>
		</footer>

		<?php
	}
}
