<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Set up Sharing functionality and management in wp-admin.
 *
 * @package automattic/jetpack
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Status;

if ( ! defined( 'WP_SHARING_PLUGIN_URL' ) ) {
	define( 'WP_SHARING_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
	define( 'WP_SHARING_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
}

/**
 * Utilities to manage sharing settings from wp-admin.
 */
class Sharing_Admin {

	/**
	 * Constructor.
	 * Hook into WordPress to add our functionality.
	 */
	public function __construct() {
		require_once WP_SHARING_PLUGIN_DIR . 'sharing-service.php';

		add_action( 'admin_init', array( $this, 'admin_init' ) );
		add_action( 'admin_menu', array( $this, 'subscription_menu' ) );

		// Insert our CSS and JS
		add_action( 'load-settings_page_sharing', array( $this, 'sharing_head' ) );

		// Catch AJAX
		add_action( 'wp_ajax_sharing_save_services', array( $this, 'ajax_save_services' ) );
		add_action( 'wp_ajax_sharing_save_options', array( $this, 'ajax_save_options' ) );
		add_action( 'wp_ajax_sharing_new_service', array( $this, 'ajax_new_service' ) );
		add_action( 'wp_ajax_sharing_delete_service', array( $this, 'ajax_delete_service' ) );
	}

	/**
	 * Enqueue scripts and styles on the sharing settings page.
	 *
	 * @return void
	 */
	public function sharing_head() {
		wp_enqueue_script(
			'sharing-js',
			Assets::get_file_url_for_environment(
				'_inc/build/sharedaddy/admin-sharing.min.js',
				'modules/sharedaddy/admin-sharing.js'
			),
			array( 'jquery', 'jquery-ui-draggable', 'jquery-ui-droppable', 'jquery-ui-sortable', 'jquery-form' ),
			2,
			false
		);

		/**
		 * Filters the switch that if set to true allows Jetpack to use minified assets. Defaults to true
		 * if the SCRIPT_DEBUG constant is not set or set to false. The filter overrides it.
		 *
		 * @since 6.2.0
		 *
		 * @param boolean $var should Jetpack use minified assets.
		 */
		$postfix = apply_filters( 'jetpack_should_use_minified_assets', true ) ? '.min' : '';
		if ( is_rtl() ) {
			wp_enqueue_style( 'sharing-admin', WP_SHARING_PLUGIN_URL . 'admin-sharing-rtl' . $postfix . '.css', false, JETPACK__VERSION );
		} else {
			wp_enqueue_style( 'sharing-admin', WP_SHARING_PLUGIN_URL . 'admin-sharing' . $postfix . '.css', false, JETPACK__VERSION );
		}
		wp_enqueue_style( 'sharing', WP_SHARING_PLUGIN_URL . 'sharing.css', false, JETPACK__VERSION );

		wp_enqueue_style( 'social-logos' );
		wp_enqueue_script( 'sharing-js-fe', WP_SHARING_PLUGIN_URL . 'sharing.js', array(), 4, false );
		add_thickbox();

		// On Jetpack sites, make sure we include CSS to style the admin page.
		if ( ! defined( 'IS_WPCOM' ) || ! IS_WPCOM ) {
			Jetpack_Admin_Page::load_wrapper_styles();
		}
	}

	/**
	 * Load the process that handles saving changes on the sharing settings page.
	 *
	 * @return void
	 */
	public function admin_init() {
		if ( isset( $_GET['page'] ) && ( $_GET['page'] === 'sharing.php' || $_GET['page'] === 'sharing' ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- nonces are handled in process_requests.
			$this->process_requests();
		}
	}

	/**
	 * Save changes to sharing settings.
	 *
	 * @return void
	 */
	public function process_requests() {
		if (
			isset( $_POST['_wpnonce'] )
			&& wp_verify_nonce( sanitize_key( wp_unslash( $_POST['_wpnonce'] ) ), 'sharing-options' )
		) {
			$sharer = new Sharing_Service();
			$sharer->set_global_options( $_POST );
			/**
			 * Fires when updating sharing settings.
			 *
			 * @module sharedaddy
			 *
			 * @since 1.1.0
			 */
			do_action( 'sharing_admin_update' );

			wp_safe_redirect( admin_url( 'options-general.php?page=sharing&update=saved' ) );
			die();
		}
	}

	/**
	 * Register Sharing settings menu page.
	 */
	public function subscription_menu() {
		if ( ! defined( 'IS_WPCOM' ) || ! IS_WPCOM ) {
			$active = Jetpack::get_active_modules();
			if (
				! in_array( 'publicize', $active, true )
				&& ! current_user_can( 'manage_options' )
			) {
				return;
			}
		}

		add_submenu_page(
			'options-general.php',
			__( 'Sharing Settings', 'jetpack' ),
			__( 'Sharing', 'jetpack' ),
			'publish_posts',
			'sharing',
			array( $this, 'wrapper_admin_page' )
		);
	}

	/**
	 * Save changes to sharing services via AJAX.
	 *
	 * @return void
	 */
	public function ajax_save_services() {
		if (
			isset( $_POST['_wpnonce'] )
			&& wp_verify_nonce( sanitize_key( wp_unslash( $_POST['_wpnonce'] ) ), 'sharing-options' )
			&& isset( $_POST['hidden'] )
			&& isset( $_POST['visible'] )
		) {
			$sharer = new Sharing_Service();

			$sharer->set_blog_services(
				explode( ',', sanitize_text_field( wp_unslash( $_POST['visible'] ) ) ),
				explode( ',', sanitize_text_field( wp_unslash( $_POST['hidden'] ) ) )
			);
			die();
		}
	}

	/**
	 * Create a new custom sharing service via AJAX.
	 *
	 * @return void
	 */
	public function ajax_new_service() {
		if (
			isset( $_POST['_wpnonce'] )
			&& isset( $_POST['sharing_name'] )
			&& isset( $_POST['sharing_url'] )
			&& isset( $_POST['sharing_icon'] )
			&& wp_verify_nonce( sanitize_key( wp_unslash( $_POST['_wpnonce'] ) ), 'sharing-new_service' )
		) {
			$sharer  = new Sharing_Service();
			$service = $sharer->new_service(
				sanitize_text_field( wp_unslash( $_POST['sharing_name'] ) ),
				esc_url_raw( wp_unslash( $_POST['sharing_url'] ) ),
				esc_url_raw( wp_unslash( $_POST['sharing_icon'] ) )
			);

			if ( $service ) {
				$this->output_service( $service->get_id(), $service );
				echo '<!--->';
				$service->button_style = 'icon-text';
				$this->output_preview( $service );

				die();
			}
		}

		// Fail
		die( '1' );
	}

	/**
	 * Delete a sharing service via AJAX.
	 *
	 * @return void
	 */
	public function ajax_delete_service() {
		if (
			isset( $_POST['_wpnonce'] )
			&& isset( $_POST['service'] )
			&& wp_verify_nonce(
				sanitize_key( wp_unslash( $_POST['_wpnonce'] ) ),
				'sharing-options_' . sanitize_text_field( wp_unslash( $_POST['service'] ) )
			)
		) {
			$sharer = new Sharing_Service();
			$sharer->delete_service( sanitize_text_field( wp_unslash( $_POST['service'] ) ) );
		}
	}

	/**
	 * Save changes to sharing settings via AJAX.
	 *
	 * @return void
	 */
	public function ajax_save_options() {
		if (
			isset( $_POST['_wpnonce'] )
			&& isset( $_POST['service'] )
			&& wp_verify_nonce(
				sanitize_key( wp_unslash( $_POST['_wpnonce'] ) ),
				'sharing-options_' . sanitize_text_field( wp_unslash( $_POST['service'] ) )
			)
		) {
			$sharer  = new Sharing_Service();
			$service = $sharer->get_service( sanitize_text_field( wp_unslash( $_POST['service'] ) ) );

			if ( $service && $service instanceof Sharing_Advanced_Source ) {
				$service->update_options( $_POST );

				$sharer->set_service( sanitize_text_field( wp_unslash( $_POST['service'] ) ), $service );
			}

			$this->output_service( $service->get_id(), $service, true );
			echo '<!--->';
			$service->button_style = 'icon-text';
			$this->output_preview( $service );
			die();
		}
	}

	/**
	 * Display a preview of a sharing service.
	 *
	 * @param object $service Sharing service object.
	 *
	 * @return void
	 */
	public function output_preview( $service ) {
		$klasses = array( 'advanced', 'preview-item' );

		if ( $service->button_style !== 'text' || $service->has_custom_button_style() ) {
			$klasses[] = 'preview-' . $service->get_class();
			$klasses[] = 'share-' . $service->get_class();
			if ( $service->is_deprecated() ) {
				$klasses[] = 'share-deprecated';
			}

			if ( $service->get_class() !== $service->get_id() ) {
				$klasses[] = 'preview-' . $service->get_id();
			}
		}

		echo '<li class="' . esc_attr( implode( ' ', $klasses ) ) . '">';
		$service->display_preview();
		echo '</li>';
	}

	/**
	 * Display a specific sharing service.
	 *
	 * @param int    $id            Service unique ID.
	 * @param object $service       Sharing service.
	 * @param bool   $show_dropdown Display a dropdown. Not in use at the moment.
	 *
	 * @return void
	 */
	public function output_service( $id, $service, $show_dropdown = false ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$title             = '';
		$klasses           = array( 'service', 'advanced', 'share-' . $service->get_class() );
		$displayed_klasses = implode( ' ', $klasses );

		if ( $service->is_deprecated() ) {
			/* translators: %1$s is the name of a deprecated Sharing Service like "Google+" */
			$title     = sprintf( __( 'The %1$s service has shut down. This sharing button is not displayed to your visitors and should be removed.', 'jetpack' ), $service->get_name() );
			$klasses[] = 'share-deprecated';
		}

		?>
	<li class="<?php echo esc_attr( $displayed_klasses ); ?>" id="<?php echo esc_attr( $service->get_id() ); ?>" tabindex="0" title="<?php echo esc_attr( $title ); ?>">
		<span class="options-left"><?php echo esc_html( $service->get_name() ); ?></span>
		<?php if ( 0 === strpos( $service->get_id(), 'custom-' ) || $service->has_advanced_options() ) : ?>
		<span class="close"><a href="#" class="remove">&times;</a></span>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>">
			<input type="hidden" name="action" value="sharing_delete_service" />
			<input type="hidden" name="service" value="<?php echo esc_attr( $id ); ?>" />
			<input type="hidden" name="_wpnonce" value="<?php echo esc_attr( wp_create_nonce( 'sharing-options_' . $id ) ); ?>" />
		</form>
		<?php endif; ?>
	</li>
		<?php
	}

	/**
	 * Display admin UI within a Jetpack header and footer.
	 *
	 * @return void
	 */
	public function wrapper_admin_page() {
		Jetpack_Admin_Page::wrap_ui( array( $this, 'management_page' ), array( 'is-wide' => true ) );
	}

	/**
	 * Sharing settings inner page structure.
	 *
	 * @return void
	 */
	public function management_page() {
		$sharer  = new Sharing_Service();
		$enabled = $sharer->get_blog_services();
		$global  = $sharer->get_global_options();

		$shows = array_values( get_post_types( array( 'public' => true ) ) );
		array_unshift( $shows, 'index' );

		if ( ! function_exists( 'mb_stripos' ) ) {
			echo '<div id="message" class="updated fade"><h3>' . esc_html__( 'Warning! Multibyte support missing!', 'jetpack' ) . '</h3>';
			echo '<p>' . wp_kses(
				sprintf(
					/* Translators: placeholder is a link to a PHP support document. */
					__( 'This plugin will work without it, but multibyte support is used <a href="%s" rel="noopener noreferrer" target="_blank">if available</a>. You may see minor problems with Tweets and other sharing services.', 'jetpack' ),
					'https://www.php.net/manual/en/mbstring.installation.php'
				),
				array(
					'a' => array(
						'href'   => array(),
						'rel'    => array(),
						'target' => array(),
					),
				)
			) . '</p></div>';
		}

		if ( isset( $_GET['update'] ) && 'saved' === $_GET['update'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- only used to display a message.
			echo '<div class="updated"><p>' . esc_html__( 'Settings have been saved', 'jetpack' ) . '</p></div>';
		}

		if ( ! isset( $global['sharing_label'] ) ) {
			$global['sharing_label'] = __( 'Share this:', 'jetpack' );
		}
		?>

	<div class="wrap">
		<div class="icon32" id="icon-options-general"><br /></div>
		<h1><?php esc_html_e( 'Sharing Settings', 'jetpack' ); ?></h1>

		<?php
		/**
		 * Fires at the top of the admin sharing settings screen.
		 *
		 * @module sharedaddy
		 *
		 * @since 1.6.0
		 */
		do_action( 'pre_admin_screen_sharing' );
		?>

		<?php if ( current_user_can( 'manage_options' ) ) : ?>

		<div class="share_manage_options">
		<h2><?php esc_html_e( 'Sharing Buttons', 'jetpack' ); ?></h2>
		<p><?php esc_html_e( 'Add sharing buttons to your blog and allow your visitors to share posts with their friends.', 'jetpack' ); ?></p>

		<div id="services-config">
			<table id="available-services">
					<tr>
					<td class="description">
						<h3><?php esc_html_e( 'Available Services', 'jetpack' ); ?></h3>
						<p><?php esc_html_e( "Drag and drop the services you'd like to enable into the box below.", 'jetpack' ); ?></p>
						<p><a href="#TB_inline?height=395&amp;width=600&amp;inlineId=new-service" class="thickbox" id="add-a-new-service"><?php esc_html_e( 'Add a new service', 'jetpack' ); ?></a></p>
					</td>
					<td class="services">
						<ul class="services-available" style="height: 100px;">
							<?php foreach ( $sharer->get_all_services_blog() as $id => $service ) : ?>
								<?php
								if ( ! isset( $enabled['all'][ $id ] ) ) {
										$this->output_service( $id, $service );
								}
								?>
							<?php endforeach; ?>
						</ul>
						<?php
						if ( ( new Status() )->is_private_site() ) {
							echo '<p><strong>' . esc_html__( 'Please note that your services have been restricted because your site is private.', 'jetpack' ) . '</strong></p>';
						}
						?>
						<br class="clearing" />
					</td>
					</tr>
			</table>

			<table id="enabled-services">
				<tr>
					<td class="description">
						<h3>
							<?php esc_html_e( 'Enabled Services', 'jetpack' ); ?>
							<img src="<?php echo esc_url( admin_url( 'images/loading.gif' ) ); ?>" width="16" height="16" alt="loading" style="vertical-align: middle; display: none" />
						</h3>
						<p><?php esc_html_e( 'Services dragged here will appear individually.', 'jetpack' ); ?></p>
					</td>
					<td class="services" id="share-drop-target">
							<h2 id="drag-instructions"
							<?php
							if ( count( $enabled['visible'] ) > 0 ) {
								echo ' style="display: none"';}
							?>
							><?php esc_html_e( 'Drag and drop available services here.', 'jetpack' ); ?></h2>

								<ul class="services-enabled">
									<?php foreach ( $enabled['visible'] as $id => $service ) : ?>
										<?php $this->output_service( $id, $service, true ); ?>
									<?php endforeach; ?>

									<li class="end-fix"></li>
								</ul>
					</td>
					<td id="hidden-drop-target" class="services">
							<p><?php esc_html_e( 'Services dragged here will be hidden behind a share button.', 'jetpack' ); ?></p>

							<ul class="services-hidden">
									<?php foreach ( $enabled['hidden'] as $id => $service ) : ?>
										<?php $this->output_service( $id, $service, true ); ?>
									<?php endforeach; ?>
									<li class="end-fix"></li>
							</ul>
					</td>
				</tr>
			</table>

			<table id="live-preview">
				<tr>
					<td class="description">
						<h3><?php esc_html_e( 'Live Preview', 'jetpack' ); ?></h3>
					</td>
					<td class="services">
						<h2 <?php echo ( count( $enabled['all'] ) > 0 ) ? ' style="display: none"' : ''; ?>><?php esc_html_e( 'Sharing is off. Add services above to enable.', 'jetpack' ); ?></h2>
						<div class="sharedaddy sd-sharing-enabled">
							<?php if ( count( $enabled['all'] ) > 0 ) : ?>
							<h3 class="sd-title"><?php echo esc_html( $global['sharing_label'] ); ?></h3>
							<?php endif; ?>
							<div class="sd-content">
								<ul class="preview">
									<?php foreach ( $enabled['visible'] as $id => $service ) : ?>
										<?php $this->output_preview( $service ); ?>
									<?php endforeach; ?>

									<?php if ( count( $enabled['hidden'] ) > 0 ) : ?>
									<li class="advanced"><a href="#" class="sharing-anchor sd-button share-more"><span><?php esc_html_e( 'More', 'jetpack' ); ?></span></a></li>
									<?php endif; ?>
								</ul>

								<?php if ( count( $enabled['hidden'] ) > 0 ) : ?>
								<div class="sharing-hidden">
									<div class="inner" style="display: none; <?php echo count( $enabled['hidden'] ) === 1 ? 'width:150px;' : ''; ?>">
										<?php if ( count( $enabled['hidden'] ) === 1 ) : ?>
											<ul style="background-image:none;">
										<?php else : ?>
											<ul>
										<?php endif; ?>

										<?php
										foreach ( $enabled['hidden'] as $id => $service ) {
											$this->output_preview( $service );
										}
										?>
										</ul>
									</div>
								</div>
								<?php endif; ?>

								<ul class="archive" style="display:none;">
								<?php
								foreach ( $sharer->get_all_services_blog() as $id => $service ) :
									if ( isset( $enabled['visible'][ $id ] ) ) {
										$service = $enabled['visible'][ $id ];
									} elseif ( isset( $enabled['hidden'][ $id ] ) ) {
										$service = $enabled['hidden'][ $id ];
									}

									$service->button_style = 'icon-text';   // The archive needs the full text, which is removed in JS later.
									$service->smart        = false;
									$this->output_preview( $service );
									endforeach;
								?>
									<li class="advanced"><a href="#" class="sharing-anchor sd-button share-more"><span><?php esc_html_e( 'More', 'jetpack' ); ?></span></a></li>
								</ul>
							</div>
						</div>
						<br class="clearing" />
					</td>
				</tr>
			</table>

				<form method="post" action="<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>" id="save-enabled-shares">
					<input type="hidden" name="action" value="sharing_save_services" />
					<input type="hidden" name="visible" value="<?php echo esc_attr( implode( ',', array_keys( $enabled['visible'] ) ) ); ?>" />
					<input type="hidden" name="hidden" value="<?php echo esc_attr( implode( ',', array_keys( $enabled['hidden'] ) ) ); ?>" />
					<input type="hidden" name="_wpnonce" value="<?php echo esc_attr( wp_create_nonce( 'sharing-options' ) ); ?>" />
				</form>
		</div>

		<form method="post" action="">
			<table class="form-table">
				<tbody>
					<tr valign="top">
						<th scope="row"><label><?php esc_html_e( 'Button style', 'jetpack' ); ?></label></th>
						<td>
							<select name="button_style" id="button_style">
								<option<?php echo ( $global['button_style'] === 'icon-text' ) ? ' selected="selected"' : ''; ?> value="icon-text"><?php esc_html_e( 'Icon + text', 'jetpack' ); ?></option>
								<option<?php echo ( $global['button_style'] === 'icon' ) ? ' selected="selected"' : ''; ?> value="icon"><?php esc_html_e( 'Icon only', 'jetpack' ); ?></option>
								<option<?php echo ( $global['button_style'] === 'text' ) ? ' selected="selected"' : ''; ?> value="text"><?php esc_html_e( 'Text only', 'jetpack' ); ?></option>
								<option<?php echo ( $global['button_style'] === 'official' ) ? ' selected="selected"' : ''; ?> value="official"><?php esc_html_e( 'Official buttons', 'jetpack' ); ?></option>
							</select>
						</td>
					</tr>
					<tr valign="top">
						<th scope="row"><label><?php esc_html_e( 'Sharing label', 'jetpack' ); ?></label></th>
						<td>
							<input type="text" name="sharing_label" value="<?php echo esc_attr( $global['sharing_label'] ); ?>" />
						</td>
					</tr>
					<?php
					/**
					 * Filters the HTML at the beginning of the "Show button on" row.
					 *
					 * @module sharedaddy
					 *
					 * @since 2.1.0
					 *
					 * @param string $var Opening HTML tag at the beginning of the "Show button on" row.
					 */
					echo apply_filters( 'sharing_show_buttons_on_row_start', '<tr valign="top">' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					?>
						<th scope="row"><label><?php esc_html_e( 'Show buttons on', 'jetpack' ); ?></label></th>
							<td>
								<?php
								$br = false;
								foreach ( $shows as $show ) :
									if ( 'index' === $show ) {
										$label = __( 'Front Page, Archive Pages, and Search Results', 'jetpack' );
									} else {
										$post_type_object = get_post_type_object( $show );
										$label            = $post_type_object->labels->name;
									}
									?>
									<?php
									if ( $br ) {
										echo '<br />';
									}
									?>
								<label><input type="checkbox"<?php checked( in_array( $show, $global['show'], true ) ); ?> name="show[]" value="<?php echo esc_attr( $show ); ?>" /> <?php echo esc_html( $label ); ?></label>
									<?php
									$br = true;
								endforeach;
								?>
							</td>
					<?php
					/**
					 * Filters the HTML at the end of the "Show button on" row.
					 *
					 * @module sharedaddy
					 *
					 * @since 2.1.0
					 *
					 * @param string $var Closing HTML tag at the end of the "Show button on" row.
					 */
					echo apply_filters( 'sharing_show_buttons_on_row_end', '</tr>' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					?>

					<?php
					/**
					 * Fires at the end of the sharing global options settings table.
					 *
					 * @module sharedaddy
					 *
					 * @since 1.1.0
					 */
					do_action( 'sharing_global_options' );
					?>
				</tbody>
			</table>

			<p class="submit">
					<input type="submit" name="submit" class="button-primary" value="<?php esc_attr_e( 'Save Changes', 'jetpack' ); ?>" />
			</p>

				<input type="hidden" name="_wpnonce" value="<?php echo esc_attr( wp_create_nonce( 'sharing-options' ) ); ?>" />
		</form>

	<div id="new-service" style="display: none">
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-ajax.php' ) ); ?>" id="new-service-form">
			<table class="form-table">
				<tbody>
					<tr valign="top">
						<th scope="row" width="100"><label><?php esc_html_e( 'Service name', 'jetpack' ); ?></label></th>
						<td>
							<input type="text" name="sharing_name" id="new_sharing_name" size="40" />
						</td>
					</tr>
					<tr valign="top">
						<th scope="row" width="100"><label><?php esc_html_e( 'Sharing URL', 'jetpack' ); ?></label></th>
						<td>
							<input type="text" name="sharing_url" id="new_sharing_url" size="40" />

							<p><?php esc_html_e( 'You can add the following variables to your service sharing URL:', 'jetpack' ); ?><br/>
							<code>%post_id%</code>, <code>%post_title%</code>, <code>%post_slug%</code>, <code>%post_url%</code>, <code>%post_full_url%</code>, <code>%post_excerpt%</code>, <code>%post_tags%</code>, <code>%home_url%</code></p>
						</td>
					</tr>
					<tr valign="top">
						<th scope="row" width="100"><label><?php esc_html_e( 'Icon URL', 'jetpack' ); ?></label></th>
						<td>
							<input type="text" name="sharing_icon" id="new_sharing_icon" size="40" />
							<p><?php esc_html_e( 'Enter the URL of a 16x16px icon you want to use for this service.', 'jetpack' ); ?></p>
						</td>
					</tr>
					<tr valign="top" width="100">
						<th scope="row"></th>
						<td>
							<input type="submit" class="button-primary" value="<?php esc_attr_e( 'Create Share Button', 'jetpack' ); ?>" />
							<img src="<?php echo esc_url( admin_url( 'images/loading.gif' ) ); ?>" width="16" height="16" alt="loading" style="vertical-align: middle; display: none" />
						</td>
					</tr>

					<?php
					/**
					 * Fires after the custom sharing service form
					 *
					 * @module sharedaddy
					 *
					 * @since 1.1.0
					 */
					do_action( 'sharing_new_service_form' );
					?>
				</tbody>
			</table>

			<?php
			/**
			 * Fires at the bottom of the admin sharing settings screen.
			 *
			 * @module sharedaddy
			 *
			 * @since 1.6.0
			 */
			do_action( 'post_admin_screen_sharing' );
			?>

				<div class="inerror" style="display: none; margin-top: 15px">
					<p><?php esc_html_e( 'An error occurred creating your new sharing service - please check you gave valid details.', 'jetpack' ); ?></p>
				</div>

			<input type="hidden" name="action" value="sharing_new_service" />
			<input type="hidden" name="_wpnonce" value="<?php echo esc_attr( wp_create_nonce( 'sharing-new_service' ) ); ?>" />
		</form>
	</div>
	</div>

	<?php endif; ?>


	</div>

	<script type="text/javascript">
		var sharing_loading_icon = '<?php echo esc_js( admin_url( '/images/loading.gif' ) ); ?>';
		<?php
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- we handle the nonce on the PHP side.
		if (
			isset( $_GET['create_new_service'], $_GET['name'], $_GET['url'], $_GET['icon'] )
			&& 'true' == $_GET['create_new_service'] // phpcs:ignore Universal.Operators.StrictComparisons.LooseEqual
		) :
			?>
		jQuery(document).ready(function() {
			// Prefill new service box and then open it
			jQuery( '#new_sharing_name' ).val( '<?php echo esc_js( sanitize_text_field( wp_unslash( $_GET['name'] ) ) ); ?>' );
			jQuery( '#new_sharing_url' ).val( '<?php echo esc_js( sanitize_text_field( wp_unslash( $_GET['url'] ) ) ); ?>' );
			jQuery( '#new_sharing_icon' ).val( '<?php echo esc_js( sanitize_text_field( wp_unslash( $_GET['icon'] ) ) ); ?>' );
			jQuery( '#add-a-new-service' ).click();
		});
		<?php endif; ?>
	</script>
		<?php
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
	}
}

/**
 * Callback to get the value for the jetpack_sharing_enabled field.
 *
 * When the sharing_disabled post_meta is unset, we follow the global setting in Sharing.
 * When it is set to 1, we disable sharing on the post, regardless of the global setting.
 * It is not possible to enable sharing on a post if it is disabled globally.
 *
 * @param array $post The post object.
 *
 * @return bool
 */
function jetpack_post_sharing_get_value( array $post ) {
	// if sharing IS disabled on this post, enabled=false, so negate the meta
	return (bool) ! get_post_meta( $post['id'], 'sharing_disabled', true );
}

/**
 * Callback to set sharing_disabled post_meta when the
 * jetpack_sharing_enabled field is updated.
 *
 * When the sharing_disabled post_meta is unset, we follow the global setting in Sharing.
 * When it is set to 1, we disable sharing on the post, regardless of the global setting.
 * It is not possible to enable sharing on a post if it is disabled globally.
 *
 * @param bool    $enable_sharing Should sharing be enabled on this post.
 * @param WP_Post $post_object    The post object.
 *
 * @return int|bool
 */
function jetpack_post_sharing_update_value( $enable_sharing, $post_object ) {
	if ( $enable_sharing ) {
		// delete the override if we want to enable sharing
		return delete_post_meta( $post_object->ID, 'sharing_disabled' );
	} else {
		return update_post_meta( $post_object->ID, 'sharing_disabled', true );
	}
}

/**
 * Add Sharing post_meta to the REST API Post response.
 *
 * @action rest_api_init
 * @uses register_rest_field
 * @link https://developer.wordpress.org/rest-api/extending-the-rest-api/modifying-responses/
 */
function jetpack_post_sharing_register_rest_field() {
	$post_types = get_post_types( array( 'public' => true ) );
	foreach ( $post_types as $post_type ) {
		register_rest_field(
			$post_type,
			'jetpack_sharing_enabled',
			array(
				'get_callback'    => 'jetpack_post_sharing_get_value',
				'update_callback' => 'jetpack_post_sharing_update_value',
				'schema'          => array(
					'description' => __( 'Are sharing buttons enabled?', 'jetpack' ),
					'type'        => 'boolean',
				),
			)
		);

		/**
		 * Ensures all public internal post-types support `sharing`
		 * This feature support flag is used by the REST API and Gutenberg.
		 */
		add_post_type_support( $post_type, 'jetpack-sharing-buttons' );
	}
}

// Add Sharing post_meta to the REST API Post response.
add_action( 'rest_api_init', 'jetpack_post_sharing_register_rest_field' );

// Some CPTs (e.g. Jetpack portfolios and testimonials) get registered with
// restapi_theme_init because they depend on theme support, so let's also hook to that
add_action( 'restapi_theme_init', 'jetpack_post_likes_register_rest_field', 20 );

/**
 * Initialize sharing settings in WP Admin.
 *
 * @return void
 */
function sharing_admin_init() {
	global $sharing_admin;

	$sharing_admin = new Sharing_Admin();
}

/**
 * Set the Likes and Sharing Gutenberg extension as available
 */
function jetpack_sharing_set_extension_availability() {
	Jetpack_Gutenberg::set_extension_available( 'sharing' );
}

add_action( 'jetpack_register_gutenberg_extensions', 'jetpack_sharing_set_extension_availability' );

add_action( 'init', 'sharing_admin_init' );
