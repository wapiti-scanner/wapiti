<?php
namespace W3TC;

class Cdn_Plugin_Admin {
	function run() {
		$config_labels = new Cdn_ConfigLabels();
		add_filter( 'w3tc_config_labels', array( $config_labels, 'config_labels' ) );

		$c = Dispatcher::config();
		$cdn_engine = $c->get_string( 'cdn.engine' );

		if ( $c->get_boolean( 'cdn.enabled' ) ) {
			$admin_notes = new Cdn_AdminNotes();
			add_filter( 'w3tc_notes', array( $admin_notes, 'w3tc_notes' ) );
			add_filter( 'w3tc_errors', array( $admin_notes, 'w3tc_errors' ) );

			if ( $c->get_boolean( 'cdn.admin.media_library' ) &&
				$c->get_boolean( 'cdn.uploads.enable' ) ) {

				add_filter( 'wp_get_attachment_url',
					array( $this, 'wp_get_attachment_url' ), 0 );

				add_filter( 'attachment_link',
					array( $this, 'wp_get_attachment_url' ), 0 );
			}
		}


		// attach to actions without firing class loading at all without need
		if ( $cdn_engine == 'google_drive' ) {
			add_action( 'w3tc_settings_cdn_boxarea_configuration', array(
					'\W3TC\Cdn_GoogleDrive_Page',
					'w3tc_settings_cdn_boxarea_configuration'
				) );
		} elseif ( $cdn_engine == 'highwinds' ) {
			add_action( 'w3tc_ajax', array(
					'\W3TC\Cdn_Highwinds_Popup',
					'w3tc_ajax' ) );
			add_action( 'admin_init_w3tc_dashboard', array(
					'\W3TC\Cdn_Highwinds_Widget',
					'admin_init_w3tc_dashboard' ) );
			add_action( 'w3tc_ajax_cdn_highwinds_widgetdata', array(
					'\W3TC\Cdn_Highwinds_Widget',
					'w3tc_ajax_cdn_highwinds_widgetdata' ) );
			add_action( 'w3tc_settings_cdn_boxarea_configuration', array(
					'\W3TC\Cdn_Highwinds_Page',
					'w3tc_settings_cdn_boxarea_configuration' ) );
		} elseif ( $cdn_engine == 'limelight' ) {
			add_action( 'w3tc_ajax', array(
					'\W3TC\Cdn_LimeLight_Popup',
					'w3tc_ajax' ) );
			add_action( 'w3tc_settings_cdn_boxarea_configuration', array(
					'\W3TC\Cdn_LimeLight_Page',
					'w3tc_settings_cdn_boxarea_configuration'
				) );
		} elseif ( $cdn_engine == 'rackspace_cdn' ) {
			add_filter( 'w3tc_admin_actions', array(
					'\W3TC\Cdn_RackSpaceCdn_Page',
					'w3tc_admin_actions' ) );
			add_action( 'w3tc_ajax', array(
					'\W3TC\Cdn_RackSpaceCdn_Popup',
					'w3tc_ajax' ) );
			add_action( 'w3tc_settings_cdn_boxarea_configuration', array(
					'\W3TC\Cdn_RackSpaceCdn_Page',
					'w3tc_settings_cdn_boxarea_configuration' ) );
		} elseif ( $cdn_engine == 'rscf' ) {
			add_action( 'w3tc_ajax', array(
					'\W3TC\Cdn_RackSpaceCloudFiles_Popup',
					'w3tc_ajax' ) );
			add_action( 'w3tc_settings_cdn_boxarea_configuration', array(
					'\W3TC\Cdn_RackSpaceCloudFiles_Page',
					'w3tc_settings_cdn_boxarea_configuration' ) );
		} elseif ( $cdn_engine == 'stackpath' ) {
			add_action( 'w3tc_ajax', array(
					'\W3TC\Cdn_StackPath_Popup',
					'w3tc_ajax' ) );
			add_action( 'w3tc_settings_cdn_boxarea_configuration', array(
					'\W3TC\Cdn_StackPath_Page',
					'w3tc_settings_cdn_boxarea_configuration'
				) );
			add_action( 'admin_init_w3tc_dashboard', array(
					'\W3TC\Cdn_StackPath_Widget',
					'admin_init_w3tc_dashboard' ) );
			add_action( 'w3tc_ajax_cdn_stackpath_widgetdata', array(
					'\W3TC\Cdn_StackPath_Widget',
					'w3tc_ajax_cdn_stackpath_widgetdata' ) );
		} elseif ( $cdn_engine == 'stackpath2' ) {
			add_action( 'w3tc_ajax', array(
					'\W3TC\Cdn_StackPath2_Popup',
					'w3tc_ajax' ) );
			add_action( 'w3tc_settings_cdn_boxarea_configuration', array(
					'\W3TC\Cdn_StackPath2_Page',
					'w3tc_settings_cdn_boxarea_configuration'
				) );
			add_action( 'admin_init_w3tc_dashboard', array(
					'\W3TC\Cdn_StackPath2_Widget',
					'admin_init_w3tc_dashboard' ) );
			add_action( 'w3tc_ajax_cdn_stackpath2_widgetdata', array(
					'\W3TC\Cdn_StackPath2_Widget',
					'w3tc_ajax_cdn_stackpath2_widgetdata' ) );
		} else {
			// default cdn widget
			add_action( 'admin_init_w3tc_dashboard', array(
					'\W3TC\Cdn_StackPath2_Widget',
					'admin_init_w3tc_dashboard' ) );
			add_action( 'w3tc_ajax_cdn_stackpath2_widgetdata', array(
					'\W3TC\Cdn_StackPath2_Widget',
					'w3tc_ajax_cdn_stackpath2_widgetdata' ) );
		}

		add_action( 'w3tc_settings_general_boxarea_cdn', array(
				$this,
				'w3tc_settings_general_boxarea_cdn'
			) );
	}



	public function w3tc_settings_general_boxarea_cdn() {
		$config = Dispatcher::config();

		$engine_optgroups = array();
		$engine_values = array();

		$optgroup_pull = count( $engine_optgroups );
		$engine_optgroups[] = __( 'Origin Pull / Mirror:', 'w3-total-cache' );

		$optgroup_push = count( $engine_optgroups );
		$engine_optgroups[] = __( 'Origin Push:', 'w3-total-cache' );


		$engine_values['akamai'] = array(
			'label' => __( 'Akamai', 'w3-total-cache' ),
			'optgroup' => $optgroup_pull
		);
		$engine_values['cf2'] = array(
			'label' => __( 'Amazon CloudFront', 'w3-total-cache' ),
			'disabled' => ( !Util_Installed::curl() ? true : null ),
			'optgroup' => $optgroup_pull
		);
		$engine_values['att'] = array(
			'label' => __( 'AT&amp;T', 'w3-total-cache' ),
			'optgroup' => $optgroup_pull
		);
		$engine_values['cotendo'] = array(
			'label' => __( 'Cotendo (Akamai)', 'w3-total-cache' ),
			'optgroup' => $optgroup_pull
		);
		$engine_values['mirror'] = array(
			'label' => __( 'Generic Mirror', 'w3-total-cache' ),
			'optgroup' => $optgroup_pull
		);
		$engine_values['highwinds'] = array(
			'label' => __( 'Highwinds', 'w3-total-cache' ),
			'optgroup' => $optgroup_pull
		);
		$engine_values['limelight'] = array(
			'label' => __( 'LimeLight', 'w3-total-cache' ),
			'optgroup' => $optgroup_pull
		);
		$engine_values['rackspace_cdn'] = array(
			'label' => __( 'RackSpace CDN', 'w3-total-cache' ),
			'optgroup' => $optgroup_pull
		);
		$engine_values['stackpath2'] = array(
			'label' => __( 'StackPath (recommended)', 'w3-total-cache' ),
			'optgroup' => $optgroup_pull
		);
		$engine_values['stackpath'] = array(
			'label' => __( 'StackPath SecureCDN (Legacy)', 'w3-total-cache' ),
			'optgroup' => $optgroup_pull
		);
		$engine_values['edgecast'] = array(
			'label' => __( 'Verizon Digital Media Services (EdgeCast) / Media Temple ProCDN', 'w3-total-cache' ),
			'optgroup' => $optgroup_pull
		);
		$engine_values['cf'] = array(
			'disabled' => ( !Util_Installed::curl() ? true : null ),
			'label' => __( 'Amazon CloudFront Over S3', 'w3-total-cache' ),
			'optgroup' => $optgroup_push
		);
		$engine_values['s3'] = array(
			'disabled' => ( !Util_Installed::curl() ? true : null ),
			'label' => __( 'Amazon Simple Storage Service (S3)', 'w3-total-cache' ),
			'optgroup' => $optgroup_push
		);
		$engine_values['s3_compatible'] = array(
			'disabled' => ( !Util_Installed::curl() ? true : null ),
			'label' => __( 'Amazon Simple Storage Service (S3) Compatible', 'w3-total-cache' ),
			'optgroup' => $optgroup_push
		);
		$engine_values['google_drive'] = array(
			'label' => __( 'Google Drive', 'w3-total-cache' ),
			'optgroup' => $optgroup_push
		);
		$engine_values['azure'] = array(
			'label' => __( 'Microsoft Azure Storage', 'w3-total-cache' ),
			'optgroup' => $optgroup_push
		);
		$engine_values['rscf'] = array(
			'disabled' => ( !Util_Installed::curl() ? true : null ),
			'label' => __( 'Rackspace Cloud Files', 'w3-total-cache' ),
			'optgroup' => $optgroup_push
		);
		$engine_values['ftp'] = array(
			'disabled' => ( !Util_Installed::ftp() ? true : null ),
			'label' => __( 'Self-hosted / File Transfer Protocol Upload', 'w3-total-cache' ),
			'optgroup' => $optgroup_push
		);

		$cdn_enabled = $config->get_boolean( 'cdn.enabled' );
		$cdn_engine = $config->get_string( 'cdn.engine' );

		include  W3TC_DIR . '/Cdn_GeneralPage_View.php';
	}



	/**
	 * Adjusts attachment urls to cdn. This is for those who rely on
	 * wp_get_attachment_url()
	 *
	 * @param 	string   $url	the local url to modify
	 * @return 	string
	 */
	function wp_get_attachment_url( $url ) {
		if ( defined( 'WP_ADMIN' ) ) {
			$url = trim( $url );

			if ( !empty( $url ) ) {
				$parsed = parse_url( $url );
				$uri = ( isset( $parsed['path'] ) ? $parsed['path'] : '/' ) .
						   ( isset( $parsed['query'] ) ? '?' . $parsed['query'] : '' );

				$wp_upload_dir = wp_upload_dir();
				$upload_base_url = $wp_upload_dir['baseurl'];

				if ( substr($url, 0, strlen( $upload_base_url ) ) == $upload_base_url ) {
					$common = Dispatcher::component( 'Cdn_Core' );
					$new_url = $common->url_to_cdn_url( $url, $uri );
					if ( !is_null( $new_url ) ) {
						$url = $new_url;
					}
				}
			}
		}

		return $url;
	}
}
