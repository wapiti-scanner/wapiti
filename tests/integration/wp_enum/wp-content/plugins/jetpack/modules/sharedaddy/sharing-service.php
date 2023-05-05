<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Utilities to register and interact with a sharing service.
 *
 * Sharing_Service gets info about a service.
 * Sharing_Service_Total and Sharing_Post_Total get stats data.
 *
 * @package automattic/jetpack
 *
 * phpcs:disable Generic.Files.OneObjectStructurePerFile.MultipleFound
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

use Automattic\Jetpack\Assets;
use Automattic\Jetpack\Redirect;
use Automattic\Jetpack\Status;
use Automattic\Jetpack\Sync\Settings;

require_once __DIR__ . '/sharing-sources.php';

define( 'WP_SHARING_PLUGIN_VERSION', JETPACK__VERSION );

/**
 * Interact with a sharing service.
 */
class Sharing_Service {
	/**
	 * Should the service be available globally?
	 *
	 * @var bool
	 */
	private $global = false;

	/**
	 * Default sharing label.
	 *
	 * @var string
	 */
	public $default_sharing_label = '';

	/**
	 * Initialize the sharing service.
	 * Only run this method once upon module loading.
	 *
	 * @return void
	 */
	public static function init() {
		add_filter( 'the_content', 'sharing_display', 19 );
		add_filter( 'the_excerpt', 'sharing_display', 19 );
	}

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->default_sharing_label = __( 'Share this:', 'jetpack' );
	}

	/**
	 * Gets a generic list of all services, without any config
	 *
	 * @return array
	 */
	public function get_all_services_blog() {
		$options  = get_option( 'sharing-options' );
		$all      = $this->get_all_services();
		$services = array();

		foreach ( $all as $id => $name ) {
			if ( isset( $all[ $id ] ) ) {
				$config = array();

				// Pre-load custom modules otherwise they won't know who they are
				if ( substr( $id, 0, 7 ) === 'custom-' && is_array( $options[ $id ] ) ) {
					$config = $options[ $id ];
				}

				$services[ $id ] = new $all[ $id ]( $id, $config );
			}
		}

		return $services;
	}

	/**
	 * Gets a list of all available service names and classes
	 *
	 * @param bool $include_custom Include custom sharing services.
	 *
	 * @return array
	 */
	public function get_all_services( $include_custom = true ) {
		// Default services
		// if you update this list, please update the REST API tests
		// in bin/tests/api/suites/SharingTest.php
		$services = array(
			'print'            => 'Share_Print',
			'email'            => 'Share_Email',
			'facebook'         => 'Share_Facebook',
			'linkedin'         => 'Share_LinkedIn',
			'reddit'           => 'Share_Reddit',
			'twitter'          => 'Share_Twitter',
			'tumblr'           => 'Share_Tumblr',
			'pinterest'        => 'Share_Pinterest',
			'pocket'           => 'Share_Pocket',
			'telegram'         => 'Share_Telegram',
			'jetpack-whatsapp' => 'Jetpack_Share_WhatsApp',
			'skype'            => 'Share_Skype',
			'mastodon'         => 'Share_Mastodon',
		);

		if ( is_multisite() && is_plugin_active( 'press-this/press-this-plugin.php' ) ) {
			$services['press-this'] = 'Share_PressThis';
		}

		if ( $include_custom ) {
			// Add any custom services in
			$options = $this->get_global_options();
			foreach ( (array) $options['custom'] as $custom_id ) {
				$services[ $custom_id ] = 'Share_Custom';
			}
		}

		/**
		 * Filters the list of available Sharing Services.
		 *
		 * @module sharedaddy
		 *
		 * @since 1.1.0
		 *
		 * @param array $services Array of all available Sharing Services.
		 */
		return apply_filters( 'sharing_services', $services );
	}

	/**
	 * Save a new custom sharing service.
	 *
	 * @param string $label Service name.
	 * @param string $url   Service sharing URL.
	 * @param string $icon  Service icon.
	 *
	 * @return bool|Share_Custom
	 */
	public function new_service( $label, $url, $icon ) {
		// Validate.
		$label = trim( wp_html_excerpt( wp_kses( $label, array() ), 30 ) );
		$url   = trim( esc_url_raw( $url ) );
		$icon  = trim( esc_url_raw( $icon ) );

		if ( $label && $url && $icon ) {
			$options = get_option( 'sharing-options' );
			if ( ! is_array( $options ) ) {
				$options = array();
			}

			$service_id = 'custom-' . time();

			// Add a new custom service
			$options['global']['custom'][] = $service_id;
			if ( false !== $this->global ) {
				$this->global['custom'][] = $service_id;
			}

			update_option( 'sharing-options', $options );

			// Create a custom service and set the options for it
			$service = new Share_Custom(
				$service_id,
				array(
					'name' => $label,
					'url'  => $url,
					'icon' => $icon,
				)
			);
			$this->set_service( $service_id, $service );

			// Return the service
			return $service;
		}

		return false;
	}

	/**
	 * Delete a sharing service.
	 *
	 * @param string $service_id Service ID.
	 *
	 * @return bool
	 */
	public function delete_service( $service_id ) {
		$options = get_option( 'sharing-options' );
		if ( isset( $options[ $service_id ] ) ) {
			unset( $options[ $service_id ] );
		}

		$key = array_search( $service_id, $options['global']['custom'], true );
		if ( $key !== false ) {
			unset( $options['global']['custom'][ $key ] );
		}

		update_option( 'sharing-options', $options );
		return true;
	}

	/**
	 * Save enabled sharing services.
	 *
	 * @param array $visible Visible sharing services.
	 * @param array $hidden  Hidden sharing services (available under a dropdown).
	 *
	 * @return bool
	 */
	public function set_blog_services( array $visible, array $hidden ) {
		$services = $this->get_all_services();
		// Validate the services
		$available = array_keys( $services );

		// Only allow services that we have defined
		$hidden  = array_intersect( $hidden, $available );
		$visible = array_intersect( $visible, $available );

		// Ensure we don't have the same ones in hidden and visible
		$hidden = array_diff( $hidden, $visible );

		/**
		 * Control the state of the list of sharing services.
		 *
		 * @module sharedaddy
		 *
		 * @since 1.1.0
		 *
		 * @param array $args {
		 *  Array of options describing the state of the sharing services.
		 *
		 *  @type array $services List of all available service names and classes.
		 *  @type array $available Validated list of all available service names and classes.
		 *  @type array $hidden List of services hidden behind a "More" button.
		 *  @type array $visible List of visible services.
		 *  @type array $this->get_blog_services() Array of Sharing Services currently enabled.
		 * }
		 */
		do_action(
			'sharing_get_services_state',
			array(
				'services'          => $services,
				'available'         => $available,
				'hidden'            => $hidden,
				'visible'           => $visible,
				'currently_enabled' => $this->get_blog_services(),
			)
		);

		return update_option(
			'sharing-services',
			array(
				'visible' => $visible,
				'hidden'  => $hidden,
			)
		);
	}

	/**
	 * Get information about enabled sharing services on the site.
	 *
	 * @return array
	 */
	public function get_blog_services() {
		$options  = get_option( 'sharing-options' );
		$enabled  = get_option( 'sharing-services' );
		$services = $this->get_all_services();

		/**
		 * Check if options exist and are well formatted.
		 * This avoids issues on sites with corrupted options.
		 *
		 * @see https://github.com/Automattic/jetpack/issues/6121
		 */
		if ( ! is_array( $options ) || ! isset( $options['button_style'], $options['global'] ) ) {
			$global_options = array( 'global' => $this->get_global_options() );
			$options        = is_array( $options )
				? array_merge( $options, $global_options )
				: $global_options;
		}

		$global = $options['global'];

		// Default services
		if ( ! is_array( $enabled ) ) {
			$enabled = array(
				'visible' => array(
					'twitter',
					'facebook',
				),
				'hidden'  => array(),
			);

			/**
			 * Filters the list of default Sharing Services.
			 *
			 * @module sharedaddy
			 *
			 * @since 1.1.0
			 *
			 * @param array $enabled Array of default Sharing Services.
			 */
			$enabled = apply_filters( 'sharing_default_services', $enabled );
		}

		// Cleanup after any filters that may have produced duplicate services
		if ( is_array( $enabled['visible'] ) ) {
			$enabled['visible'] = array_unique( $enabled['visible'] );
		} else {
			$enabled['visible'] = array();
		}

		if ( is_array( $enabled['hidden'] ) ) {
			$enabled['hidden'] = array_unique( $enabled['hidden'] );
		} else {
			$enabled['hidden'] = array();
		}

		// Form the enabled services
		$blog = array(
			'visible' => array(),
			'hidden'  => array(),
		);

		foreach ( $blog as $area => $stuff ) {
			foreach ( (array) $enabled[ $area ] as $service ) {
				if ( isset( $services[ $service ] ) ) {
					if ( ! isset( $options[ $service ] ) || ! is_array( $options[ $service ] ) ) {
						$options[ $service ] = array();
					}
					$blog[ $area ][ $service ] = new $services[ $service ]( $service, array_merge( $global, $options[ $service ] ) );
				}
			}
		}

		/**
		 * Filters the list of enabled Sharing Services.
		 *
		 * @module sharedaddy
		 *
		 * @since 1.1.0
		 *
		 * @param array $blog Array of enabled Sharing Services.
		 */
		$blog = apply_filters( 'sharing_services_enabled', $blog );

		// Add CSS for NASCAR
		if ( count( $blog['visible'] ) || count( $blog['hidden'] ) ) {
			add_filter( 'post_flair_block_css', 'post_flair_service_enabled_sharing' );
		}

		// Convenience for checking if a service is present
		$blog['all'] = array_flip( array_merge( array_keys( $blog['visible'] ), array_keys( $blog['hidden'] ) ) );
		return $blog;
	}

	/**
	 * Get information about a specific enabled sharing service.
	 *
	 * @param string $service_name Service name.
	 *
	 * @return bool|Sharing_Source
	 */
	public function get_service( $service_name ) {
		$services = $this->get_blog_services();

		if ( isset( $services['visible'][ $service_name ] ) ) {
			return $services['visible'][ $service_name ];
		}

		if ( isset( $services['hidden'][ $service_name ] ) ) {
			return $services['hidden'][ $service_name ];
		}

		return false;
	}

	/**
	 * Update global sharing options.
	 *
	 * @param array $data Array of new sharing options to save.
	 */
	public function set_global_options( $data ) {
		$options = get_option( 'sharing-options' );

		// No options yet.
		if ( ! is_array( $options ) ) {
			$options = array();
		}

		// Defaults.
		$options['global'] = array(
			'button_style'  => 'icon-text',
			'sharing_label' => $this->default_sharing_label,
			'open_links'    => 'same',
			'show'          => ! isset( $options['global'] ) ? array( 'post', 'page' ) : array(),
			'custom'        => isset( $options['global']['custom'] ) ? $options['global']['custom'] : array(),
		);

		/**
		 * Filters global sharing settings.
		 *
		 * @module sharedaddy
		 *
		 * @since 1.1.0
		 *
		 * @param array $options['global'] Array of global sharing settings.
		 */
		$options['global'] = apply_filters( 'sharing_default_global', $options['global'] );

		// Validate options and set from our data
		if (
			isset( $data['button_style'] )
			&& in_array( $data['button_style'], array( 'icon-text', 'icon', 'text', 'official' ), true )
		) {
			$options['global']['button_style'] = $data['button_style'];
		}

		if ( isset( $data['sharing_label'] ) ) {
			if ( $this->default_sharing_label === $data['sharing_label'] ) {
				$options['global']['sharing_label'] = false;
			} else {
				$options['global']['sharing_label'] = trim( wp_kses( stripslashes( $data['sharing_label'] ), array() ) );
			}
		}

		if (
			isset( $data['open_links'] )
			&& in_array( $data['open_links'], array( 'new', 'same' ), true )
		) {
			$options['global']['open_links'] = $data['open_links'];
		}

		$shows   = array_values( get_post_types( array( 'public' => true ) ) );
		$shows[] = 'index';
		if ( isset( $data['show'] ) ) {
			if ( is_scalar( $data['show'] ) ) {
				switch ( $data['show'] ) {
					case 'posts':
						$data['show'] = array( 'post', 'page' );
						break;
					case 'index':
						$data['show'] = array( 'index' );
						break;
					case 'posts-index':
						$data['show'] = array( 'post', 'page', 'index' );
						break;
				}
			}

			$data['show'] = array_intersect( $data['show'], $shows );
			if ( $data['show'] ) {
				$options['global']['show'] = $data['show'];
			}
		}

		update_option( 'sharing-options', $options );
		return $options['global'];
	}

	/**
	 * Get global sharing options for the site.
	 *
	 * @return array
	 */
	public function get_global_options() {
		if ( $this->global === false ) {
			$options = get_option( 'sharing-options' );

			if ( is_array( $options ) && isset( $options['global'] ) && is_array( $options['global'] ) ) {
				$this->global = $options['global'];
			} else {
				$this->global = $this->set_global_options( $options );
			}
		}

		if ( ! isset( $this->global['show'] ) ) {
			$this->global['show'] = array( 'post', 'page' );
		} elseif ( is_scalar( $this->global['show'] ) ) {
			switch ( $this->global['show'] ) {
				case 'posts':
					$this->global['show'] = array( 'post', 'page' );
					break;
				case 'index':
					$this->global['show'] = array( 'index' );
					break;
				case 'posts-index':
					$this->global['show'] = array( 'post', 'page', 'index' );
					break;
			}
		}

		if ( false === $this->global['sharing_label'] ) {
			$this->global['sharing_label'] = $this->default_sharing_label;
		}

		return $this->global;
	}

	/**
	 * Save a sharing service for use.
	 *
	 * @param int            $id Sharing unique ID.
	 * @param Sharing_Source $service Sharing service.
	 *
	 * @return void
	 */
	public function set_service( $id, Sharing_Source $service ) {
		// Update the options for this service
		$options = get_option( 'sharing-options' );

		// No options yet
		if ( ! is_array( $options ) ) {
			$options = array();
		}

		/**
		 * Get the state of a sharing button.
		 *
		 * @module sharedaddy
		 *
		 * @since 1.1.0
		 *
		 * @param array $args {
		 *  State of a sharing button.
		 *
		 *  @type string $id Service ID.
		 *  @type array $options Array of all sharing options.
		 *  @type array $service Details about a service.
		 * }
		 */
		do_action(
			'sharing_get_button_state',
			array(
				'id'      => $id,
				'options' => $options,
				'service' => $service,
			)
		);

		$options[ $id ] = $service->get_options();

		update_option( 'sharing-options', array_filter( $options ) );
	}

	/**
	 * Get stats for a site, a post, or a sharing service.
	 * Soon to come to a .org plugin near you!
	 *
	 * @param string|bool $service_name Service name.
	 * @param int|bool    $post_id      Post ID.
	 * @param int|bool    $_blog_id     Blog ID.
	 *
	 * @return int
	 */
	public function get_total( $service_name = false, $post_id = false, $_blog_id = false ) {
		global $wpdb, $blog_id;
		if ( ! $_blog_id ) {
			$_blog_id = $blog_id;
		}
		if ( $service_name === false ) {
			if ( $post_id > 0 ) {
				// total number of shares for this post
				$sql       = $wpdb->prepare( 'SELECT SUM( count ) FROM sharing_stats WHERE blog_id = %d AND post_id = %d', $_blog_id, $post_id );
				$cache_key = "sharing_service_get_total_b{$_blog_id}_p{$post_id}";
			} else {
				// total number of shares for this blog
				$sql       = $wpdb->prepare( 'SELECT SUM( count ) FROM sharing_stats WHERE blog_id = %d', $_blog_id );
				$cache_key = "sharing_service_get_total_b{$_blog_id}";
			}
		} elseif ( $post_id > 0 ) {
			$sql       = $wpdb->prepare( 'SELECT SUM( count ) FROM sharing_stats WHERE blog_id = %d AND post_id = %d AND share_service = %s', $_blog_id, $post_id, $service_name );
			$cache_key = "sharing_service_get_total_b{$_blog_id}_p{$post_id}_s{$service_name}";
		} else {
			$sql       = $wpdb->prepare( 'SELECT SUM( count ) FROM sharing_stats WHERE blog_id = %d AND share_service = %s', $_blog_id, $service_name );
			$cache_key = "sharing_service_get_total_b{$_blog_id}_s{$service_name}";
		}

		$ret = wp_cache_get( $cache_key, 'sharing' );
		if ( $ret === false ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery -- Prepared above.
			$ret = (int) $wpdb->get_var( $sql );
			wp_cache_set( $cache_key, $ret, 'sharing', 5 * MINUTE_IN_SECONDS );
		}
		return $ret;
	}

	/**
	 * Get total stats for a site, for all sharing services.
	 *
	 * @param int|bool $post_id Post ID.
	 *
	 * @return array
	 */
	public function get_services_total( $post_id = false ) {
		$totals   = array();
		$services = $this->get_blog_services();

		if ( ! empty( $services ) && isset( $services['all'] ) ) {
			foreach ( $services['all'] as $key => $value ) {
				$totals[ $key ] = new Sharing_Service_Total( $key, $this->get_total( $key, $post_id ) );
			}
		}
		usort( $totals, array( 'Sharing_Service_Total', 'cmp' ) );

		return $totals;
	}

	/**
	 * Get sharing stats for all posts on the site.
	 *
	 * @return array
	 */
	public function get_posts_total() {
		$totals = array();
		global $wpdb, $blog_id;

		$cache_key = "sharing_service_get_posts_total_{$blog_id}";
		$my_data   = wp_cache_get( $cache_key, 'sharing' );
		if ( $my_data === false ) {
			$my_data = $wpdb->get_results( $wpdb->prepare( 'SELECT post_id as id, SUM( count ) as total FROM sharing_stats WHERE blog_id = %d GROUP BY post_id ORDER BY count DESC ', $blog_id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			wp_cache_set( $cache_key, $my_data, 'sharing', 5 * MINUTE_IN_SECONDS );
		}

		if ( ! empty( $my_data ) ) {
			foreach ( $my_data as $row ) {
				$totals[] = new Sharing_Post_Total( $row->id, $row->total );
			}
		}

		usort( $totals, array( 'Sharing_Post_Total', 'cmp' ) );

		return $totals;
	}
}

/**
 * Get stats for a specific sharing service.
 */
class Sharing_Service_Total {
	/**
	 * Sharing service ID.
	 *
	 * @var int
	 */
	public $id = '';

	/**
	 * Service name.
	 *
	 * @var string
	 */
	public $name = '';

	/**
	 * Sharing service name.
	 *
	 * @var string
	 */
	public $service = '';

	/**
	 * Total number of shares for this service.
	 *
	 * @var string
	 */
	public $total = 0;

	/**
	 * Constructor.
	 *
	 * @param int $id      Service ID.
	 * @param int $total   Total shares.
	 */
	public function __construct( $id, $total ) {
		$services      = new Sharing_Service();
		$this->id      = esc_html( $id );
		$this->service = $services->get_service( $id );
		$this->total   = (int) $total;

		$this->name = $this->service->get_name();
	}

	/**
	 * Compare total shares between 2 posts.
	 *
	 * @param object $a Sharing_Service_Total object.
	 * @param object $b Sharing_Service_Total object.
	 *
	 * @return bool
	 */
	public static function cmp( $a, $b ) {
		if ( $a->total === $b->total ) {
			return $a->name < $b->name;
		}
		return $a->total < $b->total;
	}
}

/**
 * Get sharing stats for a specific post.
 */
class Sharing_Post_Total {
	/**
	 * Sharing service ID.
	 *
	 * @var int
	 */
	public $id = 0;

	/**
	 * Total shares.
	 *
	 * @var int
	 */
	public $total = 0;

	/**
	 * Post title.
	 *
	 * @var string
	 */
	public $title = '';

	/**
	 * Post permalink.
	 *
	 * @var string
	 */
	public $url = '';

	/**
	 * Constructor.
	 *
	 * @param int $id      Service ID.
	 * @param int $total   Total shares.
	 */
	public function __construct( $id, $total ) {
		$this->id    = (int) $id;
		$this->total = (int) $total;
		$this->title = get_the_title( $this->id );
		$this->url   = get_permalink( $this->id );
	}

	/**
	 * Compare total shares between 2 posts.
	 *
	 * @param object $a Sharing_Post_Total object.
	 * @param object $b Sharing_Post_Total object.
	 *
	 * @return bool
	 */
	public static function cmp( $a, $b ) {
		if ( $a->total === $b->total ) {
			return $a->id < $b->id;
		}
		return $a->total < $b->total;
	}
}

/**
 * Populate sharing counts global with a post we want to count shares for.
 *
 * @param int $post_id Post ID.
 *
 * @return void
 */
function sharing_register_post_for_share_counts( $post_id ) {
	global $jetpack_sharing_counts;

	if ( ! isset( $jetpack_sharing_counts ) || ! is_array( $jetpack_sharing_counts ) ) {
		$jetpack_sharing_counts = array();
	}

	$jetpack_sharing_counts[ (int) $post_id ] = get_permalink( $post_id );
}

/**
 * Determine whether we should load sharing scripts or not.
 *
 * @return bool
 */
function sharing_maybe_enqueue_scripts() {
	$sharer         = new Sharing_Service();
	$global_options = $sharer->get_global_options();

	$enqueue = false;
	if ( is_singular() && in_array( get_post_type(), $global_options['show'], true ) ) {
		$enqueue = true;
	} elseif (
		in_array( 'index', $global_options['show'], true )
		&& (
			is_home()
			|| is_front_page()
			|| is_archive()
			|| is_search()
			|| in_array( get_post_type(), $global_options['show'], true )
		)
	) {
		$enqueue = true;
	}

	/**
	 * Filter to decide when sharing scripts should be enqueued.
	 *
	 * @module sharedaddy
	 *
	 * @since 3.2.0
	 *
	 * @param bool $enqueue Decide if the sharing scripts should be enqueued.
	 */
	return (bool) apply_filters( 'sharing_enqueue_scripts', $enqueue );
}

/**
 * Add sharing JavaScript to the footer of a page.
 *
 * @return void
 */
function sharing_add_footer() {
	if (
		class_exists( 'Jetpack_AMP_Support' )
		&& Jetpack_AMP_Support::is_amp_request()
	) {
		return;
	}

	global $jetpack_sharing_counts;

	if (
		/**
		 * Filter all JavaScript output by the sharing module.
		 *
		 * @module sharedaddy
		 *
		 * @since 1.1.0
		 *
		 * @param bool true Control whether the sharing module should add any JavaScript to the site. Default to true.
		 */
		apply_filters( 'sharing_js', true )
		&& sharing_maybe_enqueue_scripts()
	) {
		if (
			/**
			 * Filter the display of sharing counts next to the sharing buttons.
			 *
			 * @module sharedaddy
			 *
			 * @since 3.2.0
			 *
			 * @param bool true Control the display of counters next to the sharing buttons. Default to true.
			 */
			apply_filters( 'jetpack_sharing_counts', true )
			&& is_array( $jetpack_sharing_counts )
			&& count( $jetpack_sharing_counts )
		) :
			$sharing_post_urls = array_filter( $jetpack_sharing_counts );
			if ( $sharing_post_urls ) :
				?>

	<script type="text/javascript">
		window.WPCOM_sharing_counts = <?php echo wp_json_encode( array_flip( $sharing_post_urls ) ); ?>;
	</script>
				<?php
			endif;
		endif;

		wp_enqueue_script( 'sharing-js' );
		$sharing_js_options = array(
			'lang'            => get_base_recaptcha_lang_code(),
			/** This filter is documented in modules/sharedaddy/sharing-service.php */
			'counts'          => apply_filters( 'jetpack_sharing_counts', true ),
			'is_stats_active' => Jetpack::is_module_active( 'stats' ),
		);
		wp_localize_script( 'sharing-js', 'sharing_js_options', $sharing_js_options );
	}
	$sharer  = new Sharing_Service();
	$enabled = $sharer->get_blog_services();
	foreach ( array_merge( $enabled['visible'], $enabled['hidden'] ) as $service ) {
		$service->display_footer();
	}
}

/**
 * Enqueue sharing CSS in head.
 *
 * @return void
 */
function sharing_add_header() {
	$sharer  = new Sharing_Service();
	$enabled = $sharer->get_blog_services();

	foreach ( array_merge( $enabled['visible'], $enabled['hidden'] ) as $service ) {
		$service->display_header();
	}

	if ( count( $enabled['all'] ) > 0 && sharing_maybe_enqueue_scripts() ) {
		wp_enqueue_style( 'sharedaddy', plugin_dir_url( __FILE__ ) . 'sharing.css', array(), JETPACK__VERSION );
		wp_enqueue_style( 'social-logos' );
	}
}
add_action( 'wp_head', 'sharing_add_header', 1 );

/**
 * Launch sharing requests on page load when a specific query string is used.
 *
 * @return void
 */
function sharing_process_requests() {
	global $post;

	// Only process if: single post and share=X defined
	if ( ( is_page() || is_single() ) && isset( $_GET['share'] ) && is_string( $_GET['share'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$sharer = new Sharing_Service();

		$service = $sharer->get_service( sanitize_text_field( wp_unslash( $_GET['share'] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( $service ) {
			$service->process_request( $post, $_POST ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
		}
	}
}
add_action( 'template_redirect', 'sharing_process_requests', 9 );

/**
 * Gets the url to customise the sharing buttons in Calypso.
 *
 * @return string the customisation URL or null if it couldn't be determinde.
 */
function get_sharing_buttons_customisation_url() {
	return Redirect::get_url( 'calypso-marketing-sharing-buttons', array( 'site' => ( new Status() )->get_site_suffix() ) );
}

/**
 * Append sharing links to text.
 *
 * @param string $text The original text to append sharing links onto.
 * @param bool   $echo Where to echo the text or return.
 *
 * @return string The original $text with, if conditions are met, the sharing links.
 */
function sharing_display( $text = '', $echo = false ) {
	global $post, $wp_current_filter;

	if ( Settings::is_syncing() ) {
		return $text;
	}

	if ( empty( $post ) ) {
		return $text;
	}

	if ( ( is_preview() || is_admin() ) && ! ( defined( 'DOING_AJAX' ) && DOING_AJAX ) ) {
		return $text;
	}

	// Prevent from rendering sharing buttons in block which is fetched from REST endpoint by editor
	if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
		return $text;
	}

	// Don't output flair on excerpts.
	if ( in_array( 'get_the_excerpt', (array) $wp_current_filter, true ) ) {
		return $text;
	}

	// Ensure we don't display sharing buttons on post excerpts that are hooked inside the post content
	if ( in_array( 'the_excerpt', (array) $wp_current_filter, true ) &&
		in_array( 'the_content', (array) $wp_current_filter, true ) ) {
		return $text;
	}

	// Don't allow flair to be added to the_content more than once (prevent infinite loops).
	$done = false;
	foreach ( $wp_current_filter as $filter ) {
		if ( 'the_content' === $filter ) {
			if ( $done ) {
				return $text;
			} else {
				$done = true;
			}
		}
	}

	// check whether we are viewing the front page and whether the front page option is checked.
	$options         = get_option( 'sharing-options' );
	$display_options = null;

	if ( is_array( $options ) ) {
		$display_options = $options['global']['show'];
	}

	if ( is_front_page() && ( is_array( $display_options ) && ! in_array( 'index', $display_options, true ) ) ) {
		return $text;
	}

	if ( is_attachment() && in_array( 'the_excerpt', (array) $wp_current_filter, true ) ) {
		// Many themes run the_excerpt() conditionally on an attachment page, then run the_content().
		// We only want to output the sharing buttons once.  Let's stick with the_content().
		return $text;
	}

	$sharer = new Sharing_Service();
	$global = $sharer->get_global_options();

	$show = false;
	if ( ! is_feed() ) {
		if ( is_singular() && in_array( get_post_type(), $global['show'], true ) ) {
			$show = true;
		} elseif ( in_array( 'index', $global['show'], true ) && ( is_home() || is_front_page() || is_archive() || is_search() || in_array( get_post_type(), $global['show'], true ) ) ) {
			$show = true;
		}
	}

	/**
	 * Filter to decide if sharing buttons should be displayed.
	 *
	 * @module sharedaddy
	 *
	 * @since 1.1.0
	 *
	 * @param bool $show Should the sharing buttons be displayed.
	 * @param WP_Post $post The post to share.
	 */
	$show = apply_filters( 'sharing_show', $show, $post );

	// Disabled for this post?
	$switched_status = get_post_meta( $post->ID, 'sharing_disabled', false );

	if ( ! empty( $switched_status ) ) {
		$show = false;
	}

	// Is the post private?
	$post_status = get_post_status( $post->ID );

	if ( 'private' === $post_status ) {
		$show = false;
	}

	// Hide on password protected posts unless password is provided.
	if ( post_password_required( $post->ID ) ) {
			$show = false;
	}

	/**
	 * Filter the Sharing buttons' Ajax action name Jetpack checks for.
	 * This allows the use of the buttons with your own Ajax implementation.
	 *
	 * @module sharedaddy
	 *
	 * @since 7.3.0
	 *
	 * @param string $sharing_ajax_action_name Name of the Sharing buttons' Ajax action.
	 */
	$ajax_action = apply_filters( 'sharing_ajax_action', 'get_latest_posts' );

	// Allow to be used in ajax requests for latest posts.
	if (
		defined( 'DOING_AJAX' )
		&& DOING_AJAX
		&& isset( $_REQUEST['action'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce handling happens within each custom implementation.
		&& $ajax_action === $_REQUEST['action'] // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce handling happens within each custom implementation.
	) {
		$show = true;
	}

	$sharing_content = '';
	$enabled         = false;

	if ( $show ) {
		/**
		 * Filters the list of enabled Sharing Services.
		 *
		 * @module sharedaddy
		 *
		 * @since 2.2.3
		 *
		 * @param array $sharer->get_blog_services() Array of Sharing Services currently enabled.
		 */
		$enabled = apply_filters( 'sharing_enabled', $sharer->get_blog_services() );

		if ( count( $enabled['all'] ) > 0 ) {
			$dir = get_option( 'text_direction' );

			// Wrapper.
			$sharing_content .= '<div class="sharedaddy sd-sharing-enabled"><div class="robots-nocontent sd-block sd-social sd-social-' . $global['button_style'] . ' sd-sharing">';
			if ( '' !== $global['sharing_label'] ) {
				$sharing_content .= sprintf(
					/**
					 * Filter the sharing buttons' headline structure.
					 *
					 * @module sharedaddy
					 *
					 * @since 4.4.0
					 *
					 * @param string $sharing_headline Sharing headline structure.
					 * @param string $global['sharing_label'] Sharing title.
					 * @param string $sharing Module name.
					 */
					apply_filters( 'jetpack_sharing_headline_html', '<h3 class="sd-title">%s</h3>', $global['sharing_label'], 'sharing' ),
					esc_html( $global['sharing_label'] )
				);
			}
			$sharing_content .= '<div class="sd-content"><ul>';

			// Visible items.
			$visible = '';
			foreach ( $enabled['visible'] as $service ) {
				$klasses = array( 'share-' . $service->get_class() );
				if ( $service->is_deprecated() ) {
					if ( ! current_user_can( 'manage_options' ) ) {
						continue;
					}
					$klasses[] = 'share-deprecated';
				}
				// Individual HTML for sharing service.
				$visible .= '<li class="' . implode( ' ', $klasses ) . '">' . $service->get_display( $post ) . '</li>';
			}

			$parts   = array();
			$parts[] = $visible;
			if ( count( $enabled['hidden'] ) > 0 ) {
				if ( count( $enabled['visible'] ) > 0 ) {
					$expand = __( 'More', 'jetpack' );
				} else {
					$expand = __( 'Share', 'jetpack' );
				}
				$parts[] = '<li><a href="#" class="sharing-anchor sd-button share-more"><span>' . $expand . '</span></a></li>';
			}

			if ( 'rtl' === $dir ) {
				$parts = array_reverse( $parts );
			}

			$sharing_content .= implode( '', $parts );
			$sharing_content .= '<li class="share-end"></li></ul>';

			// Link to customization options if user can manage them.
			if ( current_user_can( 'manage_options' ) ) {
				$link_url = get_sharing_buttons_customisation_url();
				if ( ! empty( $link_url ) ) {
					$link_text        = __( 'Customize buttons', 'jetpack' );
					$sharing_content .= '<p class="share-customize-link"><a href="' . esc_url( $link_url ) . '" target="_blank" rel="noopener noreferrer">' . esc_html( $link_text ) . '</a></p>';
				}
			}

			if ( count( $enabled['hidden'] ) > 0 ) {
				$sharing_content .= '<div class="sharing-hidden"><div class="inner" style="display: none;';

				if ( count( $enabled['hidden'] ) === 1 ) {
					$sharing_content .= 'width:150px;';
				}

				$sharing_content .= '">';

				if ( count( $enabled['hidden'] ) === 1 ) {
					$sharing_content .= '<ul style="background-image:none;">';
				} else {
					$sharing_content .= '<ul>';
				}

				foreach ( $enabled['hidden'] as $service ) {
					// Individual HTML for sharing service.
					$klasses = array( 'share-' . $service->get_class() );
					if ( $service->is_deprecated() ) {
						if ( ! current_user_can( 'manage_options' ) ) {
							continue;
						}
						$klasses[] = 'share-deprecated';
					}
					$sharing_content .= '<li class="' . implode( ' ', $klasses ) . '">';
					$sharing_content .= $service->get_display( $post );
					$sharing_content .= '</li>';
				}

				// End of wrapper.
				$sharing_content .= '<li class="share-end"></li></ul></div></div>';
			}

			$sharing_content .= '</div></div></div>';

			// Register our JS.
			if ( defined( 'JETPACK__VERSION' ) ) {
				$ver = JETPACK__VERSION;
			} else {
				$ver = '20211226';
			}

			// @todo: Investigate if we can load this JS in the footer instead.
			wp_register_script(
				'sharing-js',
				Assets::get_file_url_for_environment(
					'_inc/build/sharedaddy/sharing.min.js',
					'modules/sharedaddy/sharing.js'
				),
				array(),
				$ver,
				false
			);

			// Enqueue scripts for the footer.
			add_action( 'wp_footer', 'sharing_add_footer' );
		}
	}

	/**
	 * Filters the content markup of the Jetpack sharing links
	 *
	 * @module sharedaddy
	 *
	 * @since 3.8.0
	 * @since 6.2.0 Started sending $enabled as a second parameter.
	 *
	 * @param string $sharing_content Content markup of the Jetpack sharing links
	 * @param array  $enabled         Array of Sharing Services currently enabled.
	 */
	$sharing_markup = apply_filters( 'jetpack_sharing_display_markup', $sharing_content, $enabled );

	if ( $echo ) {
		echo $text . $sharing_markup; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	} else {
		return $text . $sharing_markup;
	}
}

/**
 * Get reCAPTCHA language code based off the language code of the site.
 *
 * @return string
 */
function get_base_recaptcha_lang_code() {
	$base_recaptcha_lang_code_mapping = array(
		'en'    => 'en',
		'nl'    => 'nl',
		'fr'    => 'fr',
		'fr-be' => 'fr',
		'fr-ca' => 'fr',
		'fr-ch' => 'fr',
		'de'    => 'de',
		'pt'    => 'pt',
		'pt-br' => 'pt',
		'ru'    => 'ru',
		'es'    => 'es',
		'tr'    => 'tr',
	);

	$blog_lang_code = get_bloginfo( 'language' );
	if ( isset( $base_recaptcha_lang_code_mapping[ $blog_lang_code ] ) ) {
		return $base_recaptcha_lang_code_mapping[ $blog_lang_code ];
	}

	// if no base mapping is found return default 'en'
	return 'en';
}

Sharing_Service::init();
