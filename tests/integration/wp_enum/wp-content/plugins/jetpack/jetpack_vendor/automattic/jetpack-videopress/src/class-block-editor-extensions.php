<?php
/**
 * VideoPress Extensions
 *
 * @package automattic/jetpack-videopress
 */

namespace Automattic\Jetpack\VideoPress;

use Automattic\Jetpack\Connection\Initial_State as Connection_Initial_State;
use Automattic\Jetpack\Constants;
use Automattic\Jetpack\Status\Host;

/**
 * VideoPress Extensions class.
 */
class Block_Editor_Extensions {
	/**
	 * What version of the blocks we are loading.
	 *
	 * @var string
	 */
	public static $blocks_variation = 'production';

	/**
	 * Script handle
	 *
	 * @var string
	 */
	public static $script_handle = '';

	/**
	 * Initializer
	 *
	 * This method should be called only once by the Block registrar.
	 * Do not call this method again.
	 *
	 * @param string $script_handle - The script handle.
	 */
	public static function init( $script_handle ) {
		if ( ! Status::is_registrant_plugin_active() ) {
			return;
		}

		/*
		 * Use the videopress/video editor script handle to localize enqueue scripts.
		 * @see https://developer.wordpress.org/reference/functions/generate_block_asset_handle
		 */
		self::$script_handle = $script_handle;

		/**
		* Alternative to `JETPACK_BETA_BLOCKS`, set to `true` to load Beta Blocks.
		*
		* @since 6.9.0
		* @deprecated Jetpack 11.8.0 Use jetpack_blocks_variation filter instead.
		*
		* @param boolean
		*/
		if (
			apply_filters_deprecated(
				'jetpack_load_beta_blocks',
				array( false ),
				'jetpack-11.8.0',
				'jetpack_blocks_variation'
			)
		) {
			self::$blocks_variation = 'beta';
		}

		/*
		 * Get block variation, from the new constant or the old one.
		 */
		if ( Constants::is_true( 'JETPACK_BETA_BLOCKS' ) ) {
			self::$blocks_variation = 'beta';
		}

		$blocks_variation = Constants::get_constant( 'JETPACK_BLOCKS_VARIATION' );
		if ( ! empty( $blocks_variation ) ) {
			/**
			 * Allow customizing the variation of blocks in use on a site.
			 * Overwrites any previously set values, whether by constant or filter.
			 *
			 * @since Jetpack 8.1.0
			 *
			 * @param string $block_variation Can be beta, experimental, and production. Defaults to production.
			 */
			self::$blocks_variation = apply_filters( 'jetpack_blocks_variation', $blocks_variation );
		}

		// Register the script.
		add_action( 'enqueue_block_editor_assets', array( __CLASS__, 'enqueue_extensions' ), 1 );
	}

	/**
	 * Return the extensions list
	 *
	 * @return array The extensions list.
	 */
	public static function get_list() {
		$videopress_extensions_file        = __DIR__ . '/../build/block-editor/extensions/index.json';
		$videopress_extensions_file_exists = file_exists( $videopress_extensions_file );
		if ( ! $videopress_extensions_file_exists ) {
			return;
		}

		$videopress_extensions_data = (array) json_decode(
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			file_get_contents( $videopress_extensions_file )
		);

		$extensions_list = array_map(
			function ( $extension ) {
				return (array) array(
					'name'      => $extension,
					'isBeta'    => true,
					'isEnabled' => 'beta' === self::$blocks_variation,
				);
			},
			$videopress_extensions_data['beta']
		);

		return $extensions_list;
	}

	/**
	 * Check if the extension is available
	 *
	 * @param string $slug The extension slug.
	 * @return boolean True if the extension is available, false otherwise.
	 */
	public static function is_extension_available( $slug ) {
		$extensions_list = self::get_list();
		foreach ( $extensions_list as $extension ) {
			if ( $extension['name'] === $slug ) {
				return $extension['isEnabled'];
			}
		}

		return false;
	}

	/**
	 * Enqueues the extensions script.
	 */
	public static function enqueue_extensions() {
		$extensions_list = self::get_list();

		$site_type = 'jetpack';
		if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
			$site_type = 'simple';
		} elseif ( ( new Host() )->is_woa_site() ) {
			$site_type = 'atomic';
		}

		$videopress_editor_state = array(
			'extensions'                  => $extensions_list,
			'siteType'                    => $site_type,
			'myJetpackConnectUrl'         => admin_url( 'admin.php?page=my-jetpack#/connection' ),
			'jetpackVideoPressSettingUrl' => admin_url( 'admin.php?page=jetpack#/settings?term=videopress' ),
			'isVideoPressModuleActive'    => Status::is_jetpack_plugin_and_videopress_module_active(),
			'isStandaloneActive'          => Status::is_standalone_plugin_active(),
			'imagesURLBase'               => plugin_dir_url( __DIR__ ) . 'build/images/',
			'playerBridgeUrl'             => plugins_url( '../build/lib/player-bridge.js', __FILE__ ),
		);

		// Expose initital state of site connection
		wp_add_inline_script( self::$script_handle, Connection_Initial_State::render(), 'before' );

		// Expose initital state of videoPress editor
		wp_localize_script( self::$script_handle, 'videoPressEditorState', $videopress_editor_state );
	}
}
