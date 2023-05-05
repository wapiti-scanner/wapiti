<?php
/**
 * PostSettings class.
 *
 * @package automattic/jetpack-publicize
 */

namespace Automattic\Jetpack\Publicize\Social_Image_Generator;

use Automattic\Jetpack\Publicize\Publicize;

/**
 * This class is used to get SIG-specific information from a post.
 */
class Post_Settings {
	/**
	 * Post to get information from.
	 *
	 * @var int $post_id
	 */
	public $post_id;

	/**
	 * The post's settings.
	 *
	 * @var array $settings;
	 */
	public $settings;

	/**
	 * Constructor.
	 *
	 * @param int $post_id Post to get information from.
	 */
	public function __construct( $post_id ) {
		$this->post_id  = $post_id;
		$this->settings = $this->get_settings();
	}

	/**
	 * Get the SIG settings.
	 *
	 * @param bool $raw Whether to get the raw settings, skipping the defaults.
	 * @return array
	 */
	public function get_settings( $raw = false ) {
		$social_options = $raw
			? get_metadata_raw( 'post', $this->post_id, Publicize::POST_JETPACK_SOCIAL_OPTIONS, true )
			: get_post_meta( $this->post_id, Publicize::POST_JETPACK_SOCIAL_OPTIONS, true );

		if ( ! is_array( $social_options ) || empty( $social_options['image_generator_settings'] ) ) {
			return array();
		}

		return $social_options['image_generator_settings'];
	}

	/**
	 * Update a SIG setting.
	 *
	 * @param string $key The key to update.
	 * @param mixed  $value The value to set for the key.
	 * @return bool True if the update was successful.
	 */
	public function update_setting( $key, $value ) {
		$social_options = get_post_meta( $this->post_id, Publicize::POST_JETPACK_SOCIAL_OPTIONS, true );

		if ( empty( $social_options ) ) {
			$social_options = array();
		}

		$updated_options = array_replace_recursive( $social_options, array( 'image_generator_settings' => array( $key => $value ) ) );

		$updated = update_post_meta( $this->post_id, Publicize::POST_JETPACK_SOCIAL_OPTIONS, $updated_options );

		if ( $updated ) {
			$this->settings = $updated_options['image_generator_settings'];
		}

		return (bool) $updated;
	}

	/**
	 * Check if SIG is enabled for a specific post.
	 *
	 * @return bool
	 */
	public function is_enabled() {
		return ! empty( $this->settings['enabled'] );
	}

	/**
	 * Get the text to use for the generated image.
	 *
	 * @return string
	 */
	public function get_custom_text() {
		if ( ! empty( $this->settings['custom_text'] ) ) {
			return $this->settings['custom_text'];
		}

		return get_the_title( $this->post_id );
	}

	/**
	 * Get the image type for the generated image.
	 *
	 * @return string
	 */
	public function get_image_type() {
		$type = isset( $this->settings['image_type'] ) ? $this->settings['image_type'] : null;

		// By default, we use the featured image.
		if ( empty( $type ) ) {
			return 'featured';
		}

		return $type;
	}

	/**
	 * Get the image to use for the generated image.
	 *
	 * @return ?string
	 */
	public function get_image_url() {
		$type = $this->get_image_type();

		switch ( $type ) {
			case 'featured':
				$image_id = get_post_thumbnail_id( $this->post_id );
				break;
			case 'custom':
				$image_id = isset( $this->settings['image_id'] ) ? $this->settings['image_id'] : null;
				break;
			case 'none':
				return null;
		}

		if ( empty( $image_id ) ) {
			return null;
		}

		$url = wp_get_attachment_image_url( $image_id, 'large' );

		if ( ! $url ) {
			return null;
		}

		return $url;
	}

	/**
	 * Get the template to use for the generated image.
	 *
	 * @return string
	 */
	public function get_template() {
		if ( ! empty( $this->settings['template'] ) ) {
			return $this->settings['template'];
		}

		return Templates::DEFAULT_TEMPLATE;
	}

	/**
	 * Get an image token.
	 *
	 * @return string
	 */
	public function get_token() {
		return ! empty( $this->settings['token'] ) ? $this->settings['token'] : '';
	}
}
